/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif


#include "pcap.h"
#include "packetparser.h"
#include"packetmanager.h"
#include <time.h>


/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


pcap_t *adhandle;

int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;
    char packet_filter[] = "arp";
                           //"tcp or udp";
    struct bpf_program fcode;

    /* Retrieve the device list */
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &inum);

    /* Check if the user specified a valid adapter */
    if(inum < 1 || inum > i)
    {
        printf("\nAdapter number out of range.\n");

        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }


    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

    /* Open the adapter */
    if ((adhandle= pcap_open_live(d->name,	// name of the device
                             65536,			// portion of the packet to capture.
                                            // 65536 grants that the whole packet will be captured on all the MACs.
                             1,				// promiscuous mode (nonzero means promiscuous)
                             1000,			// read timeout
                             errbuf			// error buffer
                             )) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. is not supported by WinPcap\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }



    /* Check the link layer. We support only Ethernet for simplicity. */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }


    if(d->addresses != NULL)
    {
        /* Retrieve the mask of the first address of the interface */
        if(d->addresses->netmask)
        {
#ifdef WIN32
            netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
#else
            netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.s_addr;
#endif
            printf("netmask set\n");
        }
        else
        {
            netmask=0xffffff;
            printf("netmask error\n");
        }
    }
    else
    {
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask=0xffffff;
        printf("netmask error\n");
    }


    /* start the capture */
    //pcap_loop(adhandle, 0, packet_handler, NULL);
    u_int8_t ipSourceBuffer[]={1,1,1,1,1,1,1,0,0,};
    u_int8_t ipDestinationBuffer[]={2,2,2,2,2,2,2,0,0,};
    u_int8_t arpEtherSourceBuffer[]={1,1,1,1,1,1,1,0,0,};
    u_int8_t arpEtherDestinationBuffer[]={2,2,2,2,2,2,2,0,0,};
    u_int8_t etherSourceBuffer[]={1,1,1,1,1,1,1,0,0,};
    u_int8_t etherDestinationBuffer[]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0,0,};
    u_int8_t operation;
    printf("\nEthernet config :\n");

    printf("\nenter source mac address:");
    for(int i=0;i<5;i++)
        scanf("%02x:",etherSourceBuffer+i);
    scanf("%02x",etherSourceBuffer+5);

    printf("\nenter destination mac address:");
    for(int i=0;i<5;i++)
        scanf("%02x:",etherDestinationBuffer+i);
    scanf("%02x",etherDestinationBuffer+5);

    printf("\nARP config :\n");
    printf("\noperation Type (1:request/2:reply):");
    scanf("%d",&operation);

    printf("\nenter source mac address:");
    for(int i=0;i<5;i++)
        scanf("%02x:",arpEtherSourceBuffer+i);
    scanf("%02x",arpEtherSourceBuffer+5);

    printf("\nenter source ip address:");
    for(int i=0;i<3;i++)
        scanf("%02x.",ipSourceBuffer+i);
    scanf("%02x",ipSourceBuffer+3);

    printf("\nenter destination mac address:");
    for(int i=0;i<5;i++)
        scanf("%02x:",arpEtherDestinationBuffer+i);
    scanf("%02x",arpEtherDestinationBuffer+5);

    printf("\nenter destination ip address:");
    for(int i=0;i<3;i++)
        scanf("%02x.",ipDestinationBuffer+i);
    scanf("%02x",ipDestinationBuffer+3);

    ARPManager* arpManager=new ARPManager(arpEtherSourceBuffer,ipSourceBuffer,arpEtherDestinationBuffer,ipDestinationBuffer,ARPHRD_ETHER,ETHER_ADDR_LEN,ETHERTYPE_IP,4,operation);

    EthernetManager* ethernetManager=new EthernetManager(etherSourceBuffer,etherDestinationBuffer,ETHERTYPE_ARP,arpManager);

    fprintf(stderr,"\nPacket Data : \n");
    u_int8_t* data=ethernetManager->getRawStream();
    for(int i=0;i<ethernetManager->getRawStreamLength();i++)
    {
        if((i+1)%16==0)
            fprintf(stderr,"\n");
        fprintf(stderr,"%02x ",data[i]);
    }
    fprintf(stderr,"\n");

    if(pcap_sendpacket(adhandle,ethernetManager->getRawStream(),ethernetManager->getRawStreamLength()))
        printf("error\n");


    printf("Packet Sended\n");

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
    return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
    Ethernet_Parser ethernetInformation(pkt_data,header->len);
    IP_Parser* ipInformation;
    UDP_Parser* udpInformation;
    TCP_Parser* tcpInformation;
    IPManager* ipInformation2;
    EthernetManager* ethernetInformation2;
    /*
     * unused parameter
     */
    (void)(param);

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* print timestamp and length of the packet */
    printf("%s.%.6d len:%d \n", timestr, header->ts.tv_usec, header->len);

    char* src,* dst, *type;
    u_int8_t* data;
    ProtocolManager* protocolManager    =new EthernetManager((u_int8_t*)pkt_data,header->len);
    ProtocolManager* subProtocolManager;
/*
    subProtocolManager = protocolManager->getSubProtocolManager();
    ((ARPManager*)subProtocolManager)->setHardwareAddress((u_int8_t*)"\0\0\0\0\0\0\0",(u_int8_t*)"\0\0\0\0\0\0\0",6);
    protocolManager->setSubProtocolManager(ETHERTYPE_ARP,subProtocolManager);
    delete subProtocolManager;
*/
    fprintf(stderr,"Data : ");
    data=protocolManager->getRawStream();
    for(int i=0;i<protocolManager->getRawStreamLength();i++)
    {
        if((i+1)%16==0)
            fprintf(stderr,"\n");
        fprintf(stderr,"%02x ",data[i]);
    }
    fprintf(stderr,"\n");
    if(pcap_sendpacket(adhandle,pkt_data,header->len))
//    if(pcap_sendpacket(adhandle,data,protocolManager->getRawStreamLength()))
        fprintf(stderr,"error\n");
    delete data;
    //delete protocolManager;
//*
    while(protocolManager)
    {
        type=protocolManager->getProtocolTypeAsString();
        src=protocolManager->getSourceAddressAsString();
        dst=protocolManager->getDestinationAddressAsString();

        printf("%s",type);
        for(int i=0;i<2-strlen(type)/8;i++)
            printf("\t");
        if(strlen(type))
            printf(": %s to %s \n",src,dst);

        if(src)
            delete[] src;
        if(dst)
            delete[] dst;
        if(type)
            delete[] type;

        subProtocolManager =protocolManager->getSubProtocolManager();
        delete protocolManager;
        protocolManager=subProtocolManager;
    }
    printf("\n");

}
