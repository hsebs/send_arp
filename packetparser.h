#ifndef PACKETPARSER_H
#define PACKETPARSER_H

#ifdef WIN32
#include<WinSock2.h>
#include"libnet/in_systm.h"
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
typedef u_int32_t n_time;
#endif

#include"libnet/libnet-types.h"
#include"libnet/libnet-macros.h"
#include"libnet/libnet-structures.h"
#include"libnet/libnet-headers.h"
#include"libnet/libnet-functions.h"
#include <string.h>

class Protocol_Parser
{
protected:

public :
    virtual u_int64_t getLength()=0;
    virtual u_int64_t getHeaderLength()=0;
    u_int64_t getDataLength()
    {
        return getLength()-getHeaderLength();
    }
    virtual char* getSourceAddressAsString()=0;
    virtual char* getDestinationAddressAsString()=0;
};

class TCP_Parser : public Protocol_Parser
{
private:
    libnet_tcp_hdr* tcpHeader;
    u_int64_t size;
public :
    TCP_Parser(const u_int8_t* data, u_int64_t size)
    {
        tcpHeader=(libnet_tcp_hdr*)new char[size];
        memcpy(tcpHeader,data,size);
        this->size=size;
    }

    ~TCP_Parser()
    {
        delete tcpHeader;
    }

     u_int64_t getLength()
     {
         return size;
     }

     u_int64_t getHeaderLength()
     {
         u_int64_t hsize= ((*(((u_int8_t*)tcpHeader)+12)&0xf0)>>4)*4;
         return hsize;
     }

     char* getSourceAddressAsString()
     {
        char* buffer = new char[128];
        sprintf(buffer,"%u",ntohs(tcpHeader->th_sport));
        return buffer;
     }

     char* getDestinationAddressAsString()
     {
         char* buffer = new char[128];
         sprintf(buffer,"%u",ntohs(tcpHeader->th_dport));
         return buffer;
     }
};

class UDP_Parser : public Protocol_Parser
{
    libnet_udp_hdr* udpHeader;
public :
    UDP_Parser(const u_int8_t* data)
    {
        udpHeader=(libnet_udp_hdr*)new u_int8_t[ntohs(((libnet_udp_hdr*)data)->uh_ulen)];
        memcpy(udpHeader,data,ntohs(((libnet_udp_hdr*)data)->uh_ulen));
    }
    ~UDP_Parser()
    {
        delete udpHeader;
    }

    u_int64_t getLength()
    {
        return ntohs(udpHeader->uh_ulen);
    }

    u_int64_t getHeaderLength()
    {
        return sizeof(libnet_udp_hdr);
    }

    char* getSourceAddressAsString()
    {
       char* buffer = new char[128];
       sprintf(buffer,"%u",ntohs(udpHeader->uh_sport));
       return buffer;
    }

    char* getDestinationAddressAsString()
    {
        char* buffer = new char[128];
        sprintf(buffer,"%u",ntohs(udpHeader->uh_dport));
        return buffer;
    }
};

class ARP_Parser : public Protocol_Parser
{
private:
    libnet_arp_hdr* arpHeader;
public:
    ARP_Parser(const u_int8_t* data)
    {
        int size=0;
        size+=((libnet_arp_hdr*)data)->ar_pln;
        size+=((libnet_arp_hdr*)data)->ar_hln;
        size*=2;
        size+=sizeof(libnet_arp_hdr);
        arpHeader = (libnet_arp_hdr*)new u_int8_t[size];
        memcpy(arpHeader,data,size);
    }

    ~ARP_Parser()
    {
        delete arpHeader;
    }

    u_int64_t getLength(){
        int size=0;
        size+=arpHeader->ar_pln;
        size+=arpHeader->ar_hln;
        size*=2;
        size+=sizeof(libnet_arp_hdr);
        return size;
    }

    u_int64_t getHeaderLength()
    {
        return sizeof(libnet_arp_hdr);
    }

    char* getDestinationAddressAsString()
    {
        char* buffer=new char[100];
        u_int8_t*  base;
        switch(arpHeader->ar_hrd)
        {
        case ARPHRD_ETHER:
            base=((u_int8_t*)arpHeader)+sizeof(libnet_arp_hdr)+arpHeader->ar_hln+arpHeader->ar_pln;
            for(int i=0;i<arpHeader->ar_hln-1;i++)
                sprintf(buffer+3*i,"%02x:",base[i]);
            sprintf(buffer+3*(arpHeader->ar_hln-1),"%02x\t",base[arpHeader->ar_hln-1]);
            /*
            switch(arpHeader->ar_pro)
            {
            case ETHERTYPE_IP:
                sprintf_s(&buffer[strlen(buffer)], "");
                break;
            }
            */
            break;
        }
        return buffer;
    }

    char* getSourceAddressAsString()
    {
        char* buffer=new char[100];
        u_int8_t*  base;
        switch(arpHeader->ar_hrd)
        {
        case ARPHRD_ETHER:
            base=((u_int8_t*)arpHeader)+sizeof(libnet_arp_hdr);
            for(int i=0;i<arpHeader->ar_hln-1;i++)
                sprintf(buffer+3*i,"%02x:",base[i]);
            sprintf(buffer+3*(arpHeader->ar_hln-1),"%02x\t",base[arpHeader->ar_hln-1]);
            /*
            switch(arpHeader->ar_pro)
            {
            case ETHERTYPE_IP:
                base=((u_int8_t*)arpHeader)+sizeof(libnet_arp_hdr)+arpHeader->ar_hln;
                for(int i=0;i<4;i++)
                {
                }
                sprintf_s(&buffer[strlen(buffer)], "");
                break;
            }
            */
            break;
        }
        return buffer;
    }
};

class IP_Parser : public Protocol_Parser
{
protected:
    libnet_ipv4_hdr * ipv4Header;
    libnet_ipv6_hdr * ipv6Header;
public :
    IP_Parser(const u_int8_t* data)
    {
        ipv4Header=NULL;
        ipv6Header=NULL;

        if((data[0]&0xF0)>>4 == 4)
        {
            ipv4Header=(libnet_ipv4_hdr*)new u_int8_t[ntohs(((libnet_ipv4_hdr*)data)->ip_len)];
            memcpy(ipv4Header,data,ntohs(((libnet_ipv4_hdr*)data)->ip_len));
        }
        if((data[0]&0xF0)>>4 == 6)
        {
            ipv6Header=(libnet_ipv6_hdr*)new u_int8_t[ntohs(((libnet_ipv6_hdr*)data)->ip_len)];
            memcpy(ipv6Header,data,ntohs(((libnet_ipv4_hdr*)data)->ip_len));
        }
    }

    ~IP_Parser()
    {
        if(ipv4Header)
            delete[] (char*)ipv4Header;
        if(ipv6Header)
            delete[] (char*)ipv6Header;

    }

    u_int8_t getVersion()
    {
        if(ipv4Header)
            return 4;
        if(ipv6Header)
            return 6;
        return 0;
    }

    u_int8_t getProtocol()
    {
        if(ipv4Header!=NULL)
            return ipv4Header->ip_p;

        if(ipv6Header!=NULL)
            return 0xFF;

        return 0xFF;
    }

    in_addr         getV4SourceAddress()
    {
        if(ipv4Header!=NULL)
            return ipv4Header->ip_src;
        return {0,};
    }

    libnet_in6_addr getV6SourceAddress()
    {
        if(ipv6Header!=NULL)
            return ipv6Header->ip_src;
        return {0,};
    }

    TCP_Parser* getTCP()
    {
        if(getProtocol()==IPPROTO_TCP)
        {
            if(ipv4Header)
                return new TCP_Parser(((u_int8_t*)ipv4Header)+(*((u_int8_t*)ipv4Header) & 0xf) * 4,getDataLength());
        }
        return NULL;
    }

    UDP_Parser* getUDP()
    {
        if(getProtocol()==IPPROTO_UDP)
        {
            if(ipv4Header)
                return new UDP_Parser(((u_int8_t*)ipv4Header)+(*((u_int8_t*)ipv4Header) & 0xf) * 4);
        }
        return NULL;
    }

    u_int64_t getLength()
    {
        if(ipv4Header!=NULL)
            return ntohs(ipv4Header->ip_len);
        if(ipv6Header!=NULL)
            return ntohs(ipv6Header->ip_len);
        return 0;
    }

    u_int64_t getHeaderLength()
    {
        if(ipv4Header)
            return sizeof(libnet_ipv4_hdr);
        if(ipv6Header)
            return sizeof(libnet_ipv6_hdr);
        return 0;
    }

    char* getDestinationAddressAsString()
    {
        char* buffer=NULL;
        switch(getVersion())
        {
        case 4:
            buffer=new char[20];
#ifdef WIN32
            sprintf(buffer,"%u.%u.%u.%u",ipv4Header->ip_dst.S_un.S_un_b.s_b1,ipv4Header->ip_dst.S_un.S_un_b.s_b2,ipv4Header->ip_dst.S_un.S_un_b.s_b3,ipv4Header->ip_dst.S_un.S_un_b.s_b4);
#else
            sprintf(buffer,"%u.%u.%u.%u",((unsigned char*)&ipv4Header->ip_dst.s_addr)[0],((unsigned char*)&ipv4Header->ip_dst.s_addr)[1],((unsigned char*)&ipv4Header->ip_dst.s_addr)[2],((unsigned char*)&ipv4Header->ip_dst.s_addr)[3]);
#endif
            break;
        case 6:
            buffer=new char[50];
            for(int i=0;i<7;i++)
                sprintf(buffer+5*i,"%04x:",ipv6Header->ip_dst.__u6_addr.__u6_addr16[i]);
            sprintf(buffer+5*7,"%04x",ipv6Header->ip_dst.__u6_addr.__u6_addr16[7]);
            break;
        }
        return buffer;
    }

    char* getSourceAddressAsString()
    {
        char* buffer=NULL;
        switch(getVersion())
        {
        case 4:
            buffer=new char[20];
#ifdef WIN32
            sprintf(buffer,"%u.%u.%u.%u",ipv4Header->ip_src.S_un.S_un_b.s_b1,ipv4Header->ip_src.S_un.S_un_b.s_b2,ipv4Header->ip_src.S_un.S_un_b.s_b3,ipv4Header->ip_src.S_un.S_un_b.s_b4);
#else
            sprintf(buffer,"%u.%u.%u.%u",((unsigned char*)&ipv4Header->ip_src.s_addr)[0],((unsigned char*)&ipv4Header->ip_src.s_addr)[1],((unsigned char*)&ipv4Header->ip_src.s_addr)[2],((unsigned char*)&ipv4Header->ip_src.s_addr)[3]);
#endif
            break;
        case 6:
            buffer=new char[50];
            for(int i=0;i<7;i++)
                sprintf(buffer+5*i,"%04x:",ipv6Header->ip_src.__u6_addr.__u6_addr16[i]);
            sprintf(buffer+5*7,"%04x",ipv6Header->ip_src.__u6_addr.__u6_addr16[7]);
            break;
        }
        return buffer;

    }
};

class Ethernet_Parser: public Protocol_Parser
{
protected:
    libnet_ethernet_hdr* ethernetHeader;
    u_int32_t size;
public :
    Ethernet_Parser(const u_int8_t* packet, u_int32_t size)
    {
        ethernetHeader=(libnet_ethernet_hdr*)new u_int8_t[size];
        memcpy(ethernetHeader,packet,size);
        this->size=size;
    }

    ~Ethernet_Parser()
    {
        delete[] (char*)ethernetHeader;
    }

    u_int16_t getProtocol()
    {
        return ntohs(ethernetHeader->ether_type);
    }

    u_int8_t* getSourceAddress()
    {
        return ethernetHeader->ether_shost;
    }

    u_int8_t* getDestinationAddress()
    {
        return ethernetHeader->ether_dhost;
    }

    IP_Parser* getIPInformation()
    {
        if(getProtocol()==ETHERTYPE_IP)
            return new IP_Parser(((u_int8_t*)ethernetHeader)+sizeof(libnet_ethernet_hdr));
        else
            return NULL;
    }

    u_int64_t getLength()
    {
        return size;
    }

    u_int64_t getHeaderLength()
    {
        return 14;
    }

    char* getDestinationAddressAsString()
    {
        char* buffer=new char[20];
        for(int i=0;i<ETHER_ADDR_LEN-1;i++)
            sprintf(buffer+3*i,"%02x:",ethernetHeader->ether_dhost[i]);
        sprintf(buffer+3*(ETHER_ADDR_LEN-1),"%02x",ethernetHeader->ether_dhost[ETHER_ADDR_LEN-1]);
        return buffer;
    }

    char* getSourceAddressAsString()
    {
        char* buffer=new char[20];
        for(int i=0;i<ETHER_ADDR_LEN-1;i++)
            sprintf(buffer+3*i,"%02x:",ethernetHeader->ether_shost[i]);
        sprintf(buffer+3*(ETHER_ADDR_LEN-1),"%02x",ethernetHeader->ether_shost[ETHER_ADDR_LEN-1]);
        return buffer;
    }
};

#endif // PACKETPARSER_H
