#ifndef PACKETMANAGER_H
#define PACKETMANAGER_H

#ifdef WIN32
#include<WinSock2.h>
#include"libnet/in_systm.h"
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
typedef u_int32_t n_time;
#endif //WIN32

#include"libnet/libnet-types.h"
#include"libnet/libnet-macros.h"
#include"libnet/libnet-structures.h"
#include"libnet/libnet-headers.h"
#include"libnet/libnet-functions.h"
#include <string.h>
#include <stdio.h>

//do not make pointer as pointer in subclass.
class ProtocolManager
{
private:
    ProtocolManager* subProtocolManager;

protected:

    //must delete return value after use;
    char*                   GetAddressAsString(u_int8_t* addr ,u_int8_t size)
    {
        char* buffer;
        switch(size)
        {
        case 2://port
            buffer=new char[8];
            sprintf_s(buffer,8,"%u",ntohs(*(u_int16_t*)addr));
            break;
        case 4://ipv4
            buffer=new char[20];
            buffer[0]=0;
            for(int i=0;i<size-1;i++)
                sprintf_s(&buffer[strlen(buffer)],  20-strlen(buffer),"%u.",*(addr+i));
            sprintf_s(&buffer[strlen(buffer)],      20-strlen(buffer),"%u.",*(addr+size-1));
            break;
        case 6://MAC
            buffer=new char[20];
            for(int i=0;i<size-1;i++)
                sprintf_s(buffer+3*i,       20-3*i,         "%02x:",*(addr+i));
            sprintf_s(buffer+3*(size-1),    20-3*(size-1),  "%02x",*(addr+size-1));
            break;
        case 16://ipv6
            buffer=new char[3*size+2];
            for(int i=0;i<size/2-1;i++)
                sprintf_s(buffer+5*i,       20-5*i,         "%02x%02x:",*(addr+2*i),*(addr+2*i+1));
            sprintf_s(buffer+5*(size/2-1),  20-5*(size/2-1),"%02x%02x",*(addr+size-2),*(addr+size-1));
            break;
        default:
            buffer=new char[3*size+2];
            for(int i=0;i<size-1;i++)
                sprintf_s(buffer+3*i,       20-3*i,         "%02x:",*(addr+i));
            sprintf_s(buffer+3*(size-1),    20-3*(size-1),  "%02x",*(addr+size-1));
            break;
        }
        return buffer;
    }

    /*It uses deep copy of origin.*/
    void                    setSubProtocolManager(ProtocolManager* origin)
    {
        if(subProtocolManager)
        {
            delete subProtocolManager;
        }
        this->subProtocolManager=origin->clone();
    }
public:

    ProtocolManager()
    {
        subProtocolManager=NULL;
    }

    ~ProtocolManager()
    {
        if(subProtocolManager)
            delete subProtocolManager;
    }

    virtual ProtocolManager*clone()=0;

    //must delete return value after use;
    ProtocolManager*        getSubProtocolManager()
    {
        if(subProtocolManager)
            return subProtocolManager->clone();
        else
            return NULL;
    }
    virtual void            setSubProtocolManager(u_int64_t,ProtocolManager*)=0;
    virtual u_int64_t       getSubProtocolType()=0;

    virtual u_int8_t*       getRawStream()=0;
    virtual u_int64_t       getRawStreamLength()=0;

    virtual char*           getSourceAddressAsString()=0;
    virtual char*           getDestinationAddressAsString()=0;
    virtual char*           getProtocolTypeAsString()=0;
};

class ARPManager : public ProtocolManager
{
private:
    libnet_arp_hdr arpHeader;
    u_int8_t hardwareSourceAddress[16];
    u_int8_t hardwareDestinationAddress[16];
    u_int8_t protocolSourceAddress[16];
    u_int8_t protocolDestinationAddress[16];
public:
    ARPManager(ARPManager* origin)
    {
        this->arpHeader=origin->arpHeader;
        memcpy(hardwareSourceAddress,origin->hardwareSourceAddress,arpHeader.ar_hln);
        memcpy(hardwareDestinationAddress,origin->hardwareDestinationAddress,arpHeader.ar_hln);
        memcpy(protocolSourceAddress,origin->protocolSourceAddress,arpHeader.ar_pln);
        memcpy(protocolDestinationAddress,origin->protocolDestinationAddress,arpHeader.ar_pln);
    }

    ARPManager(u_int8_t* protocolStream, int size)
    {
        if(size<sizeof(libnet_arp_hdr))
        {
            fprintf(stderr,"ARP size error");
            return;
        }
        arpHeader=*(libnet_arp_hdr*)protocolStream;

        if(size<sizeof(libnet_arp_hdr)+2*(arpHeader.ar_hln+arpHeader.ar_pln))
        {
            fprintf(stderr,"ARP addr size error");
            return;
        }

        memcpy(hardwareSourceAddress,
               protocolStream+sizeof(arpHeader),
               arpHeader.ar_hln);
        memcpy(protocolSourceAddress,
               protocolStream+sizeof(arpHeader)+arpHeader.ar_hln,
               arpHeader.ar_pln);

        memcpy(hardwareDestinationAddress,
               protocolStream +sizeof(arpHeader)+arpHeader.ar_hln+arpHeader.ar_pln,
               arpHeader.ar_hln);
        memcpy(protocolDestinationAddress,
               protocolStream +sizeof(arpHeader)+arpHeader.ar_hln+arpHeader.ar_pln+arpHeader.ar_hln,
               arpHeader.ar_pln);
    }

    ARPManager(u_int8_t* hardwareSourceAddress,u_int8_t* protocolSourceAddress,u_int8_t* hardwareDestinationAddress,u_int8_t* protocolDestinationAddress,u_int16_t hardwareAddressType,u_int8_t hardwareAddressSize, u_int16_t protocolAddressType, u_int8_t protocolAddressSize, u_int8_t operation)
    {
        arpHeader.ar_hrd=ntohs(hardwareAddressType);
        arpHeader.ar_pro=ntohs(protocolAddressType);
        arpHeader.ar_op=ntohs(operation);
        arpHeader.ar_hln=hardwareAddressSize;
        arpHeader.ar_pln=protocolAddressSize;
        memcpy(this->hardwareSourceAddress,     hardwareSourceAddress,      arpHeader.ar_hln);
        memcpy(this->hardwareDestinationAddress,hardwareDestinationAddress, arpHeader.ar_hln);
        memcpy(this->protocolSourceAddress,     protocolSourceAddress,      arpHeader.ar_pln);
        memcpy(this->protocolDestinationAddress,protocolDestinationAddress, arpHeader.ar_pln);
    }

    ProtocolManager* clone()
    {
        return new ARPManager(this);
    }


    void            setSubProtocolManager(u_int64_t subProtocolType,ProtocolManager* subProtocoolManager)
    {
        printf("ARP unable to set subprotocol");
        return;
    }


    u_int64_t       getSubProtocolType()
    {
        return 0;
    }

    u_int8_t*       getRawStream()
    {
        u_int8_t*   buffer;
        buffer=new u_int8_t[getRawStreamLength()];
        memcpy(buffer,&arpHeader,sizeof(libnet_arp_hdr));


        memcpy(buffer+sizeof(arpHeader),
               hardwareSourceAddress,
               arpHeader.ar_hln);
        memcpy(buffer+sizeof(arpHeader)+arpHeader.ar_hln,
               protocolSourceAddress,
               arpHeader.ar_pln);

        memcpy(buffer +sizeof(arpHeader)+arpHeader.ar_hln+arpHeader.ar_pln,
               hardwareDestinationAddress,
               arpHeader.ar_hln);
        memcpy(buffer +sizeof(arpHeader)+arpHeader.ar_hln+arpHeader.ar_pln+arpHeader.ar_hln,
               protocolDestinationAddress,
               arpHeader.ar_pln);

        return buffer;
    }

    u_int64_t       getRawStreamLength()
    {
        u_int64_t size;
        size = sizeof(libnet_arp_hdr)+2*(arpHeader.ar_hln+arpHeader.ar_pln);
        return size;
    }

    char*           getSourceAddressAsString()
    {
        return GetAddressAsString(hardwareSourceAddress,arpHeader.ar_hln);
    }

    char*           getDestinationAddressAsString()
    {
        return GetAddressAsString(hardwareDestinationAddress,arpHeader.ar_hln);
    }

    char*           getProtocolTypeAsString()
    {
        char* buffer=new char[8];
        sprintf_s(buffer,8,"ARP");
        return buffer;
    }

    //input must be Big Endian
    void            setHardwareAddress(u_int8_t* sourceAddress,u_int8_t* destinationAddress,u_int8_t size)
    {
        memcpy(hardwareSourceAddress,sourceAddress,size);
        memcpy(hardwareDestinationAddress,destinationAddress,size);
        arpHeader.ar_hln=size;
    }

    //input must be Big Endian
    void            setProtocolAddress(u_int8_t* sourceAddress,u_int8_t* destinationAddress,u_int8_t size)
    {
        memcpy(protocolSourceAddress,sourceAddress,size);
        memcpy(protocolDestinationAddress,destinationAddress,size);
        arpHeader.ar_pln=size;
    }
};


class IPManager : public ProtocolManager
{
private:
    u_int8_t version;
    libnet_ipv4_hdr ipv4Header;
public:
    IPManager(IPManager* origin)
    {
        this->version=origin->version;
        this->ipv4Header=origin->ipv4Header;
        //TODO : ipv6

        ProtocolManager* subProtocolManager=origin->getSubProtocolManager();
        if(subProtocolManager)
        {
            this->ProtocolManager::setSubProtocolManager(subProtocolManager);
            delete subProtocolManager;
        }
    }

    IPManager(u_int8_t* protocolStream, int size)
    {
        version=0;

        switch((protocolStream[0]&0xF0)>>4)
        {
        case 4:
            if((protocolStream[0]&0x0F)*4<sizeof(libnet_ipv4_hdr) || size<sizeof(libnet_ipv4_hdr))
            {
                fprintf(stderr,"IPv4 size error");
                return;
            }
            version=4;
            ipv4Header=*(libnet_ipv4_hdr*)protocolStream;

            //TODO
            switch(ipv4Header.ip_p)
            {
            case IPPROTO_UDP:
                break;
            case IPPROTO_TCP:
                break;
            default:
                break;
            }
            break;
        default:
            fprintf(stderr,"IP version is not supported ");
            return;
        }
    }

    ProtocolManager* clone()
    {
        return new IPManager(this);
    }


    void            setSubProtocolManager(u_int64_t subProtocolType,ProtocolManager* subProtocoolManager)
    {
        switch(version)
        {
        case 4:
            if(subProtocolType < 1<<sizeof(u_int8_t))
                ipv4Header.ip_p=(u_int8_t)subProtocolType;
            else
                fprintf(stderr,"IP subProtocolType is wrong\n");
            break;
        default:
            break;
        }
        ProtocolManager::setSubProtocolManager(subProtocoolManager);
    }


    u_int64_t       getSubProtocolType()
    {
        switch(version)
        {
        case 4:
            return ipv4Header.ip_p;
        default:
            return 0;
        }
    }

    u_int8_t*       getRawStream()
    {
        u_int8_t*   buffer;
        u_int8_t*   data;
        buffer=new u_int8_t[getRawStreamLength()];
        switch(version)
        {
        case 4:
            memcpy(buffer,&ipv4Header,sizeof(libnet_ipv4_hdr));
            {
                ProtocolManager* subProtocolManager=getSubProtocolManager();
                if(subProtocolManager)
                {
                    data = subProtocolManager->getRawStream();
                    memcpy(buffer+sizeof(libnet_ipv4_hdr),data,subProtocolManager->getRawStreamLength());
                    delete data;
                    delete subProtocolManager;
                }
            }
            break;
        default:
            delete buffer;
            return NULL;
        }

        return buffer;
    }

    u_int64_t       getRawStreamLength()
    {
        u_int64_t size;
        ProtocolManager* subProtocolManager;
        switch(version)
        {
        case 4:
            subProtocolManager=getSubProtocolManager();
            if(subProtocolManager)
            {
                size = sizeof(libnet_ipv4_hdr)+subProtocolManager->getRawStreamLength();
                delete subProtocolManager;
            }
            else
                size = sizeof(libnet_ipv4_hdr);
            break;
        default:
            //TODO
            return 0;
        }
        return size;
    }

    char*           getSourceAddressAsString()
    {
        switch(version)
        {
        case 4:
            return GetAddressAsString((u_int8_t*)&ipv4Header.ip_src,sizeof(in_addr));
            break;
        default:
            return NULL;
        }
    }

    char*           getDestinationAddressAsString()
    {
        switch(version)
        {
        case 4:
            return GetAddressAsString((u_int8_t*)&ipv4Header.ip_dst,sizeof(in_addr));
            break;
        default:
            return NULL;
        }
    }

    char*           getProtocolTypeAsString()
    {
        char* buffer=new char[8];
        sprintf_s(buffer,8,"IP");
        return buffer;
    }
};

class EthernetManager : public ProtocolManager
{
private:
    libnet_ethernet_hdr ethernetHeader;
public:

    EthernetManager(u_int8_t* packetStream, int size)
    {
        ProtocolManager* subProtocoolManager;
        if(size<sizeof(libnet_ethernet_hdr))
        {
            fprintf(stderr,"Ethernet size error\n");
            return;
        }

        ethernetHeader=*(libnet_ethernet_hdr*)packetStream;

        if(size==sizeof(libnet_ethernet_hdr))
        {
            fprintf(stderr,"Ethernet subprotocol size error\n");
            return;
        }

        switch(ntohs(ethernetHeader.ether_type))
        {
        case ETHERTYPE_IP:
            subProtocoolManager=new IPManager(packetStream+sizeof(libnet_ethernet_hdr), size-sizeof(libnet_ethernet_hdr));
            setSubProtocolManager(ETHERTYPE_IP,subProtocoolManager);
            delete subProtocoolManager;
            break;
        case ETHERTYPE_ARP:
            //TODO
            subProtocoolManager=new ARPManager(packetStream+sizeof(libnet_ethernet_hdr), size-sizeof(libnet_ethernet_hdr));
            setSubProtocolManager(ETHERTYPE_ARP,subProtocoolManager);
            delete subProtocoolManager;
            break;
        default:
            fprintf(stderr,"Ethernet subprotocol is not supported by Packet Manager.\n");
            break;
        }
    }

    EthernetManager(EthernetManager* origin)
    {
        this->ethernetHeader=origin->ethernetHeader;
        ProtocolManager* subProtocolManager=origin->getSubProtocolManager();
        if(subProtocolManager)
        {
            this->ProtocolManager::setSubProtocolManager(subProtocolManager);
            delete subProtocolManager;
        }
    }

    EthernetManager(u_int8_t* sourceAddress,u_int8_t* destinationAddress,u_int64_t subProtocolType,ProtocolManager* subProtocoolManager)
    {
        memcpy(ethernetHeader.ether_shost,sourceAddress,6);
        memcpy(ethernetHeader.ether_dhost,destinationAddress,6);
        setSubProtocolManager(subProtocolType, subProtocoolManager);
    }

    ProtocolManager* clone()
    {
        return new EthernetManager(this);
    }

    void            setSubProtocolManager(u_int64_t subProtocolType,ProtocolManager* subProtocoolManager)
    {
        if(subProtocolType < 0xFFFF+1)
            ethernetHeader.ether_type=ntohs((u_int16_t)subProtocolType);
        else
            fprintf(stderr,"Ethernet subProtocolType is wrong\n");

        ProtocolManager::setSubProtocolManager(subProtocoolManager);
    }

    //must delete return value after use;
    ProtocolManager* getSubProtocolManager()
    {
        return ProtocolManager::getSubProtocolManager();
    }

    u_int64_t       getSubProtocolType()
    {
        return ntohs(ethernetHeader.ether_type);
    }

    u_int8_t*       getRawStream()
    {
        ProtocolManager* subProtocolManager;
        u_int8_t*   buffer;
        u_int8_t*   data;
        buffer=new u_int8_t[getRawStreamLength()];
        memset(buffer,0,getRawStreamLength());
        memcpy(buffer,&ethernetHeader,sizeof(ethernetHeader));
        subProtocolManager=ProtocolManager::getSubProtocolManager();
        if(subProtocolManager)
        {
            data=subProtocolManager->getRawStream();
            memcpy(buffer+sizeof(libnet_ethernet_hdr),data,subProtocolManager->getRawStreamLength());
            delete data;
            delete subProtocolManager;
        }
        return buffer;
    }

    u_int64_t       getRawStreamLength()
    {
        u_int64_t size;
        ProtocolManager* subProtocolManager;
        subProtocolManager=ProtocolManager::getSubProtocolManager();
        if(subProtocolManager)
        {
            size= sizeof(libnet_ethernet_hdr)+subProtocolManager->getRawStreamLength();
            delete subProtocolManager;
        }
        else
            size= sizeof(libnet_ethernet_hdr);
        if(size<60)
            size=60;
        return size;
    }

    //must delete return value after use;
    char*           getSourceAddressAsString()
    {
        return GetAddressAsString(ethernetHeader.ether_shost,ETHER_ADDR_LEN);
    }

    //must delete return value after use;
    char*           getDestinationAddressAsString()
    {
        return GetAddressAsString(ethernetHeader.ether_dhost,ETHER_ADDR_LEN);
    }

    char*           getProtocolTypeAsString()
    {
        char* buffer=new char[10];
        sprintf_s(buffer,10,"Ethernet");
        return buffer;
    }
};

#endif // PACKETMANAGER_H
