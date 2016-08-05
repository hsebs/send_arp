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

//do not make pointer as field in subclass.
class ProtocolManager
{
private:
    ProtocolManager* subProtocolManager;

protected:
    //버퍼가 작을 시 필요한 버퍼크기 반환
    u_int8_t                GetAddressAsString  (char* buffer,      u_int8_t bufferSize,    u_int8_t* address,  u_int8_t addressSize)
    {
        switch(addressSize)
        {
        case 2://port
            if(bufferSize<6)
                return 8;
            sprintf_s(buffer,8,"%u",ntohs(*(u_int16_t*)address));
            break;
        case 4://ipv4
            if(bufferSize<16)
                return 16;
            buffer[0]=0;
            for(int i=0;i<addressSize-1;i++)
                sprintf_s(&buffer[strlen(buffer)],  20-strlen(buffer),"%u.",*(address+i));
            sprintf_s(&buffer[strlen(buffer)],      20-strlen(buffer),"%u",*(address+addressSize-1));
            break;
        case 6://MAC
            if(bufferSize<18)
                return 18;
            for(int i=0;i<addressSize-1;i++)
                sprintf_s(buffer+3*i,       20-3*i,         "%02x:",*(address+i));
            sprintf_s(buffer+3*(addressSize-1),    20-3*(addressSize-1),  "%02x",*(address+addressSize-1));
            break;
        case 16://ipv6
            if(bufferSize<40)
                return 40;
            for(int i=0;i<addressSize/2-1;i++)
                sprintf_s(buffer+5*i,       40-5*i,         "%02x%02x:",*(address+2*i),*(address+2*i+1));
            sprintf_s(buffer+5*(addressSize/2-1),  40-5*(addressSize/2-1),"%02x%02x",*(address+addressSize-2),*(address+addressSize-1));
            break;
        default:
            if(bufferSize<3*addressSize)
                return 3*addressSize;
            for(int i=0;i<addressSize-1;i++)
                sprintf_s(buffer+3*i,       3*addressSize-3*i,         "%02x:",*(address+i));
            sprintf_s(buffer+3*(addressSize-1),    3*addressSize-3*(addressSize-1),  "%02x",*(address+addressSize-1));
            break;
        }
        return 0;
    }

    u_int8_t                GetAddressFromString(u_int8_t* address, u_int8_t addressSize ,  char* buffer,       u_int8_t bufferSize)
    {
        switch(addressSize)
        {
        case 2://port
            sscanf(buffer,"%hu",(unsigned short*)address);
            break;
        case 4://ipv4
            sscanf(buffer,"%hhu.%hhu.%hhu.%hhu",address,address+1,address+2,address+3);
            break;
        case 6://MAC
            for(int i=0;i<addressSize;i++)
                sscanf(buffer+3*i,"%02hhx",address+i);
            break;
        case 16://ipv6
            for(int i=0;i<addressSize/2;i++)
                sscanf(buffer+5*i,"%02hhx%02hhx",address+2*i,address+2*i+1);
            break;
        default:
            for(int i=0;i<addressSize;i++)
                sscanf(buffer+3*i,"%02hhx",address+i);
            break;
        }
        return 0;
    }

    /*It uses deep copy of origin.*/
    void                    setSubProtocolManager(ProtocolManager* newSubProtocolManager)
    {
        if(subProtocolManager)
        {
            delete subProtocolManager;
        }
        if(newSubProtocolManager)
            this->subProtocolManager=newSubProtocolManager->clone();
        else
            this->subProtocolManager=NULL;
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

    //파싱 & 편집을 위한 기능, SubProtocol이 없을 수 도 있으니 포인터형태로 처리
    ProtocolManager*const   getSubProtocolManager   ()
    {
        return subProtocolManager;
    }

    //파싱을 위한 기능
    virtual u_int32_t       getRawStream            (u_int8_t*,u_int32_t)=0;
    virtual u_int32_t       getRawStreamLength      ()=0;

    virtual u_int8_t       getSourceAddressAsString(char*,u_int8_t)=0;
    virtual u_int8_t       getDestinationAddressAsString(char*,u_int8_t)=0;
    virtual u_int8_t       getProtocolTypeAsString (char*,u_int8_t)=0;


    virtual u_int8_t       getSourceAddress(u_int8_t*,u_int8_t)=0;
    virtual u_int8_t       getDestinationAddress(u_int8_t*,u_int8_t)=0;
};

//for exception
class StringManager : public ProtocolManager
{
private:
    char buffer[70000];
    u_int32_t size;
public:
    StringManager(u_int8_t* protocolStream, int size)
    {
        memcpy(buffer,protocolStream,size);
        this->size=size;
    }

    StringManager(StringManager* origin)
    {
        *this=*origin;
    }

    ProtocolManager*clone()
    {
        return new StringManager(this);
    }

    u_int32_t       getRawStream            (u_int8_t* buffer,u_int32_t size)
    {
        if(size<this->size)
            return size;
        memcpy(buffer,this->buffer,this->size);
        return 0;
    }

    u_int32_t       getRawStreamLength      ()
    {
        return this->size;
    }

    u_int8_t       getSourceAddressAsString(char*,u_int8_t)
    {
        return 0;
    }
    u_int8_t       getDestinationAddressAsString(char*,u_int8_t)
   {
       return 0;
   }
    u_int8_t       getProtocolTypeAsString (char*,u_int8_t)
   {
       return 0;
   }

    u_int8_t       getSourceAddress(u_int8_t*,u_int8_t)
    {
        return 0;
    }

    u_int8_t       getDestinationAddress(u_int8_t*,u_int8_t)
    {
        return 0;
    }
};


//4rd Layer
class HTTPManager : public ProtocolManager
{
private:
public:
     ProtocolManager*clone()
     {
         return new HTTPManager();
     }

     u_int32_t       getRawStream            (u_int8_t*,u_int32_t)
     {
         return 0;
     }

     u_int32_t       getRawStreamLength      ()
     {
         return 0;
     }

     u_int8_t       getSourceAddressAsString(char*,u_int8_t)
     {
         return 0;
     }
     u_int8_t       getDestinationAddressAsString(char*,u_int8_t)
    {
        return 0;
    }
     u_int8_t       getProtocolTypeAsString (char*,u_int8_t)
    {
        return 0;
    }

     u_int8_t       getSourceAddress(u_int8_t*,u_int8_t)
     {
         return 0;
     }

     u_int8_t       getDestinationAddress(u_int8_t*,u_int8_t)
     {
         return 0;
     }
};


//3rd Layer
class UDPManager : public ProtocolManager
{
private:
    libnet_udp_hdr udpHeader;
public:
    UDPManager(UDPManager* origin)
    {
        this->udpHeader=origin->udpHeader;
        ProtocolManager* subProtocolManager=origin->getSubProtocolManager();
        if(subProtocolManager)
        {
            this->ProtocolManager::setSubProtocolManager(subProtocolManager);
        }
    }

    UDPManager(u_int8_t* protocolStream, u_int32_t size)
    {
        ProtocolManager* subProtocolManager;
        if(size<sizeof(libnet_udp_hdr))
        {
            fprintf(stderr,"UDP header size error\n");
            return;
        }
        udpHeader=*(libnet_udp_hdr*)protocolStream;
        if(size<ntohs(udpHeader.uh_ulen))
        {
            fprintf(stderr,"UDP size error\n");
            return;
        }
        subProtocolManager=new StringManager(protocolStream+sizeof(libnet_udp_hdr),size-sizeof(libnet_udp_hdr));
        setSubProtocolManager(subProtocolManager);
        delete subProtocolManager;
    }

    ProtocolManager*clone()
    {
        return new UDPManager(this);
    }

    u_int32_t       getRawStream(u_int8_t* buffer,u_int32_t size)
    {
        if(size<getRawStreamLength())
            return getRawStreamLength();

        memcpy(buffer,&udpHeader,sizeof(libnet_udp_hdr));
        {
            ProtocolManager* subProtocolManager=getSubProtocolManager();
            if(subProtocolManager)
            {
                subProtocolManager->getRawStream(buffer+sizeof(libnet_udp_hdr),subProtocolManager->getRawStreamLength());
            }
        }
        return 0;
    }

    u_int32_t       getRawStreamLength()
    {
        u_int32_t size;
        ProtocolManager* subProtocolManager;
        subProtocolManager=getSubProtocolManager();
        if(subProtocolManager)
        {
            size = sizeof(libnet_udp_hdr)+subProtocolManager->getRawStreamLength();
        }
        else
            size = sizeof(libnet_udp_hdr);
        return size;
    }

    u_int8_t        getSourceAddressAsString        (char* buffer,u_int8_t size)
    {
        return GetAddressAsString(buffer,size,(u_int8_t*)&udpHeader.uh_sport,2);
    }

    u_int8_t        getDestinationAddressAsString   (char* buffer,u_int8_t size)
    {
        return GetAddressAsString(buffer,size,(u_int8_t*)&udpHeader.uh_dport,2);
    }

    u_int8_t        getProtocolTypeAsString         (char* buffer,u_int8_t size)
    {
        if(size<3)
            return 3;
        sprintf_s(buffer,8,"UDP");
        return 0;
    }

    u_int8_t       getSourceAddress(u_int8_t* address,u_int8_t size)
    {
        if(size<2)
            return 2;
        memcpy(address,&udpHeader.uh_sport,2);
        return 0;
    }

    u_int8_t       getDestinationAddress(u_int8_t* address,u_int8_t size)
    {
        if(size<2)
            return 2;
        memcpy(address,&udpHeader.uh_dport,2);
        return 0;
    }
};

/*
class TCPManager //: public ProtocolManager
{
private:
    u_int8_t version;
    libnet_tcp_hdr tcpHeader;
public:

};
*/

//2nd Layer
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

    ARPManager(u_int8_t* hardwareSourceAddress,u_int8_t* protocolSourceAddress,u_int8_t* hardwareDestinationAddress,u_int8_t* protocolDestinationAddress,u_int16_t hardwareAddressType, u_int16_t protocolAddressType, u_int8_t operation)
    {
        arpHeader.ar_hrd=ntohs(hardwareAddressType);
        arpHeader.ar_pro=ntohs(protocolAddressType);
        arpHeader.ar_op=ntohs(operation);
        switch(hardwareAddressType)
        {
        case ARPHRD_ETHER:
            arpHeader.ar_hln=ETHER_ADDR_LEN;
            switch(protocolAddressType)
            {
            case ETHERTYPE_IP:
                //IPv6는 ARP를 사용하지 않는다.
                arpHeader.ar_pln=4;
                break;
            }
            break;
        }
        setHardwareAddress(hardwareSourceAddress,hardwareDestinationAddress,arpHeader.ar_hln);
        setProtocolAddress(protocolSourceAddress,protocolDestinationAddress,arpHeader.ar_pln);
    }

    ARPManager(char* hardwareSourceAddress,char* protocolSourceAddress,char* hardwareDestinationAddress,char* protocolDestinationAddress,u_int16_t hardwareAddressType,u_int8_t hardwareAddressSize, u_int16_t protocolAddressType, u_int8_t protocolAddressSize, u_int8_t operation)
    {
        arpHeader.ar_hrd=ntohs(hardwareAddressType);
        arpHeader.ar_pro=ntohs(protocolAddressType);
        arpHeader.ar_op=ntohs(operation);
        arpHeader.ar_hln=hardwareAddressSize;
        arpHeader.ar_pln=protocolAddressSize;
        setHardwareAddress(hardwareSourceAddress,hardwareDestinationAddress,arpHeader.ar_hln);
        setProtocolAddress(protocolSourceAddress,protocolDestinationAddress,arpHeader.ar_pln);
    }

    ARPManager(char* hardwareSourceAddress,char* protocolSourceAddress,char* hardwareDestinationAddress,char* protocolDestinationAddress,u_int16_t hardwareAddressType, u_int16_t protocolAddressType, u_int8_t operation)
    {
        arpHeader.ar_hrd=ntohs(hardwareAddressType);
        arpHeader.ar_pro=ntohs(protocolAddressType);
        arpHeader.ar_op=ntohs(operation);
        switch(hardwareAddressType)
        {
        case ARPHRD_ETHER:
            arpHeader.ar_hln=ETHER_ADDR_LEN;
            switch(protocolAddressType)
            {
            case ETHERTYPE_IP:
                //IPv6는 ARP를 사용하지 않는다.
                arpHeader.ar_pln=4;
                break;
            }
            break;
        }
        setHardwareAddress(hardwareSourceAddress,hardwareDestinationAddress,arpHeader.ar_hln);
        setProtocolAddress(protocolSourceAddress,protocolDestinationAddress,arpHeader.ar_pln);
    }

    ProtocolManager* clone()
    {
        return new ARPManager(this);
    }


    ProtocolManager const* setSubProtocolManager(u_int32_t subProtocolType,ProtocolManager* subProtocolManager)
    {
        printf("ARP unable to set subprotocol");
        return this;
    }

    u_int32_t       getSubProtocolType()
    {
        return 0;
    }

    u_int32_t       getRawStream(u_int8_t* buffer, u_int32_t size)
    {
        if(size<getRawStreamLength())
            return getRawStreamLength();

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

        return 0;
    }

    u_int32_t       getRawStreamLength()
    {
        u_int32_t size;
        size = sizeof(libnet_arp_hdr)+2*(arpHeader.ar_hln+arpHeader.ar_pln);
        return size;
    }

    u_int8_t        getSourceAddressAsString        (char* buffer,u_int8_t size)
    {
        if(size<GetAddressAsString(0,0,0,arpHeader.ar_hln)+GetAddressAsString(0,0,0,arpHeader.ar_pln)+1)
            return GetAddressAsString(0,0,0,arpHeader.ar_hln)+GetAddressAsString(0,0,0,arpHeader.ar_pln)+1;

        GetAddressAsString(buffer,                      size,                       hardwareSourceAddress,arpHeader.ar_hln);
        buffer[strlen(buffer)+1]=0;
        buffer[strlen(buffer)]='\t';
        GetAddressAsString(&buffer[strlen(buffer)],   size-(arpHeader.ar_hln+1),    protocolSourceAddress,arpHeader.ar_pln);
        return 0;
    }

    u_int8_t        getDestinationAddressAsString   (char* buffer,u_int8_t size)
    {
        if(size<GetAddressAsString(0,0,0,arpHeader.ar_hln)+GetAddressAsString(0,0,0,arpHeader.ar_pln)+1)
            return GetAddressAsString(0,0,0,arpHeader.ar_hln)+GetAddressAsString(0,0,0,arpHeader.ar_pln)+1;

        GetAddressAsString(buffer,                      size,                       hardwareDestinationAddress,arpHeader.ar_hln);
        buffer[strlen(buffer)+1]=0;
        buffer[strlen(buffer)]='\t';
        GetAddressAsString(&buffer[strlen(buffer)],   size-(arpHeader.ar_hln+1),    protocolDestinationAddress,arpHeader.ar_pln);
        return 0;
    }

    u_int8_t        getProtocolTypeAsString         (char* buffer,u_int8_t size)
    {
        if(size<4)
            return 4;
        sprintf_s(buffer,8,"ARP");
        return 0;
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

    void            setHardwareAddress(char* sourceAddress,char* destinationAddress,u_int8_t addressSize)
    {
        u_int8_t buffer[200];
        GetAddressFromString(buffer,200,    sourceAddress,      addressSize);
        memcpy(hardwareSourceAddress,       buffer,addressSize);
        GetAddressFromString(buffer,200,    destinationAddress, addressSize);
        memcpy(hardwareDestinationAddress,  buffer,addressSize);
        arpHeader.ar_hln=addressSize;
    }

    void            setProtocolAddress(char* sourceAddress,char* destinationAddress,u_int8_t addressSize)
    {
        u_int8_t buffer[200];
        GetAddressFromString(buffer,200,    sourceAddress,      addressSize);
        memcpy(protocolSourceAddress,       buffer,addressSize);
        GetAddressFromString(buffer,200,    destinationAddress, addressSize);
        memcpy(protocolDestinationAddress,  buffer,addressSize);
        arpHeader.ar_pln=addressSize;
    }

    void            setOperation(u_int16_t operation)
    {
        arpHeader.ar_op=operation;
    }

    u_int16_t       getOperation()
    {
        return arpHeader.ar_op;
    }

    u_int8_t        getHardwareAddressLength()
    {
        return arpHeader.ar_hln;
    }

    u_int8_t        getProtocolAddressLength()
    {
        return arpHeader.ar_pln;
    }

    u_int8_t        getSourceAddress(u_int8_t* address,u_int8_t size)
    {
        if(size<arpHeader.ar_hln+arpHeader.ar_pln)
            return arpHeader.ar_hln+arpHeader.ar_pln;
        memcpy(address,                 hardwareSourceAddress,arpHeader.ar_hln);
        memcpy(address+arpHeader.ar_hln,protocolSourceAddress,arpHeader.ar_pln);
        return 0;
    }

    u_int8_t       getDestinationAddress(u_int8_t* address,u_int8_t size)
    {
        if(size<arpHeader.ar_hln+arpHeader.ar_pln)
            return arpHeader.ar_hln+arpHeader.ar_pln;
        memcpy(address,                 hardwareDestinationAddress,arpHeader.ar_hln);
        memcpy(address+arpHeader.ar_hln,protocolDestinationAddress,arpHeader.ar_pln);
        return 0;
    }
};

class IPManager : public ProtocolManager
{
private:
    u_int8_t version;
    libnet_ipv4_hdr ipv4Header;

    void setCheckSum()
    {
        u_int32_t sum;
        u_int16_t word;
        char* buff=(char*)&ipv4Header;
        int i;
        ipv4Header.ip_sum=0;
        for(i=0;i<sizeof(libnet_ipv4_hdr);i+=2)
        {
            word = ( ( buff[i]<<8) & 0xFF00 )+( buff[i+1] & 0xFF );
            sum = sum + (u_int)word;
        }
        while( sum >> 16 )
                sum = ( sum & 0xFFFF ) + ( sum >> 16 );
        sum = ~sum;

        ipv4Header.ip_sum = (u_int16_t)sum;
    }

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
        }
    }

    IPManager(u_int8_t* protocolStream, int size)
    {
        ProtocolManager* subProtocolManager;
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
                subProtocolManager = new UDPManager(protocolStream+sizeof(libnet_ipv4_hdr),size-sizeof(libnet_ipv4_hdr));
                setSubProtocolManager(IPPROTO_UDP,subProtocolManager);
                delete subProtocolManager;
                break;
            default:
                subProtocolManager = new StringManager(protocolStream+sizeof(libnet_ipv4_hdr),size-sizeof(libnet_ipv4_hdr));
                setSubProtocolManager(ipv4Header.ip_p,subProtocolManager);
                delete subProtocolManager;
                break;
            }
            break;
        default:
            fprintf(stderr,"IP version is not supported ");
            return;
        }
    }

    IPManager(u_int8_t version, u_int8_t* sourceAddress,u_int8_t* destinationAddress,                           ProtocolManager* subProtocolManager)
    {
        this->version=version;
        memset(&ipv4Header,0,sizeof(libnet_ipv4_hdr));
        ipv4Header.ip_ttl=64;
        setAddresss(sourceAddress,destinationAddress);
        setSubProtocolManager(subProtocolManager);
    }

    IPManager(u_int8_t version, u_int8_t* sourceAddress,u_int8_t* destinationAddress)
    {
        this->version=version;
        memset(&ipv4Header,0,sizeof(libnet_ipv4_hdr));
        ipv4Header.ip_ttl=64;
        setAddresss(sourceAddress,destinationAddress);
        setSubProtocolManager(NULL);
    }

    ProtocolManager* clone()
    {
        return new IPManager(this);
    }

    void            setAddresss(u_int8_t* sourceAddress,u_int8_t* destinationAddress)
    {
        switch(version)
        {
        case 4:
            memcpy(&ipv4Header.ip_src,sourceAddress,     4);
            memcpy(&ipv4Header.ip_dst,destinationAddress,4);
            setCheckSum();
            break;
        case 6:
            break;
        }
    }

    ProtocolManager*setSubProtocolManager(ProtocolManager* subProtocolManager)
    {
        char buffer[256];
        switch(version)
        {
        case 4:
            subProtocolManager->getProtocolTypeAsString(buffer,200);
            do
            {
                if(strcmp(buffer,"TCP")==0)
                {
                    ipv4Header.ip_p=IPPROTO_TCP;
                    break;
                }
                if(strcmp(buffer,"UDP")==0)
                {
                    ipv4Header.ip_p=IPPROTO_UDP;
                    break;
                }
                if(strcmp(buffer,"ICMP")==0)
                {
                    ipv4Header.ip_p=IPPROTO_ICMP;
                    break;
                }
            }
            while(0);
            break;
        default:
            break;
        }
        ProtocolManager::setSubProtocolManager(subProtocolManager);
        return this;
    }

    ProtocolManager*setSubProtocolManager(u_int32_t subProtocolType,ProtocolManager* subProtocolManager)
    {
        switch(version)
        {
        case 4:
            if(subProtocolType < 256)
                ipv4Header.ip_p=(u_int8_t)subProtocolType;
            else
                fprintf(stderr,"IP subProtocolType is wrong\n");
            break;
        default:
            break;
        }
        ProtocolManager::setSubProtocolManager(subProtocolManager);
        return this;
    }

    void            setTimeToLive(u_int8_t ttl)
    {
        ipv4Header.ip_ttl=ttl;
        setCheckSum();
    }

    u_int8_t        getTimeToLive()
    {
        return ipv4Header.ip_ttl;
    }


    u_int32_t       getSubProtocolType()
    {
        switch(version)
        {
        case 4:
            return ipv4Header.ip_p;
        default:
            return 0;
        }
    }

    u_int32_t       getRawStream(u_int8_t* buffer,u_int32_t size)
    {
        if(size<getRawStreamLength())
            return getRawStreamLength();
        switch(version)
        {
        case 4:
            memcpy(buffer,&ipv4Header,sizeof(libnet_ipv4_hdr));
            {
                ProtocolManager* subProtocolManager=getSubProtocolManager();
                if(subProtocolManager)
                {
                    subProtocolManager->getRawStream(buffer+sizeof(libnet_ipv4_hdr),subProtocolManager->getRawStreamLength());
                }
            }
            break;
        default:
            return -1;
        }

        return 0;
    }

    u_int32_t       getRawStreamLength()
    {
        u_int32_t size;
        ProtocolManager* subProtocolManager;
        switch(version)
        {
        case 4:
            subProtocolManager=getSubProtocolManager();
            if(subProtocolManager)
            {
                size = sizeof(libnet_ipv4_hdr)+subProtocolManager->getRawStreamLength();
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

    u_int8_t        getSourceAddressAsString        (char* buffer,u_int8_t size)
    {
        switch(version)
        {
        case 4:
            return GetAddressAsString(buffer,size,(u_int8_t*)&ipv4Header.ip_src,sizeof(in_addr));
            break;
        default:
            return NULL;
        }
    }

    u_int8_t        getDestinationAddressAsString   (char* buffer,u_int8_t size)
    {
        switch(version)
        {
        case 4:
            return GetAddressAsString(buffer,size,(u_int8_t*)&ipv4Header.ip_dst,sizeof(in_addr));
            break;
        default:
            return -1;
        }
    }

    u_int8_t        getProtocolTypeAsString         (char* buffer,u_int8_t size)
    {
        if(size<3)
            return 3;
        sprintf_s(buffer,8,"IP");
        return 0;
    }

    u_int8_t       getSourceAddress(u_int8_t* address,u_int8_t size)
    {
        if(size<4)
            return 4;
        memcpy(address,&ipv4Header.ip_src,4);
        return 0;
    }

    u_int8_t       getDestinationAddress(u_int8_t* address,u_int8_t size)
    {
        if(size<4)
            return 4;
        memcpy(address,&ipv4Header.ip_dst,4);
        return 0;
    }
};

//1st Layer
class EthernetManager : public ProtocolManager
{
private:
    libnet_ethernet_hdr ethernetHeader;

public:
    EthernetManager(u_int8_t* packetStream, int size)
    {
        ProtocolManager* subProtocolManager;
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
            subProtocolManager=new IPManager(packetStream+sizeof(libnet_ethernet_hdr), size-sizeof(libnet_ethernet_hdr));
            setSubProtocolManager(ETHERTYPE_IP,subProtocolManager);
            delete subProtocolManager;
            break;
        case ETHERTYPE_ARP:
            subProtocolManager=new ARPManager(packetStream+sizeof(libnet_ethernet_hdr), size-sizeof(libnet_ethernet_hdr));
            setSubProtocolManager(ETHERTYPE_ARP,subProtocolManager);
            delete subProtocolManager;
            break;
        default:
            //TODO
            subProtocolManager=new StringManager(packetStream+sizeof(libnet_ethernet_hdr), size-sizeof(libnet_ethernet_hdr));
            setSubProtocolManager(ntohs(ethernetHeader.ether_type),subProtocolManager);
            size=subProtocolManager->getRawStreamLength();
            delete subProtocolManager;
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
        }
    }

    EthernetManager(u_int8_t* sourceAddress,u_int8_t* destinationAddress,u_int32_t subProtocolType, ProtocolManager* subProtocolManager)
    {
        setAddresss(sourceAddress,destinationAddress);
        setSubProtocolManager(subProtocolType, subProtocolManager);
    }

    EthernetManager(u_int8_t* sourceAddress,u_int8_t* destinationAddress,                           ProtocolManager* subProtocolManager)
    {
        setAddresss(sourceAddress,destinationAddress);
        setSubProtocolManager(subProtocolManager);
    }

    EthernetManager(u_int8_t* sourceAddress,u_int8_t* destinationAddress)
    {
        setAddresss(sourceAddress,destinationAddress);
        setSubProtocolManager(NULL);
    }

    EthernetManager(char* sourceAddress,char* destinationAddress, u_int32_t subProtocolType,ProtocolManager* subProtocolManager)
    {
        setAddresss(sourceAddress,destinationAddress);
        setSubProtocolManager(subProtocolType, subProtocolManager);
    }

    EthernetManager(char* sourceAddress,char* destinationAddress,                           ProtocolManager* subProtocolManager)
    {
        setAddresss(sourceAddress,destinationAddress);
        setSubProtocolManager(subProtocolManager);
    }

    EthernetManager(char* sourceAddress,char* destinationAddress)
    {
        setAddresss(sourceAddress,destinationAddress);
        ethernetHeader.ether_type=0;
        ProtocolManager::setSubProtocolManager(NULL);
    }

    EthernetManager()
    {
        memset(&ethernetHeader,0,sizeof(ethernetHeader));
        ProtocolManager::setSubProtocolManager(NULL);
    }

    ProtocolManager* clone()
    {
        return new EthernetManager(this);
    }

    void            setAddresss(u_int8_t* sourceAddress,u_int8_t* destinationAddress)
    {
        memcpy(ethernetHeader.ether_shost,sourceAddress,     ETHER_ADDR_LEN);
        memcpy(ethernetHeader.ether_dhost,destinationAddress,ETHER_ADDR_LEN);
    }

    void            setAddresss(char* sourceAddress,char* destinationAddress)
    {
        u_int8_t buffer[256];
        GetAddressFromString(buffer,200,sourceAddress,      ETHER_ADDR_LEN);
        memcpy(ethernetHeader.ether_shost,buffer,              ETHER_ADDR_LEN);
        GetAddressFromString(buffer,200,destinationAddress, ETHER_ADDR_LEN);
        memcpy(ethernetHeader.ether_dhost,buffer,              ETHER_ADDR_LEN);
    }

    ProtocolManager*setSubProtocolManager(u_int32_t subProtocolType,ProtocolManager* subProtocolManager)
    {
        if(subProtocolType < 0xFFFF+1)
            ethernetHeader.ether_type=ntohs((u_int16_t)subProtocolType);
        else
            fprintf(stderr,"Ethernet subProtocolType is wrong\n");

        ProtocolManager::setSubProtocolManager(subProtocolManager);
        return this;
    }

    ProtocolManager*setSubProtocolManager(ProtocolManager* subProtocolManager)
    {
        if(subProtocolManager)
        {
            char type[256];
            subProtocolManager->getProtocolTypeAsString(type,200);

            do{
                if(strcmp(type,"IP")==0)
                {
                    ethernetHeader.ether_type=htons(ETHERTYPE_IP);
                    break;
                }
                if(strcmp(type,"ARP")==0)
                {
                    ethernetHeader.ether_type=htons(ETHERTYPE_ARP);
                    break;
                }
                if(strcmp(type,"EAP")==0)
                {
                    ethernetHeader.ether_type=htons(ETHERTYPE_EAP);
                    break;
                }
                if(strcmp(type,"PUP")==0)
                {
                    ethernetHeader.ether_type=htons(ETHERTYPE_PUP);
                    break;
                }
                if(strcmp(type,"VLAN")==0)
                {
                    ethernetHeader.ether_type=htons(ETHERTYPE_VLAN);
                    break;
                }

                fprintf(stderr,"Ethernet : subProtocolType is unknown\n");
                ethernetHeader.ether_type=0;
            }while(0);
        }
        ProtocolManager::setSubProtocolManager(subProtocolManager);
        return this;
    }

    ProtocolManager* getSubProtocolManager()
    {
        return ProtocolManager::getSubProtocolManager();
    }

    u_int32_t       getSubProtocolType()
    {
        return ntohs(ethernetHeader.ether_type);
    }

    u_int32_t       getRawStream(u_int8_t* buffer,u_int32_t size)
    {
        ProtocolManager* subProtocolManager;
        if(size<getRawStreamLength())
            return getRawStreamLength();

        memset(buffer,0,getRawStreamLength());
        memcpy(buffer,&ethernetHeader,sizeof(ethernetHeader));
        subProtocolManager=ProtocolManager::getSubProtocolManager();
        if(subProtocolManager)
        {
            subProtocolManager->getRawStream(buffer+sizeof(libnet_ethernet_hdr),subProtocolManager->getRawStreamLength());
        }
        return 0;
    }

    u_int32_t       getRawStreamLength()
    {
        u_int32_t size;
        ProtocolManager* subProtocolManager;
        subProtocolManager=ProtocolManager::getSubProtocolManager();
        if(subProtocolManager)
        {
            size= sizeof(libnet_ethernet_hdr)+subProtocolManager->getRawStreamLength();
        }
        else
            size= sizeof(libnet_ethernet_hdr);
        //if(size<60)
        //    size=60;
        return size;
    }

    u_int8_t        getSourceAddressAsString(char* buffer,u_int8_t size)
    {
        return GetAddressAsString(buffer,size,ethernetHeader.ether_shost,ETHER_ADDR_LEN);
    }

    u_int8_t        getDestinationAddressAsString(char* buffer,u_int8_t size)
    {
        return GetAddressAsString(buffer,size,ethernetHeader.ether_dhost,ETHER_ADDR_LEN);
    }

    u_int8_t        getProtocolTypeAsString(char* buffer,u_int8_t size)
    {
        if(size<8)
            return 8;
        sprintf_s(buffer,10,"Ethernet");
        return 0;
    }

    u_int8_t       getSourceAddress(u_int8_t* address,u_int8_t size)
    {
        if(size<6)
            return ETHER_ADDR_LEN;
        memcpy(address,ethernetHeader.ether_shost,ETHER_ADDR_LEN);
        return 0;
    }

    u_int8_t       getDestinationAddress(u_int8_t* address,u_int8_t size)
    {
        if(size<6)
            return ETHER_ADDR_LEN;
        memcpy(address,ethernetHeader.ether_dhost,ETHER_ADDR_LEN);
        return 0;
    }

};


#endif // PACKETMANAGER_H
