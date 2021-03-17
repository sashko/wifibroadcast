//
// Created by consti10 on 05.12.20.
//

#ifndef WIFIBROADCAST_SOCKETHELPER_H
#define WIFIBROADCAST_SOCKETHELPER_H

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <resolv.h>
#include <cstring>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>
#include <endian.h>
#include <fcntl.h>
#include <ctime>
#include <sys/mman.h>
#include <string>
#include <vector>
#include <chrono>
#include <cstdarg>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <termio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <iostream>
#include <memory>
#include <cassert>
#include <functional>

// For all the stuff that was once in wifibroadcast.hpp

namespace StringFormat{
    static std::string convert(const char *format, ...){
        va_list args;
        va_start(args, format);
        size_t size = vsnprintf(nullptr, 0, format, args) + 1; // Extra space for '\0'
        va_end(args);
        std::unique_ptr<char[]> buf(new char[size]);
        va_start(args, format);
        vsnprintf(buf.get(), size, format, args);
        va_end(args);
        return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
    }
}

namespace GenericHelper{
    // fill buffer with random bytes
    static void fillBufferWithRandomData(std::vector<uint8_t>& data){
        const std::size_t size=data.size();
        for(std::size_t i=0;i<size;i++){
            data[i] = rand() % 255;
        }
    }
    template<std::size_t size>
    static void fillArrayWithRandomData(std::array<uint8_t,size>& data){
        for(std::size_t i=0;i<size;i++){
            data[i] = rand() % 255;
        }
    }
    // Create a buffer filled with random data of size sizeByes
    std::vector<uint8_t> createRandomDataBuffer(const ssize_t sizeBytes){
        std::vector<uint8_t> buf(sizeBytes);
        fillBufferWithRandomData(buf);
        return buf;
    }
    // same as above but return shared ptr
    std::shared_ptr<std::vector<uint8_t>> createRandomDataBuffer2(const ssize_t sizeBytes){
        return std::make_shared<std::vector<uint8_t>>(createRandomDataBuffer(sizeBytes));
    }
    // Create a buffer filled with random data where size is chosen Randomly between [minSizeB,...,maxSizeB]
    std::vector<uint8_t> createRandomDataBuffer(const ssize_t minSizeB,const ssize_t maxSizeB){
        // https://stackoverflow.com/questions/12657962/how-do-i-generate-a-random-number-between-two-variables-that-i-have-stored
        const auto sizeBytes = rand()%(maxSizeB-minSizeB + 1) + minSizeB;
        return createRandomDataBuffer(sizeBytes);
    }
    // create n random data buffers with size [minSizeB,...,maxSizeB]
    std::vector<std::vector<uint8_t>> createRandomDataBuffers(const std::size_t nBuffers, const std::size_t minSizeB, const std::size_t maxSizeB){
        assert(minSizeB >= 0);
        std::vector<std::vector<uint8_t>> buffers;
        for(std::size_t i=0;i<nBuffers;i++){
            buffers.push_back(GenericHelper::createRandomDataBuffer(minSizeB, maxSizeB));
        }
        return buffers;
    }
    bool compareVectors(const std::vector<uint8_t>& sb,const std::vector<uint8_t>& rb){
        if(sb.size()!=rb.size()){
            return false;
        }
        const int result=memcmp (sb.data(),rb.data(),sb.size());
        return result==0;
    }
    void assertVectorsEqual(const std::vector<uint8_t>& sb,const std::vector<uint8_t>& rb){
        assert(sb.size()==rb.size());
        const int result=memcmp (sb.data(),rb.data(),sb.size());
        assert(result==0);
    }
    using namespace std::chrono;
    constexpr nanoseconds timevalToDuration(timeval tv){
        auto duration = seconds{tv.tv_sec}
                        + microseconds {tv.tv_usec};
        return duration_cast<nanoseconds>(duration);
    }
    constexpr time_point<system_clock, nanoseconds>
    timevalToTimePointSystemClock(timeval tv){
        return time_point<system_clock, nanoseconds>{
                duration_cast<system_clock::duration>(timevalToDuration(tv))};
    }
    constexpr time_point<steady_clock, nanoseconds>
    timevalToTimePointSteadyClock(timeval tv){
        return time_point<steady_clock, nanoseconds>{
                duration_cast<steady_clock::duration>(timevalToDuration(tv))};
    }
    constexpr timeval durationToTimeval(nanoseconds dur){
        const auto secs = duration_cast<seconds>(dur);
        dur -= secs;
        const auto us=duration_cast<microseconds>(dur);
        return timeval{secs.count(), us.count()};
    }
}

namespace SocketHelper{
    // originally in wifibroadcast.cpp/ h
    // I thought it might be a good idea to have all these helpers inside their own namespace
    static int open_udp_socket(const std::string &client_addr, int client_port) {
        struct sockaddr_in saddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw std::runtime_error(StringFormat::convert("Error opening socket: %s", strerror(errno)));

        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
        saddr.sin_port = htons((unsigned short) client_port);

        if (connect(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
            throw std::runtime_error(StringFormat::convert("Connect error: %s", strerror(errno)));
        }
        return fd;
    }
    static int open_udp_socket_for_tx(const std::string &client_addr, int client_port) {
        struct sockaddr_in saddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw std::runtime_error(StringFormat::convert("Error opening socket: %s", strerror(errno)));

        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
        saddr.sin_port = htons((unsigned short) client_port);

        if (connect(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
            throw std::runtime_error(StringFormat::convert("Connect error: %s", strerror(errno)));
        }
        return fd;
    }
    static int open_udp_socket_for_rx(int port){
        struct sockaddr_in saddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw std::runtime_error(StringFormat::convert("Error opening socket: %s", strerror(errno)));

        int optval = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = htonl(INADDR_ANY);
        saddr.sin_port = htons((unsigned short)port);

        if (bind(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
        {
            throw std::runtime_error(StringFormat::convert("Bind error: %s", strerror(errno)));
        }
        return fd;
    }
    // Open the specified port for udp receiving
    // sets SO_REUSEADDR to true if possible
    // throws a runtime exception if opening the socket fails
    static int openUdpSocketForRx(const int port){
        int fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd < 0) throw std::runtime_error(StringFormat::convert("Error opening socket %d: %s",port, strerror(errno)));
        int enable = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
            //throw std::runtime_error(StringFormat::convert("Error setting reuse on socket %d: %s",port, strerror(errno)));
            // don't crash here
            std::cout<<"Cannot set socket reuse\n";
        }
        struct sockaddr_in saddr{};
        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = htonl(INADDR_ANY);
        saddr.sin_port = htons((unsigned short)port);
        if (bind(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0){
            throw std::runtime_error(StringFormat::convert("Bind error on socket %d: %s",port, strerror(errno)));
        }
        return fd;
    }
    // returns the current socket receive timeout
    static std::chrono::nanoseconds getCurrentSocketReceiveTimeout(int socketFd){
        timeval tv{};
        socklen_t len=sizeof(tv);
        auto res=getsockopt(socketFd,SOL_SOCKET,SO_RCVTIMEO,&tv,&len);
        assert(res==0);
        assert(len==sizeof(tv));
        return GenericHelper::timevalToDuration(tv);
    }
    // set the receive timeout on the socket
    // throws runtime exception if this step fails (should never fail on linux)
    static void setSocketReceiveTimeout(int socketFd,const std::chrono::nanoseconds timeout){
        const auto currentTimeout=getCurrentSocketReceiveTimeout(socketFd);
        if(currentTimeout!=timeout){
            //std::cout<<"Changing timeout\n";
            auto tv=GenericHelper::durationToTimeval(timeout);
            if (setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
                throw std::runtime_error(StringFormat::convert("Cannot set socket timeout %d",timeout.count()));
                //std::cout<<"Cannot set socket timeout "<<timeout.count()<<"\n";
            }
        }
    }
    // taken from https://github.com/OpenHD/Open.HD/blob/2.0/wifibroadcast-base/tx_rawsock.c#L86
    // open wifi interface using a socket (somehow this works ?!)
    static int openWifiInterfaceAsTx(const std::string& wifi) {
        struct sockaddr_ll ll_addr{};
        struct ifreq ifr{};
        int sock = socket(AF_PACKET, SOCK_RAW, 0);
        if (sock == -1) {
            throw std::runtime_error(StringFormat::convert("Socket failed %s %s",wifi.c_str(),strerror(errno)));
        }

        ll_addr.sll_family = AF_PACKET;
        ll_addr.sll_protocol = 0;
        ll_addr.sll_halen = ETH_ALEN;

        strncpy(ifr.ifr_name, wifi.c_str(), IFNAMSIZ);

        if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
            throw std::runtime_error(StringFormat::convert("ioctl(SIOCGIFINDEX) failed\n"));
        }

        ll_addr.sll_ifindex = ifr.ifr_ifindex;

        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
            throw std::runtime_error(StringFormat::convert("ioctl(SIOCGIFHWADDR) failed\n"));
        }

        memcpy(ll_addr.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

        if (bind(sock, (struct sockaddr *)&ll_addr, sizeof(ll_addr)) == -1) {
            close(sock);
            throw std::runtime_error("bind failed\n");
        }
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 8000;
        if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
            throw std::runtime_error("setsockopt SO_SNDTIMEO\n");
        }
        int sendbuff = 131072;
        if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff)) < 0) {
            throw std::runtime_error("setsockopt SO_SNDBUF\n");
        }
        return sock;
    }
}

namespace RTPLockup{
    // Look here for more details (or just look into the rtp rfc:
    // https://github.com/Consti10/LiveVideo10ms/tree/99e2c4ca31dd8c446952cd409ed51f798e29a137/VideoCore/src/main/cpp/Parser
    static constexpr auto RTP_HEADER_SIZE=12;
    namespace H264{
        struct nalu_header_t {
            uint8_t type:   5;
            uint8_t nri:    2;
            uint8_t f:      1;
        } __attribute__ ((packed));
        typedef struct fu_header_t {
            uint8_t type:   5;
            uint8_t r:      1;
            uint8_t e:      1;
            uint8_t s:      1;
        } __attribute__ ((packed));
    }
    namespace H265{
        struct nal_unit_header_h265_t{
            uint8_t f:      1;
            uint8_t type:   6;
            uint8_t layerId:6;
            uint8_t tid:    3;
        }__attribute__ ((packed));
        static_assert(sizeof(nal_unit_header_h265_t)==2);
        struct fu_header_h265_t{
            uint8_t fuType:6;
            uint8_t e:1;
            uint8_t s:1;
        }__attribute__ ((packed));
        static_assert(sizeof(fu_header_h265_t)==1);

    }
    // Use if input is rtp h264 stream
    // returns true if the FEC encoder shall end the block with this packet
    static bool h264_end_block(const uint8_t* payload, const std::size_t payloadSize){
        if(payloadSize<RTP_HEADER_SIZE+sizeof(H264::nalu_header_t)){
            std::cerr<<"Got packet that cannot be rtp h264\n";
            return false;
        }
        const H264::nalu_header_t& naluHeader=*(H264::nalu_header_t*)(&payload[RTP_HEADER_SIZE]);
        if (naluHeader.type == 28) {// fragmented nalu
            if(payloadSize<RTP_HEADER_SIZE+sizeof(H264::nalu_header_t)+sizeof(H264::fu_header_t)){
                std::cerr<<"Got invalid h264 rtp fu packet\n";
                return false;
            }
            //std::cout<<"Got fragmented NALU\n";
            const H264::fu_header_t& fuHeader=*(H264::fu_header_t*)&payload[RTP_HEADER_SIZE+sizeof(H264::nalu_header_t)];
            if(fuHeader.e){
                //std::cout<<"Got end of fragmented NALU\n";
                // end of fu-a
                return true;
            }else{
                //std::cout<<"Got start or middle of fragmented NALU\n";
                return false;
            }
        } else if(naluHeader.type>0 && naluHeader.type<24){//full nalu
            //std::cout<<"Got full NALU\n";
            return true;
        }else{
            std::cerr<<"Unknown rtp h264 packet\n";
            return true;
        }
    }
    static bool h265_end_block(const uint8_t* payload, const std::size_t payloadSize){
        if(payloadSize<RTP_HEADER_SIZE+sizeof(H265::nal_unit_header_h265_t)){
            std::cerr<<"Got packet that cannot be rtp h265\n";
            return false;
        }
        const H265::nal_unit_header_h265_t& naluHeader=*(H265::nal_unit_header_h265_t*)(&payload[RTP_HEADER_SIZE]);
        if(naluHeader.type==49){
            if(payloadSize<RTP_HEADER_SIZE+sizeof(H265::nal_unit_header_h265_t)+sizeof(H265::fu_header_h265_t)){
                std::cerr<<"Got invalid h265 rtp fu packet\n";
                return false;
            }
            const H265::fu_header_h265_t& fuHeader=*(H265::fu_header_h265_t*)&payload[RTP_HEADER_SIZE+sizeof(H265::nal_unit_header_h265_t)];
            if(fuHeader.e){
                //std::cout<<"Got end of fragmented NALU\n";
                // end of fu-a
                return true;
            }else{
                //std::cout<<"Got start or middle of fragmented NALU\n";
                return false;
            }
        }else{
            //std::cout<<"Got h265 nalu that is not a fragmentation unit\n";
            return true;
        }
    }
    static bool mjpeg_end_block(const uint8_t* payload, const std::size_t payloadSize){
        // TODO not yet supported
        return false;
    }
}

//https://stackoverflow.com/questions/66588729/is-there-an-alternative-to-stdbind-that-doesnt-require-placeholders-if-functi/66640702#66640702
namespace notstd{
    template<class F, class...Args>
    auto inline bind_front( F&& f, Args&&...args ) {
        return [f = std::forward<F>(f), tup=std::make_tuple(std::forward<Args>(args)...)](auto&&... more_args)
                ->decltype(auto)
        {
            return std::apply([&](auto&&...args)->decltype(auto){
                return std::invoke( f, decltype(args)(args)..., decltype(more_args)(more_args)... );
            }, tup);
        };
    }
}
/*#include <linux/wireless.h>
#include <ifaddrs.h>
#include <linux/nl80211.h>
#include <linux/netlink.h>

namespace Experiment{
}*/



#endif //WIFIBROADCAST_SOCKETHELPER_H
