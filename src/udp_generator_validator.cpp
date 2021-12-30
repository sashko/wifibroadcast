//
// Created by consti10 on 30.12.21.
//

// testing utility
// when run as creator, creates deterministic packets and forwards them as udp packets
// when run as validator, validates these (deterministic) packets

#include "HelperSources/Helper.hpp"
#include <cassert>
#include <cstdio>
#include <cinttypes>
#include <unistd.h>
#include <poll.h>
#include <memory>
#include <string>
#include <chrono>
#include <sstream>
#include <thread>
#include <random>

// the content of each packet is simple -
// the sequence number appended by some random data depending on the sequence number

/*static bool quit = false;
static void sigterm_handler(int sig) {
    fprintf(stderr, "signal %d\n", sig);
    quit = true;
}*/

struct Options{
    // size of each packet
    int PACKET_SIZE=1446;
    // wanted bitrate (MBit/s)
    int wanted_packets_per_second=1;
    bool generator=true; // else validator
    int udp_port=5600; // port to send data to (generator) or listen on (validator)
    std::string udp_host=SocketHelper::ADDRESS_LOCALHOST;
};

using SEQUENCE_NUMBER=uint32_t;

Options options{};

// holds x buffers with (semi-random) data.
class RandomBufferPot{
public:
    /**
     * Holds @param nBuffers random data buffers of size @param bufferSize
     */
    RandomBufferPot(const std::size_t nBuffers,const std::size_t bufferSize):m_buffers(nBuffers,std::make_unique<std::vector<uint8_t>>(bufferSize)){
        // fill all buffers with random data
        int seqNr=0;
        std::mt19937 random_engine(seqNr);
        for(auto& buffer:m_buffers){
            random_engine.seed(seqNr);
            std::generate(buffer->data(),buffer->data()+buffer->size(),random_engine);
            //std::cout<<StringHelper::vectorAsString(*buffer.get())<<"\n\n";
            seqNr++;
        }
    }
    // get a semi-random data buffer for this sequence number. If the sequence number is higher than the n of allocated buffers,
    // it loops around. As long as this pot is big enough, it should be sufficient to emulate a random data stream
    std::shared_ptr<std::vector<uint8_t>> getBuffer(SEQUENCE_NUMBER sequenceNumber){
        auto index=sequenceNumber % m_buffers.size();
        return m_buffers.at(index);
    }
private:
    std::vector<std::shared_ptr<std::vector<uint8_t>>> m_buffers;
    //static constexpr const uint32_t SEED=12345;
};

static std::unique_ptr<RandomBufferPot> randomBufferPot= nullptr;

// Get one of the random data packets and
// write the sequence number as first x bytes such that the rx knows which packet was received
// (and can validate the semi-random data by using the sequence number)
static std::shared_ptr<std::vector<uint8_t>> generateDeterministicPacket(SEQUENCE_NUMBER sequenceNumber){
    auto packet=randomBufferPot->getBuffer(sequenceNumber);
    sequenceNumber= htonl(sequenceNumber);
    std::memcpy(packet->data(),&sequenceNumber,sizeof(sequenceNumber));
    return packet;
}

// extract the sequence number from the packet, then validate the rest
static bool validateDeterministicPacket(const std::vector<uint8_t>& packet,SEQUENCE_NUMBER& sequenceNumber){
    assert(packet.size()>=sizeof(SEQUENCE_NUMBER));
    std::memcpy(&sequenceNumber,packet.data(),sizeof(sequenceNumber));
    sequenceNumber= htonl(sequenceNumber);
    // now that we have the sequence number, check if the content is right
    const auto validPacket= generateDeterministicPacket(sequenceNumber);
    return GenericHelper::compareVectors(packet,*validPacket.get());
}


int main(int argc, char *const *argv) {
    int opt;

    while ((opt = getopt(argc, argv, "s:v:u:b:h:p:")) != -1) {
        switch (opt) {
            case 's':
                options.PACKET_SIZE = atoi(optarg);
                break;
            case 'v':
                options.generator = false;
                break;
            case 'u':
                options.udp_port = std::stoi(optarg);
                break;
            case 'p':
                options.wanted_packets_per_second = std::atoi(optarg);
                break;
            case 'h':
                options.udp_host=std::string(optarg);
                break;
            default: /* '?' */
            show_usage:
                std::cout<<"Usage: [-s=packet size in bytes,default:"<<options.PACKET_SIZE<<"] [-v validate packets (else generate packets)] [-u udp port,default:"<<options.udp_port<<
                "] [-h udp host default:"<<options.udp_host<<"]"<<"[-p wanted packets per second, default:"<<options.wanted_packets_per_second<<"]"<<"\n";
                return 1;
        }
    }
    if(options.PACKET_SIZE<sizeof(SEQUENCE_NUMBER)){
        std::cout<<"Error min packet size is "<<sizeof(SEQUENCE_NUMBER)<<" bytes\n";
        return 0;
    }
    const float wantedBitRate_MBits=options.PACKET_SIZE*options.wanted_packets_per_second*8.0f/1024.0f/1024.0f;
    std::cout<<"PACKET_SIZE: "<<options.PACKET_SIZE<<"\n";
    std::cout<<"wanted_packets_per_second: "<<options.wanted_packets_per_second<<"\n";
    std::cout<<"wanted Bitrate: "<<wantedBitRate_MBits<<"MBit/s"<<"\n";
    std::cout<<"Generator: "<<(options.generator ? "yes":"no")<<"\n";
    std::cout<<"UDP port: "<<options.udp_port<<"\n";
    std::cout<<"UDP host: "<<options.udp_host<<"\n";

    //RandomBufferPot randomBufferPot{10,100};
    randomBufferPot=std::make_unique<RandomBufferPot>(1000,options.PACKET_SIZE);


    const auto deltaBetweenPackets=std::chrono::nanoseconds((1000*1000*1000)/options.wanted_packets_per_second);
    auto lastLog=std::chrono::steady_clock::now();

    if(options.generator){
        static bool quit=false;
        signal(SIGTERM, [](int sig){quit=true;});
        uint32_t seqNr=0;
        SocketHelper::UDPForwarder forwarder(options.udp_host,options.udp_port);
        auto before=std::chrono::steady_clock::now();
        while (!quit){
            const auto packet= generateDeterministicPacket(seqNr);
            forwarder.forwardPacketViaUDP(packet->data(),packet->size());
            // keep logging to a minimum for fast testing
            if(options.wanted_packets_per_second<10){
                std::cout<<"Sent packet:"<<seqNr<<"\n";
            }else{
                if(std::chrono::steady_clock::now()-lastLog>std::chrono::seconds(1)){
                    std::cout<<"Sent packets:"<<seqNr<<"\n";
                    lastLog=std::chrono::steady_clock::now();
                }
            }
            seqNr++;
            //std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            while (std::chrono::steady_clock::now()-before<deltaBetweenPackets){
                // busy wait
            }
            before=std::chrono::steady_clock::now();
        }
    }else{
        static int nValidPackets=0;
        static int nInvalidPackets=0;
        static auto lastLog=std::chrono::steady_clock::now();
        const auto cb=[](const uint8_t* payload,const std::size_t payloadSize)mutable {
            SEQUENCE_NUMBER seqNr;
            bool valid=validateDeterministicPacket(std::vector<uint8_t>(payload,payload+payloadSize),seqNr);
            if(valid){
                nValidPackets++;
            }else{
                nInvalidPackets++;
            }
            auto delta=std::chrono::steady_clock::now()-lastLog;
            if(delta>std::chrono::milliseconds (500)){
                std::cout<<"Packet nr:"<<seqNr<<"Valid:"<<(valid ? "y":"n")<<" N packets V,INV:"<<nValidPackets<<","<<nInvalidPackets<<"\n";
                lastLog=std::chrono::steady_clock::now();
            }
        };

        static SocketHelper::UDPReceiver receiver{SocketHelper::ADDRESS_LOCALHOST,options.udp_port,cb};
        signal(SIGTERM, [](int sig){receiver.stop();});
        // run until ctr+x
        receiver.start();
    }

    return 0;
}

