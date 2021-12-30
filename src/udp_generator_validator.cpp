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

struct Options{
    // size of each packet
    int PACKET_SIZE=1446;
    // wanted bitrate (MBit/s)
    int bitrate_mbits=10;
    bool generator=true; // else validator
    int udp_port=5600; // port to send data to (generator) or listen on (validator)
    std::string udp_host=SocketHelper::ADDRESS_LOCALHOST;
};

using SEQUENCE_NUMBER=uint32_t;

Options options{};

// generate a packet where the first bytes are the sequence number
// TODO and the rest is random data
static std::vector<uint8_t> generateDeterministicPacket(SEQUENCE_NUMBER sequenceNumber){
    std::vector<uint8_t> packet(options.PACKET_SIZE);
    sequenceNumber= htonl(sequenceNumber);
    std::memcpy(packet.data(),&sequenceNumber,sizeof(sequenceNumber));
    // now fill the rest with (non-random ;) data
    std::mt19937 random_engine(sequenceNumber);

    std::generate(packet.data()+sizeof(SEQUENCE_NUMBER),packet.data()+packet.size(),random_engine);
    //std::cout<<StringHelper::vectorAsString(packet);
    return packet;
}

// extract the sequence number from the packet, then validate the rest
static bool validateDeterministicPacket(std::vector<uint8_t> packet,SEQUENCE_NUMBER& sequenceNumber){
    assert(packet.size()>=sizeof(SEQUENCE_NUMBER));
    std::memcpy(&sequenceNumber,packet.data(),sizeof(sequenceNumber));
    sequenceNumber= htonl(sequenceNumber);
    // now that we have the sequence number, check if the content is right
    const auto validPacket= generateDeterministicPacket(sequenceNumber);
    return GenericHelper::compareVectors(packet,validPacket);
}


int main(int argc, char *const *argv) {
    int opt;

    while ((opt = getopt(argc, argv, "s:v:u:b:h:")) != -1) {
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
            case 'b':
                options.bitrate_mbits = std::stoi(optarg); //TODO unimplemented
                break;
            case 'h':
                options.udp_host=std::string(optarg);
                break;
            default: /* '?' */
            show_usage:
                std::cout<<"Usage: [-s=packet size in bytes,default:"<<options.PACKET_SIZE<<"] [-v validate packets (else generate packets)] [-u udp port,default:"<<options.udp_port<<
                "] [-h udp host default:"<<options.udp_host<<"]\n";
                return 1;
        }
    }
    if(options.PACKET_SIZE<sizeof(SEQUENCE_NUMBER)){
        std::cout<<"Error min packet size is "<<sizeof(SEQUENCE_NUMBER)<<" bytes\n";
        return 0;
    }

    std::cout<<"PACKET_SIZE: "<<options.PACKET_SIZE<<"\n";
    std::cout<<"Bitrate: "<<options.bitrate_mbits<<"MBit/s"<<"\n";
    std::cout<<"Generator: "<<(options.generator ? "yes":"no")<<"\n";
    std::cout<<"UDP port: "<<options.udp_port<<"\n";
    std::cout<<"UDP host: "<<options.udp_host<<"\n";

    if(options.generator){
        uint32_t seqNr=0;
        SocketHelper::UDPForwarder forwarder(options.udp_host,options.udp_port);
        while (true){
            const auto packet= generateDeterministicPacket(seqNr);
            forwarder.forwardPacketViaUDP(packet.data(),packet.size());
            std::cout<<"Sent packet:"<<seqNr<<"\n";
            seqNr++;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            if(seqNr>10000000)break;
        }
    }else{
        const auto cb=[](const uint8_t* payload,const std::size_t payloadSize)mutable {
            SEQUENCE_NUMBER seqNr;
            bool valid=validateDeterministicPacket(std::vector<uint8_t>(payload,payload+payloadSize),seqNr);
            std::cout<<"Packet:"<<seqNr<<"Valid:"<<(valid ? "y":"n")<<"\n";
        };

        SocketHelper::UDPReceiver receiver(SocketHelper::ADDRESS_LOCALHOST,options.udp_port,cb);
        // run for infinity
    }

    return 0;
}

