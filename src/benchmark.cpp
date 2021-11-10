
// Copyright (C) 2017, 2018 Vasily Evseenko <svpcom@p2ptech.org>
// 2020 Constantin Geier

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "RawReceiver.hpp"
#include "wifibroadcast.hpp"
#include "HelperSources/SchedulingHelper.hpp"
#include <cassert>
#include <cstdio>
#include <cinttypes>
#include <unistd.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <memory>
#include <string>
#include <chrono>
#include <sstream>
#include "FECEnabled.hpp"

// Test the FEC encoding / decoding performance of this system
// Basically measures the throughput of both encoding and decoding FEC packets on one CPU core

struct Options{
    // size of each packet
    int PACKET_SIZE=1446;
    // how many packets per second
    int WANTED_PACKETS_PER_SECOND=1024;
    int FEC_K=10;
    int FEC_PERCENTAGE=50;
};

static std::size_t N_ALLOCATED_BUFFERS=1024;
static int TEST_TIME_SECONDS=60;

void test(const Options& options){
    auto testPackets=GenericHelper::createRandomDataBuffers(N_ALLOCATED_BUFFERS,options.PACKET_SIZE,options.PACKET_SIZE);
    for(const auto& packet:testPackets){
        assert(packet.size()== options.PACKET_SIZE);
    }
    // init encoder and decoder, link the callback
    FECEncoder encoder(options.FEC_K,options.FEC_PERCENTAGE);
    FECDecoder decoder;
    const auto cb1=[&decoder](const uint64_t nonce,const uint8_t* payload,const std::size_t payloadSize)mutable {
        decoder.validateAndProcessPacket(nonce, std::vector<uint8_t>(payload,payload +payloadSize));
    };
    const auto cb2=[](const uint8_t * payload,std::size_t payloadSize)mutable{
        // do nothing here
    };
    encoder.outputDataCallback=cb1;
    decoder.mSendDecodedPayloadCallback=cb2;

    const std::chrono::steady_clock::time_point testBegin=std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point logTs=std::chrono::steady_clock::now();
    std::size_t packetsDelta=0;

    // run the test for X seconds
    while ((std::chrono::steady_clock::now()-testBegin)<std::chrono::seconds(TEST_TIME_SECONDS)){
        for(const auto& packet:testPackets){
            encoder.encodePacket(packet.data(),packet.size());
            packetsDelta++;
            const auto delta=std::chrono::steady_clock::now()-logTs;
            if(delta>std::chrono::seconds(1)){
                float rawBitrate_MBits=packetsDelta*options.PACKET_SIZE*8/1024/1024.0f;
                std::cout<<"Packets per second:"<<packetsDelta<<" before FEC: "<<rawBitrate_MBits<<"Mbit/s after FEC: "<<rawBitrate_MBits*(100+options.FEC_PERCENTAGE)/100.0f<<"MBit/s\n";
                logTs=std::chrono::steady_clock::now();
                packetsDelta=0;
            }
        }
    }
}

int main(int argc, char *const *argv) {
    int opt;
    Options options{};

    while ((opt = getopt(argc, argv, "s:p:t:i:o:")) != -1) {
        switch (opt) {
            case 's':
                options.PACKET_SIZE = atoi(optarg);
                break;
            case 'p':
                options.WANTED_PACKETS_PER_SECOND = atoi(optarg);
                break;
            default: /* '?' */
            show_usage:
                std::cout<<"Usage: [-s=packet size in bytes] [-p=packets per second]\n";
                return 1;
        }
    }

    std::cout<<"Benchmark start. PacketSize:"<<options.PACKET_SIZE<<" FEC_K:"<<options.FEC_K<<"FEC_PERCENTAGE:"<<options.FEC_PERCENTAGE<<"\n";
    test(options);

    return 0;
}

