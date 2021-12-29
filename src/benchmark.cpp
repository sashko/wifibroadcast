
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
#include "HelperSources/SchedulingHelper.hpp"
#include "FECEnabled.hpp"
#include <cassert>
#include <cstdio>
#include <cinttypes>
#include <unistd.h>
#include <poll.h>
#include <memory>
#include <string>
#include <chrono>
#include <sstream>

// Test the FEC encoding / decoding performance (throughput) of this system
// Basically measures the throughput of encoding,decoding or en&decoding FEC packets on one CPU core
// NOTE: Does not take WIFI card throughput into account

//TODO: Decode only is not implemented yet.
enum BenchmarkType{ENCODE_ONLY=0,DECODE_ONLY=1,ENCODE_AND_DECODE=2};
static std::string benchmarkTypeReadable(const BenchmarkType value){
    switch (value) {
        case ENCODE_ONLY:return "ENCODE_ONLY";
        case DECODE_ONLY:return "DECODE_ONLY";
        case ENCODE_AND_DECODE:return "ENCODE_AND_DECODE";
        default:return "ERROR";
    }
}

struct Options{
    // size of each packet
    int PACKET_SIZE=1446;
    int FEC_K=10;
    int FEC_PERCENTAGE=50;
    BenchmarkType benchmarkType=BenchmarkType::ENCODE_ONLY;
    // How long the benchmark will take
    int benchmarkTimeSeconds=60;
};

// How many buffers we allocate (must be enough to simulate a constant flow of random data, but too many packets might result in OOM)
static std::size_t N_ALLOCATED_BUFFERS=1024;

void test(const Options& options){
    const auto testPackets=GenericHelper::createRandomDataBuffers(N_ALLOCATED_BUFFERS,options.PACKET_SIZE,options.PACKET_SIZE);
    // only used when we want to benchmark decoding performance only
    auto testPacketsAfterEncode=std::vector<std::pair<uint64_t,std::vector<uint8_t>>>();
    // when benchmarking the decoding performance only pre-compute the FEC packets before starting the test
    if(options.benchmarkType==DECODE_ONLY){
        FECEncoder encoder(options.FEC_K,options.FEC_PERCENTAGE);
        const auto cb1=[&testPacketsAfterEncode](const uint64_t nonce,const uint8_t* payload,const std::size_t payloadSize)mutable {
            testPacketsAfterEncode.push_back(std::make_pair(nonce,std::vector<uint8_t>(payload,payload+payloadSize)));
        };
        for(const auto& packet:testPackets){
            encoder.encodePacket(packet.data(),packet.size());
        }
    }
    // init encoder and decoder, link the callback
    FECEncoder encoder(options.FEC_K,options.FEC_PERCENTAGE);
    FECDecoder decoder;
    const auto cb1=[&decoder,&options](const uint64_t nonce,const uint8_t* payload,const std::size_t payloadSize)mutable {
        if(options.benchmarkType==DECODE_ONLY || options.benchmarkType==ENCODE_AND_DECODE){
            decoder.validateAndProcessPacket(nonce, std::vector<uint8_t>(payload,payload +payloadSize));
        }
    };
    const auto cb2=[](const uint8_t * payload,std::size_t payloadSize)mutable{
        // do nothing here. Let's hope the compiler doesn't notice.
    };
    encoder.outputDataCallback=cb1;
    decoder.mSendDecodedPayloadCallback=cb2;

    const std::chrono::steady_clock::time_point testBegin=std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point logTs=std::chrono::steady_clock::now();
    std::size_t packetsDelta=0;
    std::size_t totalPacketsDelta=0;

    // run the test for X seconds
    while ((std::chrono::steady_clock::now()-testBegin)<std::chrono::seconds(options.benchmarkTimeSeconds)){
        for(const auto& packet:testPackets){
            encoder.encodePacket(packet.data(),packet.size());
            packetsDelta++;
            totalPacketsDelta++;
            const auto delta=std::chrono::steady_clock::now()-logTs;
            if(delta>std::chrono::seconds(1)){
                float rawBitrate_MBits=packetsDelta*options.PACKET_SIZE*8/1024/1024.0f;
                std::cout<<"curr. Packets per second:"<<packetsDelta<<" before FEC: "<<rawBitrate_MBits<<"Mbit/s after FEC: "<<rawBitrate_MBits*(100+options.FEC_PERCENTAGE)/100.0f<<"MBit/s\n";
                logTs=std::chrono::steady_clock::now();
                packetsDelta=0;
            }
        }
    }
    const auto testDuration=std::chrono::steady_clock::now()-testBegin;
    std::cout<<"Wanted duration:"<<options.benchmarkTimeSeconds<<" actual duration:"<<std::chrono::duration_cast<std::chrono::milliseconds>(testDuration)/1000.0f<<"\n";

    float rawBitrate_MBits=totalPacketsDelta*options.PACKET_SIZE*8/1024/1024.0f/options.benchmarkTimeSeconds;
    std::cout<<"TOTAL Packets per second:"<<totalPacketsDelta/options.benchmarkTimeSeconds<<" before FEC: "<<rawBitrate_MBits<<"Mbit/s after FEC: "<<rawBitrate_MBits*(100+options.FEC_PERCENTAGE)/100.0f<<"MBit/s\n";
}

int main(int argc, char *const *argv) {
    int opt;
    Options options{};

    while ((opt = getopt(argc, argv, "s:k:p:x:t:")) != -1) {
        switch (opt) {
            case 's':
                options.PACKET_SIZE = atoi(optarg);
                break;
            case 'k':
                options.FEC_K = atoi(optarg);
                break;
            case 'p':
                options.FEC_PERCENTAGE = atoi(optarg);
                break;
            case 'x':{
                options.benchmarkType=(BenchmarkType)atoi(optarg);
            }
                break;
            case 't':
                options.benchmarkTimeSeconds= atoi(optarg);
                break;
            default: /* '?' */
            show_usage:
                std::cout<<"Usage: [-s=packet size in bytes] [-k=FEC_K] [-p=FEC_P] [-x Benchmark type. 0=encoding 1=decoding 2=encoding & decoding] [-t benchmark time in seconds]\n";
                return 1;
        }
    }

    std::cout<<"Benchmark type: "<<options.benchmarkType<<"("<<benchmarkTypeReadable(options.benchmarkType)<<")\n";
    std::cout<<"PacketSize: "<<options.PACKET_SIZE<<" B\n";
    std::cout<<"FEC_K: "<<options.FEC_K<<"\n";
    std::cout<<"FEC_PERCENTAGE: "<<options.FEC_PERCENTAGE<<"\n";
    std::cout<<"Benchmark time: "<<options.benchmarkTimeSeconds<<" s\n";
    test(options);

    return 0;
}

