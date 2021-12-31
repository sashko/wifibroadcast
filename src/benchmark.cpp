
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
#include "Encryption.hpp"
#include "HelperSources/RandomBufferPot.hpp"
#include <cassert>
#include <cstdio>
#include <cinttypes>
#include <unistd.h>
#include <poll.h>
#include <memory>
#include <string>
#include <chrono>
#include <sstream>
#include "HelperSources/PacketizedBenchmark.hpp"

// Test the FEC encoding / decoding performance (throughput) of this system
// Basically measures the throughput of encoding,decoding or en&decoding FEC packets on one CPU core
// NOTE: Does not take WIFI card throughput into account


//TODO: Decode only is not implemented yet.
enum BenchmarkType{ENCODE_ONLY=0,DECODE_ONLY=1,ENCODE_AND_DECODE=2,ENCRYPT=3,DECRYPT=4};
static std::string benchmarkTypeReadable(const BenchmarkType value){
    switch (value) {
        case ENCODE_ONLY:return "ENCODE_ONLY";
        case DECODE_ONLY:return "DECODE_ONLY";
        case ENCODE_AND_DECODE:return "ENCODE_AND_DECODE";
        case ENCRYPT:return "ENCRYPT";
        case DECRYPT:return "DECRYPT";
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

void benchmark_fec(const Options& options){
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
        // only decode packets if enabled (no decoding is done if test is encode only)
        if(options.benchmarkType==DECODE_ONLY || options.benchmarkType==ENCODE_AND_DECODE){
            decoder.validateAndProcessPacket(nonce, std::vector<uint8_t>(payload,payload +payloadSize));
        }
    };
    const auto cb2=[](const uint8_t * payload,std::size_t payloadSize)mutable{
        // do nothing here. Let's hope the compiler doesn't notice.
    };
    encoder.outputDataCallback=cb1;
    decoder.mSendDecodedPayloadCallback=cb2;

    PacketizedBenchmark packetizedBenchmark("FEC",(100+options.FEC_PERCENTAGE)/100.0f);

    const std::chrono::steady_clock::time_point testBegin=std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point logTs=std::chrono::steady_clock::now();
    int packetsDelta=0;
    int totalPacketsDelta=0;

    packetizedBenchmark.begin();
    // run the test for X seconds
    while ((std::chrono::steady_clock::now()-testBegin)<std::chrono::seconds(options.benchmarkTimeSeconds)){
        for(const auto& packet:testPackets){
            encoder.encodePacket(packet.data(),packet.size());
            packetsDelta++;
            totalPacketsDelta++;
            const auto delta=std::chrono::steady_clock::now()-logTs;
            if(delta>std::chrono::seconds(1)){
                const float currPacketsPerSecond=packetsDelta;
                const float currRawBitrate_MBits=currPacketsPerSecond*options.PACKET_SIZE*8.0/1024.0/1024.0;
                std::cout<<"curr. Packets per second:"<<currPacketsPerSecond<<" before FEC: "<<currRawBitrate_MBits<<"Mbit/s after FEC: "<<currRawBitrate_MBits*(100+options.FEC_PERCENTAGE)/100.0f<<"MBit/s\n";
                logTs=std::chrono::steady_clock::now();
                packetsDelta=0;
            }
            packetizedBenchmark.doneWithPacket(packet.size());
        }
    }
    const auto testDuration=std::chrono::steady_clock::now()-testBegin;
    const float testDurationSeconds=std::chrono::duration_cast<std::chrono::milliseconds>(testDuration).count()/1000.0f;
    //std::cout<<"Wanted duration:"<<options.benchmarkTimeSeconds<<" actual duration:"<<testDurationSeconds<<"\n";

    float totalPacketsPerSecond=totalPacketsDelta/(float)options.benchmarkTimeSeconds;
    float rawBitrate_MBits=totalPacketsPerSecond*options.PACKET_SIZE*8.0/1024.0/1024.0;
    std::cout<<"TOTAL Packets per second:"<<totalPacketsPerSecond<<" before FEC: "<<rawBitrate_MBits<<"Mbit/s after FEC: "<<rawBitrate_MBits*(100+options.FEC_PERCENTAGE)/100.0f<<"MBit/s\n";
    packetizedBenchmark.end();
}

void benchmark_crypt(const Options& options){
    Encryptor encryptor{std::nullopt};
    std::array<uint8_t,crypto_box_NONCEBYTES> sessionKeyNonce;
    std::array<uint8_t,crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES> sessionKeyData;
    encryptor.makeNewSessionKey(sessionKeyNonce,sessionKeyData);

    constexpr auto N_BUFFERS=1000;
    RandomBufferPot randomBufferPot{N_BUFFERS,1466};
    uint64_t nonce=0;

    const std::chrono::steady_clock::time_point testBegin=std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point logTs=std::chrono::steady_clock::now();
    int packetsDelta=0;
    int totalPacketsDelta=0;

    while ((std::chrono::steady_clock::now()-testBegin)<std::chrono::seconds(options.benchmarkTimeSeconds)){
        for(int i=0;i<N_BUFFERS;i++){
            const auto buffer=randomBufferPot.getBuffer(i);
            uint8_t add=1;
            const auto encrypted=encryptor.encryptPacket(nonce,buffer->data(),buffer->size(),add);
            assert(encrypted.size()>0);
            nonce++;

            packetsDelta++;
            totalPacketsDelta++;
            const auto delta=std::chrono::steady_clock::now()-logTs;
            if(delta>std::chrono::seconds(1)){
                const float currPacketsPerSecond=packetsDelta;
                const float currRawBitrate_MBits=currPacketsPerSecond*options.PACKET_SIZE*8.0/1024.0/1024.0;
                std::cout<<"curr. Packets per second:"<<currPacketsPerSecond<<" bitrate: "<<currRawBitrate_MBits<<"MBit/s\n";
                logTs=std::chrono::steady_clock::now();
                packetsDelta=0;
            }
        }
    }

    const auto testDuration=std::chrono::steady_clock::now()-testBegin;
    const float testDurationSeconds=std::chrono::duration_cast<std::chrono::milliseconds>(testDuration).count()/1000.0f;
    //std::cout<<"Wanted duration:"<<options.benchmarkTimeSeconds<<" actual duration:"<<testDurationSeconds<<"\n";

    float totalPacketsPerSecond=totalPacketsDelta/(float)options.benchmarkTimeSeconds;
    float rawBitrate_MBits=totalPacketsPerSecond*options.PACKET_SIZE*8.0/1024.0/1024.0;
    std::cout<<"TOTAL Packets per second:"<<totalPacketsPerSecond<<" bitrate: "<<"MBit/s\n";
}

int main(int argc, char *const *argv) {
    int opt;
    Options options{};

    SchedulingHelper::setThreadParamsMaxRealtime();
    SchedulingHelper::printCurrentThreadPriority("TEST_MAIN");
    SchedulingHelper::printCurrentThreadSchedulingPolicy("TEST_MAIN");

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
    if(options.benchmarkType==BenchmarkType::ENCRYPT || options.benchmarkType==BenchmarkType::DECRYPT){
        benchmark_crypt(options);
    }else{
        benchmark_fec(options);
    }

    return 0;
}

