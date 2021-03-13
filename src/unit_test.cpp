
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

#include <cassert>
#include <cstdio>
#include <cinttypes>
#include <ctime>
#include <climits>

#include <memory>
#include <string>
#include <chrono>
#include <sstream>

#include "wifibroadcast.hpp"
#include "FEC.hpp"

#include "HelperSources/Helper.hpp"
#include "Encryption.hpp"

// Simple unit testing for the lib that doesn't require wifi cards

namespace TestFEC{
    // test the FECEncoder / FECDecoder tuple
    static void testWithoutPacketLoss(const int k, const int n, const std::vector<std::vector<uint8_t>>& testIn){
        std::cout<<"Test without packet loss. K:"<<k<<" N:"<<n<<" N_PACKETS:"<<testIn.size()<<"\n";
        FECEncoder encoder(k,n);
        FECDecoder decoder;
        std::vector<std::vector<uint8_t>> testOut;

        const auto cb1=[&decoder](const uint64_t nonce,const uint8_t* payload,const std::size_t payloadSize)mutable {
            decoder.validateAndProcessPacket(nonce, std::vector<uint8_t>(payload,payload +payloadSize));
        };
        const auto cb2=[&testOut](const uint8_t * payload,std::size_t payloadSize)mutable{
            testOut.emplace_back(payload,payload+payloadSize);
        };
        encoder.outputDataCallback=cb1;
        decoder.mSendDecodedPayloadCallback=cb2;
        // If there is no data loss the packets should arrive immediately
        for(std::size_t i=0;i<testIn.size();i++){
            //std::cout<<"Step\n";
            const auto& in=testIn[i];
            encoder.encodePacket(in.data(),in.size());
            const auto& out=testOut[i];
            assert(GenericHelper::compareVectors(in,out)==true);
        }
    }

    static void testRxQueue(const int k, const int n){
        std::cout<<"Test rx queue. K:"<<k<<" N:"<<n<<"\n";
        constexpr auto QUEUE_SIZE=FECDecoder::RX_QUEUE_MAX_SIZE;
        const auto testIn=GenericHelper::createRandomDataBuffers(QUEUE_SIZE*k, FEC_MAX_PAYLOAD_SIZE, FEC_MAX_PAYLOAD_SIZE);
        FECEncoder encoder(k,n);
        FECDecoder decoder;
        // begin test
        std::vector<std::pair<uint64_t,std::vector<uint8_t>>> fecPackets;
        const auto cb1=[&fecPackets](const uint64_t nonce,const uint8_t* payload,const std::size_t payloadSize)mutable {
            fecPackets.emplace_back(nonce,std::vector<uint8_t>(payload,payload +payloadSize));
        };
        encoder.outputDataCallback=cb1;
        // process all input packets
        for(const auto& in:testIn){
            encoder.encodePacket(in.data(),in.size());
        }
        // now add them to the decoder (queue):
        std::vector<std::vector<uint8_t>> testOut;
        const auto cb2=[&testOut](const uint8_t * payload,std::size_t payloadSize)mutable{
            testOut.emplace_back(payload,payload+payloadSize);
        };
        decoder.mSendDecodedPayloadCallback=cb2;
        // add fragments (primary fragments only to not overcomplicate things)
        // but in the following order:
        // block 0, fragment 0, block 1, fragment 0, block 2, fragment 0, ... until block X, fragment n
        for(int frIdx=0; frIdx < k; frIdx++){
            for(int i=0;i<QUEUE_SIZE;i++){
                const auto idx=i*n + frIdx;
                std::cout<<"adding"<<idx<<"\n";
                const auto& packet=fecPackets.at(idx);
                decoder.validateAndProcessPacket(packet.first,packet.second);
            }
        }
        // and then check if in and out match
        for(std::size_t i=0;i<testIn.size();i++){
            std::cout<<"Step\n";
            const auto& in=testIn[i];
            const auto& out=testOut[i];
            GenericHelper::assertVectorsEqual(in,out);
        }
    }

    // No packet loss
    // Fixed packet size
    static void testWithoutPacketLossFixedPacketSize(const int k, const int n, const std::size_t N_PACKETS){
        auto testIn=GenericHelper::createRandomDataBuffers(N_PACKETS, FEC_MAX_PAYLOAD_SIZE, FEC_MAX_PAYLOAD_SIZE);
        testWithoutPacketLoss(k, n, testIn);
    }

    // No packet loss
    // Dynamic packet size (up to N bytes)
    static void testWithoutPacketLossDynamicPacketSize(const int k, const int n, const std::size_t N_PACKETS){
        auto testIn=GenericHelper::createRandomDataBuffers(N_PACKETS, 1, FEC_MAX_PAYLOAD_SIZE);
        testWithoutPacketLoss(k, n, testIn);
    }

    // test with packet loss
    // but only drop as much as everything must be still recoverable
    static void testWithPacketLossButEverythingIsRecoverable(const int k, const int n, const std::vector<std::vector<uint8_t>>& testIn,const int DROP_MODE,const bool SEND_DUPLICATES=false) {
        assert(testIn.size() % k==0);
        // drop mode 2 is impossible if (n-k)<2
        if(DROP_MODE==2)assert((n-k)>=2);
        std::cout << "Test (with packet loss) K:" << k << " N:" << n << " N_PACKETS:" << testIn.size() <<" DROP_MODE:"<<DROP_MODE<< "\n";
        FECEncoder encoder(k, n);
        FECDecoder decoder;
        std::vector <std::vector<uint8_t>> testOut;
        const auto cb1 = [&decoder,n,k,DROP_MODE,SEND_DUPLICATES](const uint64_t nonce,const uint8_t* payload,const std::size_t payloadSize)mutable {
            const FECNonce fecNonce=fecNonceFrom(nonce);
            const auto blockIdx=fecNonce.blockIdx;
            const auto fragmentIdx=fecNonce.fragmentIdx;
            if(DROP_MODE==0){
                // drop all FEC correction packets but no data packets (everything should be still recoverable
                if(fragmentIdx>=k){
                    std::cout<<"Dropping FEC-CORRECTION packet:["<<blockIdx<<","<<(int)fragmentIdx<<"]\n";
                    return;
                }
            }else if(DROP_MODE==1){
                // drop 1 data packet and let FEC do its magic
                if(fragmentIdx==0){
                    std::cout<<"Dropping FEC-DATA packet:["<<blockIdx<<","<<(int)fragmentIdx<<"]\n";
                    return;
                }
            }else if(DROP_MODE==2){
                // drop 1 data packet and 1 FEC packet but that still shouldn't pose any issues
                if(fragmentIdx==0){
                    std::cout<<"Dropping FEC-DATA packet:["<<blockIdx<<","<<(int)fragmentIdx<<"]\n";
                    return;
                }else if(fragmentIdx==k-1){
                    std::cout<<"Dropping FEC-CORRECTION packet:["<<blockIdx<<","<<(int)fragmentIdx<<"]\n";
                    return;
                }
            }
            if(SEND_DUPLICATES){
                // emulate not more than N multiple wifi cards as rx
                const auto duplicates=std::rand() % 8;
                for(int i=0;i<duplicates+1;i++){
                    decoder.validateAndProcessPacket(nonce,
                                                     std::vector<uint8_t>(payload, payload +payloadSize));
                }
            }else{
                decoder.validateAndProcessPacket(nonce, std::vector<uint8_t>(payload,payload + payloadSize));
            }
        };
        const auto cb2 = [&testOut](const uint8_t *payload, std::size_t payloadSize)mutable {
            testOut.emplace_back(payload, payload + payloadSize);
        };
        encoder.outputDataCallback = cb1;
        decoder.mSendDecodedPayloadCallback = cb2;
        for (std::size_t i = 0; i < testIn.size(); i++) {
            const auto &in = testIn[i];
            encoder.encodePacket(in.data(), in.size());
            // every time we have sent enough packets to form a block, check if everything arrived
            // This way we would also catch any unwanted latency created by the decoder as an error
            if(i % k ==0 && i>0){
                for(std::size_t j=0;j<i;j++){
                    assert(GenericHelper::compareVectors(testIn[j], testOut[j]) == true);
                }
            }
        }
        // just to be sure, check again
        assert(testIn.size()==testOut.size());
        for (std::size_t i = 0; i < testIn.size(); i++) {
            const auto &in = testIn[i];
            const auto &out = testOut[i];
            assert(GenericHelper::compareVectors(in, out) == true);
        }
    }

    static void testWithPacketLossButEverythingIsRecoverable(const int k, const int n, const std::size_t N_PACKETS, const int DROP_MODE){
        std::vector<std::vector<uint8_t>> testIn;
        for(std::size_t i=0;i<N_PACKETS;i++){
            const auto size= (rand() % FEC_MAX_PAYLOAD_SIZE) + 1;
            testIn.push_back(GenericHelper::createRandomDataBuffer(size));
        }
        testWithPacketLossButEverythingIsRecoverable(k, n, testIn,DROP_MODE, true);
    }
}

namespace TestEncryption{
    static void test(){
        Encryptor encryptor("gs.key");
        Decryptor decryptor("drone.key");
        WBSessionKeyPacket sessionKeyPacket;
        // make session key (tx)
        encryptor.makeNewSessionKey(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData);
        // and "receive" session key (rx)
        assert(decryptor.onNewPacketSessionKeyData(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData) == true);
        // now encrypt a couple of packets and decrypt them again afterwards
        for(uint64_t nonce=0; nonce < 20; nonce++){
            const auto data=GenericHelper::createRandomDataBuffer(FEC_MAX_PAYLOAD_SIZE);
            const WBDataHeader wbDataHeader(nonce);

            //const auto encrypted= encryptor.encryptWBDataPacket(wbDataPacket);
            const auto encrypted=encryptor.encryptPacket(wbDataHeader.nonce,data.data(),data.size(),wbDataHeader);

            const auto decrypted=decryptor.decryptPacket(wbDataHeader.nonce,encrypted.data(), encrypted.size(),wbDataHeader);

            assert(decrypted!=std::nullopt);
            assert(GenericHelper::compareVectors(data,*decrypted) == true);
        }
    }
}


int main(int argc, char *argv[]){
    std::cout<<"Tests for Wifibroadcast\n";
    try {
        std::cout<<"Testing FEC\n";
        const int N_PACKETS=1200;
        TestFEC::testWithoutPacketLossFixedPacketSize(1,1, N_PACKETS);
        TestFEC::testWithoutPacketLossFixedPacketSize(1,2, N_PACKETS);
        // only test with FEC enabled
        const std::vector<std::pair<uint8_t,uint8_t>> fecParams={
                {1,3},
                {3,5},{3,6},{6,8},{6,9},
                {2,4},{4,8},
                {6,12},{8,16},{12,24},
                {4,6},{12,14}
        };
        for(const auto& fecParam:fecParams){
            const uint8_t k=fecParam.first;
            const uint8_t n=fecParam.second;
            TestFEC::testWithoutPacketLossFixedPacketSize(k, n, N_PACKETS);
            TestFEC::testWithoutPacketLossDynamicPacketSize(k, n, N_PACKETS);
            TestFEC::testRxQueue(k,n);
            for(int dropMode=0;dropMode<3;dropMode++){
                TestFEC::testWithPacketLossButEverythingIsRecoverable(k, n, N_PACKETS, dropMode);
            }
        }
        //
        std::cout<<"Testing Encryption\n";
        TestEncryption::test();
        //
    }catch (std::runtime_error &e) {
        std::cerr<<"Error: "<<std::string(e.what());
        exit(1);
    }
    std::cout<<"All Tests Passing\n";
    return 0;
}