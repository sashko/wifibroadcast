
// Copyright (C) 2017, 2018, 2019 Vasily Evseenko <svpcom@p2ptech.org>
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

#include "tx.hpp"
#include "HelperSources/SchedulingHelper.hpp"

#include <cstdio>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <ctime>
#include <sys/resource.h>
#include <pcap/pcap.h>
#include <cassert>
#include <chrono>
#include <memory>
#include <string>
#include <memory>
#include <vector>
#include <thread>


WBTransmitter::WBTransmitter(RadiotapHeader radiotapHeader, Options options1) :
        options(std::move(options1)),
        mPcapTransmitter(options.wlan),
        mEncryptor(options.keypair),
        mRadiotapHeader(radiotapHeader),
        FLUSH_INTERVAL(std::chrono::milliseconds (-1)),
        IS_FEC_ENABLED(options.IS_FEC_ENABLED){
    if(FLUSH_INTERVAL>LOG_INTERVAL){
        std::cerr<<"Please use a flush interval smaller than the log interval\n";
    }
    if(FLUSH_INTERVAL==std::chrono::milliseconds(0)){
        std::cerr<<"Please do not use a flush interval of 0 (would hog the cpu)\n";
    }
    mEncryptor.makeNewSessionKey(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData);
    if(IS_FEC_ENABLED){
        if(options.fec.index()==0){
            const FECFixed fecFixed=std::get<FECFixed>(options.fec);
            mFecEncoder=std::make_unique<FECEncoder>(fecFixed.k,fecFixed.n);
            mFecEncoder->outputDataCallback=std::bind(&WBTransmitter::sendFecPrimaryOrSecondaryFragment, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
        }else{
            const FECVariable fecVariable=std::get<FECVariable>(options.fec);
            mFecEncoder=std::make_unique<FECEncoder>(fecVariable.percentage);
            mFecEncoder->outputDataCallback=std::bind(&WBTransmitter::sendFecPrimaryOrSecondaryFragment, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
        }
    }else{
        mFecDisabledEncoder=std::make_unique<FECDisabledEncoder>();
        mFecDisabledEncoder->outputDataCallback=std::bind(&WBTransmitter::sendFecPrimaryOrSecondaryFragment, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    }
    mInputSocket=SocketHelper::openUdpSocketForRx(options.udp_port);
    fprintf(stderr, "WB-TX Listen on UDP Port %d assigned ID %d assigned WLAN %s FLUSH_INTERVAL(ms) %d\n", options.udp_port,options.radio_port,options.wlan.c_str(),-1);
    // the rx needs to know if FEC is enabled or disabled. Note, both variable and fixed fec counts as FEC enabled
    sessionKeyPacket.IS_FEC_ENABLED=IS_FEC_ENABLED;
}

WBTransmitter::~WBTransmitter() {
    close(mInputSocket);
}


void WBTransmitter::sendPacket(const AbstractWBPacket& abstractWbPacket) {
    //std::cout << "WBTransmitter::sendPacket\n";
    mIeee80211Header.writeParams(options.radio_port, ieee80211_seq);
    ieee80211_seq += 16;
    const auto injectionTime=mPcapTransmitter.injectPacket(mRadiotapHeader,mIeee80211Header,abstractWbPacket);
    nInjectedPackets++;
#ifdef ENABLE_ADVANCED_DEBUGGING
    pcapInjectionTime.add(injectionTime);
    if(pcapInjectionTime.getMax()>std::chrono::milliseconds (1)){
        std::cerr<<"Injecting PCAP packet took really long:"<<pcapInjectionTime.getAvgReadable()<<"\n";
        pcapInjectionTime.reset();
    }
#endif
}

void WBTransmitter::sendFecPrimaryOrSecondaryFragment(const uint64_t nonce, const uint8_t* payload, const std::size_t payloadSize) {
    //std::cout << "WBTransmitter::sendFecBlock"<<(int)wbDataPacket.payloadSize<<"\n";
    const WBDataHeader wbDataHeader(nonce);
    const auto encryptedData=mEncryptor.encryptPacket(nonce,payload,payloadSize,wbDataHeader);
    //
    sendPacket({(const uint8_t*)&wbDataHeader,sizeof(WBDataHeader),encryptedData.data(),encryptedData.size()});
#ifdef ENABLE_ADVANCED_DEBUGGING
    //LatencyTestingPacket latencyTestingPacket;
    //sendPacket((uint8_t*)&latencyTestingPacket,sizeof(latencyTestingPacket));
#endif
}

void WBTransmitter::sendSessionKey() {
    std::cout << "sendSessionKey()\n";
    sendPacket({(uint8_t *)&sessionKeyPacket, WBSessionKeyPacket::SIZE_BYTES});
}

void WBTransmitter::processInputPacket(const uint8_t *buf, size_t size) {
    //std::cout << "WBTransmitter::send_packet\n";
    // this calls a callback internally
    if(IS_FEC_ENABLED){
        mFecEncoder->encodePacket(buf,size);
        if(mFecEncoder->resetOnOverflow()){
            // running out of sequence numbers should never happen during the lifetime of the TX instance, but handle it properly anyways
            mEncryptor.makeNewSessionKey(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData);
            sendSessionKey();
        }
    }else{
        mFecDisabledEncoder->encodePacket(buf,size);
    }
}

void WBTransmitter::loop() {
    constexpr auto MAX_UDP_PAYLOAD_SIZE=65507;
    // If we'd use a smaller buffer, in case the user doesn't respect the max packet size, the OS will silently drop all bytes exceeding FEC_MAX_PAYLOAD_BYTES.
    // This way we can throw an error in case the above happens.
    std::array<uint8_t,MAX_UDP_PAYLOAD_SIZE> buf{};
    std::chrono::steady_clock::time_point session_key_announce_ts{};
    std::chrono::steady_clock::time_point log_ts{};
    // send the key a couple of times on startup to increase the likeliness it is received
    bool firstTime=true;
    // -1 would mean "flushing disabled"
    if(FLUSH_INTERVAL>std::chrono::milliseconds(0)){
        SocketHelper::setSocketReceiveTimeout(mInputSocket,FLUSH_INTERVAL);
    }else{
        SocketHelper::setSocketReceiveTimeout(mInputSocket,LOG_INTERVAL);
    }
    for(;;){
        // send the session key a couple of times on startup
        if(firstTime){
            for(int i=0;i<5;i++){
                sendSessionKey();
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            firstTime=false;
        }
        // only use a small timeout when the pipeline might need a flush
        //if(isAlreadyInFinishedState()){
        //    SocketHelper::setSocketReceiveTimeout(mInputSocket,LOG_INTERVAL);
        //}else{
        //    SocketHelper::setSocketReceiveTimeout(mInputSocket,FLUSH_INTERVAL);
        //}

        // we set the timeout earlier when creating the socket
        const ssize_t message_length = recvfrom(mInputSocket, buf.data(),buf.size(), 0, nullptr, nullptr);
        if(std::chrono::steady_clock::now()>=log_ts){
            const auto runTimeMs=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-INIT_TIME).count();
            std::cout<<runTimeMs<<"\tTX "<<nPacketsFromUdpPort<<":"<<nInjectedPackets<<"\n";
            log_ts= std::chrono::steady_clock::now() + WBTransmitter::LOG_INTERVAL;
        }
        if(message_length>0){
            if(message_length>FEC_MAX_PAYLOAD_SIZE){
                throw std::runtime_error(StringFormat::convert("Error: This link doesn't support payload exceeding %d", FEC_MAX_PAYLOAD_SIZE));
            }
            nPacketsFromUdpPort++;
            const auto cur_ts=std::chrono::steady_clock::now();
            // send session key in SESSION_KEY_ANNOUNCE_DELTA intervals
            if ((cur_ts >= session_key_announce_ts) ) {
                // Announce session key
                sendSessionKey();
                session_key_announce_ts = cur_ts + SESSION_KEY_ANNOUNCE_DELTA;
            }
            processInputPacket(buf.data(), message_length);
        }else{
            if(errno==EAGAIN || errno==EWOULDBLOCK){
                // timeout
                if(FLUSH_INTERVAL.count()>0){
                    // smaller than 0 means no flush enabled
                    // else we didn't receive data for FLUSH_INTERVAL ms
                    // if nothing needs to be flushed, this call returns immediately
                    //if(mFecEncoder){
                    //    mFecEncoder->finishCurrentBlock();
                    //}
                }
                continue;
            }
            if (errno == EINTR){
                std::cout<<"Got EINTR"<<"\n";
                continue;
            }
            throw std::runtime_error(StringFormat::convert("recvfrom error: %s", strerror(errno)));
        }
    }
}


int main(int argc, char *const *argv) {
    int opt;
    Options options{};
    // use -1 for no flush interval
    std::chrono::milliseconds flushInterval=std::chrono::milliseconds(-1);
    int k=8,n=12;
    std::string videoType;
    bool userSetKorN=false;

    RadiotapHeader::UserSelectableParams wifiParams{20, false, 0, false, 1};

    std::cout << "MAX_PAYLOAD_SIZE:" << FEC_MAX_PAYLOAD_SIZE << "\n";

    while ((opt = getopt(argc, argv, "K:k:n:u:r:p:B:G:S:L:M:f:V:")) != -1) {
        switch (opt) {
            case 'K':
                options.keypair = optarg;
                break;
            case 'k':
                k = atoi(optarg);
                userSetKorN=true;
                break;
            case 'n':
                n = atoi(optarg);
                userSetKorN=true;
                break;
            case 'u':
                options.udp_port = atoi(optarg);
                break;
            case 'p':
                options.radio_port = atoi(optarg);
                break;
            case 'B':
                wifiParams.bandwidth = atoi(optarg);
                break;
            case 'G':
                wifiParams.short_gi = (optarg[0] == 's' || optarg[0] == 'S');
                break;
            case 'S':
                wifiParams.stbc = atoi(optarg);
                break;
            case 'L':
                wifiParams.ldpc = atoi(optarg);
                break;
            case 'M':
                wifiParams.mcs_index = atoi(optarg);
                break;
            case 'f':
                flushInterval=std::chrono::milliseconds(atoi(optarg));
                break;
            case 'V':
                videoType=std::string(optarg);
                break;
            default: /* '?' */
            show_usage:
                fprintf(stderr,
                        "Usage: %s [-K tx_key] [-k RS_K] [-n RS_N] [-u udp_port] [-p radio_port] [-B bandwidth] [-G guard_interval] [-S stbc] [-L ldpc] [-M mcs_index] [-f flushInterval(ms)] interface \n",
                        argv[0]);
                fprintf(stderr,
                        "Default: K='%s', k=%d, n=%d, udp_port=%d, radio_port=%d bandwidth=%d guard_interval=%s stbc=%d ldpc=%d mcs_index=%d flushInterval=%d\n",
                        options.keypair.c_str(), k, n, options.udp_port, options.radio_port, wifiParams.bandwidth, wifiParams.short_gi ? "short" : "long", wifiParams.stbc, wifiParams.ldpc, wifiParams.mcs_index,
                        (int)std::chrono::duration_cast<std::chrono::milliseconds>(flushInterval).count());
                fprintf(stderr, "Radio MTU: %lu\n", (unsigned long) FEC_MAX_PAYLOAD_SIZE);
                fprintf(stderr, "WFB version "
                WFB_VERSION
                "\n");
                exit(1);
        }
    }
    if (optind >= argc) {
        goto show_usage;
    }
    options.wlan=argv[optind];

    if(videoType.empty()){
        std::cout<<"";
        // either FEC disabled or FEC fixed
        if(k==0){
            assert(n==0);
            options.IS_FEC_ENABLED= false;
        }
    }else{

    }

    // check if variable is wanted
    if(!videoType.empty()){
        if(userSetKorN){
            std::cerr<<"Do not use k,n with variable fec size\n";
            exit(1);
        }
        options.IS_FEC_ENABLED=true;
        //options.fec={k,n};
    }

    // option one : K=N=0 == fec disabled

    if(!videoType.empty()){
        //running variable FEC
    }

    RadiotapHeader radiotapHeader{wifiParams};

    //RadiotapHelper::debugRadiotapHeader((uint8_t*)&radiotapHeader,sizeof(RadiotapHeader));
    //RadiotapHelper::debugRadiotapHeader((uint8_t*)&OldRadiotapHeaders::u8aRadiotapHeader80211n, sizeof(OldRadiotapHeaders::u8aRadiotapHeader80211n));
    //RadiotapHelper::debugRadiotapHeader((uint8_t*)&OldRadiotapHeaders::u8aRadiotapHeader, sizeof(OldRadiotapHeaders::u8aRadiotapHeader));
    SchedulingHelper::setThreadParamsMaxRealtime();

    // Validate the user input regarding K,N
    if(k==0){
        // Use K=0 and N=0 to have no FEC correction (advanced option for applications that want to do FEC or similar in the upper level)
        if(n!=0){
            std::cerr<<"Use K=0 only in combination with N=0.\n"
                       "This is an advanced option that removes duplicates, but doesn't check for packet order.\n"
                       "(UDP also allows duplicates but we want to get rid of duplicates as fast as possible to save memory bandwidth)\n."
                       "Latency overhead is 0 in this mode.\n"
                       "If you don't know what this means, use FEC_K==1 and FEC_N==1 for no duplicates and no packet re-ordering.\n";
            exit(1);
        }
    }else{
        if(n < k){
            std::cerr<<"N must be bigger or equal to K\n";
            exit(1);
        }
    }

    try {
        std::shared_ptr<WBTransmitter> t = std::make_shared<WBTransmitter>(
                radiotapHeader,options);
        t->loop();
    } catch (std::runtime_error &e) {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }
    return 0;
}

