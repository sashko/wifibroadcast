//
// Created by consti10 on 03.05.22.
//

#ifndef WIFIBROADCAST_UDPWFIBROADCASTWRAPPER_HPP
#define WIFIBROADCAST_UDPWFIBROADCASTWRAPPER_HPP

#include "WBTransmitter.h"
#include "WBReceiver.h"
#include "HelperSources/SocketHelper.hpp"

#include <memory>

// Convenient methods to create WB transmitter / receiver with UDP as input/output
// Used for wfb_tx / wfb_rx executables and OpenHD

class UDPWBTransmitter{
public:
    UDPWBTransmitter(RadiotapHeader radiotapHeader,const TOptions& options1,std::string client_addr,int client_udp_port){
        wbTransmitter=std::make_unique<WBTransmitter>(
                radiotapHeader,options1);
        udpReceiver=std::make_unique<SocketHelper::UDPReceiver>(SocketHelper::ADDRESS_LOCALHOST,client_udp_port,[this](const uint8_t* payload,const std::size_t payloadSize){
            wbTransmitter->feedPacket(payload,payloadSize);
        });
    }
    void loopUntilError(){
        udpReceiver->loopUntilError();
    }
private:
    std::unique_ptr<WBTransmitter> wbTransmitter;
    std::unique_ptr<SocketHelper::UDPReceiver> udpReceiver;
};

class UDPWBReceiver{
public:
    UDPWBReceiver(const ROptions& options1,std::string client_addr,int client_udp_port){
        udpForwarder=std::make_unique<SocketHelper::UDPForwarder>(client_addr,client_udp_port);
        wbReceiver=std::make_unique<WBReceiver>(options1, [this](const uint8_t* payload, const std::size_t payloadSize){
            udpForwarder->forwardPacketViaUDP(payload,payloadSize);
        });
    }
    void loopUntilError(){
        wbReceiver->loop();
    }
private:
    std::unique_ptr<WBReceiver> wbReceiver;
    std::unique_ptr<SocketHelper::UDPForwarder> udpForwarder;
};

#endif //WIFIBROADCAST_UDPWFIBROADCASTWRAPPER_HPP
