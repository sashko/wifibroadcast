//
// Created by consti10 on 21.04.22.
//

#include <thread>
#include <chrono>
#include "SocketHelper.hpp"

int main(int argc, char *const *argv) {

    static constexpr auto XPORT=5600;
    std::size_t nReceivedBytes=0;
    SocketHelper::UDPReceiver receiver(SocketHelper::ADDRESS_LOCALHOST,XPORT,[&nReceivedBytes](const uint8_t* payload,const std::size_t payloadSize){
        std::cout<<"Got data\n";
        nReceivedBytes+=payloadSize;
    });
    receiver.runInBackground();

    SocketHelper::UDPForwarder forwarder(SocketHelper::ADDRESS_LOCALHOST,XPORT);
    std::vector<uint8_t> data(100);
    int nForwardedBytes;
    for(int i=0;i<100;i++){
        forwarder.forwardPacketViaUDP(data.data(),data.size());
        nForwardedBytes+=data.size();
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::cout<<"Test end\n";
    receiver.stopBackground();
    std::cout<<"N sent bytes:"<<nForwardedBytes<<" Received:"<<nReceivedBytes<<"\n";
    return 0;
}