//
// Created by consti10 on 21.04.22.
//

#include <thread>
#include <chrono>
#include "../src/HelperSources/SocketHelper.hpp"

static void test_send_and_receive(){
  static constexpr auto XPORT=5600;
  std::size_t nReceivedBytes=0;
  SocketHelper::UDPReceiver receiver(SocketHelper::ADDRESS_LOCALHOST,XPORT,[&nReceivedBytes](const uint8_t* payload,const std::size_t payloadSize){
	//std::cout<<"Got data\n";
	nReceivedBytes+=payloadSize;
  });
  receiver.runInBackground();
  // wait a bit to account for OS delay
  std::this_thread::sleep_for(std::chrono::seconds(1));
  SocketHelper::UDPForwarder forwarder(SocketHelper::ADDRESS_LOCALHOST,XPORT);
  std::vector<uint8_t> data(100);
  std::size_t nForwardedBytes=0;
  for(int i=0;i<100;i++){
	forwarder.forwardPacketViaUDP(data.data(),data.size());
	nForwardedBytes+=data.size();
  }
  // wait a bit to account for OS delays
  std::this_thread::sleep_for(std::chrono::seconds(1));
  std::cout<<"Test end\n";
  receiver.stopBackground();
  std::cout<<"N sent bytes:"<<nForwardedBytes<<" Received:"<<nReceivedBytes<<"\n";
  if(nForwardedBytes!=nReceivedBytes){
	throw std::runtime_error("Dropped packets or impl bugged\n");
  }
}

int main(int argc, char *const *argv) {

    test_send_and_receive();
    return 0;
}