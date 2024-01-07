//
// Created by consti10 on 07.01.24.
//

#include <iostream>

#include "../src/dummy_link/DummyLink.h"
#include "Helper.hpp"

static std::vector<std::shared_ptr<std::vector<uint8_t>>> pull_all_buffered_packets(DummyLink& dummyLink){
  std::vector<std::shared_ptr<std::vector<uint8_t>>> rx_packets;
  while (true){
    auto packet=dummyLink.rx_radiotap();
    if(!packet) break ;
    rx_packets.push_back(packet);
  }
  return rx_packets;
}

int main(int argc, char *const *argv) {
  auto dummy_air=std::make_shared<DummyLink>(true);
  auto dummy_gnd=std::make_shared<DummyLink>(false);
  auto dummy_packets1=GenericHelper::createRandomDataBuffers(20,1024,1024);
  auto dummy_packets2=GenericHelper::createRandomDataBuffers(20,1024,1024);

  for(auto& packet:dummy_packets1){
    dummy_air->tx_radiotap(packet.data(),packet.size());
  }
  for(auto& packet:dummy_packets2){
    dummy_gnd->tx_radiotap(packet.data(),packet.size());
  }
  auto rx_air= pull_all_buffered_packets(*dummy_air);
  auto rx_gnd= pull_all_buffered_packets(*dummy_gnd);
  GenericHelper::assertVectorsOfVectorsEqual(rx_gnd,dummy_packets1);
  GenericHelper::assertVectorsOfVectorsEqual(rx_air,dummy_packets2);
  std::cout<<"Done"<<std::endl;
  return 0;
}
