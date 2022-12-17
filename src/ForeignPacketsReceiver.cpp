//
// Created by consti10 on 17.12.22.
//

#include "ForeignPacketsReceiver.h"

#include <utility>

ForeignPacketsReceiver::ForeignPacketsReceiver(std::vector<std::string> wlans,std::vector<int> openhd_radio_ports):
  m_openhd_radio_ports(std::move(openhd_radio_ports)) {
  auto cb=[this](const uint8_t wlan_idx, const pcap_pkthdr &hdr, const uint8_t *pkt){
    on_foreign_packet(wlan_idx,hdr,pkt);
  };
  auto cb2=[this](){
  };
  MultiRxPcapReceiver::Options options;
  options.rxInterfaces=wlans;
  options.dataCallback=cb;
  options.logCallback=cb2;
  options.log_interval=std::chrono::milliseconds(100);
  options.radio_port=-1;
  options.excluded_radio_ports=m_openhd_radio_ports;
  m_receiver=std::make_unique<MultiRxPcapReceiver>(options);
  m_thread=std::make_unique<std::thread>(&ForeignPacketsReceiver::m_loop, this);
}

ForeignPacketsReceiver::~ForeignPacketsReceiver() {
  m_receiver->stop();
  if(m_thread->joinable())m_thread->join();
  m_thread= nullptr;
}

void ForeignPacketsReceiver::on_foreign_packet(const uint8_t wlan_idx,const pcap_pkthdr &hdr,const uint8_t *pkt) {
  wifibroadcast::log::get_default()->debug("X got packet");
}

void ForeignPacketsReceiver::m_loop() {
  m_receiver->loop();
}
