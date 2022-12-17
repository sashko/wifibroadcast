//
// Created by consti10 on 17.12.22.
//

#ifndef WIFIBROADCAST_SRC_FOREIGNPACKETSRECEIVER_H_
#define WIFIBROADCAST_SRC_FOREIGNPACKETSRECEIVER_H_

#include <cstdint>
#include <vector>
#include <memory>

#include "RawReceiver.hpp"

// Helper - get (most likely all) packets that are not coming from a running openhd instance,
// but rather someone else talking on this channel.
// most likely because of the radio port - we really need to migrate to a single rx instance for all cards
class ForeignPacketsReceiver {
 public:
  explicit ForeignPacketsReceiver(std::vector<std::string> wlans,std::vector<int> openhd_radio_ports);
  ~ForeignPacketsReceiver();
 private:
  void on_foreign_packet(uint8_t wlan_idx, const pcap_pkthdr &hdr, const uint8_t *pkt);
  void m_loop();
  std::unique_ptr<MultiRxPcapReceiver> m_receiver;
  std::vector<int> m_openhd_radio_ports;
  std::unique_ptr<std::thread> m_thread;
};

#endif  // WIFIBROADCAST_SRC_FOREIGNPACKETSRECEIVER_H_
