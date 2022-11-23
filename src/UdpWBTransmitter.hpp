//
// Created by consti10 on 03.05.22.
//

#ifndef WIFIBROADCAST_UDPWFIBROADCASTWRAPPER_HPP
#define WIFIBROADCAST_UDPWFIBROADCASTWRAPPER_HPP

#include "WBTransmitter.h"
#include "HelperSources/SocketHelper.hpp"

#include <memory>
#include <thread>
#include <mutex>
#include <utility>
#include <list>

// Convenient methods to create WB transmitter / receiver with UDP as input/output
// Used for wfb_tx / wfb_rx executables and OpenHD

class UDPWBTransmitter {
 public:
  UDPWBTransmitter(RadiotapHeader::UserSelectableParams radiotapHeaderParams,
                   TOptions options1,
                   const std::string &client_addr,
                   int client_udp_port,
                   std::optional<int> wanted_recv_buff_size=std::nullopt) {
    wbTransmitter = std::make_unique<WBTransmitter>(radiotapHeaderParams, std::move(options1));
    udpReceiver = std::make_unique<SocketHelper::UDPReceiver>(client_addr,
                                                              client_udp_port,
                                                              [this](const uint8_t *payload,
                                                                     const std::size_t payloadSize) {
                                                                wbTransmitter->feedPacket(payload, payloadSize);
                                                              },wanted_recv_buff_size);
  }
  /**
   * Loop until an error occurs.
   * Blocks the calling thread.
   */
  void loopUntilError() {
    udpReceiver->loopUntilError();
  }
  /**
   * Start looping in the background, creates a new thread.
   */
  void runInBackground() {
    udpReceiver->runInBackground();
  }
  void stopBackground(){
    udpReceiver->stopBackground();
  }
  [[nodiscard]] std::string createDebug() const {
    return wbTransmitter->createDebugState();
  }
  // temporary
  void update_mcs_index(uint8_t mcs_index){
    wbTransmitter->update_mcs_index(mcs_index);
  }
  [[nodiscard]] int64_t get_n_injected_packets()const{
    return wbTransmitter->get_n_injected_packets();
  }
  [[nodiscard]] uint64_t get_n_injected_bytes()const{
    return wbTransmitter->get_n_injected_bytes();
  }
  uint64_t get_current_injected_bits_per_second(){
    return wbTransmitter->get_current_injected_bits_per_second();
  }
  [[nodiscard]] uint64_t get_count_tx_injections_error_hint()const{
    return wbTransmitter->get_count_tx_injections_error_hint();
  }
  uint64_t get_current_provided_bits_per_second(){
    return wbTransmitter->get_current_provided_bits_per_second();
  }
  uint64_t get_current_packets_per_second(){
    return wbTransmitter->get_current_packets_per_second();
  }
  std::size_t get_estimate_buffered_packets(){
    return wbTransmitter->get_estimate_buffered_packets();
  }
  uint64_t get_n_dropped_packets()const{
    return wbTransmitter->get_n_dropped_packets();
  }
  WBTransmitter& get_wb_tx(){
    return *wbTransmitter;
  }
 private:
  std::unique_ptr<WBTransmitter> wbTransmitter;
  std::unique_ptr<SocketHelper::UDPReceiver> udpReceiver;
};


#endif //WIFIBROADCAST_UDPWFIBROADCASTWRAPPER_HPP
