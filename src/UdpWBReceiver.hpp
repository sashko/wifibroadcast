//
// Created by consti10 on 23.11.22.
//

#ifndef WIFIBROADCAST_SRC_UDPWBRECEIVER_H_
#define WIFIBROADCAST_SRC_UDPWBRECEIVER_H_

#include "WBReceiver.h"
#include "HelperSources/SocketHelper.hpp"

#include <memory>
#include <thread>
#include <mutex>
#include <utility>
#include <list>

/**
 * Creates a WB Receiver whose data is forwarded to one or more UDP host::port tuples.
 */
class UDPWBReceiver {
 public:
  UDPWBReceiver(ROptions options1, std::string client_addr, int client_udp_port) {
    udpMultiForwarder = std::make_unique<SocketHelper::UDPMultiForwarder>();
    addForwarder(std::move(client_addr), client_udp_port);
    wbReceiver = std::make_unique<WBReceiver>(std::move(options1), [this](const uint8_t *payload, const std::size_t payloadSize) {
      onNewData(payload, payloadSize);
      _anyDataReceived=true;
    });
  }
  ~UDPWBReceiver(){
    stop_looping();
  }
  /**
   * Loop until an error occurs. Blocks the calling thread.
   */
  void loopUntilError() {
    wbReceiver->loop();
  }
  void stop_looping(){
    wbReceiver->stop_looping();
    if(backgroundThread && backgroundThread->joinable()){
      backgroundThread->join();
    }
  }
  /**
   * Start looping in the background, creates a new thread.
   */
  void runInBackground() {
    backgroundThread = std::make_unique<std::thread>(&UDPWBReceiver::loopUntilError, this);
  }
  void addForwarder(std::string client_addr, int client_udp_port) {
    udpMultiForwarder->addForwarder(client_addr, client_udp_port);
  }
  void removeForwarder(std::string client_addr, int client_udp_port) {
    udpMultiForwarder->removeForwarder(client_addr, client_udp_port);
  }
  [[nodiscard]] std::string createDebug() const {
    return wbReceiver->createDebugState();
  }
  [[nodiscard]] bool anyDataReceived()const{
    return _anyDataReceived;
  }
  [[nodiscard]] WBReceiverStats get_latest_stats()const{
    return wbReceiver->get_latest_stats();
  }
  WBReceiver& get_wb_receiver(){
    return *wbReceiver;
  }
 private:
  // forwards the data to all registered udp forwarder instances.
  void onNewData(const uint8_t *payload, const std::size_t payloadSize) {
    udpMultiForwarder->forwardPacketViaUDP(payload, payloadSize);
  }
  std::unique_ptr<SocketHelper::UDPMultiForwarder> udpMultiForwarder;
  std::unique_ptr<WBReceiver> wbReceiver;
  std::unique_ptr<std::thread> backgroundThread;
  bool _anyDataReceived=false;
};

#endif  // WIFIBROADCAST_SRC_UDPWBRECEIVER_H_
