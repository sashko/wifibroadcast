//
// Created by consti10 on 03.05.22.
//

#ifndef WIFIBROADCAST_UDPWFIBROADCASTWRAPPER_HPP
#define WIFIBROADCAST_UDPWFIBROADCASTWRAPPER_HPP

#include "WBTransmitter.h"
#include "WBReceiver.h"
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
  UDPWBTransmitter(RadiotapHeader radiotapHeader,
				   const TOptions &options1,
				   const std::string &client_addr,
				   int client_udp_port) {
	wbTransmitter = std::make_unique<WBTransmitter>(
		radiotapHeader, options1);
	udpReceiver = std::make_unique<SocketHelper::UDPReceiver>(client_addr,
															  client_udp_port,
															  [this](const uint8_t *payload,
																	 const std::size_t payloadSize) {
																wbTransmitter->feedPacket(payload, payloadSize);
															  });
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
  [[nodiscard]] std::string createDebug() const {
	return wbTransmitter->createDebugState();
  }
 private:
  std::unique_ptr<WBTransmitter> wbTransmitter;
  std::unique_ptr<SocketHelper::UDPReceiver> udpReceiver;
};

/**
 * Creates a WB Receiver whose data is forwarded to one or more UDP host::port tuples.
 */
class UDPWBReceiver {
 public:
  UDPWBReceiver(const ROptions &options1, std::string client_addr, int client_udp_port) {
	addForwarder(std::move(client_addr), client_udp_port);
	wbReceiver = std::make_unique<WBReceiver>(options1, [this](const uint8_t *payload, const std::size_t payloadSize) {
	  onNewData(payload, payloadSize);
	});
  }
  /**
   * Loop until an error occurs. Blocks the calling thread.
   */
  void loopUntilError() {
	wbReceiver->loop();
  }
  /**
   * Start looping in the background, creates a new thread.
   */
  void runInBackground() {
	backgroundThread = std::make_unique<std::thread>(&UDPWBReceiver::loopUntilError, this);
  }
  /**
   * Add another UDP forwarding instance.
   */
  void addForwarder(std::string client_addr, int client_udp_port) {
	std::lock_guard<std::mutex> guard(udpForwardersLock);
	// check if we already forward data to this addr::port tuple
	for(const auto& udpForwarder:udpForwarders){
	  if(udpForwarder->client_addr==client_addr && udpForwarder->client_udp_port==client_udp_port){
		std::cout<<"UDPWBReceiver: already forwarding to:"<<client_addr<<":"<<client_udp_port<<"\n";
		return;
	  }
	}
	std::cout<<"UDPWBReceiver: add forwarding to:"<<client_addr<<":"<<client_udp_port<<"\n";
	udpForwarders.emplace_back(std::make_unique<SocketHelper::UDPForwarder>(client_addr, client_udp_port));
  }
  /**
   * Remove an already existing udp forwarding instance.
   * Do nothing if such an instance is not found.
   */
  void removeForwarder(std::string client_addr, int client_udp_port) {
	std::lock_guard<std::mutex> guard(udpForwardersLock);
	udpForwarders.erase(std::find_if(udpForwarders.begin(),udpForwarders.end(), [&client_addr,&client_udp_port](const auto& udpForwarder) {
	  return udpForwarder->client_addr==client_addr && udpForwarder->client_udp_port==client_udp_port;
	}));
  }
  [[nodiscard]] std::string createDebug() const {
	return wbReceiver->createDebugState();
  }
 private:
  // forwards the data to all registered udp forwarder instances.
  void onNewData(const uint8_t *payload, const std::size_t payloadSize) {
	std::lock_guard<std::mutex> guard(udpForwardersLock);
	for (const auto &udpForwarder: udpForwarders) {
	  udpForwarder->forwardPacketViaUDP(payload, payloadSize);
	}
  }
  // list of host::port tuples where we send the data to.
  std::list<std::unique_ptr<SocketHelper::UDPForwarder>> udpForwarders;
  // modifying the list of forwarders must be thread-safe
  std::mutex udpForwardersLock;
  std::unique_ptr<WBReceiver> wbReceiver;
  std::unique_ptr<std::thread> backgroundThread;
};

#endif //WIFIBROADCAST_UDPWFIBROADCASTWRAPPER_HPP
