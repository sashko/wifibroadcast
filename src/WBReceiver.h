#ifndef CONSTI10_WIFIBROADCAST_WB_RECEIVER_H
#define CONSTI10_WIFIBROADCAST_WB_RECEIVER_H
// Copyright (C) 2017, 2018 Vasily Evseenko <svpcom@p2ptech.org>
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
#include "wifibroadcast.hpp"
#include "Encryption.hpp"
#include "FECEnabled.hpp"
#include "FECDisabled.hpp"
#include "HelperSources/Helper.hpp"
#include "OpenHDStatisticsWriter.hpp"
#include "HelperSources/TimeHelper.hpp"
#include "RawReceiver.hpp"

// A wifi card with more than 4 antennas still has to be found :)
static constexpr const auto MAX_N_ANTENNAS_PER_WIFI_CARD = 4;
//

struct ROptions {
  uint8_t radio_port = 0;
  // The wlan adapters to listen on
  std::vector<std::string> rxInterfaces;
  // file for encryptor
  // make optional for ease of use - with no keypair given the default "seed" is used
  std::optional<std::string> keypair = std::nullopt;
  // allows setting the log interval.
  std::chrono::milliseconds log_interval = std::chrono::seconds(1);
  // Print log messages about the current status in regular intervals to stdout.
  // However, in OpenHD, it is more verbose to log all the tx/rx instances together.
  bool enableLogAlive = true;
  unsigned int rx_queue_depth=10; // RX queue depth (max n of blocks that can be buffered in the rx pipeline)
};

class WBReceiver {
 public:
  typedef std::function<void(const uint8_t *payload, const std::size_t payloadSize)> OUTPUT_DATA_CALLBACK;
  /**
   * This class processes the received wifi raw wifi data
   * (aggregation, FEC decoding) and forwards it via the callback.
   * Each instance has to be assigned with a Unique ID (same id as the corresponding tx instance).
   * @param options1 the options for this instance (some options - so to say - come from the tx instance)
   * @param output_data_callback Callback that is called with the decoded data, can be null for debugging.
   */
  WBReceiver(ROptions options1, OUTPUT_DATA_CALLBACK output_data_callback);
  WBReceiver(const WBReceiver &) = delete;
  WBReceiver &operator=(const WBReceiver &) = delete;
  void processPacket(uint8_t wlan_idx, const pcap_pkthdr &hdr, const uint8_t *pkt);
  // dump statistics
  void dump_stats();
  const ROptions options;
  /**
   * Process incoming data packets as long as nothing goes wrong (nothing should go wrong as long
   * as the computer does not crash or the wifi card disconnects).
   * NOTE: This class won't be able to receive any wifi packages until loop() is called.
   * NOTE: This blocks the calling thread (never returns unless error).
   */
  void loop();
  void stop_looping();
  /**
   * Create a verbose string that gives debugging information about the current state of this wb receiver.
   * Since this one only reads, it is safe to call from any thread.
   * Note that this one doesn't print to stdout.
   * @return a string without new line at the end.
   */
  [[nodiscard]] std::string createDebugState() const;
  /**
   * Fetch the current / latest statistics, can be called in regular intervals.
   * Thread-safe and guaranteed to not block for a significant amount of time
   */
  OpenHDStatisticsWriter::Data get_latest_stats();
 private:
  const std::chrono::steady_clock::time_point INIT_TIME = std::chrono::steady_clock::now();
  Decryptor mDecryptor;
  std::array<RSSIForWifiCard, MAX_RX_INTERFACES> rssiForWifiCard;
  WBRxStats wb_rx_stats{};
  // for calculating the current rx bitrate
  BitrateCalculator rxBitrateCalculator{};
  //We know that once we get the first session key packet
  bool IS_FEC_ENABLED = false;
  // On the rx, either one of those two is active at the same time. NOTE: nullptr until the first session key packet
  std::unique_ptr<FECDecoder> mFECDDecoder = nullptr;
  std::unique_ptr<FECDisabledDecoder> mFECDisabledDecoder = nullptr;
  //Ieee80211HeaderSeqNrCounter mSeqNrCounter;
  // Callback that is called with the decoded data
  const OUTPUT_DATA_CALLBACK mOutputDataCallback;
  std::unique_ptr<MultiRxPcapReceiver> receiver;
  std::mutex m_last_stats_mutex;
  OpenHDStatisticsWriter::Data m_last_stats{};
  void set_latest_stats(OpenHDStatisticsWriter::Data new_stats);
 public:
#ifdef ENABLE_ADVANCED_DEBUGGING
  // time between <packet arrives at pcap processing queue> <<->> <packet is pulled out of pcap by RX>
  AvgCalculator avgPcapToApplicationLatency;
  AvgCalculator2 avgLatencyBeaconPacketLatency;
#endif
 private:
  uint16_t last_seq_nr;
  int x_n_received_packets=0;
  int x_n_missing_packets=0;
  std::chrono::steady_clock::time_point x_last_rec=std::chrono::steady_clock::now();
  int x_curr_packet_loss=0;
};

#endif //CONSTI10_WIFIBROADCAST_WB_RECEIVER_H