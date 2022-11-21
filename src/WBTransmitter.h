#ifndef CONSTI10_WIFIBROADCAST_WB_TRANSMITTER_H
#define CONSTI10_WIFIBROADCAST_WB_TRANSMITTER_H
//
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

#include <queue>
#include <thread>
#include <variant>

#include "Encryption.hpp"
#include "FECDisabled.hpp"
#include "FECEnabled.hpp"
#include "HelperSources/Helper.hpp"
#include "HelperSources/TimeHelper.hpp"
#include "RawTransmitter.hpp"
#include "wifibroadcast-spdlog.h"
#include "wifibroadcast.hpp"
//#include <atomic>
#include "../readerwriterqueue/readerwritercircularbuffer.h"

// Note: The UDP port is missing as an option here, since it is not an option for WFBTransmitter anymore.
// Only an option when you run this program via the command line.
struct TOptions {
  // the radio port is what is used as an index to multiplex multiple streams (telemetry,video,...)
  // into the one wfb stream
  uint8_t radio_port = 1;
  // file for encryptor
  // make optional for ease of use - with no keypair given the default "seed" is used
  std::optional<std::string> keypair = std::nullopt;
  // wlan interface to send packets with
  std::string wlan;
  // either fixed or variable. If int==fixed, if string==variable but hook needs to be added (currently only hooked h264 and h265)
  std::variant<int, std::string> fec_k = 8;
  int fec_percentage = 50;
  // Print log messages about the current status in regular intervals to stdout.
  // However, in OpenHD, it is more verbose to log all the tx/rx instances together.
  bool enableLogAlive = true;
};
enum FEC_VARIABLE_INPUT_TYPE { none, h264, h265 };

class WBTransmitter {
 public:
  /**
   * Each instance has to be assigned with a Unique ID to differentiate between streams on the RX
   * It does all the FEC encoding & encryption for this stream, then uses PcapTransmitter to inject the generated packets
   * FEC can be either enabled or disabled.
   * When run as an executable from the command line, a UDPReceiver is created for forwarding data to an instance of this class.
   * @param radiotapHeader the radiotap header that is used for injecting, contains configurable data like the mcs index.
   * @param options1 options for this instance, some of them are forwarded to the receiver instance.
   */
  WBTransmitter(RadiotapHeader::UserSelectableParams radioTapHeaderParams, TOptions options1,std::shared_ptr<spdlog::logger> console= nullptr);
  WBTransmitter(const WBTransmitter &) = delete;
  WBTransmitter &operator=(const WBTransmitter &) = delete;
  ~WBTransmitter();
  /**
   * feed a new packet to this instance.
   * Depending on the selected mode, this might add FEC packets or similar.
   * If the packet size exceeds the max packet size, the packet is dropped.
   * @param buf packet data buffer
   * @param size packet data buffer size
   */
  void feedPacket(const uint8_t *buf, size_t size);
  /**
  * Create a verbose string that gives debugging information about the current state of this wb receiver.
   * Since this one only reads, it is safe to call from any thread.
   * Note that this one doesn't print to stdout.
  * @return a string without new line at the end.
  */
  [[nodiscard]] std::string createDebugState() const;
  // These are for updating parameters at run time
  void update_mcs_index(uint8_t mcs_index);

  const TOptions options;
  // temporary
  [[nodiscard]] int64_t get_n_injected_packets()const{
    return nInjectedPackets;
  }
  [[nodiscard]] uint64_t get_n_injected_bytes()const{
    return static_cast<uint64_t>(count_bytes_data_injected);
  }
  uint64_t get_current_injected_bits_per_second(){
    return bitrate_calculator_injected_bytes.get_last_or_recalculate(count_bytes_data_injected,std::chrono::seconds(2));
  }
  uint64_t get_current_provided_bits_per_second(){
    return bitrate_calculator_data_provided.get_last_or_recalculate(count_bytes_data_provided,std::chrono::seconds(2));
  }
  [[nodiscard]] uint64_t get_count_tx_injections_error_hint()const{
    return count_tx_injections_error_hint;
  }
  // Other than bits per second, packets per second is also an important metric -
  // Sending a lot of small packets for example should be avoided)
  uint64_t get_current_packets_per_second(){
    return _packets_per_second_calculator.get_last_or_recalculate(nInjectedPackets,std::chrono::seconds(2));
  }
  std::size_t get_estimate_buffered_packets(){
    return m_data_queue.size_approx();
  }
 private:
  // send the current session key via WIFI (located in mEncryptor)
  void sendSessionKey();
  // for the FEC encoder
  void sendFecPrimaryOrSecondaryFragment(uint64_t nonce, const uint8_t *payload, size_t payloadSize);
  // send packet by prefixing data with the current IEE and Radiotap header
  void sendPacket(const AbstractWBPacket &abstractWbPacket);
  // print some simple debug information. Called in regular intervals by the logAliveThread
  void logAlive() const;
  std::shared_ptr<spdlog::logger> m_console;
  // this one is used for injecting packets
  PcapTransmitter mPcapTransmitter;
  //RawSocketTransmitter mPcapTransmitter;
  // Used to encrypt the packets
  Encryptor mEncryptor;
  // Used to inject packets
  Ieee80211Header mIeee80211Header;
  // this one never changes,also used to inject packets
  RadiotapHeader::UserSelectableParams _radioTapHeaderParams;
  std::mutex radiotapHeaderMutex;
  RadiotapHeader mRadiotapHeader;
  //std::atomic<bool> test={false};
  uint16_t ieee80211_seq = 0;
  // statistics for console
  // n of packets fed to the instance
  int64_t nInputPackets = 0;
  // n of actually injected packets
  int64_t nInjectedPackets = 0;
  // n of injected session key packets
  int64_t nInjectedSessionKeypackets=0;
  // count of bytes we got passed (aka for examle, what the video encoder produced - does not include FEC)
  uint64_t count_bytes_data_provided=0;
  BitrateCalculator bitrate_calculator_data_provided{};
  // count of bytes we injected into the wifi card
  uint64_t count_bytes_data_injected=0;
  // a tx error is thrown if injecting the packet takes longer than MAX_SANE_INJECTION_TIME,
  // which hints at a overflowing tx queue (unfortunately I don't know a way to directly get the tx queue yet)
  // However, this hint can be misleading - for example, during testing (MCS set to 3) and with about 5MBit/s video after FEC
  // I get about 5 tx error(s) per second with my atheros, but it works fine. This workaround also seems to not work at all
  // with the RTL8812au.
  uint64_t count_tx_injections_error_hint=0;
  static constexpr std::chrono::nanoseconds MAX_SANE_INJECTION_TIME=std::chrono::milliseconds(5);
  BitrateCalculator bitrate_calculator_injected_bytes{};
  PacketsPerSecondCalculator _packets_per_second_calculator{};
  const std::chrono::steady_clock::time_point INIT_TIME = std::chrono::steady_clock::now();
  std::chrono::steady_clock::time_point session_key_announce_ts{};
  static constexpr const std::chrono::nanoseconds LOG_INTERVAL = std::chrono::seconds(1);
  Chronometer pcapInjectionTime{"PcapInjectionTime"};
  WBSessionKeyPacket sessionKeyPacket;
  const bool IS_FEC_DISABLED;
  const bool IS_FEC_VARIABLE;
  const FEC_VARIABLE_INPUT_TYPE fecVariableInputType;
  // On the tx, either one of those two is active at the same time
  std::unique_ptr<FECEncoder> mFecEncoder = nullptr;
  std::unique_ptr<FECDisabledEncoder> mFecDisabledEncoder = nullptr;
  bool keepLogAliveThreadRunning;
  // this threads only purpose is to print statistics (if enabled).
  // since when no messages come in, no methods of this class are called,
  // so we cannot do any automatic logging in fixed intervalls.
  std::unique_ptr<std::thread> logAliveThread;
  //
  uint16_t m_curr_seq_nr=0;
 private:
  moodycamel::BlockingReaderWriterCircularBuffer<std::shared_ptr<std::vector<uint8_t>>> m_data_queue{1024};
  std::unique_ptr<std::thread> m_process_data_thread;
  bool m_process_data_thread_run=true;
  void loop_process_data();
  void feedPacket2(const uint8_t *buf, size_t size);
};

#endif //CONSTI10_WIFIBROADCAST_WB_TRANSMITTER_H
