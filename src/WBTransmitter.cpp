
// Copyright (C) 2017, 2018, 2019 Vasily Evseenko <svpcom@p2ptech.org>
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

#include "WBTransmitter.h"

#include <utility>
#include "HelperSources/SchedulingHelper.hpp"
#include "HelperSources/RTPHelper.hpp"


WBTransmitter::WBTransmitter(RadiotapHeader::UserSelectableParams radioTapHeaderParams, TOptions options1,std::shared_ptr<spdlog::logger> opt_console) :
    options(std::move(options1)),
      m_pcap_transmitter(options.wlan),
      m_encryptor(options.keypair),
      m_radioTapHeaderParams(radioTapHeaderParams),
    kEnableFec(options.enable_fec),
    m_tx_fec_options(options.tx_fec_options),
    mRadiotapHeader{RadiotapHeader{m_radioTapHeaderParams}},
    m_console(std::move(opt_console)){
  if(!m_console){
    m_console=wifibroadcast::log::create_or_get("wb_tx"+std::to_string(options.radio_port));
  }
  assert(m_console);
  m_console->info("WBTransmitter radio_port: {} wlan: {} keypair:{}", options.radio_port, options.wlan.c_str(),
                  (options.keypair.has_value() ? options.keypair.value() : "none" ));
  m_encryptor.makeNewSessionKey(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData);
  if (kEnableFec) {
    // variable if k is a string with video type
    const int kMax=m_tx_fec_options.variable_input_type ==FEC_VARIABLE_INPUT_TYPE::NONE ? options.tx_fec_options.fixed_k
            : MAX_N_P_FRAGMENTS_PER_BLOCK;
    m_console->info("fec enabled, kMax:{}",kMax);
    m_fec_encoder = std::make_unique<FECEncoder>(kMax, options.tx_fec_options.overhead_percentage);
    m_fec_encoder->outputDataCallback = notstd::bind_front(&WBTransmitter::sendFecPrimaryOrSecondaryFragment, this);
  } else {
    m_console->info("fec disabled");
    m_fec_disabled_encoder = std::make_unique<FECDisabledEncoder>();
    m_fec_disabled_encoder->outputDataCallback =
        notstd::bind_front(&WBTransmitter::sendFecPrimaryOrSecondaryFragment, this);
  }
  // the rx needs to know if FEC is enabled or disabled. Note, both variable and fixed fec counts as FEC enabled
  sessionKeyPacket.IS_FEC_ENABLED = kEnableFec;
  // send session key a couple of times on startup to make it more likely an already running rx picks it up immediately
  m_console->info("Sending Session key on startup");
  for (int i = 0; i < 5; i++) {
    sendSessionKey();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  // next session key in delta ms if packets are being fed
  session_key_announce_ts = std::chrono::steady_clock::now()+SESSION_KEY_ANNOUNCE_DELTA;

  m_process_data_thread_run=true;
  m_process_data_thread=std::make_unique<std::thread>(&WBTransmitter::loop_process_data, this);
}

WBTransmitter::~WBTransmitter() {
  m_process_data_thread_run=false;
  if(m_process_data_thread && m_process_data_thread->joinable()){
    m_process_data_thread->join();
  }
}

void WBTransmitter::sendPacket(const AbstractWBPacket &abstractWbPacket) {
  count_bytes_data_injected+=abstractWbPacket.payloadSize;
  mIeee80211Header.writeParams(options.radio_port, ieee80211_seq);
  ieee80211_seq += 16;
  //mIeee80211Header.printSequenceControl();
  std::lock_guard<std::mutex> guard(m_radiotapHeaderMutex);
  const auto injectionTime = m_pcap_transmitter.injectPacket(mRadiotapHeader, mIeee80211Header, abstractWbPacket);
  if(injectionTime>MAX_SANE_INJECTION_TIME){
    count_tx_injections_error_hint++;
    //m_console->warn("Injecting PCAP packet took really long:",MyTimeHelper::R(injectionTime));
  }
  nInjectedPackets++;
}

void WBTransmitter::sendFecPrimaryOrSecondaryFragment(const uint64_t nonce,
                                                      const uint8_t *payload,
                                                      const std::size_t payloadSize) {
  //m_console->info("WBTransmitter::sendFecBlock {}",(int)payloadSize);
  const WBDataHeader wbDataHeader(nonce,m_curr_seq_nr);
  m_curr_seq_nr++;
  const auto encryptedData =
      m_encryptor.encryptPacket(nonce, payload, payloadSize, wbDataHeader);
  //
  sendPacket({(const uint8_t *) &wbDataHeader, sizeof(WBDataHeader), encryptedData.data(), encryptedData.size()});
#ifdef ENABLE_ADVANCED_DEBUGGING
  //LatencyTestingPacket latencyTestingPacket;
  //sendPacket((uint8_t*)&latencyTestingPacket,sizeof(latencyTestingPacket));
#endif
}

void WBTransmitter::sendSessionKey() {
  sendPacket({(uint8_t *) &sessionKeyPacket, WBSessionKeyPacket::SIZE_BYTES});
  nInjectedSessionKeypackets++;
}

std::string WBTransmitter::createDebugState() const {
  std::stringstream ss;
  // input packets & injected packets
  const auto nInjectedDataPackets=nInjectedPackets-nInjectedSessionKeypackets;
  //ss << runTimeSeconds << "\tTX:in:("<<nInputPackets<<")out:(" << nInjectedDataPackets << ":" << nInjectedSessionKeypackets << ")\n";
  ss <<"TX:in:("<<nInputPackets<<")out:(" << nInjectedDataPackets << ":" << nInjectedSessionKeypackets << ")\n";
  return ss.str();
}

void WBTransmitter::feedPacket(const uint8_t *buf, size_t size) {
  count_bytes_data_provided+=size;
  auto packet=std::make_shared<std::vector<uint8_t>>(buf,buf+size);
  const bool res=m_data_queue.try_enqueue(packet);
  if(!res){
    m_n_dropped_packets++;
  }
}

void WBTransmitter::update_mcs_index(uint8_t mcs_index) {
  m_radioTapHeaderParams.mcs_index=mcs_index;
  auto newRadioTapHeader=RadiotapHeader{m_radioTapHeaderParams};
  std::lock_guard<std::mutex> guard(m_radiotapHeaderMutex);
  mRadiotapHeader=newRadioTapHeader;
}

void WBTransmitter::loop_process_data() {
  SchedulingHelper::setThreadParamsMaxRealtime();
  std::shared_ptr<std::vector<uint8_t>> packet;
  while (m_process_data_thread_run){
    static constexpr std::int64_t timeout_usecs=100*1000;
    if(m_data_queue.wait_dequeue_timed(packet,timeout_usecs)){
      feedPacket2(packet->data(),packet->size());
    }
  }
}

void WBTransmitter::feedPacket2(const uint8_t *buf, size_t size) {
  if (size <= 0 || size > FEC_MAX_PAYLOAD_SIZE) {
    m_console->warn("Fed packet with incompatible size:",size);
    return;
  }
  const auto cur_ts = std::chrono::steady_clock::now();
  // send session key in SESSION_KEY_ANNOUNCE_DELTA intervals
  if ((cur_ts >= session_key_announce_ts)) {
    // Announce session key
    sendSessionKey();
    session_key_announce_ts = cur_ts + SESSION_KEY_ANNOUNCE_DELTA;
  }
  // this calls a callback internally
  if (kEnableFec) {
    if (m_tx_fec_options.variable_input_type ==FEC_VARIABLE_INPUT_TYPE::NONE) {
      // fixed k
      m_fec_encoder->encodePacket(buf, size);
    } else {
      // variable k
      bool endBlock = false;
      if (m_tx_fec_options.variable_input_type == FEC_VARIABLE_INPUT_TYPE::RTP_H264) {
        endBlock = RTPLockup::h264_end_block(buf, size);
      } else {
        endBlock = RTPLockup::h265_end_block(buf, size);
      }
      m_fec_encoder->encodePacket(buf, size, endBlock);
    }
    if (m_fec_encoder->resetOnOverflow()) {
      // running out of sequence numbers should never happen during the lifetime of the TX instance, but handle it properly anyways
      m_encryptor.makeNewSessionKey(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData);
      sendSessionKey();
    }
  } else {
    m_fec_disabled_encoder->encodePacket(buf, size);
  }
  nInputPackets++;
}

void WBTransmitter::update_fec_percentage(uint32_t fec_percentage) {
  if(!kEnableFec){
    m_console->warn("Cannot change fec overhead when fec is disabled");
    return;
  }
  assert(m_fec_encoder);
  m_fec_encoder->update_fec_overhead_percentage(fec_percentage);
}

void WBTransmitter::update_fec_video_codec() {
  if(!kEnableFec){
    m_console->warn("Cannot update_fec_video_codec, fec disabled");
    return;
  }
  //TODO
  m_console->warn("TODO");
}
