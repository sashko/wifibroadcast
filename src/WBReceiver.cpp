
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
#include "WBReceiver.h"
#include "RawReceiver.hpp"
#include "wifibroadcast.hpp"
#include "HelperSources/SchedulingHelper.hpp"
#include <cassert>
#include <cinttypes>
#include <unistd.h>
#include <pcap/pcap.h>
#include <memory>
#include <string>
#include <sstream>
#include <utility>

static int diff_between_packets(int last_packet,int curr_packet){
  if(last_packet==curr_packet){
    std::cerr<<"Duplicate?!\n";
  }
  if(curr_packet<last_packet){
    // We probably have overflown the uin16_t range
    const auto diff=curr_packet+UINT16_MAX+1-last_packet;
    return diff;
  }else{
    return curr_packet-last_packet;
  }
}

WBReceiver::WBReceiver(ROptions options1, OUTPUT_DATA_CALLBACK output_data_callback,std::shared_ptr<spdlog::logger> console) :
    options(std::move(options1)),
    mDecryptor(options.keypair),
    mOutputDataCallback(std::move(output_data_callback)) {
  if(!console){
    m_console=wifibroadcast::log::create_or_get("wb_rx"+std::to_string(options.radio_port));
  }else{
    m_console=console;
  }
  receiver = std::make_unique<MultiRxPcapReceiver>(options.rxInterfaces, options.radio_port, options1.log_interval,
                                                   notstd::bind_front(&WBReceiver::processPacket, this),
                                                   notstd::bind_front(&WBReceiver::dump_stats, this));
  m_console->info("WFB-RX RADIO_PORT: {} Logging enabled:{}",(int) options.radio_port,(options.enableLogAlive ? "Y" : "N"));
}

void WBReceiver::loop() {
  receiver->loop();
}

void WBReceiver::stop_looping() {
  receiver->stop();
}

std::string WBReceiver::createDebugState() const {
  std::stringstream ss;
  ss<<wb_rx_stats<<"\n";
  if(mFECDDecoder){
    auto stats=mFECDDecoder->stats;
    ss<<stats<<"\n";
  }
  return ss.str();
}

void WBReceiver::dump_stats() {
  // first forward to OpenHD
  // re-calculate the current bitrate
  {
    wb_rx_stats.curr_bits_per_second=rxBitrateCalculator.recalculateSinceLast(wb_rx_stats.count_bytes_data_received);
  }
  std::optional<FECStreamStats> fec_stream_stats=std::nullopt;
  if(mFECDDecoder){
    fec_stream_stats=mFECDDecoder->stats;
  }
  OpenHDStatisticsWriter::Data data{options.radio_port,rssiForWifiCard,wb_rx_stats,fec_stream_stats};
  set_latest_stats(data);
  if (options.enableLogAlive) {
    for (auto &wifiCard: rssiForWifiCard) {
      // no new rssi values for this card since the last call
      if (wifiCard.count_all == 0)continue;
      std::cout << wifiCard<<"\n";
      wifiCard.reset();
    }
    std::stringstream ss;
    std::cout<<createDebugState();
  }
  // it is actually much more understandable when I use the absolute values for the logging
#ifdef ENABLE_ADVANCED_DEBUGGING
  std::cout<<"avgPcapToApplicationLatency: "<<avgPcapToApplicationLatency.getAvgReadable()<<"\n";
  //std::cout<<"avgLatencyBeaconPacketLatency"<<avgLatencyBeaconPacketLatency.getAvgReadable()<<"\n";
  //std::cout<<"avgLatencyBeaconPacketLatencyX:"<<avgLatencyBeaconPacketLatency.getNValuesLowHigh(20)<<"\n";
  //std::cout<<"avgLatencyPacketInQueue"<<avgLatencyPacketInQueue.getAvgReadable()<<"\n";
#endif
}

void WBReceiver::processPacket(const uint8_t wlan_idx, const pcap_pkthdr &hdr, const uint8_t *pkt) {
#ifdef ENABLE_ADVANCED_DEBUGGING
  const auto tmp=GenericHelper::timevalToTimePointSystemClock(hdr.ts);
  const auto latency=std::chrono::system_clock::now() -tmp;
  avgPcapToApplicationLatency.add(latency);
#endif
  wb_rx_stats.count_p_all++;
  // The radio capture header precedes the 802.11 header.
  const auto parsedPacket = RawReceiverHelper::processReceivedPcapPacket(hdr, pkt);
  if (parsedPacket == std::nullopt) {
    m_console->warn("Discarding packet due to pcap parsing error!");
    wb_rx_stats.count_p_bad++;
    return;
  }
  if (parsedPacket->frameFailedFCSCheck) {
    m_console->warn("Discarding packet due to bad FCS!");
    wb_rx_stats.count_p_bad++;
    return;
  }
  if (!parsedPacket->ieee80211Header->isDataFrame()) {
    // we only process data frames
    m_console->warn("Got packet that is not a data packet {}",(int) parsedPacket->ieee80211Header->getFrameControl());
    wb_rx_stats.count_p_bad++;
    return;
  }
  if (parsedPacket->ieee80211Header->getRadioPort() != options.radio_port) {
    // If we have the proper filter on pcap only packets with the right radiotap port should pass through
    m_console->warn("Got packet with wrong radio port ",(int) parsedPacket->ieee80211Header->getRadioPort());
    //RadiotapHelper::debugRadiotapHeader(pkt,hdr.caplen);
    wb_rx_stats.count_p_bad++;
    return;
  }
  // All these edge cases should NEVER happen if using a proper tx/rx setup and the wifi driver isn't complete crap
  if (parsedPacket->payloadSize <= 0) {
    m_console->warn("Discarding packet due to no actual payload !");
    wb_rx_stats.count_p_bad++;
    return;
  }
  if (parsedPacket->payloadSize > RAW_WIFI_FRAME_MAX_PAYLOAD_SIZE) {
    m_console->warn("Discarding packet due to payload exceeding max {}",(int) parsedPacket->payloadSize);
    wb_rx_stats.count_p_bad++;
    return;
  }
  if (parsedPacket->allAntennaValues.size() > MAX_N_ANTENNAS_PER_WIFI_CARD) {
    m_console->warn( "Wifi card with {} antennas",parsedPacket->allAntennaValues.size());
  }
  if(wlan_idx <rssiForWifiCard.size()){
    auto &thisWifiCard = rssiForWifiCard.at(wlan_idx);
    //std::cout<<all_rssi_to_string(parsedPacket->allAntennaValues);
    const auto best_rssi=RawReceiverHelper::get_best_rssi_of_card(parsedPacket->allAntennaValues);
    //std::cout<<"best_rssi:"<<(int)best_rssi<<"\n";
    if(best_rssi.has_value()){
      thisWifiCard.addRSSI(best_rssi.value());
    }
    /*for (const auto &value: parsedPacket->allAntennaValues) {
      // don't care from which antenna the value came
      // There seems to be a bug where sometimes the reported rssi is 0 ???!!
      if(value.rssi!=0){
        thisWifiCard.addRSSI(value.rssi);
      }
    }*/
  }else{
    m_console->warn("wlan idx out of bounds");
  }

  //RawTransmitterHelper::writeAntennaStats(antenna_stat, WLAN_IDX, parsedPacket->antenna, parsedPacket->rssi);
  //const Ieee80211Header* tmpHeader=parsedPacket->ieee80211Header;
  //std::cout<<"RADIO_PORT"<<(int)tmpHeader->getRadioPort()<<" IEEE_SEQ_NR "<<(int)tmpHeader->getSequenceNumber()<<"\n";
  //std::cout<<"FrameControl:"<<(int)tmpHeader->getFrameControl()<<"\n";
  //std::cout<<"DurationOrConnectionId:"<<(int)tmpHeader->getDurationOrConnectionId()<<"\n";
  //parsedPacket->ieee80211Header->printSequenceControl();
  //mSeqNrCounter.onNewPacket(*parsedPacket->ieee80211Header);


  // now to the actual payload
  const uint8_t *packetPayload = parsedPacket->payload;
  const size_t packetPayloadSize = parsedPacket->payloadSize;

  if (packetPayload[0] == WFB_PACKET_KEY) {
    if (packetPayloadSize != WBSessionKeyPacket::SIZE_BYTES) {
      m_console->warn("invalid session key packet");
      wb_rx_stats.count_p_bad++;
      return;
    }
    WBSessionKeyPacket &sessionKeyPacket = *((WBSessionKeyPacket *) parsedPacket->payload);
    if (mDecryptor.onNewPacketSessionKeyData(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData)) {
      std::cout << "Initializing new session. IS_FEC_ENABLED:" << (int) sessionKeyPacket.IS_FEC_ENABLED
                << " MAX_N_FRAGMENTS_PER_BLOCK:" << (int) sessionKeyPacket.MAX_N_FRAGMENTS_PER_BLOCK << "\n";
      // We got a new session key (aka a session key that has not been received yet)
      wb_rx_stats.count_p_decryption_ok++;
      IS_FEC_ENABLED = sessionKeyPacket.IS_FEC_ENABLED;
      auto callback = [this](const uint8_t *payload, std::size_t payloadSize) {
        if (mOutputDataCallback != nullptr) {
          mOutputDataCallback(payload, payloadSize);
        } else {
          m_console->debug("No data callback registered");
        }
      };
      if (IS_FEC_ENABLED) {
        mFECDDecoder = std::make_unique<FECDecoder>(options.rx_queue_depth,(unsigned int) sessionKeyPacket.MAX_N_FRAGMENTS_PER_BLOCK);
        mFECDDecoder->mSendDecodedPayloadCallback = callback;
      } else {
        mFECDisabledDecoder = std::make_unique<FECDisabledDecoder>();
        mFECDisabledDecoder->mSendDecodedPayloadCallback = callback;
      }
    } else {
      wb_rx_stats.count_p_decryption_ok++;
    }
    return;
  } else if (packetPayload[0] == WFB_PACKET_DATA) {
    if (packetPayloadSize < sizeof(WBDataHeader) + sizeof(FECPayloadHdr)) {
      m_console->warn("Too short packet (fec header missing)");
      wb_rx_stats.count_p_bad++;
      return;
    }
    const WBDataHeader &wbDataHeader = *((WBDataHeader *) packetPayload);
    assert(wbDataHeader.packet_type == WFB_PACKET_DATA);
    wb_rx_stats.count_bytes_data_received+=packetPayloadSize;
    if(x_last_seq_nr==-1){
      x_last_seq_nr=wbDataHeader.sequence_number_extra;
    }else{
      const auto diff= diff_between_packets(x_last_seq_nr,wbDataHeader.sequence_number_extra);
      if(diff>1){
        // as an example, a diff of 2 means one packet is missing.
        x_n_missing_packets+=diff-1;
        //m_console->debug("Diff:{}",diff);
      }else{
        x_n_received_packets++;
      }
      if(std::chrono::steady_clock::now()-x_last_rec>std::chrono::seconds(1)){
        x_last_rec=std::chrono::steady_clock::now();
        auto n_total_packets=x_n_received_packets+x_n_missing_packets;
        m_console->debug("x_n_missing_packets:{} x_n_received_packets:{} n_total_packets:{}",x_n_missing_packets,x_n_received_packets,n_total_packets);
        if(n_total_packets>=1){
          const double loss_perc=static_cast<double>(x_n_missing_packets)/static_cast<double>(n_total_packets)*100.0;
          m_console->debug("Packet loss:{} %",loss_perc);
          x_curr_packet_loss_perc=x_n_missing_packets/n_total_packets;
        }
        x_n_received_packets=0;
        x_n_missing_packets=0;
      }
      x_last_seq_nr=wbDataHeader.sequence_number_extra;
    }
    const auto decryptedPayload = mDecryptor.decryptPacket(wbDataHeader.nonce, packetPayload + sizeof(WBDataHeader),
                                                           packetPayloadSize - sizeof(WBDataHeader), wbDataHeader);
    if (decryptedPayload == std::nullopt) {
      //m_console->warn("unable to decrypt packet :",std::to_string(wbDataHeader.nonce));
      wb_rx_stats.count_p_decryption_err++;
      return;
    }

    wb_rx_stats.count_p_decryption_ok++;

    assert(decryptedPayload->size() <= FEC_MAX_PACKET_SIZE);
    if (IS_FEC_ENABLED) {
      if (!mFECDDecoder) {
        m_console->warn("FEC K,N is not set yet");
        return;
      }
      if (!mFECDDecoder->validateAndProcessPacket(wbDataHeader.nonce, *decryptedPayload)) {
        wb_rx_stats.count_p_bad++;
      }
    } else {
      if (!mFECDisabledDecoder) {
        m_console->warn("FEC K,N is not set yet(disabled)");
        return;
      }
      mFECDisabledDecoder->processRawDataBlockFecDisabled(wbDataHeader.nonce, *decryptedPayload);
    }
  }
#ifdef ENABLE_ADVANCED_DEBUGGING
    else if(payload[0]==WFB_PACKET_LATENCY_BEACON){
        // for testing only. It won't work if the tx and rx are running on different systems
            assert(payloadSize==sizeof(LatencyTestingPacket));
            const LatencyTestingPacket* latencyTestingPacket=(LatencyTestingPacket*)payload;
            const auto timestamp=std::chrono::time_point<std::chrono::steady_clock>(std::chrono::nanoseconds(latencyTestingPacket->timestampNs));
            const auto latency=std::chrono::steady_clock::now()-timestamp;
            //std::cout<<"Packet latency on this system is "<<std::chrono::duration_cast<std::chrono::nanoseconds>(latency).count()<<"\n";
            avgLatencyBeaconPacketLatency.add(latency);
    }
#endif
  else {
    m_console->warn("Unknown packet type {]",(int) packetPayload[0]);
    wb_rx_stats.count_p_bad += 1;
    return;
  }
}

void WBReceiver::set_latest_stats(OpenHDStatisticsWriter::Data new_stats) {
  std::lock_guard<std::mutex> lock(m_last_stats_mutex);
  m_last_stats=new_stats;
}

OpenHDStatisticsWriter::Data WBReceiver::get_latest_stats(){
  std::lock_guard<std::mutex> lock(m_last_stats_mutex);
  return m_last_stats;
}
