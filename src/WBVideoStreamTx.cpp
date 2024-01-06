//
// Created by consti10 on 06.01.24.
//

#include "WBVideoStreamTx.h"

#include "SchedulingHelper.hpp"

struct CodecConfig{
  uint8_t codec_type;
  uint16_t config_data_len;
  // config_data_len bytes follow
};

WBVideoStreamTx::WBVideoStreamTx(
    std::shared_ptr<WBTxRx> txrx, WBVideoStreamTx::Options options1,
    std::shared_ptr<RadiotapHeaderTxHolder> radiotap_header_holder)
    :options(options1),m_txrx(txrx),m_radiotap_header_holder(std::move(radiotap_header_holder))
{
  assert(m_txrx);
  if(options.opt_console){
    m_console=options.opt_console;
  }else{
    m_console=wifibroadcast::log::create_or_get("wb_tx"+std::to_string(options.radio_port));
  }
  assert(m_console);
  m_block_queue=std::make_unique<moodycamel::BlockingReaderWriterCircularBuffer<std::shared_ptr<EnqueuedBlock>>>(options.frame_queue_size);
  m_fec_encoder = std::make_unique<FECEncoder>();
  auto cb=[this](const uint8_t* packet,int packet_len){
    send_packet(packet,packet_len);
  };
  m_fec_encoder->m_out_cb =cb;
  m_process_data_thread_run=true;
  m_process_data_thread=std::make_unique<std::thread>(&WBVideoStreamTx::loop_process_data, this);
}

WBVideoStreamTx::~WBVideoStreamTx() {
  m_process_data_thread_run= false;
  if(m_process_data_thread && m_process_data_thread->joinable()){
    m_process_data_thread->join();
  }
}

void WBVideoStreamTx::loop_process_data() {
  if(options.dequeue_thread_max_realtime){
    SchedulingHelper::setThreadParamsMaxRealtime();
  }
  static constexpr std::int64_t timeout_usecs=100*1000;
  std::shared_ptr<EnqueuedBlock> frame= nullptr;
  std::chrono::steady_clock::time_point last_config=std::chrono::steady_clock::now();
  while (m_process_data_thread_run){
    if(m_block_queue->wait_dequeue_timed(frame,timeout_usecs)){
      process_enqueued_frame(*frame);
    }
    const auto now=std::chrono::steady_clock::now();
    if(now-last_config>=options.codec_config_interval){
      // send config data
      last_config=now;
    }
  }
}

void WBVideoStreamTx::process_enqueued_frame(const EnqueuedBlock &block) {
}

void WBVideoStreamTx::set_config_data(
    uint8_t codec_type, std::shared_ptr<std::vector<uint8_t>> codec_config) {

}

void WBVideoStreamTx::enqueue_frame(
    std::shared_ptr<std::vector<uint8_t>> codec_config) {

}

void WBVideoStreamTx::reset() {

}

void WBVideoStreamTx::send_packet(const uint8_t *packet, int packet_len) {

}
