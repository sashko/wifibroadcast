//
// Created by consti10 on 13.09.23.
//

#ifndef WIFIBROADCAST_RADIOTAPHEADERHOLDER_H
#define WIFIBROADCAST_RADIOTAPHEADERHOLDER_H

#include <mutex>

#include "../wifibroadcast_spdlog.h"
#include "RadiotapHeaderTx.hpp"

/**
 * Thread-safe holder for a (TX) radiotap header.
 * ( getter / setter) -
 * We modify the tx radiotap header in openhd at run time.
 * This kind of "atomic behaviour" is enough for openhd wifibroadcast.
 * TODO: Use std::atomic instead of std::mutex
 */
class RadiotapHeaderTxHolder {
 public:
  explicit RadiotapHeaderTxHolder(){
    m_console=wifibroadcast::log::get_default();
  }
  void thread_safe_set(RadiotapHeaderTx::UserSelectableParams params){
    auto tmp= RadiotapHeaderTx{params};
    thread_safe_set2(tmp);
  }
  void thread_safe_set2(RadiotapHeaderTx radiotap_header) {
    std::lock_guard<std::mutex> guard(m_radiotap_header_mutex);
    m_radiotap_header = radiotap_header;
  }
  RadiotapHeaderTx thread_safe_get() {
    std::lock_guard<std::mutex> guard(m_radiotap_header_mutex);
    return m_radiotap_header;
  }
 public:
  void update_mcs_index(uint8_t mcs_index){
    m_console->debug("update_mcs_index {}",mcs_index);
    m_radioTapHeaderParams.mcs_index=mcs_index;
    thread_safe_set(m_radioTapHeaderParams);
  }
  void update_channel_width(int width_mhz){
    m_console->debug("update_channel_width {}",width_mhz);
    m_radioTapHeaderParams.bandwidth=width_mhz;
    thread_safe_set(m_radioTapHeaderParams);
  }
  void update_stbc(int stbc){
    m_console->debug("update_stbc {}",stbc);
    if(stbc<0 || stbc> 3){
      m_console->warn("Invalid stbc index");
      return ;
    }
    m_radioTapHeaderParams.stbc=stbc;
    thread_safe_set(m_radioTapHeaderParams);
  }
  void update_guard_interval(bool short_gi){
    m_radioTapHeaderParams.short_gi=short_gi;
    thread_safe_set(m_radioTapHeaderParams);
  }
  void update_ldpc(bool ldpc){
    m_radioTapHeaderParams.ldpc=ldpc;
    thread_safe_set(m_radioTapHeaderParams);
  }
  void update_set_flag_tx_no_ack(bool enable){
    m_radioTapHeaderParams.set_flag_tx_no_ack=enable;
    thread_safe_set(m_radioTapHeaderParams);
  }
 private:
  std::shared_ptr<spdlog::logger> m_console;
  RadiotapHeaderTx::UserSelectableParams m_radioTapHeaderParams{};
  RadiotapHeaderTx m_radiotap_header{RadiotapHeaderTx::UserSelectableParams{}};
  std::mutex m_radiotap_header_mutex;
};

#endif  // WIFIBROADCAST_RADIOTAPHEADERHOLDER_H
