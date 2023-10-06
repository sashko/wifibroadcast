//
// Created by consti10 on 05.10.23.
//

#include "RadiotapRxRfAggregator.h"

void RadiotapRxRfAggregator::on_valid_openhd_packet(
    const radiotap::rx::ParsedRxRadiotapPacket& packet) {
  if(packet.adapter.radiotap_dbm_antsignal.has_value()){
    const auto radiotap_dbm_antsignal=packet.adapter.radiotap_dbm_antsignal.value();
    auto opt_minmaxavg= adapter_rssi.add_and_recalculate_if_needed(radiotap_dbm_antsignal);
    if(opt_minmaxavg.has_value()){
      m_current_rx_stats.adapter.rssi_dbm=opt_minmaxavg->avg;
    }
  }
  if(packet.adapter.radiotap_dbm_antnoise.has_value()){
    const auto radiotap_dbm_antnoise=packet.adapter.radiotap_dbm_antnoise.value();
    auto opt_minmaxavg= adapter_noise.add_and_recalculate_if_needed(radiotap_dbm_antnoise);
    if(opt_minmaxavg.has_value()){
      m_current_rx_stats.adapter.noise_dbm=opt_minmaxavg->avg;
    }
  }
  if(packet.adapter.radiotap_lock_quality.has_value()){
    const auto radiotap_lock_quality=packet.adapter.radiotap_lock_quality.value();
    adapter_signal_quality.add_signal_quality(radiotap_lock_quality);
    m_current_rx_stats.adapter.card_signal_quality_perc=adapter_signal_quality.get_current_signal_quality();
  }
  for(int i=0;i<packet.rf_paths.size();i++){
    const auto& path=packet.rf_paths[i];
    on_per_rf_path(i,path);
  }
  //if(m_wifi_cards[wlan_idx].type==wifibroadcast::WIFI_CARD_TYPE_RTL8812AU){
  // RTL8812AU BUG - general value cannot be used, use max of antennas instead
  //  this_wifi_card_stats.card_dbm=std::max(this_wifi_card_stats.antenna1_dbm,this_wifi_card_stats.antenna2_dbm);
  //}
}

void RadiotapRxRfAggregator::on_per_rf_path(
    int index, const radiotap::rx::ParsedRfPath& data) {
  // For simplicity, we only track up to 2 antennas
  if(index>1) return ;
  auto& per_path=index==0 ? m_antenna1 : m_antenna2;
  auto& current=index==0 ? m_current_rx_stats.antenna1 : m_current_rx_stats.antenna2;
  {
    auto opt_minmaxavg= per_path.rssi_dbm.add_and_recalculate_if_needed(data.radiotap_dbm_antsignal);
    if(opt_minmaxavg.has_value()){
      current.rssi_dbm=opt_minmaxavg->avg;
    }
  }
  {
    auto opt_minmaxavg= per_path.noise_dbm.add_and_recalculate_if_needed(data.radiotap_dbm_antnoise);
    if(opt_minmaxavg.has_value()){
      current.rssi_dbm=opt_minmaxavg->avg;
    }
  }
  {
    per_path.signal_quality.add_signal_quality(data.radiotap_dbm_antsignal);
    current.card_signal_quality_perc=per_path.signal_quality.get_current_signal_quality();
  }
}

void RadiotapRxRfAggregator::set_debug_invalid_values(bool enable) {
  adapter_rssi.set_debug_invalid_rssi(enable,0);
  adapter_noise.set_debug_invalid_rssi(enable,0);
  m_antenna1.rssi_dbm.set_debug_invalid_rssi(enable,1);
  m_antenna2.rssi_dbm.set_debug_invalid_rssi(enable,2);
}

void RadiotapRxRfAggregator::reset() {
  m_current_rx_stats={};
  adapter_rssi.reset();
  adapter_noise.reset();
  m_antenna1.rssi_dbm.reset();
  m_antenna2.rssi_dbm.reset();
}
