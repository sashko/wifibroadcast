//
// Created by consti10 on 05.10.23.
//

#ifndef WIFIBROADCAST_RADIOTAPRXRFAGGREGATOR_H
#define WIFIBROADCAST_RADIOTAPRXRFAGGREGATOR_H

#include "RadiotapHeaderRx.hpp"
#include "RSSIAccumulator.hpp"
#include "SignalQualityAccumulator.hpp"

class RadiotapRxRfAggregator {
 public:
  struct KeyRfIndicators {
    // -128 = invalid, [-127..-1] otherwise
    int8_t rssi_dbm=-128;
    int8_t noise_dbm=-128;
    // [0,100] if valid, -1 otherwise
    int8_t card_signal_quality_perc=-1;
  };
  struct CardKeyRfIndicators {
    // ------------- PER ADAPTER ------------
    KeyRfIndicators adapter;
    // -------------- PER ANTENNA ----------
    KeyRfIndicators antenna1;
    KeyRfIndicators antenna2;
  };
  // Called every time a valid openhd packet is received
  void on_valid_openhd_packet(const radiotap::rx::ParsedRxRadiotapPacket& packet);
  // debugging of the 'invalid values reported by driver' issue
  void set_debug_invalid_values(bool enable);
  // Reset all rf metrics
  void reset();
  // TODO: Thread safety ?
  CardKeyRfIndicators get_current(){
    return m_current_rx_stats;
  }
 private:
  void on_per_rf_path(int index,const radiotap::rx::ParsedRfPath& data);
  // Stats per-adapter
  RSSIAccumulator adapter_rssi{};
  RSSIAccumulator adapter_noise{};
  SignalQualityAccumulator adapter_signal_quality{};
  // Stats per antenna (we only track up to 2 antenna(s)
  struct PerAntenna{
    RSSIAccumulator rssi_dbm;
    RSSIAccumulator noise_dbm;
    SignalQualityAccumulator signal_quality;
  };
  PerAntenna m_antenna1;
  PerAntenna m_antenna2;
  CardKeyRfIndicators m_current_rx_stats{};
};

#endif  // WIFIBROADCAST_RADIOTAPRXRFAGGREGATOR_H
