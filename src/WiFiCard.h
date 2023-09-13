//
// Created by consti10 on 13.09.23.
//

#ifndef WIFIBROADCAST_WIFICARD_H
#define WIFIBROADCAST_WIFICARD_H

#include <string>
#include <sstream>
#include <vector>

namespace wifibroadcast{
// In OpenHD, we have a quite extensive WiFiCard abstraction -
// in wifibroadcast, we are a bit simpler
// (But we require info for quirks)
// RTL8812AU driver requires a quirk regarding rssi
static constexpr auto WIFI_CARD_TYPE_UNKNOWN=0;
static constexpr auto WIFI_CARD_TYPE_RTL8812AU=1;
struct WifiCard{
  std::string name;
  int type;
};
static std::vector<std::string> get_wifi_card_names(const std::vector<WifiCard>& cards){
  std::vector<std::string> ret;
  for(const auto& card:cards){
    ret.push_back(card.name);
  }
  return ret;
}
}

#endif  // WIFIBROADCAST_WIFICARD_H
