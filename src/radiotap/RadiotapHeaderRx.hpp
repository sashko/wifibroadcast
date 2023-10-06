//
// Created by consti10 on 05.10.23.
//

#ifndef WIFIBROADCAST_RADIOTAPHEADERPARSER_H
#define WIFIBROADCAST_RADIOTAPHEADERPARSER_H

#include <optional>

#include "../Ieee80211Header.hpp"
#include "RadiotapHeaderTx.hpp"

// Code for parsing the radiotap header coming from rtl8812au / rtl8812bu / other monitor mode wifi drivers

namespace radiotap::rx{

// Values per rf-path (multiple antennas)
struct ParsedRfPath{
  // which antenna the value refers to,
  // or -1 this dgm value came before a IEEE80211_RADIOTAP_ANTENNA field and the antenna idx is therefore unknown
  int8_t antennaIdx;
  // https://www.radiotap.org/fields/Antenna%20signal.html
  // IEEE80211_RADIOTAP_DBM_ANTSIGNAL
  int8_t radiotap_dbm_antsignal;
  // IEEE80211_RADIOTAP_LOCK_QUALITY
  uint16_t radiotap_lock_quality;
  // IEEE80211_RADIOTAP_DBM_ANTNOISE
  int8_t radiotap_dbm_antnoise;
};
// Values generic (not per rf-path)
struct ParsedAdapter{
  // Atheros forwards frames even though the fcs check failed ( this packet is corrupted)
  // This is pretty much the only adapter that does that though
  bool radiotap_f_bad_fcs= false;
  std::optional<int8_t> radiotap_dbm_antsignal=std::nullopt;
  std::optional<uint16_t> radiotap_lock_quality=std::nullopt;
  std::optional<int8_t> radiotap_dbm_antnoise=std::nullopt;
};

struct ParsedRxRadiotapPacket {
  // Size can be anything from size=1 to size== N where N is the number of Antennas of this adapter
  const std::vector<ParsedRfPath> allAntennaValues;
  const Ieee80211HeaderRaw *ieee80211Header;
  const uint8_t *payload;
  const std::size_t payloadSize;
  ParsedAdapter adapter;
};

// Returns std::nullopt if radiotap was unable to parse the header
// else return the *parsed information*
// To avoid confusion it might help to treat this method as a big black Box :)
static std::optional<ParsedRxRadiotapPacket> process_received_radiotap_packet(const uint8_t *pkt,const int pkt_len) {
  //int pktlen = hdr.caplen;
  int pktlen=pkt_len;
  //
  // Copy the value of this flag once present and process it after the loop is done
  uint8_t tmpCopyOfIEEE80211_RADIOTAP_FLAGS = 0;
  struct ieee80211_radiotap_iterator iterator{};
  // With AR9271 I get 39 as length of the radio-tap header
  // With my internal laptop wifi chip I get 36 as length of the radio-tap header.
  int ret = ieee80211_radiotap_iterator_init(&iterator, (ieee80211_radiotap_header *) pkt, pktlen, NULL);
  // weird, unfortunately it is not really documented / specified how raditap reporting dBm values with multiple antennas works
  // we store all values reported by IEEE80211_RADIOTAP_ANTENNA in here
  // ? there can be multiple ?
  //std::vector<uint8_t> radiotap_antennas;
  // and all values reported by IEEE80211_RADIOTAP_DBM_ANTSIGNAL in here
  //std::vector<int8_t> radiotap_antsignals;
  // for rtl8812au fixup
  //
  ParsedAdapter parsed_adapter{};

  int8_t currentAntenna = -1;
  // not confirmed yet, but one radiotap packet might include stats for multiple antennas
  std::vector<ParsedRfPath> allAntennaValues;
  while (ret == 0) {
    ret = ieee80211_radiotap_iterator_next(&iterator);
    if (ret) {
      continue;
    }
    /* see if this argument is something we can use */
    switch (iterator.this_arg_index) {
      case IEEE80211_RADIOTAP_ANTENNA:
        // RADIOTAP_DBM_ANTSIGNAL seems to come not before, but after
        currentAntenna = iterator.this_arg[0];
        //radiotap_antennas.push_back(iterator.this_arg[0]);
        break;
      case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:{
        int8_t value;
        std::memcpy(&value,iterator.this_arg,1);
        allAntennaValues.push_back({currentAntenna,value});
      }
      break;
      case IEEE80211_RADIOTAP_FLAGS:
        tmpCopyOfIEEE80211_RADIOTAP_FLAGS = *(uint8_t *) (iterator.this_arg);
        break;
      case IEEE80211_RADIOTAP_MCS:
      {
        uint8_t known = iterator.this_arg[0];
        uint8_t flags = iterator.this_arg[1];
        uint8_t mcs = iterator.this_arg[2];
        if(known & IEEE80211_RADIOTAP_MCS_HAVE_MCS){
          // Not needed for now
          //parsed_adapter.mcs_index=static_cast<uint16_t>(mcs);
        }
        if (known & IEEE80211_RADIOTAP_MCS_HAVE_BW) {
          const uint8_t bandwidth = flags & IEEE80211_RADIOTAP_MCS_BW_MASK;
          switch (bandwidth) {
            case IEEE80211_RADIOTAP_MCS_BW_20:
            case IEEE80211_RADIOTAP_MCS_BW_20U:
            case IEEE80211_RADIOTAP_MCS_BW_20L:
              // Not needed for now
              //parsed_adapter.channel_width=static_cast<uint16_t>(20);
              break;
            case IEEE80211_RADIOTAP_MCS_BW_40:
              // Not needed for now
              //parsed_adapter.channel_width=static_cast<uint16_t>(40);
              break;
            default:
              break ;
          }
        }
      }
      break;
      case IEEE80211_RADIOTAP_LOCK_QUALITY:{
        //int8_t value;
        uint16_t value;
        std::memcpy(&value,iterator.this_arg,1);
        parsed_adapter.radiotap_lock_quality=value;
      } break ;
      default:break;
    }
  }  /* while more rt headers */
  if (ret != -ENOENT) {
    //wifibroadcast::log::get_default()->warn("Error parsing radiotap header!\n";
    return std::nullopt;
  }
  bool frameFailedFcsCheck = false;
  if (tmpCopyOfIEEE80211_RADIOTAP_FLAGS & IEEE80211_RADIOTAP_F_BADFCS) {
    //wifibroadcast::log::get_default()->warn("Got packet with bad fsc\n";
    parsed_adapter.radiotap_f_bad_fcs= true;
  }
  // the fcs is at the end of the packet
  if (tmpCopyOfIEEE80211_RADIOTAP_FLAGS & IEEE80211_RADIOTAP_F_FCS) {
    //<<"Packet has IEEE80211_RADIOTAP_F_FCS";
    pktlen -= 4;
  }
  //assert(iterator._max_length==hdr.caplen);
  /* discard the radiotap header part */
  pkt += iterator._max_length;
  pktlen -= iterator._max_length;
  //
  const Ieee80211HeaderRaw *ieee80211Header = (Ieee80211HeaderRaw *) pkt;
  const uint8_t *payload = pkt + Ieee80211HeaderRaw::SIZE_BYTES;
  const std::size_t payloadSize = (std::size_t) pktlen - Ieee80211HeaderRaw::SIZE_BYTES;
  //
  /*std::stringstream ss;
  ss<<"Antennas:";
  for(const auto& antenna : radiotap_antennas){
    ss<<(int)antenna<<",";
  }
  ss<<"\nAntsignals:";
  for(const auto& antsignal : radiotap_antsignals){
    ss<<(int)antsignal<<",";
  }
  std::cout<<ss.str();*/
  return ParsedRxRadiotapPacket{allAntennaValues, ieee80211Header, payload, payloadSize, parsed_adapter};
}

static std::string rf_path_to_string(const ParsedRfPath& rf_path){
  std::stringstream ss;
  ss<<" {idx:signal:noise:lock: "<<(int)rf_path.antennaIdx<<":";
  ss<<(int)rf_path.radiotap_dbm_antsignal<<"dBm:";
  ss<<rf_path.radiotap_dbm_antnoise<<"dBm:";
  ss<<rf_path.radiotap_lock_quality<<"%}";
  return ss.str();
}

static std::string all_rf_path_to_string(const std::vector<ParsedRfPath>& all_rf_path){
  std::stringstream ss;
  ss<<"RF Path:";
  int idx=0;
  for(const auto& rf_path:all_rf_path){
    ss<<rf_path_to_string(rf_path);
    idx++;
  }
  return ss.str();
}

static std::string parsed_radiotap_to_string(const ParsedRxRadiotapPacket& parsed){
  std::stringstream ss;
  ss<<all_rf_path_to_string(parsed.allAntennaValues)<<"\n";
  if(parsed.adapter.radiotap_dbm_antsignal.has_value()){
    ss<<"Antsignal:"<<(int)parsed.adapter.radiotap_dbm_antsignal.value()<<" ";
  }
  if(parsed.adapter.radiotap_dbm_antnoise.has_value()){
    ss<<"Antnoise:"<<(int)parsed.adapter.radiotap_dbm_antnoise.value()<<" ";
  }
  if(parsed.adapter.radiotap_lock_quality.has_value()){
    ss<<"Lock:"<<(int)parsed.adapter.radiotap_lock_quality.value()<<" ";
  }
  return ss.str();
}

}

#endif  // WIFIBROADCAST_RADIOTAPHEADERPARSER_H
