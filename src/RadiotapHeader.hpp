#ifndef __WIFIBROADCAST_RADIOTAP_HEADER_HPP__
#define __WIFIBROADCAST_RADIOTAP_HEADER_HPP__

#include "HelperSources/Helper.hpp"
extern "C" {
#include "external/radiotap/radiotap_iter.h"
#include "external/radiotap/radiotap.h"
};

#include <endian.h>

#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sstream>
#include <string>
#include <vector>

#include "wifibroadcast_spdlog.h"

// everything must be in little endian byte order http://www.radiotap.org/
static_assert(__BYTE_ORDER == __LITTLE_ENDIAN, "This code is written for little endian only !");

namespace Radiotap {

static constexpr auto MCS_MAX=31;
static constexpr auto MCS_MIN=0;

// https://stackoverflow.com/questions/47981/how-do-you-set-clear-and-toggle-a-single-bit
// http://www.radiotap.org/
static uint32_t writePresenceBitfield(const std::vector<ieee80211_radiotap_presence> &valuesToBePresent) {
  uint32_t present = 0;
  for (const auto &valueToBePresent: valuesToBePresent) {
    present |= 1 << valueToBePresent;
  }
  return present;
}

// http://www.radiotap.org/fields/MCS.html
struct MCS {
  uint8_t known = 0;
  uint8_t flags = 0;
  uint8_t modulationIndex = 0;
}__attribute__ ((packed));
}

// To inject packets we need 2 radiotap fields: "TX flags"  and the "MCS field"
struct RadiotapHeaderWithTxFlagsAndMCS {
  uint8_t version = 0;
  uint8_t padding = 0;
  uint16_t length = 13;
  // http://www.radiotap.org/
  uint32_t presence = 0;
  // http://www.radiotap.org/fields/TX%20flags.html
  uint16_t txFlags = 0;
  //http://www.radiotap.org/fields/MCS.html
  // mcs is more than just the mcs index. Be carefully !
  Radiotap::MCS mcs{};
}__attribute__ ((packed));
static_assert(sizeof(RadiotapHeaderWithTxFlagsAndMCS) == 13);

// To inject packets we need a proper radiotap header. The fields of importance for use are:
// 1) "TX flags"
// 2) "MCS field"
// This class holds the bytes for a proper radiotap header after constructing it with the user-selectable Params
class RadiotapHeader {
 public:
  static constexpr auto SIZE_BYTES = 13;
  // these are the params in use by OpenHD right now
  struct UserSelectableParams {
    // 20 or 40 mhz channel width. I do not recommend using 40mhz channel width even though it might provide higher throughput.
    int bandwidth = 20;
    // I do not recommend using a short guard interval
    bool short_gi = false;
    // https://en.wikipedia.org/wiki/Space%E2%80%93time_block_code
    int stbc = 0;
    // https://en.wikipedia.org/wiki/Low-density_parity-check_code#:~:text=In%20information%20theory%2C%20a%20low,subclass%20of%20the%20bipartite%20graph).
    bool ldpc = false;
    // https://www.digitalairwireless.com/articles/blog/demystifying-modulation-and-coding-scheme-mcs-index-values
    // https://mcsindex.com/
    int mcs_index = 3;
    // depends on the driver
    bool set_flag_tx_no_ack= false;
  };
  // Make sure that this is the only constructor
  explicit RadiotapHeader(const UserSelectableParams &params) {
    if (params.mcs_index < Radiotap::MCS_MIN || params.mcs_index > Radiotap::MCS_MAX) {
      throw std::runtime_error(fmt::format("Unsupported MCS index {}", params.mcs_index));
    }
    if (!(params.bandwidth == 20 || params.bandwidth == 40)) {
      throw std::runtime_error(fmt::format("Unsupported bandwidth: {}", params.bandwidth));
    }
    if (!(params.stbc == 0 || params.stbc == 1 || params.stbc == 2 || params.stbc == 3)) {
      throw std::runtime_error(fmt::format("Unsupported STBC: {}", params.stbc));
    }
    // size is fixed here
    radiotapHeaderData.length = SIZE_BYTES;
    // we use 2 radiotap fields, tx flags and mcs field
    radiotapHeaderData.presence =
        Radiotap::writePresenceBitfield({IEEE80211_RADIOTAP_TX_FLAGS, IEEE80211_RADIOTAP_MCS});

    // in wifibroadcast we never want ack from the receiver - well, this is true,
    // but rtl8812au driver actually uses this one a bit differently
    if(params.set_flag_tx_no_ack){
      radiotapHeaderData.txFlags =
          IEEE80211_RADIOTAP_F_TX_NOACK; //| IEEE80211_RADIOTAP_F_TX_CTS | IEEE80211_RADIOTAP_F_TX_RTS
    }else{
      radiotapHeaderData.txFlags = 0;
    }

    // now onto the "MCS field"
    radiotapHeaderData.mcs.known =
        (IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW | IEEE80211_RADIOTAP_MCS_HAVE_GI
            | IEEE80211_RADIOTAP_MCS_HAVE_STBC | IEEE80211_RADIOTAP_MCS_HAVE_FEC);
    // write the mcs index
    radiotapHeaderData.mcs.modulationIndex = params.mcs_index;

    switch (params.bandwidth) {
      case 20:radiotapHeaderData.mcs.flags |= IEEE80211_RADIOTAP_MCS_BW_20;
        break;
      case 40:radiotapHeaderData.mcs.flags |= IEEE80211_RADIOTAP_MCS_BW_40;
        break;
      default:assert(true);
    }

    if (params.short_gi) {
      radiotapHeaderData.mcs.flags |= IEEE80211_RADIOTAP_MCS_SGI;
    }

    if (params.ldpc) {
      radiotapHeaderData.mcs.flags |= IEEE80211_RADIOTAP_MCS_FEC_LDPC;
    }

    switch (params.stbc) {
      case 0:break;
      case 1:radiotapHeaderData.mcs.flags |= (IEEE80211_RADIOTAP_MCS_STBC_1 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
        break;
      case 2:radiotapHeaderData.mcs.flags |= (IEEE80211_RADIOTAP_MCS_STBC_2 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
        break;
      case 3:radiotapHeaderData.mcs.flags |= (IEEE80211_RADIOTAP_MCS_STBC_3 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
        break;
      default:assert(true);
    }
  };
  const uint8_t *getData() const {
    return (const uint8_t *) &radiotapHeaderData;
  }
  constexpr std::size_t getSize() const {
    return SIZE_BYTES;
  }
  static std::string user_params_to_string(const UserSelectableParams& params){
    return fmt::format("BW:{} MCS:{} SGI:{} STBC:{} LDPC:{} NO_ACK:{}",params.bandwidth,params.mcs_index,params.short_gi,params.stbc,params.ldpc,params.set_flag_tx_no_ack);
  }
 private:
  RadiotapHeaderWithTxFlagsAndMCS radiotapHeaderData;
}__attribute__ ((packed));
static_assert(sizeof(RadiotapHeader) == RadiotapHeader::SIZE_BYTES, "ALWAYS TRUE");
static_assert(sizeof(RadiotapHeaderWithTxFlagsAndMCS) == RadiotapHeader::SIZE_BYTES, "ALWAYS TRUE");

namespace RadiotapHelper {

static std::string toStringRadiotapFlags(uint8_t flags) {
  std::stringstream ss;
  ss << "All IEEE80211_RADIOTAP flags: [";
  if (flags & IEEE80211_RADIOTAP_F_CFP) {
    ss << "CFP,";
  }
  if (flags & IEEE80211_RADIOTAP_F_SHORTPRE) {
    ss << "SHORTPRE,";
  }
  if (flags & IEEE80211_RADIOTAP_F_WEP) {
    ss << "WEP,";
  }
  if (flags & IEEE80211_RADIOTAP_F_FRAG) {
    ss << "FRAG,";
  }
  if (flags & IEEE80211_RADIOTAP_F_FCS) {
    ss << "FCS,";
  }
  if (flags & IEEE80211_RADIOTAP_F_DATAPAD) {
    ss << "DATAPAD,";
  }
  if (flags & IEEE80211_RADIOTAP_F_BADFCS) {
    ss << "BADFCS";
  }
  ss << "]";
  return ss.str();
}
// http://www.radiotap.org/fields/Channel.html
static std::string toStringRadiotapChannel(uint16_t frequency, uint16_t flags) {
  std::stringstream ss;
  ss << "All Radiotap channel values: [";
  ss << "Frequency[" << (int) frequency << "],";
  if (flags & IEEE80211_CHAN_CCK) {
    ss << "CHAN_CCK,";
  }
  if (flags & IEEE80211_CHAN_OFDM) {
    ss << "CHAN_OFDM,";
  }
  if (flags & IEEE80211_CHAN_2GHZ) {
    ss << "CHAN_2GHZ,";
  }
  if (flags & IEEE80211_CHAN_5GHZ) {
    ss << "CHAN_5GHZ,";
  }
  if (flags & IEEE80211_CHAN_DYN) {
    ss << "CHAN_DYN,";
  }
  if (flags & IEEE80211_CHAN_HALF) {
    ss << "CHAN_HALF,";
  }
  if (flags & IEEE80211_CHAN_QUARTER) {
    ss << "CHAN_QUARTER,";
  }
  ss << "]";
  return ss.str();
}
//http://www.radiotap.org/fields/RX%20flags.html
static std::string toStringRadiotapRXFlags(uint16_t rxFlags) {
  std::stringstream ss;
  ss << "All IEEE80211_RADIOTAP_RX_FLAGS values: [";
  if (rxFlags & IEEE80211_RADIOTAP_F_RX_BADPLCP) {
    ss << "RX_BADPLCP,";
  }
  ss << "]";
  return ss.str();
}
// http://www.radiotap.org/fields/TX%20flags.html
static std::string toStringRadiotapTXFlags(const uint16_t txFlags) {
  std::stringstream ss;
  ss << "All TX FLAGS: [";
  if (txFlags & IEEE80211_RADIOTAP_F_TX_FAIL) {
    ss << "TX_FAIL,";
  }
  if (txFlags & IEEE80211_RADIOTAP_F_TX_CTS) {
    ss << "TX_CTS,";
  }
  if (txFlags & IEEE80211_RADIOTAP_F_TX_RTS) {
    ss << "TX_RTS,";
  }
  if (txFlags & IEEE80211_RADIOTAP_F_TX_NOACK) {
    ss << "TX_NOACK,";
  }
  ss << "]";
  return ss.str();
}

// http://www.radiotap.org/fields/MCS.html
static std::string toStringRadiotapMCS(uint8_t known, uint8_t flags, uint8_t mcs) {
  std::stringstream ss;
  ss << "MCS Stuff: [";
  if (known & IEEE80211_RADIOTAP_MCS_HAVE_BW) {
    ss << "HAVE_BW[";
    uint8_t bandwidth = flags & IEEE80211_RADIOTAP_MCS_BW_MASK;
    switch (bandwidth) {
      case IEEE80211_RADIOTAP_MCS_BW_20: ss << "BW_20";
        break;
      case IEEE80211_RADIOTAP_MCS_BW_40: ss << "BW_40";
        break;
      case IEEE80211_RADIOTAP_MCS_BW_20L: ss << "BW_20L";
        break;
      case IEEE80211_RADIOTAP_MCS_BW_20U: ss << "BW_20U";
        break;
      default:ss << "Unknown";
    }
    ss << "],";
  }
  if (known & IEEE80211_RADIOTAP_MCS_HAVE_MCS) {
    ss << "HAVE_MCS[" << (int) mcs << "],";
  }
  if (known & IEEE80211_RADIOTAP_MCS_HAVE_GI) {
    uint8_t gi = flags & IEEE80211_RADIOTAP_MCS_SGI;
    ss << "HAVE_GI[" << (gi == 0 ? "long" : "short") << "],";
  }
  if (known & IEEE80211_RADIOTAP_MCS_HAVE_FMT) {
    uint8_t fmt = flags & IEEE80211_RADIOTAP_MCS_FMT_GF;
    ss << "HAVE_FMT[" << (fmt == 0 ? "mixed" : "greenfield") << "],";
  }
  if (known & IEEE80211_RADIOTAP_MCS_HAVE_FEC) {
    uint8_t fec_type = flags & IEEE80211_RADIOTAP_MCS_FEC_LDPC;
    ss << "HAVE_FEC[" << (fec_type == 0 ? "BBC" : "LDPC") << "]";
  }
  if (known & IEEE80211_RADIOTAP_MCS_HAVE_STBC) {
    uint8_t stbc = flags << IEEE80211_RADIOTAP_MCS_STBC_SHIFT;
    ss << "HAVE_STBC[" << (int) stbc << "],";
  }
  ss << "]";
  return ss.str();
}

static void debugRadiotapHeader(const uint8_t *pkt, int pktlen, std::shared_ptr<spdlog::logger> console= wifibroadcast::log::get_default()) {
  struct ieee80211_radiotap_iterator iterator{};
  int ret = ieee80211_radiotap_iterator_init(&iterator, (ieee80211_radiotap_header *) pkt, pktlen, NULL);
  if (ret) {
    console->warn("ill-formed ieee80211_radiotap header {}",ret);
    return;
  }
  std::stringstream ss;
  ss << "Debuging Radiotap Header \n";
  while (ret == 0) {
    ret = ieee80211_radiotap_iterator_next(&iterator);
    if (iterator.is_radiotap_ns) {
      //ss<<"Is in namespace\n";
    }
    if (ret) {
      continue;
    }
    const int curr_arg_size=iterator.this_arg_size;
    /* see if this argument is something we can use */
    switch (iterator.this_arg_index) {
      case IEEE80211_RADIOTAP_TSFT:
        ss << "IEEE80211_RADIOTAP_TSFT:"<<curr_arg_size<<"\n";
        break;
      case IEEE80211_RADIOTAP_FLAGS:
        //ss<<"IEEE80211_RADIOTAP_FLAGS\n";
        ss << toStringRadiotapFlags(*iterator.this_arg) << "\n";
        break;
      case IEEE80211_RADIOTAP_RATE:
        ss << "IEEE80211_RADIOTAP_RATE:" << (int) (*iterator.this_arg) << "\n";
        break;
      case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:{
        // This field	contains a single signed 8-bit value that indicates
        //	     the RF signal power at the	antenna, in decibels difference	from 	     1mW.
        int8_t value=*(int8_t *) iterator.this_arg;
        ss << "IEEE80211_RADIOTAP_DBM_ANTSIGNAL:" << (int) value << "dBm size:"<<curr_arg_size<<"\n";
      }
        break;
      case IEEE80211_RADIOTAP_ANTENNA:
        ss << "IEEE80211_RADIOTAP_ANTENNA:" << (int) (*iterator.this_arg) << "\n";
        break;
      case IEEE80211_RADIOTAP_CHANNEL:
        //ss<<"IEEE80211_RADIOTAP_CHANNEL\n";
      {
        auto *frequency = (uint16_t *) iterator.this_arg;
        auto *flags = (uint16_t *) &iterator.this_arg[2];
        ss << toStringRadiotapChannel(*frequency, *flags) << " \n";
      }
        break;
      case IEEE80211_RADIOTAP_MCS:
        //ss<<"IEEE80211_RADIOTAP_MCS\n";
      {
        uint8_t known = iterator.this_arg[0];
        uint8_t flags = iterator.this_arg[1];
        uint8_t mcs = iterator.this_arg[2];
        ss << toStringRadiotapMCS(known, flags, mcs) << "\n";
      }
        break;
      case IEEE80211_RADIOTAP_RX_FLAGS:
        //ss<<"IEEE80211_RADIOTAP_RX_FLAGS\n";
        ss << toStringRadiotapRXFlags(*iterator.this_arg) << "\n";
        break;
      case IEEE80211_RADIOTAP_TX_FLAGS:
        //ss<<"IEEE80211_RADIOTAP_TX_FLAGS\n";
        ss << toStringRadiotapTXFlags(*iterator.this_arg) << "\n";
        break;
      case IEEE80211_RADIOTAP_AMPDU_STATUS:
        ss << "EEE80211_RADIOTAP_AMPDU_STATUS\n";
        break;
      case IEEE80211_RADIOTAP_VHT:
        ss << "IEEE80211_RADIOTAP_VHT\n";
        break;
      case IEEE80211_RADIOTAP_TIMESTAMP:
        ss << "IEEE80211_RADIOTAP_TIMESTAMP\n";
        break;
      case IEEE80211_RADIOTAP_LOCK_QUALITY:
        ss << "IEEE80211_RADIOTAP_LOCK_QUALITY\n";
        break;
      default:
        ss << "Unknown radiotap argument:" << (int) iterator.this_arg_index << "\n";
        break;
    }
  }  /* while more rt headers */
  console->debug("{}",ss.str().c_str());
}

struct RssiForAntenna {
  // which antenna the value refers to,
  // or -1 this dgm value came before a IEEE80211_RADIOTAP_ANTENNA field and the antenna idx is therefore unknown
  const int8_t antennaIdx;
  // https://www.radiotap.org/fields/Antenna%20signal.html
  const int8_t rssi;
};
struct ParsedRxRadiotapPacket {
  // Size can be anything from size=1 to size== N where N is the number of Antennas of this adapter
  const std::vector<RssiForAntenna> allAntennaValues;
  const Ieee80211HeaderRaw *ieee80211Header;
  const uint8_t *payload;
  const std::size_t payloadSize;
  // Atheros forwards frames even though the fcs check failed ( this packet is corrupted)
  const bool frameFailedFCSCheck;
  // driver might not support that
  std::optional<uint16_t> mcs_index=std::nullopt;
  // driver might not support that
  std::optional<uint16_t> channel_width=std::nullopt;
  std::optional<int> signal_quality=std::nullopt;
};
static std::string all_rssi_to_string(const std::vector<RssiForAntenna>& all_rssi){
  std::stringstream ss;
  ss<<"RSSI for antenna:";
  int idx=0;
  for(const auto& rssiForAntenna:all_rssi){
    ss<<" {"<<(int)rssiForAntenna.antennaIdx<<":"<<(int)rssiForAntenna.rssi<<"}";
    idx++;
  }
  return ss.str();
}
// It looks as if RTL88xxau reports 3 rssi values - for example,
//RssiForAntenna0{10}
//RssiForAntenna1{10}
//RssiForAntenna2{-18}
//Now this doesn't make sense, so this helper should fix it
static std::optional<int8_t> get_best_rssi_of_card(const std::vector<RssiForAntenna>& all_rssi,const bool fixup_rssi_rtl8812au){
  if(all_rssi.empty())return std::nullopt;
  // best rssi == highest value
  int8_t highest_value=INT8_MIN;
  for(int i=0;i<all_rssi.size();i++){
    const auto& rssi_for_antenna=all_rssi[i];
    if(fixup_rssi_rtl8812au || true){
      if(i==0) continue ;
      if(rssi_for_antenna.rssi>highest_value){
        highest_value=rssi_for_antenna.rssi;
      }
    }
  }
  for(const auto& rssiForAntenna:all_rssi){
    if(fixup_rssi_rtl8812au){
      if(rssiForAntenna.antennaIdx==-1){
        continue ;
      }
    }
    if(rssiForAntenna.rssi>highest_value){
      highest_value=rssiForAntenna.rssi;
    }
  }
  return highest_value;
}

// Returns std::nullopt if radiotap was unable to parse the header
// else return the *parsed information*
// To avoid confusion it might help to treat this method as a big black Box :)
static std::optional<ParsedRxRadiotapPacket> process_received_radiotap_packet(const uint8_t *pkt,const int pkt_len) {
  //int pktlen = hdr.caplen;
  int pktlen=pkt_len;
  //
  //RadiotapHelper::debugRadiotapHeader(pkt,pktlen);
  // Copy the value of this flag once present and process it after the loop is done
  uint8_t tmpCopyOfIEEE80211_RADIOTAP_FLAGS = 0;
  //RadiotapHelper::debugRadiotapHeader(pkt, pktlen);
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
  bool is_first_reported_antenna_value= true;
  //
  std::optional<uint16_t> mcs_index=std::nullopt;
  std::optional<uint16_t> channel_width=std::nullopt;
  std::optional<int> signal_quality=std::nullopt;

  int8_t currentAntenna = -1;
  // not confirmed yet, but one radiotap packet might include stats for multiple antennas
  std::vector<RssiForAntenna> allAntennaValues;
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
        mcs_index=static_cast<uint16_t>(mcs);
        }
        if (known & IEEE80211_RADIOTAP_MCS_HAVE_BW) {
        const uint8_t bandwidth = flags & IEEE80211_RADIOTAP_MCS_BW_MASK;
        switch (bandwidth) {
          case IEEE80211_RADIOTAP_MCS_BW_20:
          case IEEE80211_RADIOTAP_MCS_BW_20U:
          case IEEE80211_RADIOTAP_MCS_BW_20L:
            channel_width=static_cast<uint16_t>(20);
            break;
          case IEEE80211_RADIOTAP_MCS_BW_40:
            channel_width=static_cast<uint16_t>(40);
            break;
          default:
            break ;
        }
        }
      }
      break;
      case IEEE80211_RADIOTAP_LOCK_QUALITY:{
        int8_t value;
        std::memcpy(&value,iterator.this_arg,1);
        signal_quality=static_cast<int>(value);
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
    frameFailedFcsCheck = true;
  }
  // the fcs is at the end of the packet
  if (tmpCopyOfIEEE80211_RADIOTAP_FLAGS & IEEE80211_RADIOTAP_F_FCS) {
    //<<"Packet has IEEE80211_RADIOTAP_F_FCS";
    pktlen -= 4;
  }
#ifdef ENABLE_ADVANCED_DEBUGGING
  wifibroadcast::log::get_default()->debug(RadiotapFlagsToString::flagsIEEE80211_RADIOTAP_MCS(mIEEE80211_RADIOTAP_MCS));
  wifibroadcast::log::get_default()->debug(RadiotapFlagsToString::flagsIEEE80211_RADIOTAP_FLAGS(mIEEE80211_RADIOTAP_FLAGS));
  // With AR9271 I get 39 as length of the radio-tap header
  // With my internal laptop wifi chip I get 36 as length of the radio-tap header
  wifibroadcast::log::get_default()->debug("iterator._max_length was {}",iterator._max_length);
#endif
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
  return ParsedRxRadiotapPacket{allAntennaValues, ieee80211Header, payload, payloadSize, frameFailedFcsCheck,mcs_index,channel_width,signal_quality};
}

// [RadiotapHeader | Ieee80211HeaderRaw | customHeader (if not size 0) | payload (if not size 0)]
static std::vector<uint8_t> create_radiotap_wifi_packet(const RadiotapHeader& radiotapHeader,
                                                        const Ieee80211HeaderRaw &ieee80211Header,
                                                        const uint8_t* data,int data_len){
  std::vector<uint8_t> packet(radiotapHeader.getSize() + sizeof(ieee80211Header.data) + data_len);
  uint8_t *p = packet.data();
  // radiotap header
  memcpy(p, radiotapHeader.getData(), radiotapHeader.getSize());
  p += radiotapHeader.getSize();
  // ieee80211 wbDataHeader
  memcpy(p, &ieee80211Header.data, sizeof(ieee80211Header.data));
  p += sizeof(ieee80211Header.data);
  memcpy(p, data, data_len);
  p += data_len;
  return packet;
}

}

// what people used for whatever reason once on OpenHD / EZ-Wifibroadcast
namespace OldRadiotapHeaders {
// https://github.com/OpenHD/Open.HD/blob/2.0/wifibroadcast-base/tx_telemetry.c#L123
static uint8_t u8aRadiotapHeader[] = {
    0x00, 0x00,             // <-- radiotap version
    0x0c, 0x00,             // <- radiotap header length
    0x04, 0x80, 0x00, 0x00, // <-- radiotap present flags
    0x00,                   // datarate (will be overwritten later)
    0x00,
    0x00, 0x00
};
static uint8_t u8aRadiotapHeader80211n[] = {
    0x00, 0x00,             // <-- radiotap version
    0x0d, 0x00,             // <- radiotap header length
    0x00, 0x80, 0x08, 0x00, // <-- radiotap present flags (tx flags, mcs)
    0x08, 0x00,             // tx-flag
    0x37,                   // mcs have: bw, gi, stbc ,fec
    0x30,                   // mcs: 20MHz bw, long guard interval, stbc, ldpc
    0x00,                   // mcs index 0 (speed level, will be overwritten later)
};

// this is what's used in
//https://github.com/OpenHD/Open.HD/blob/master/wifibroadcast-rc-Ath9k/rctx.cpp
static std::array<uint8_t, RadiotapHeader::SIZE_BYTES> radiotap_rc_ath9k = {
    0, // <-- radiotap version      (0x00)
    0, // <-- radiotap version      (0x00)

    13, // <- radiotap header length (0x0d)
    0, // <- radiotap header length (0x00)

    0, // <-- radiotap present flags(0x00)
    128, // <-- RADIOTAP_TX_FLAGS +   (0x80)
    8, // <-- RADIOTAP_MCS          (0x08)
    0, //                           (0x00)

    8, // <-- RADIOTAP_F_TX_NOACK   (0x08)
    0, //                           (0x00)
    55, // <-- bitmap                (0x37)
    48, // <-- flags                 (0x30)
    0, // <-- mcs_index             (0x00)
};
}

#endif //__WIFIBROADCAST_RADIOTAP_HEADER_HPP__