#ifndef __WIFIBROADCAST_IEEE80211_HEADER_HPP__
#define __WIFIBROADCAST_IEEE80211_HEADER_HPP__

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <resolv.h>
#include <cstring>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>
#include <endian.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <endian.h>
#include <string>
#include <vector>
#include <array>
#include <iostream>

// Wrapper around the Ieee80211 header (declared as raw array initially)
// info https://witestlab.poly.edu/blog/802-11-wireless-lan-2/
// In the way this is declared it is an IEE80211 data frame
// https://en.wikipedia.org/wiki/802.11_Frame_Types
//TODO maybe use https://elixir.bootlin.com/linux/latest/source/include/linux/ieee80211.h
class Ieee80211Header {
 public:
  static constexpr auto SIZE_BYTES = 24;
  //the last byte of the mac address is recycled as a port number
  static constexpr const auto SRC_MAC_LASTBYTE = 15;
  static constexpr const auto DST_MAC_LASTBYTE = 21;
  static constexpr const auto FRAME_SEQ_LB = 22;
  static constexpr const auto FRAME_SEQ_HB = 23;
  // raw data buffer
  std::array<uint8_t, SIZE_BYTES> data = {
      0x08, 0x01, // first 2 bytes control fiels
      0x00, 0x00, // 2 bytes duration (has this even an effect ?!)
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // something MAC ( 6 bytes), I think Receiver address (MAC of AP)
      0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // something MAC ( 6 bytes), I think SRC MAC  (mac of source STA)- last byte is used as radio port
      0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // something MAC ( 6 bytes), I think DEST MAC (mac of dest STA)  - last byte is als used as radio port
      0x00, 0x00,  // iee80211 sequence control ( 2 bytes )
  };
  struct OpenHDHeader{
    // We do not touch the control field (driver)
    uint8_t control_field1;
    uint8_t control_field2;
    // We do not touch the duration field (driver)
    uint8_t duration1;
    uint8_t duration2;
    // We do not touch this MAC (driver)
    std::array<uint8_t, 6> mac_ap;
    // We can and do use this mac - first 4 bytes for part 1 of nonce, 1 byte for unique identifier, last byte for radio port
    uint32_t mac_src_nonce_part1;
    uint8_t mac_src_unique_id_part;
    uint8_t mac_src_radio_port;
    // We can and do use this mac - first 4 bytes for part 2 of nonce, 1 byte for unique identifier, last byte for radio port
    uint32_t mac_dst_nonce_part2;
    uint8_t mac_dst_unique_id_part;
    uint8_t mac_dst_radio_port;
    // iee80211 sequence control ( 2 bytes ) - might be overridden by the driver, and or even repurposed
    uint16_t sequence_control=0;
    // See the data layout above for more info
    void write_nonce(const uint64_t& nonce){
      memcpy((uint8_t*)&mac_src_nonce_part1,(uint8_t*)nonce,4);
      memcpy((uint8_t*)&mac_dst_nonce_part2,((uint8_t*)nonce)+4,4);
      // From https://stackoverflow.com/questions/2810280/how-to-store-a-64-bit-integer-in-two-32-bit-integers-and-convert-back-again
      //mac_src_nonce_part1 = static_cast<int32_t>(nonce >> 32);
      //mac_dst_nonce_part2 = static_cast<int32_t>(nonce);
    }
    uint64_t get_nonce()const{
      uint64_t nonce;
      memcpy((uint8_t*)nonce,(uint8_t*)&mac_src_nonce_part1,4);
      memcpy(((uint8_t*)nonce)+4,(uint8_t*)&mac_dst_nonce_part2,4);
      return nonce;
    }
    // NOTE: We write the radio port 2 times - this way we have a pretty reliable way to check if this is an openhd packet or packet from someone else
    void write_radio_port_src_dst(uint8_t radio_port){
      mac_src_radio_port=radio_port;
      mac_dst_radio_port=radio_port;
    }
  }__attribute__ ((packed));
  static_assert(sizeof(OpenHDHeader)==SIZE_BYTES);


  // default constructor
  Ieee80211Header() = default;
  // write the port re-using the MAC address (which is unused for broadcast)
  // write sequence number (not used on rx right now)
  void writeParams(const uint8_t radioPort, const uint16_t seqenceNumber) {
    write_radio_port(radioPort);
    write_ieee80211_seq_nr(seqenceNumber);
  }
  void write_ieee80211_seq_nr(const uint16_t seq_nr){
    data[FRAME_SEQ_LB] = seq_nr & 0xff;
    data[FRAME_SEQ_HB] = (seq_nr >> 8) & 0xff;
  }
  void write_radio_port(const uint8_t radioPort){
    data[SRC_MAC_LASTBYTE] = radioPort;
    data[DST_MAC_LASTBYTE] = radioPort;
  }
  // Except the last byte (radio port) the mac has to match the openhd default
  bool has_valid_openhd_src_mac()const{
      return data[10]==0x13 && data[11]==0x22 && data[12]==0x33 && data[13]==0x44 && data[14]==0x55; //data[15]==radio port
  }
  bool has_valid_openhd_dst_mac()const{
      return data[16]==0x13 && data[17]==0x22 && data[18]==0x33 && data[19]==0x44 && data[20]==0x55; //data[21]==radio port
  }
  uint8_t get_src_mac_radio_port() const {
    return data[SRC_MAC_LASTBYTE];
  }
  uint8_t get_dst_mac_radio_port()const{
    return data[DST_MAC_LASTBYTE];
  }
  uint16_t getSequenceNumber() const {
    uint16_t ret;
    memcpy(&ret, &data[FRAME_SEQ_LB], sizeof(uint16_t));
    return ret;
  }
  const uint8_t *getData() const {
    return data.data();
  }
  constexpr std::size_t getSize() const {
    return data.size();
  }
  uint16_t getFrameControl() const {
    uint16_t ret;
    memcpy(&ret, &data[0], 2);
    return ret;
  }
  uint16_t getDurationOrConnectionId() const {
    uint16_t ret;
    memcpy(&ret, &data[2], 2);
    return ret;
  }
  bool isDataFrame() const {
    return data[0] == 0x08 && data[1] == 0x01;
  }
  //https://witestlab.poly.edu/blog/802-11-wireless-lan-2/
  //Sequence Control: Contains a 4-bit fragment number subfield, used for frag- mentation and reassembly, and a 12-bit sequence number used to number
  //frames sent between a given transmitter and receiver.
  struct SequenceControl {
    uint8_t subfield: 4;
    uint16_t sequence_nr: 12;
  }__attribute__ ((packed));
  static_assert(sizeof(SequenceControl) == 2);
  void setSequenceControl(const SequenceControl &sequenceControl) {
    memcpy(&data[FRAME_SEQ_LB], (void *) &sequenceControl, sizeof(SequenceControl));
  };
  [[nodiscard]] SequenceControl getSequenceControl() const {
    SequenceControl ret{};
    memcpy(&ret, &data[FRAME_SEQ_LB], sizeof(SequenceControl));
    return ret;
  }
  void printSequenceControl() const {
    const auto tmp = getSequenceControl();
    std::cout << "SequenceControl subfield:" << (int) tmp.subfield << " sequenceNr:" << (int) tmp.sequence_nr << "\n";
  }

}__attribute__ ((packed));
static_assert(sizeof(Ieee80211Header) == Ieee80211Header::SIZE_BYTES, "ALWAYS TRUE");

static void testLol() {
  Ieee80211Header ieee80211Header;
  uint16_t seqenceNumber = 0;
  for (int i = 0; i < 5; i++) {
    ieee80211Header.data[Ieee80211Header::FRAME_SEQ_LB] = seqenceNumber & 0xff;
    ieee80211Header.data[Ieee80211Header::FRAME_SEQ_HB] = (seqenceNumber >> 8) & 0xff;
    // now print it
    ieee80211Header.printSequenceControl();
    seqenceNumber += 16;
  }
}

// Unfortunately / luckily the sequence number is overwritten by the TX. This means we can't get
// lost packets per stream, but rather lost packets per all streams only
class Ieee80211HeaderSeqNrCounter {
 public:
  void onNewPacket(const Ieee80211Header &ieee80211Header) {
    const auto seqCtrl = ieee80211Header.getSequenceControl();
    if (lastSeqNr == -1) {
      lastSeqNr = seqCtrl.sequence_nr;
      countPacketsOutOfOrder = 0;
      return;
    }
    const int32_t delta = seqCtrl.sequence_nr - lastSeqNr;
    std::cout << "Delta: " << delta << "\n";
    lastSeqNr = seqCtrl.sequence_nr;
  }
 private:
  int64_t lastSeqNr = -1;
  int countPacketsOutOfOrder = 0;
};

namespace Ieee80211ControllFrames {
static uint8_t u8aIeeeHeader_rts[] = {
    0xb4, 0x01, 0x00, 0x00, // frame control field (2 bytes), duration (2 bytes)
    0xff                    // 1st byte of MAC will be overwritten with encoded port
};
}

// hmmmm ....
// https://github.com/OpenHD/Open.HD/blob/2.0/wifibroadcast-base/tx_rawsock.c#L175
// https://github.com/OpenHD/Open.HD/blob/2.0/wifibroadcast-base/tx_telemetry.c#L144
namespace OldWifibroadcastIeee8021Header {
static uint8_t u8aIeeeHeader_data[] = {
    0x08, 0x02, 0x00, 0x00,             // frame control field (2 bytes), duration (2 bytes)
    0xff, 0x00, 0x00, 0x00, 0x00, 0x00, // 1st byte of MAC will be overwritten with encoded port
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac
    0x00, 0x00                          // IEEE802.11 seqnum, (will be overwritten later by Atheros firmware/wifi chip)
};
// I think this is actually this type of frame
// https://en.wikipedia.org/wiki/Block_acknowledgement
// has only 64*16=1024 bits payload
static uint8_t u8aIeeeHeader_data_short[] = {
    0x08, 0x01, 0x00, 0x00, // frame control field (2 bytes), duration (2 bytes)
    0xff                    // 1st byte of MAC will be overwritten with encoded port
};
// I think this is this type of frame 01 Control 1011 RTS
// https://en.wikipedia.org/wiki/IEEE_802.11_RTS/CTS
// however, rts frames usually don't have a payload
static uint8_t u8aIeeeHeader_rts[] = {
    0xb4, 0x01, 0x00, 0x00, // frame control field (2 bytes), duration (2 bytes)
    0xff                    // 1st byte of MAC will be overwritten with encoded port
};
}
#endif