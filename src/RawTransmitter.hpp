//
// Created by consti10 on 12.12.20.
//

#ifndef WIFIBROADCAST_RAWTRANSMITTER_HPP
#define WIFIBROADCAST_RAWTRANSMITTER_HPP

#include "Ieee80211Header.hpp"
#include "RadiotapHeader.hpp"

#include <cstdlib>
#include <endian.h>
#include <fcntl.h>
#include <ctime>
#include <sys/mman.h>
#include <string>
#include <vector>
#include <chrono>
#include <optional>
#include <poll.h>
#include <pcap.h>

// This is a single header-only file you can use to build your own wifibroadcast link
// It doesn't specify if / what FEC to use and so on

// Doesn't specify what / how big the custom header is.
// This way it is easy to make the injection part generic for future changes
// by using a pointer / size tuple the data for the customHeader and payload can reside at different memory locations
// When injecting the packet we have to always copy the data anyways since Radiotap and IEE80211 header
// are stored at different locations, too
class AbstractWBPacket {
 public:
  // constructor for packet without header (or the header is already merged into payload)
  AbstractWBPacket(const uint8_t *payload, const std::size_t payloadSize) :
      customHeader(nullptr), customHeaderSize(0), payload(payload), payloadSize(payloadSize) {};
  // constructor for packet with header and payload at different memory locations
  AbstractWBPacket(const uint8_t *customHeader,
                   const std::size_t customHeaderSize,
                   const uint8_t *payload,
                   const std::size_t payloadSize) :
      customHeader(customHeader), customHeaderSize(customHeaderSize), payload(payload), payloadSize(payloadSize) {};
  AbstractWBPacket(AbstractWBPacket &) = delete;
  AbstractWBPacket(AbstractWBPacket &&) = delete;
 public:
  // can be nullptr if size 0
  const uint8_t *customHeader;
  // can be 0 for special use cases
  const std::size_t customHeaderSize;
  // can be nullptr if size 0
  const uint8_t *payload;
  // can be 0 for special use cases
  const std::size_t payloadSize;
};

namespace RawTransmitterHelper {
// construct a radiotap packet with the following data layout:
// [RadiotapHeader | Ieee80211Header | customHeader (if not size 0) | payload (if not size 0)]
static std::vector<uint8_t>
createRadiotapPacket(const RadiotapHeader &radiotapHeader,
                     const Ieee80211Header &ieee80211Header,
                     const AbstractWBPacket &abstractWbPacket) {
  const auto customHeaderAndPayloadSize = abstractWbPacket.customHeaderSize + abstractWbPacket.payloadSize;
  std::vector<uint8_t> packet(radiotapHeader.getSize() + ieee80211Header.getSize() + customHeaderAndPayloadSize);
  uint8_t *p = packet.data();
  // radiotap wbDataHeader
  memcpy(p, radiotapHeader.getData(), radiotapHeader.getSize());
  p += radiotapHeader.getSize();
  // ieee80211 wbDataHeader
  memcpy(p, ieee80211Header.getData(), ieee80211Header.getSize());
  p += ieee80211Header.getSize();
  if (abstractWbPacket.customHeaderSize > 0) {
    // customHeader
    memcpy(p, abstractWbPacket.customHeader, abstractWbPacket.customHeaderSize);
    p += abstractWbPacket.customHeaderSize;
  }
  if (abstractWbPacket.payloadSize > 0) {
    // payload
    memcpy(p, abstractWbPacket.payload, abstractWbPacket.payloadSize);
  }
  return packet;
}
// log error if injecting pcap packet goes wrong (should never happen)
static void injectPacket(pcap_t *pcap, const std::vector<uint8_t> &packetData) {
  const auto len_injected=pcap_inject(pcap, packetData.data(), packetData.size());
  if (len_injected != (int) packetData.size()) {
    std::stringstream ss;
    ss<<"pcap -unable to inject packet "<<packetData.size()<<" ret:"<<len_injected<<" "<<pcap_geterr(pcap)<<"\n";
    std::cout<<ss.str();
  }
}
// copy paste from svpcom
static pcap_t *openTxWithPcap(const std::string &wlan) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *p = pcap_create(wlan.c_str(), errbuf);
  if (p == nullptr) {
    std::cerr<<StringFormat::convert("Unable to open interface %s in pcap: %s", wlan.c_str(), errbuf);
  }
  if (pcap_set_snaplen(p, 4096) != 0) std::cerr<<"set_snaplen failed";
  if (pcap_set_promisc(p, 1) != 0) std::cerr<<"set_promisc failed";
  //if (pcap_set_rfmon(p, 1) !=0) std::cerr<<"set_rfmon failed";
  if (pcap_set_timeout(p, -1) != 0) std::cerr<<"set_timeout failed";
  //if (pcap_set_buffer_size(p, 2048) !=0) std::cerr<<"set_buffer_size failed";
  // NOTE: Immediate not needed on TX
  if (pcap_activate(p) != 0){
    std::cerr<<StringFormat::convert("pcap_activate failed: %s",
                                       pcap_geterr(p));
  }
  //if (pcap_setnonblock(p, 1, errbuf) != 0) std::cerr<<string_format("set_nonblock failed: %s", errbuf));
  return p;
}
}

class IRawPacketInjector {
 public:
  /**
   * Inject the packet data after prefixing it with Radiotap and IEEE80211 header
   * @return time it took to inject the packet
   */
  virtual std::chrono::steady_clock::duration injectPacket(const RadiotapHeader &radiotapHeader,
                                                           const Ieee80211Header &ieee80211Header,
                                                           const AbstractWBPacket &abstractWbPacket) const = 0;
};

// Pcap Transmitter injects packets into the wifi adapter using pcap
// It does not specify what the payload is and therefore is just a really small wrapper around the pcap interface
// that properly opens / closes the interface on construction/destruction
class PcapTransmitter : public IRawPacketInjector {
 public:
  explicit PcapTransmitter(const std::string &wlan) {
    ppcap = RawTransmitterHelper::openTxWithPcap(wlan);
  }
  ~PcapTransmitter() {
    pcap_close(ppcap);
  }
  // inject packet by prefixing wifibroadcast packet with the IEE and Radiotap header
  // return: time it took to inject the packet.If the injection time is absurdly high, you might want to do something about it
  [[nodiscard]] std::chrono::steady_clock::duration injectPacket(const RadiotapHeader &radiotapHeader,
                                                   const Ieee80211Header &ieee80211Header,
                                                   const AbstractWBPacket &abstractWbPacket) const override {
    const auto packet = RawTransmitterHelper::createRadiotapPacket(radiotapHeader, ieee80211Header, abstractWbPacket);
    const auto before = std::chrono::steady_clock::now();
    RawTransmitterHelper::injectPacket(ppcap, packet);
    return std::chrono::steady_clock::now() - before;
  }
  void injectControllFrame(const RadiotapHeader &radiotapHeader, const std::vector<uint8_t> &iee80211ControllHeader) {
    std::vector<uint8_t> packet(radiotapHeader.getSize() + iee80211ControllHeader.size());
    memcpy(packet.data(), &radiotapHeader, RadiotapHeader::SIZE_BYTES);
    memcpy(&packet[RadiotapHeader::SIZE_BYTES], iee80211ControllHeader.data(), iee80211ControllHeader.size());
    RawTransmitterHelper::injectPacket(ppcap, packet);
  }
 private:
  pcap_t *ppcap;
};

// Doesn't use pcap but somehow directly talks to the OS via socket
// note that you still have to prefix data with the proper RadiotapHeader in this mode (just as if you were using pcap)
// NOTE: I didn't measure any advantage for RawSocketTransmitter compared to PcapTransmitter, so I'd recommend using PcapTransmitter only
class RawSocketTransmitter : public IRawPacketInjector {
 public:
  explicit RawSocketTransmitter(const std::string &wlan) {
    sockFd = openWifiInterfaceAsTxRawSocket(wlan);
  }
  ~RawSocketTransmitter() {
    close(sockFd);
  }
  // inject packet by prefixing wifibroadcast packet with the IEE and Radiotap header
  // return: time it took to inject the packet.If the injection time is absurdly high, you might want to do something about it
  [[nodiscard]] std::chrono::steady_clock::duration injectPacket(const RadiotapHeader &radiotapHeader,
                                                   const Ieee80211Header &ieee80211Header,
                                                   const AbstractWBPacket &abstractWbPacket) const override {
    const auto packet = RawTransmitterHelper::createRadiotapPacket(radiotapHeader, ieee80211Header, abstractWbPacket);
    const auto before = std::chrono::steady_clock::now();
    const auto len_written=write(sockFd, packet.data(), packet.size());
    if (len_written != packet.size()) {
      std::stringstream ss;
      ss<<"Unable to inject packet (raw sock) size:"<<packet.size()<<" res:"<<len_written<<" "<<strerror(errno)<<"\n";
      std::cerr<<ss.str();
    }
    return std::chrono::steady_clock::now() - before;
  }
  // taken from https://github.com/OpenHD/Open.HD/blob/2.0/wifibroadcast-base/tx_rawsock.c#L86
  // open wifi interface using a socket (somehow this works ?!)
  static int openWifiInterfaceAsTxRawSocket(const std::string &wifi) {
    struct sockaddr_ll ll_addr{};
    struct ifreq ifr{};
    int sock = socket(AF_PACKET, SOCK_RAW, 0);
    if (sock == -1) {
      std::stringstream ss;
      ss<<"RawSocketTransmitter:: open socket failed "<<wifi.c_str()<<" "<<strerror(errno)<<"\n";
      std::cerr<<ss.str();
    }

    ll_addr.sll_family = AF_PACKET;
    ll_addr.sll_protocol = 0;
    ll_addr.sll_halen = ETH_ALEN;

    strncpy(ifr.ifr_name, wifi.c_str(), IFNAMSIZ);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
      std::stringstream ss;
      ss<<"ioctl(SIOCGIFINDEX) failed\n";
      std::cerr<<ss.str();
    }

    ll_addr.sll_ifindex = ifr.ifr_ifindex;

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
      std::stringstream ss;
      ss<<"ioctl(SIOCGIFHWADDR) failed\n";
      std::cerr<<ss.str();
    }

    memcpy(ll_addr.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    if (bind(sock, (struct sockaddr *) &ll_addr, sizeof(ll_addr)) == -1) {
      close(sock);
      std::cerr<<"bind failed\n";
    }
    struct timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 8000;
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout)) < 0) {
      std::cerr<<"setsockopt SO_SNDTIMEO\n";
    }
    int sendbuff = 131072;
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff)) < 0) {
      std::cerr<<"setsockopt SO_SNDBUF\n";
    }
    return sock;
  }
 private:
  int sockFd;
};

#endif //WIFIBROADCAST_RAWTRANSMITTER_HPP
