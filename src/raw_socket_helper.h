//
// Created by consti10 on 16.08.23.
//

#ifndef WIFIBROADCAST_RAW_SOCKET_HELPER_H
#define WIFIBROADCAST_RAW_SOCKET_HELPER_H

#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include "HelperSources/SocketHelper.hpp"

#include "wifibroadcast_spdlog.h"

// taken from
// https://github.com/OpenHD/Open.HD/blob/2.0/wifibroadcast-base/tx_rawsock.c#L86
// open wifi interface using a socket (somehow this works ?!)
static int openWifiInterfaceAsTxRawSocket(const std::string &wifi) {
  auto console=wifibroadcast::log::create_or_get("raw_sock");
  struct sockaddr_ll ll_addr{};
  struct ifreq ifr{};
  int sock = socket(AF_PACKET, SOCK_RAW, 0);
  if (sock == -1) {
    std::stringstream ss;
    ss<<"RawSocketTransmitter:: open socket failed "<<wifi.c_str()<<" "<<strerror(errno);
    console->error(ss.str());
  }

  ll_addr.sll_family = AF_PACKET;
  ll_addr.sll_protocol = 0;
  ll_addr.sll_halen = ETH_ALEN;

  strncpy(ifr.ifr_name, wifi.c_str(), IFNAMSIZ);

  if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
    console->error("ioctl(SIOCGIFINDEX) failed");
  }

  ll_addr.sll_ifindex = ifr.ifr_ifindex;

  if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
    console->error("ioctl(SIOCGIFHWADDR) failed");
  }

  memcpy(ll_addr.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

  if (bind(sock, (struct sockaddr *) &ll_addr, sizeof(ll_addr)) == -1) {
    close(sock);
    console->error("bind failed");
  }
  struct timeval timeout{};
  timeout.tv_sec = 0;
  timeout.tv_usec = 1*1000; // timeout of 1 ms
  if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
    console->warn("setsockopt SO_SNDTIMEO");
  }
  // for some reason setting the timeout does not seem to work here, I always get 10ms back
  //console->debug("RawSocketTransmitter::timeout: {}ms", static_cast<double>(get_socket_timeout_us(sock))/1000.0);
  //console->debug("RawSocketTransmitter::curr_send_buffer_size:{}",get_socket_send_buffer_size(sock));
  const int wanted_sendbuff = 128*1024; //131072
  if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &wanted_sendbuff, sizeof(wanted_sendbuff)) < 0) {
    console->warn("setsockopt SO_SNDBUF");
  }
  //console->debug("RawSocketTransmitter::applied_send_buffer_size:{}",get_socket_send_buffer_size(sock));
  console->error("{} socket opened",wifi);
  return sock;
}

#endif  // WIFIBROADCAST_RAW_SOCKET_HELPER_H
