// Copyright (C) 2017, 2018, 2019 Vasily Evseenko <svpcom@p2ptech.org>
// 2020 Constantin Geier
/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#ifndef __WIFIBROADCAST_HPP__
#define __WIFIBROADCAST_HPP__

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <resolv.h>
#include <cstring>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <endian.h>
#include <fcntl.h>
#include <ctime>
#include <sys/mman.h>
#include <sodium.h>
#include <endian.h>
#include <string>
#include <vector>
#include <chrono>
#include <optional>

#include "Ieee80211Header.hpp"
#include "RadiotapHeader.hpp"

/**
 * Wifibroadcast protocol:
 * radiotap_header
 * * ieee_80211_header
 * ** if WFB_PACKET_KEY
 * *** WBSessionKeyPacket
 * ** if WFB_PACKET_DATA
 * *** WBDataHeader
 * **** encrypted payload data (dynamic size)
 */

static constexpr const uint8_t WFB_PACKET_DATA=0x1;
static constexpr const uint8_t WFB_PACKET_KEY=0x2;
// for testing, do not use in production (just don't send it on the tx)
static constexpr const uint8_t WFB_PACKET_LATENCY_BEACON=0x3;

// the encryption key is sent every n seconds ( but not re-created every n seconds, it is only re-created when reaching the max sequence number)
// also it is only sent if a new packet needs to be transmitted to save bandwidth
// it needs to be sent multiple times instead of once since it might get lost on the first or nth time respective
static constexpr const auto SESSION_KEY_ANNOUNCE_DELTA=std::chrono::seconds(1);


// Session key packet
// Since the size of each session key packet never changes, this memory layout is the easiest
class WBSessionKeyPacket{
public:
    // note how this member doesn't add up to the size of this class (c++ is so great !)
    static constexpr auto SIZE_BYTES=1+crypto_box_NONCEBYTES+crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES+2;
public:
    const uint8_t packet_type=WFB_PACKET_KEY;
    std::array<uint8_t,crypto_box_NONCEBYTES> sessionKeyNonce;  // random data
    std::array<uint8_t,crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES> sessionKeyData; // encrypted session key
    uint8_t FEC_N_PRIMARY_FRAGMENTS; // info about this session's K,N parameters
    uint8_t FEC_N_SECONDARY_FRAGMENTS; // info about this session's K,N parameters
}__attribute__ ((packed));
static_assert(sizeof(WBSessionKeyPacket) == WBSessionKeyPacket::SIZE_BYTES, "ALWAYS_TRUE");


// This header comes with each FEC packet (primary or secondary)
// This part is not encrypted !
class WBDataHeader{
public:
    explicit WBDataHeader(uint64_t nonce1):nonce(nonce1){};
public:
    const uint8_t packet_type=WFB_PACKET_DATA;
    const uint64_t nonce;  // big endian, nonce = block_idx << 8 + fragment_idx
    //const uint8_t reserved=0;
}  __attribute__ ((packed));
static_assert(sizeof(WBDataHeader)==8+1,"ALWAYS_TRUE");


// this header is written before the data of each primary FEC fragment
// ONLY for primary FEC fragments though ! (up to n bytes workaround)
class FECDataHeader {
private:
    // private member to make sure it has always the right endian
    uint16_t packet_size;
    //uint16_t packet_size : 15; // big endian | 15 bits packet size
    //bool isSecondaryFragment: 1 ;          //|  1 bit flag, set if this is a secondary (FEC) packet
public:
    explicit FECDataHeader(std::size_t packetSize1){
        // convert to big endian if needed
        packet_size=htobe16(packetSize1);
        //packet_size=packetSize1;
    }
    // convert from big endian if needed
    std::size_t get()const{
        return be16toh(packet_size);
        //return (std::size_t) packet_size;
    }
}  __attribute__ ((packed));
static_assert(sizeof(FECDataHeader) == 2, "ALWAYS_TRUE");



struct LatencyTestingPacket{
    const uint8_t packet_type=WFB_PACKET_LATENCY_BEACON;
    const int64_t timestampNs=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}__attribute__ ((packed));

// The final packet size ( radiotap header + iee80211 header + payload ) is never bigger than that
// the reasoning behind this value: https://github.com/svpcom/wifibroadcast/issues/69
static constexpr const auto MAX_PCAP_PACKET_SIZE=1510;
// Max n of wifi cards connected as an RX array
static constexpr const auto MAX_RX_INTERFACES=8;

// 1510-(13+24+9+16+2)
//A: Any UDP with packet size <= 1466. For example x264 inside RTP or Mavlink.
static constexpr const auto MAX_PAYLOAD_SIZE=(MAX_PCAP_PACKET_SIZE - RadiotapHeader::SIZE_BYTES - Ieee80211Header::SIZE_BYTES - sizeof(WBDataHeader) - sizeof(FECDataHeader) - crypto_aead_chacha20poly1305_ABYTES);
static constexpr const auto MAX_FEC_PAYLOAD=(MAX_PCAP_PACKET_SIZE - RadiotapHeader::SIZE_BYTES - Ieee80211Header::SIZE_BYTES - sizeof(WBDataHeader) - crypto_aead_chacha20poly1305_ABYTES);
static constexpr const auto MAX_FORWARDER_PACKET_SIZE=(MAX_PCAP_PACKET_SIZE - RadiotapHeader::SIZE_BYTES - Ieee80211Header::SIZE_BYTES);

// comment this for a release
//#define ENABLE_ADVANCED_DEBUGGING

#endif //__WIFIBROADCAST_HPP__
