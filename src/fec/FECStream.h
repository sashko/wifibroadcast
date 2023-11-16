//
// Created by consti10 on 28.06.23.
//

#ifndef WIFIBROADCAST_FECSTREAM_H
#define WIFIBROADCAST_FECSTREAM_H

#include <array>
#include <cassert>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <functional>


#include "../HelperSources/TimeHelper.hpp"
#include "FECPayloadHdr.hpp"
#include "RxBlock.hpp"
#include "FECConstants.hpp"

/**
 * For dynamic block sizes, we switched to a FEC overhead "percentage" value.
 * e.g. the final data throughput ~= original data throughput * fec overhead percentage
 * Rounds up / down (.5), but always at least 1
 */
uint32_t calculate_n_secondary_fragments(uint32_t n_primary_fragments,uint32_t fec_overhead_perc);

/**
 * calculate n from k and percentage as used in FEC terms
 * (k: number of primary fragments, n: primary + secondary fragments)
 */
unsigned int calculateN(unsigned int k, unsigned int percentage);

void fec_stream_print_fec_optimization_method();

class FECEncoder {
 public:
  typedef std::function<void(const uint8_t* packet,int packet_len)>
      OUTPUT_DATA_CALLBACK;
  OUTPUT_DATA_CALLBACK outputDataCallback;
  explicit FECEncoder()=default;
  FECEncoder(const FECEncoder &other) = delete;
 public:
  /**
   * Encodes a new block and forwards the packets for this block
   * forwards data packets first, then generated fec packets
   * (if needed) and forwards them after.
   * @param data_packets the packets for this block
   * @param n_secondary_fragments how many secondary fragments (FEC packets) should be created
   */
  void encode_block(std::vector<std::shared_ptr<std::vector<uint8_t>>> data_packets,int n_secondary_fragments);
  // Pre-allocated to have space for storing primary fragments (they are needed once the fec step needs to be performed)
  // and creating the wanted amount of secondary packets
  std::array<std::array<uint8_t, MAX_PAYLOAD_BEFORE_FEC>,MAX_TOTAL_FRAGMENTS_PER_BLOCK> m_block_buffer{};
  uint32_t m_curr_block_idx=0;
  static_assert(sizeof(m_curr_block_idx)==sizeof(FECPayloadHdr::block_idx));
  AvgCalculator m_fec_block_encode_time;
  MinMaxAvg<std::chrono::nanoseconds> m_curr_fec_block_encode_time{};
  BaseAvgCalculator<uint16_t> m_block_sizes{};
  MinMaxAvg<uint16_t> m_curr_fec_block_sizes{};
};

// quick math regarding sequence numbers:
//uint32_t holds max 4294967295 . At 10 000 pps (packets per seconds) (which is already completely out of reach) this allows the tx to run for 429496.7295 seconds
// 429496.7295 / 60 / 60 = 119.304647083 hours which is also completely overkill for OpenHD (and after this time span, a "reset" of the sequence number happens anyways)
// unsigned 24 bits holds 16777215 . At 1000 blocks per second this allows the tx to create blocks for 16777.215 seconds or 4.6 hours. That should cover a flight (and after 4.6h a reset happens,
// which means you might lose a couple of blocks once every 4.6 h )
// and 8 bits holds max 255.

#endif  // WIFIBROADCAST_FECSTREAM_H
