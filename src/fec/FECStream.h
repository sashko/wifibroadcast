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

// Takes a continuous stream of packets (data and fec correction packets) and
// processes them such that the output is exactly (or as close as possible) to the
// Input stream fed to FECEncoder.
// Most importantly, it also handles re-ordering of packets and packet duplicates due to multiple rx cards
class FECDecoder {
 public:
  /**
   * @param rx_queue_max_depth max size of rx queue - since in case of openhd, one frame is either one or two FEC blocks
   *        we don't need that big of an rx queue
   * @param maxNFragmentsPerBlock memory per block is pre-allocated, reduce this value if you know the encoder doesn't ever exceed a given
   *        n of fragments per block
   * @param enable_log_debug
   */
  explicit FECDecoder(const unsigned int rx_queue_max_depth,const unsigned int maxNFragmentsPerBlock = MAX_TOTAL_FRAGMENTS_PER_BLOCK,
                      bool enable_log_debug=false) :
                                                       RX_QUEUE_MAX_SIZE(rx_queue_max_depth),
                                                       maxNFragmentsPerBlock(maxNFragmentsPerBlock),
                                                       m_enable_log_debug(enable_log_debug){
    assert(rx_queue_max_depth<20);
    assert(rx_queue_max_depth>=1);
  }
  FECDecoder(const FECDecoder &other) = delete;
  ~FECDecoder() = default;
  // data forwarded on this callback is always in-order but possibly with gaps
  typedef std::function<void(const uint8_t *payload, std::size_t payloadSize)> SEND_DECODED_PACKET;
  // WARNING: Don't forget to register this callback !
  SEND_DECODED_PACKET mSendDecodedPayloadCallback;
  // A value too high doesn't really give much benefit and increases memory usage
  const unsigned int RX_QUEUE_MAX_SIZE;
  const unsigned int maxNFragmentsPerBlock;
  const bool m_enable_log_debug;
  AvgCalculator m_fec_decode_time{};
 public:
  static bool validate_packet_size(int data_len);
  // process a valid packet
  bool process_valid_packet(const uint8_t* data,int data_len);
 private:
  // since we also need to search this data structure, a std::queue is not enough.
  // since we have an upper limit on the size of this dequeue, it is basically a searchable ring buffer
  std::deque<std::unique_ptr<RxBlock>> rx_queue;
  uint64_t last_known_block = ((uint64_t) -1);  //id of last known block
  /**
   * For this Block,
   * starting at the primary fragment we stopped on last time,
   * forward as many primary fragments as they are available until there is a gap
   * @param discardMissingPackets : if true, gaps are ignored and fragments are forwarded even though this means the missing ones are irreversible lost
   * Be carefully with this param, use it only before you need to get rid of a block
   */
  void forwardMissingPrimaryFragmentsIfAvailable(RxBlock &block, const bool discardMissingPackets = false);
  // also increase lost block count if block is not fully recovered
  void rxQueuePopFront();
  // create a new RxBlock for the specified block_idx and push it into the queue
  // NOTE: Checks first if this operation would increase the size of the queue over its max capacity
  // In this case, the only solution is to remove the oldest block before adding the new one
  void rxRingCreateNewSafe(const uint64_t blockIdx);

  // If block is already known and not in the queue anymore return nullptr
  // else if block is inside the ring return pointer to it
  // and if it is not inside the ring add as many blocks as needed, then return pointer to it
  RxBlock *rxRingFindCreateBlockByIdx(const uint64_t blockIdx);
  void process_with_rx_queue(const FECPayloadHdr& header,const uint8_t* data,int data_size);
 public:
  // matches FECDecoder
  struct FECRxStats {
    // total block count
    uint64_t count_blocks_total = 0;
    // a block counts as "lost" if it was removed before being fully received or recovered
    uint64_t count_blocks_lost = 0;
    // a block counts as "recovered" if it was recovered using FEC packets
    uint64_t count_blocks_recovered = 0;
    // n of primary fragments that were reconstructed during the recovery process of a block
    uint64_t count_fragments_recovered = 0;
    // n of forwarded bytes
    uint64_t count_bytes_forwarded=0;
    MinMaxAvg<std::chrono::nanoseconds> curr_fec_decode_time{};
  };
  FECRxStats stats{};
  void reset_rx_queue();
};

// quick math regarding sequence numbers:
//uint32_t holds max 4294967295 . At 10 000 pps (packets per seconds) (which is already completely out of reach) this allows the tx to run for 429496.7295 seconds
// 429496.7295 / 60 / 60 = 119.304647083 hours which is also completely overkill for OpenHD (and after this time span, a "reset" of the sequence number happens anyways)
// unsigned 24 bits holds 16777215 . At 1000 blocks per second this allows the tx to create blocks for 16777.215 seconds or 4.6 hours. That should cover a flight (and after 4.6h a reset happens,
// which means you might lose a couple of blocks once every 4.6 h )
// and 8 bits holds max 255.

#endif  // WIFIBROADCAST_FECSTREAM_H
