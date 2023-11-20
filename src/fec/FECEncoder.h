#ifndef FEC_ENCODER_HPP
#define FEC_ENCODER_HPP

#include <functional>
#include <memory>

#include "FECConstants.hpp"
#include "TimeHelper.hpp"

class FECEncoder {
 public:
  typedef std::function<void(const uint8_t* packet, int packet_len)>
      OUTPUT_DATA_CALLBACK;
  OUTPUT_DATA_CALLBACK outputDataCallback;
  explicit FECEncoder() = default;
  FECEncoder(const FECEncoder& other) = delete;

 public:
  /**
   * Encodes a new block and forwards the packets for this block
   * forwards data packets first, then generated fec packets
   * (if needed) and forwards them after.
   * @param data_packets the packets for this block
   * @param n_secondary_fragments how many secondary fragments (FEC packets)
   * should be created
   */
  void encode_block(
      std::vector<std::shared_ptr<std::vector<uint8_t>>> data_packets,
      int n_secondary_fragments);
  // Pre-allocated to have space for storing primary fragments (they are needed
  // once the fec step needs to be performed) and creating the wanted amount of
  // secondary packets
  std::array<std::array<uint8_t, MAX_PAYLOAD_BEFORE_FEC>,
             MAX_TOTAL_FRAGMENTS_PER_BLOCK>
      m_block_buffer{};
  uint32_t m_curr_block_idx = 0;
  static_assert(sizeof(m_curr_block_idx) == sizeof(FECPayloadHdr::block_idx));
  AvgCalculator m_fec_block_encode_time;
  MinMaxAvg<std::chrono::nanoseconds> m_curr_fec_block_encode_time{};
  BaseAvgCalculator<uint16_t> m_block_sizes{};
  MinMaxAvg<uint16_t> m_curr_fec_block_sizes{};
};

#endif  // FEC_ENCODER_HPP