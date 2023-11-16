#include "FECEncoder.hpp"

#include <cassert>
#include <chrono>
#include <cstring>
#include <memory>

#include "../external/fec/fec_base.h"

#include "FECConstants.hpp"

void FECEncoder::encode_block(
    std::vector<std::shared_ptr<std::vector<uint8_t>>> data_packets,
    int n_secondary_fragments) {
  assert(data_packets.size() <= MAX_N_P_FRAGMENTS_PER_BLOCK);
  assert(n_secondary_fragments <= MAX_N_S_FRAGMENTS_PER_BLOCK);
  const auto n_primary_fragments = data_packets.size();
  // nice to have statistic
  m_block_sizes.add(n_primary_fragments);
  if (m_block_sizes.get_delta_since_last_reset() >= std::chrono::seconds(1)) {
    // wifibroadcast::log::get_default()->debug("Block sizes:
    // {}",m_block_sizes.getAvgReadable());
    m_curr_fec_block_sizes = m_block_sizes.getMinMaxAvg();
    m_block_sizes.reset();
  }
  FECPayloadHdr header{};
  header.block_idx = m_curr_block_idx;
  m_curr_block_idx++;
  header.n_primary_fragments = n_primary_fragments;
  // write and forward all the data packets first
  // also calculate the size of the biggest data packet
  size_t max_packet_size = 0;
  // Store a pointer where the FEC data begins for performing the FEC step later
  // on
  std::vector<const uint8_t*> primary_fragments_data_p;
  for (int i = 0; i < data_packets.size(); i++) {
    const auto& data_fragment = data_packets[i];
    // wifibroadcast::log::get_default()->debug("In:{}",(int)data_fragment->size());
    assert(!data_fragment->empty());
    assert(data_fragment->size() <= FEC_PACKET_MAX_PAYLOAD_SIZE);
    header.fragment_idx = i;
    header.data_size = data_fragment->size();
    auto buffer_p = m_block_buffer[i].data();
    // copy over the header
    memcpy(buffer_p, (uint8_t*)&header, sizeof(FECPayloadHdr));
    // write the actual data
    memcpy(buffer_p + sizeof(FECPayloadHdr), data_fragment->data(),
           data_fragment->size());
    // zero out the remaining bytes such that FEC always sees zeroes
    // same is done on the rx. These zero bytes are never transmitted via wifi
    const auto writtenDataSize = sizeof(FECPayloadHdr) + data_fragment->size();
    memset(buffer_p + writtenDataSize, 0,
           MAX_PAYLOAD_BEFORE_FEC - writtenDataSize);
    max_packet_size = std::max(max_packet_size, data_fragment->size());
    // we can forward the data packet immediately via the callback
    if (outputDataCallback) {
      outputDataCallback(buffer_p, writtenDataSize);
    }
    // NOTE: FECPayloadHdr::data_size needs to be included during the fec encode
    // step
    primary_fragments_data_p.push_back(buffer_p + sizeof(FECPayloadHdr) -
                                       sizeof(uint16_t));
  }
  // then we create as many FEC packets as needed
  if (n_secondary_fragments == 0) {
    // wifibroadcast::log::get_default()->debug("No FEC step performed");
    //  no FEC step is actually performed, usefully for debugging / performance
    //  evaluation
    return;
  }
  const auto before = std::chrono::steady_clock::now();
  // Now we perform the actual FEC encode step
  std::vector<uint8_t*> secondary_fragments_data_p;
  for (int i = 0; i < n_secondary_fragments; i++) {
    auto fragment_index = i + n_primary_fragments;
    auto buffer_p = m_block_buffer[fragment_index].data();
    header.fragment_idx = fragment_index;
    // copy over the header
    memcpy(buffer_p, (uint8_t*)&header, sizeof(FECPayloadHdr));
    // where the FEC packet correction data is written to
    secondary_fragments_data_p.push_back(buffer_p + sizeof(FECPayloadHdr) -
                                         sizeof(uint16_t));
  }
  fec_encode2(max_packet_size + sizeof(uint16_t), primary_fragments_data_p,
              secondary_fragments_data_p);
  m_fec_block_encode_time.add(std::chrono::steady_clock::now() - before);
  if (m_fec_block_encode_time.get_delta_since_last_reset() >=
      std::chrono::seconds(1)) {
    // wifibroadcast::log::get_default()->debug("FEC encode
    // time:{}",m_fec_block_encode_time.getAvgReadable());
    m_curr_fec_block_encode_time = m_fec_block_encode_time.getMinMaxAvg();
    m_fec_block_encode_time.reset();
  }
  // and forward all the FEC correction packets
  for (int i = 0; i < n_secondary_fragments; i++) {
    auto fragment_index = i + n_primary_fragments;
    if (outputDataCallback) {
      outputDataCallback(m_block_buffer[fragment_index].data(),
                         sizeof(FECPayloadHdr) + max_packet_size);
    }
  }
}
