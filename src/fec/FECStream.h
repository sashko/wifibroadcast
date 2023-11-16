//
// Created by consti10 on 28.06.23.
//

#ifndef WIFIBROADCAST_FECSTREAM_H
#define WIFIBROADCAST_FECSTREAM_H

#include <cstdint>

/**
 * For dynamic block sizes, we switched to a FEC overhead "percentage" value.
 * e.g. the final data throughput ~= original data throughput * fec overhead percentage
 * Rounds up / down (.5), but always at least 1
 */
uint32_t calculate_n_secondary_fragments(uint32_t n_primary_fragments, uint32_t fec_overhead_perc);

/**
 * calculate n from k and percentage as used in FEC terms
 * (k: number of primary fragments, n: primary + secondary fragments)
 */
uint32_t calculateN(uint32_t k, uint32_t percentage);

void fec_stream_print_fec_optimization_method();

// quick math regarding sequence numbers:
//uint32_t holds max 4294967295 . At 10 000 pps (packets per seconds) (which is already completely out of reach) this allows the tx to run for 429496.7295 seconds
// 429496.7295 / 60 / 60 = 119.304647083 hours which is also completely overkill for OpenHD (and after this time span, a "reset" of the sequence number happens anyways)
// unsigned 24 bits holds 16777215 . At 1000 blocks per second this allows the tx to create blocks for 16777.215 seconds or 4.6 hours. That should cover a flight (and after 4.6h a reset happens,
// which means you might lose a couple of blocks once every 4.6 h )
// and 8 bits holds max 255.

#endif  // WIFIBROADCAST_FECSTREAM_H
