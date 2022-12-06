//
// Created by consti10 on 07.12.22.
//

#ifndef WIFIBROADCAST_SRC_HELPERSOURCES_BLOCKSIZE_H_
#define WIFIBROADCAST_SRC_HELPERSOURCES_BLOCKSIZE_H_

#include <vector>

namespace blocksize{

static std::vector<uint32_t> calculate_best_fit(int fragments_in_this_frame,int max_block_size){
  std::vector<uint32_t> ret;
  if(fragments_in_this_frame<=max_block_size){
    ret.push_back(fragments_in_this_frame);
    return ret;
  }
  // Algorithm:
  // Given some amount of balls, fill the minimum amount of buckets as equally distributed as possible with balls
  // such that each bucket has not more than max_block_size balls
  // We need at least this many buckets (blocks)
  const int min_n_sub_blocks=std::ceil(static_cast<float>(fragments_in_this_frame)/static_cast<float>(max_block_size));
  // Fill the buckets (blocks) with fragments, one after another, until we run out of balls (fragments)
  ret.resize(min_n_sub_blocks);
  int remaining=fragments_in_this_frame;
  int index=0;
  while (remaining>0){
    ret[index]++;
    remaining--;
    index++;
    index = index % min_n_sub_blocks;
  }
  return ret;
}

}
#endif  // WIFIBROADCAST_SRC_HELPERSOURCES_BLOCKSIZE_H_
