//
// Created by consti10 on 07.12.22.
//

#ifndef WIFIBROADCAST_SRC_HELPERSOURCES_BLOCKSIZEHELPER_HPP_
#define WIFIBROADCAST_SRC_HELPERSOURCES_BLOCKSIZEHELPER_HPP_

#include <vector>

namespace blocksize{

// If a frame has more fragments than the max block size on this platform
// (Which usually depends on the compute power of the platform we are running on, since FEC blocks
// become exponentially increasing expensive the bigger they are)
// We need to split the frame into more than one block. Usually, this needs to be done only for key frames
// (which are much bigger than other frame(s) ), but depends on the platform compute and encoder bitrate, fps
static int calc_min_n_of_blocks(int fragments_in_this_frame,int max_block_size){
  return std::ceil(static_cast<float>(fragments_in_this_frame)/static_cast<float>(max_block_size));
}

static std::vector<uint32_t> calculate_best_fit_block_sizes(int fragments_in_this_frame,int max_block_size){
  if(fragments_in_this_frame<=max_block_size){
    // We can do this whole frame in one FEC block
    return {static_cast<uint32_t>(fragments_in_this_frame)};
  }
  // Algorithm:
  // Given some amount of balls, fill the minimum amount of buckets as equally distributed as possible with balls
  // such that each bucket has not more than max_block_size balls
  // We need at least this many buckets (blocks)
  const int min_n_of_blocks= calc_min_n_of_blocks(fragments_in_this_frame,max_block_size);
  std::vector<uint32_t> ret;
  ret.resize(min_n_of_blocks);
  // Fill the buckets (blocks) with fragments, one after another, until we run out of balls (fragments)
  int remaining=fragments_in_this_frame;
  int index=0;
  while (remaining>0){
    ret[index]++;
    remaining--;
    index++;
    index = index % min_n_of_blocks;
  }
  return ret;
}

static std::vector<std::vector<std::shared_ptr<std::vector<uint8_t>>>> split_frame_if_needed(
    const std::vector<std::shared_ptr<std::vector<uint8_t>>>& frame_fragments,int max_block_size){
  auto split= calculate_best_fit_block_sizes(frame_fragments.size(),max_block_size);
  if(split.size()==1){
    return {frame_fragments};
  }
  std::vector<std::vector<std::shared_ptr<std::vector<uint8_t>>>> ret;
  ret.resize(split.size());
  int n_used_fragments=0;
  for(int i=0;i<split.size();i++){
    for(int j=0;j<split[i];j++){
      ret[i].push_back(frame_fragments[n_used_fragments]);
      n_used_fragments++;
    }
  }
  return ret;
}

// From https://stackoverflow.com/questions/2745074/fast-ceiling-of-an-integer-division-in-c-c
static int div_ceil(int numerator, int denominator){
  std::div_t res = std::div(numerator, denominator);
  return res.rem ? (res.quot + 1) : res.quot;
}

static int min_num_sub_blocks(int frame_size,int max_block_size,int MTU){
  const int max_data_size=max_block_size*MTU;
  return div_ceil(frame_size,max_data_size);
}


static int find_ideal_fragment_size(int frame_size,int max_block_size){
  // First check if we need to fragment the frame into 2 or more independent blocks due to FEC limitation(s)
  const int MTU=1446;
  int min_num_blocks= div_ceil(frame_size,max_block_size*MTU);


  // Ideally we want to split the frame into blocks where each block is the size of MTU
  const int MTU=1446;
  // We need at least this many fragment(s) with a max MTU as above
  const int n_fragments= div_ceil(frame_size,MTU);

}


}
#endif  // WIFIBROADCAST_SRC_HELPERSOURCES_BLOCKSIZEHELPER_HPP_
