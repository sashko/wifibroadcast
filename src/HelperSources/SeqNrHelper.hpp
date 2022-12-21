//
// Created by consti10 on 21.12.22.
//

#ifndef WIFIBROADCAST_SRC_HELPERSOURCES_SEQNRHELPER_H_
#define WIFIBROADCAST_SRC_HELPERSOURCES_SEQNRHELPER_H_

namespace seq_nr{

static int diff_between_packets(int last_packet,int curr_packet){
  if(last_packet==curr_packet){
    wifibroadcast::log::get_default()->debug("Duplicate?!");
  }
  if(curr_packet<last_packet){
    // We probably have overflown the uin16_t range
    const auto diff=curr_packet+UINT16_MAX+1-last_packet;
    return diff;
  }else{
    return curr_packet-last_packet;
  }
}

// Helper for calculating statistics for a link with a rolling uint16_t sequence number
class Helper{
 public:
  Helper(){
    m_gaps.reserve(MAX_N_STORED_GAPS);
  }
  void on_new_sequence_number(uint16_t seq_nr){
    if(m_last_seq_nr==-1){
      // first ever packet
      m_last_seq_nr=seq_nr;
      return;
    }
    const auto diff= diff_between_packets(m_last_seq_nr,seq_nr);
    if(diff>1){
      // as an example, a diff of 2 means one packet is missing.
      m_n_missing_packets+=diff-1;
      m_n_received_packets++;
      store_gap(diff-1);
      //m_console->debug("Diff:{}",diff);
      if(diff>=MIN_SIZE_BIG_GAP){
        m_n_big_gaps_since_last++;
      }
    }else{
      m_n_received_packets++;
    }
  }
 private:
  void store_gap(int gap_size){
    m_gaps.push_back(gap_size);
    const auto elasped=std::chrono::steady_clock::now()-m_last_log;
    if(elasped>std::chrono::seconds(1)){
      wifibroadcast::log::get_default()->debug("Gaps: {}",StringHelper::vectorAsString(m_gaps));
      m_gaps.resize(0);
      m_last_log=std::chrono::steady_clock::now();
    }
    if(m_gaps.size()>=MAX_N_STORED_GAPS){
      m_gaps.resize(0);
    }
  }
 private:
  int m_last_seq_nr=-1;
  static constexpr int MAX_N_STORED_GAPS=1000;
  static constexpr auto MIN_SIZE_BIG_GAP=8;
  std::vector<int> m_gaps;
 private:
  int m_n_received_packets=0;
  int m_n_missing_packets=0;
  int m_n_big_gaps_since_last=0;
  std::chrono::steady_clock::time_point m_last_log;
};

}
#endif  // WIFIBROADCAST_SRC_HELPERSOURCES_SEQNRHELPER_H_
