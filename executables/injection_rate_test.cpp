//
// Created by consti10 on 25.07.23.
//

#include "../src/WBStreamRx.h"
#include "../src/WBStreamTx.h"
#include "../src/WBTxRx.h"
#include "../src/wifibroadcast-spdlog.h"
#include "RandomBufferPot.hpp"
#include "DummyStreamGenerator.h"

// Utility / benchmark executable to find the maximum injection rate possible for the card given a MCS index
// It works by increasing the injection rate (injected bitrate / packets per second) until there are so called
// "TX ERRORS", aka the driver tx packet queue is running full


struct TestResult{
  int mcs_index;
  int max_pps;
  int max_bps;
};



int main(int argc, char *const *argv) {
  std::string card="wlxac9e17596103";
  bool is_air= false;
  int opt;
  while ((opt = getopt(argc, argv, "w:agd")) != -1) {
    switch (opt) {
      case 'w':
        card = optarg;
        break;
      case 'a':
        is_air= true;
        break ;
      case 'g':
        is_air= false;
        break ;
        break ;
      default: /* '?' */
      show_usage:
        fprintf(stderr,
                "Example hello %s [-a run as air] [-g run as ground] [-w wifi card to use]\n",
                argv[0]);
        exit(1);
    }
  }
  std::cout<<"Running as "<<(is_air ? "Air" : "Ground")<<" on card "<<card<<"\n";

  // Create the Tx-RX
  std::vector<std::string> cards{card};
  WBTxRx::Options options_txrx{};
  options_txrx.rtl8812au_rssi_fixup= true;
  //options_txrx.set_direction= false;
  options_txrx.log_all_received_validated_packets= false;
  options_txrx.disable_encryption= true;

  std::shared_ptr<WBTxRx> txrx=std::make_shared<WBTxRx>(cards,options_txrx);

  txrx->start_receiving();

  auto m_console=wifibroadcast::log::create_or_get("main");
  std::vector<TestResult> m_test_results;

  WBTxRx::OUTPUT_DATA_CALLBACK cb=[](uint64_t nonce,int wlan_index,const uint8_t radioPort,const uint8_t *data, const std::size_t data_len){
    std::string message((const char*)data,data_len);
    fmt::print("Got packet[{}]\n",message);
  };
  txrx->rx_register_callback(cb);

  auto lastLog=std::chrono::steady_clock::now();

  uint64_t n_packets=0;
  PacketsPerSecondCalculator m_rx_packets_per_second_calculator{};

  auto tx_cb=[&txrx,&m_rx_packets_per_second_calculator,&n_packets](const uint8_t* data,int data_len){
    txrx->tx_inject_packet(10,data,data_len);
    //n_packets++;
  };
  std::this_thread::sleep_for(std::chrono::seconds(1));

  auto stream_generator=std::make_unique<DummyStreamGenerator>(tx_cb,1024);


  for(int mcs=0;mcs< 3;mcs++){
    m_console->info("Testing MCS {}",mcs);

    stream_generator->stop();
    txrx->tx_update_mcs_index(mcs);

    for(int pps=500;pps<5*1000;pps+=100){
      stream_generator->stop();
      stream_generator->set_target_pps(pps);
      txrx->tx_reset_stats();
      stream_generator->start();
      m_console->info("Testing MCS {} with {} pps",mcs,pps);
      std::this_thread::sleep_for(std::chrono::seconds(10));
      {
        const auto tmp=txrx->get_tx_stats();
        m_console->info("TX reports {}pps {}",tmp.curr_packets_per_second,StringHelper::bitrate_readable(tmp.curr_bits_per_second));
      }
      //const auto rate=m_rx_packets_per_second_calculator.get_last_or_recalculate(n_packets);
      //wifibroadcast::log::get_default()->debug("PPS:{}",rate);
      //n_packets=0;

      if(txrx->get_tx_stats().count_tx_injections_error_hint>0){
        // TX errors, fine adjust
        const auto txstats=txrx->get_tx_stats();
        m_console->info("Got TX errors at {}:{} pps",pps,txstats.curr_packets_per_second);

        const int fine_adjust_start=pps-200;
        const int fine_adjust_end=pps+500;
        for(int fine_adjust_pps=fine_adjust_start;fine_adjust_pps<fine_adjust_end;fine_adjust_pps+=20){
          m_console->info("Fine adjust {}",fine_adjust_pps);
          {
            const auto tmp=txrx->get_tx_stats();
            m_console->info("TX reports {}pps {}",tmp.curr_packets_per_second,StringHelper::bitrate_readable(tmp.curr_bits_per_second));
          }
          stream_generator->stop();
          stream_generator->set_target_pps(fine_adjust_pps);
          txrx->tx_reset_stats();
          stream_generator->start();
          std::this_thread::sleep_for(std::chrono::seconds(10));
          if(txrx->get_tx_stats().count_tx_injections_error_hint>0){
            const auto txstats=txrx->get_tx_stats();
            m_console->debug("Fine adjust done, {} - {}:{}",fine_adjust_pps,txstats.curr_packets_per_second,txstats.curr_bits_per_second);
            auto test_result=TestResult{mcs,txstats.curr_packets_per_second,txstats.curr_bits_per_second};
            m_test_results.push_back(test_result);
            break ;
          }
        }
        break ;
      }
    }
  }
  for(auto& result: m_test_results){
    m_console->debug("MCS {} Max {} {}",result.mcs_index,result.max_pps,StringHelper::bitrate_readable(result.max_bps));
  }


}