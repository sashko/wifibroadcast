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

static constexpr auto TEST_PACKETS_SIZE=1024;

struct RoughTestResult{
  int mcs_index;
  int pass_pps_set;
  int pass_pps_measured;
  int pass_bps_measured;
  int fail_pps_set;
  int fail_pps_measured;
  int fail_bps_measured;
};

static RoughTestResult increase_rate_until_fail(std::shared_ptr<WBTxRx> txrx,const int mcs,const int pps_start,const int pps_increment){
  auto m_console=wifibroadcast::log::create_or_get("main");
  txrx->tx_update_mcs_index(mcs);

  int last_passed_pps_set=0;
  int last_passed_pps_measured=0;
  int last_passed_bps_measured=0;
  for(int pps=pps_start;pps<5*1000;pps+=pps_increment) {
    auto tx_cb=[&txrx](const uint8_t* data,int data_len){
      txrx->tx_inject_packet(10,data,data_len);
    };
    auto stream_generator=std::make_unique<DummyStreamGenerator>(tx_cb,TEST_PACKETS_SIZE);
    stream_generator->set_target_pps(pps);
    std::this_thread::sleep_for(std::chrono::seconds(1));  // give driver time to empty queue
    txrx->tx_reset_stats();
    stream_generator->start();
    m_console->info("Testing MCS {} with {} pps", mcs, pps);
    std::this_thread::sleep_for(std::chrono::seconds(5));
    const auto txstats = txrx->get_tx_stats();
    if (txstats.count_tx_injections_error_hint > 0) {
      m_console->info("TX errors {} n_times_cannot_keep_up_wanted_pps {}",txstats.count_tx_injections_error_hint,stream_generator->n_times_cannot_keep_up_wanted_pps);
      // TX errors
      m_console->info("Got TX errors at set:{} actual: {} pps {} pps", pps,txstats.curr_packets_per_second,txstats.curr_packets_per_second);
      RoughTestResult result{};
      result.pass_pps_set=last_passed_pps_set;
      result.pass_pps_measured=last_passed_pps_measured;
      result.pass_bps_measured=last_passed_bps_measured;
      result.fail_pps_set=pps;
      result.fail_pps_measured=txstats.curr_packets_per_second;
      result.fail_bps_measured=txstats.curr_bits_per_second;
      return result;
    }else{
      m_console->info("MCS {} passed {} - measured {} {}", mcs,pps,txstats.curr_packets_per_second,StringHelper::bitrate_readable(txstats.curr_bits_per_second));
      last_passed_pps_set=pps;
      last_passed_pps_measured=txstats.curr_packets_per_second;
      last_passed_bps_measured=txstats.curr_bits_per_second;
    }
  }
}

static std::vector<RoughTestResult> calculate_rough(std::shared_ptr<WBTxRx> txrx){
  std::vector<RoughTestResult> ret;

  auto m_console=wifibroadcast::log::create_or_get("main");
  // Since we use increasing MCS, start where the last measurement failed to speed up testing
  int pps_start=500;

  for(int mcs=0;mcs< 4;mcs++) {
    m_console->info("Testing MCS {}", mcs);
    txrx->tx_update_mcs_index(mcs);

    auto res = increase_rate_until_fail(txrx,mcs, pps_start, 200);
    pps_start = res.pass_pps_set;
    ret.push_back(res);
  }
  return ret;
}

static void print_test_results_rough(const std::vector<RoughTestResult>& test_results){
  auto m_console=wifibroadcast::log::create_or_get("main");
  for(const auto& result: test_results){
    m_console->debug("MCS {} PASSED: {}-{}-{} FAILED {}-{}-{}",
                     result.mcs_index,
                     result.pass_pps_set,result.pass_pps_measured,StringHelper::bitrate_readable(result.pass_bps_measured),
                     result.fail_pps_set,result.fail_pps_measured,StringHelper::bitrate_readable(result.fail_bps_measured));
  }
}


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


  const auto rough_results= calculate_rough(txrx);
  m_console->info("ROUGH TEST RESULTS");
  print_test_results_rough(rough_results);
  std::this_thread::sleep_for(std::chrono::seconds(10));
  if(true){
    return 0;
  }

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
      std::this_thread::sleep_for(std::chrono::seconds(1)); // give driver time to empty queue
      txrx->tx_reset_stats();
      stream_generator->start();
      m_console->info("Testing MCS {} with {} pps",mcs,pps);
      std::this_thread::sleep_for(std::chrono::seconds(3));
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
          std::this_thread::sleep_for(std::chrono::seconds(1)); // give driver time to empty queue
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