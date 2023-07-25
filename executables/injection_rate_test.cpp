//
// Created by consti10 on 25.07.23.
//

#include "../src/WBStreamRx.h"
#include "../src/WBStreamTx.h"
#include "../src/WBTxRx.h"
#include "../src/wifibroadcast-spdlog.h"
#include "DummyStreamGenerator.hpp"
#include "RandomBufferPot.hpp"
#include "Rates.hpp"

// Utility / benchmark executable to find the maximum injection rate possible for the card given a MCS index
// It works by increasing the injection rate (injected bitrate / packets per second) until there are so called
// "TX ERRORS", aka the driver tx packet queue is running full


//static constexpr auto TEST_PACKETS_SIZE=1024;
static constexpr auto TEST_PACKETS_SIZE=1440;

struct TestResult {
  int mcs_index;
  int pass_pps_set;
  int pass_pps_measured;
  int pass_bps_measured;
  int fail_pps_set;
  int fail_pps_measured;
  int fail_bps_measured;
};

static TestResult increase_pps_until_fail(std::shared_ptr<WBTxRx> txrx,const int mcs,const int pps_start,const int pps_increment){
  auto m_console=wifibroadcast::log::create_or_get("main");
  m_console->info("Testing MCS {}", mcs);
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
    /*const auto begin=std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now()-begin<std::chrono::seconds(5)){
      auto txstats=txrx->get_tx_stats();
      if(txstats.count_tx_injections_error_hint>0 || stream_generator->n_times_cannot_keep_up_wanted_pps>20){
        // stop early
        break ;
      }
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }*/
    std::this_thread::sleep_for(std::chrono::seconds(3));
    const auto txstats = txrx->get_tx_stats();
    if (txstats.count_tx_injections_error_hint > 0 || stream_generator->n_times_cannot_keep_up_wanted_pps>10 ) {
      m_console->info("TX errors {} n_times_cannot_keep_up_wanted_pps {}",txstats.count_tx_injections_error_hint,stream_generator->n_times_cannot_keep_up_wanted_pps);
      // TX errors
      m_console->info("Got TX errors at set:{} actual: {} pps {} pps", pps,txstats.curr_packets_per_second,txstats.curr_packets_per_second);
      TestResult result{};
      result.mcs_index=mcs;
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
  //assert(false);
  return {mcs,0,0,0,0,0};
}
struct TestResultRoughFine{
  TestResult rough;
  TestResult fine;
};
static TestResultRoughFine increase_pps_until_fail_fine_adjust(std::shared_ptr<WBTxRx> txrx,const int mcs,const int pps_start,const int pps_increment){
  auto res_rough= increase_pps_until_fail(txrx,mcs,pps_start,pps_increment);
  const auto fine_pps_start=res_rough.pass_pps_set;
  const auto fine_pps_increment=pps_increment / 8;
  auto res_fine= increase_pps_until_fail(txrx,mcs,res_rough.pass_pps_set,pps_increment);
  return {res_rough,res_fine};
}

struct Validation{
  int count_tx_injections_error_hint;
  int n_times_cannot_keep_up_wanted_pps;
};
static Validation validate_specific_rate(std::shared_ptr<WBTxRx> txrx,const int mcs,const int pps){
  auto m_console=wifibroadcast::log::create_or_get("main");
  m_console->info("Validating {} - {}", mcs,pps);
  txrx->tx_update_mcs_index(mcs);
  auto tx_cb=[&txrx](const uint8_t* data,int data_len){
    txrx->tx_inject_packet(10,data,data_len);
  };
  auto stream_generator=std::make_unique<DummyStreamGenerator>(tx_cb,TEST_PACKETS_SIZE);
  stream_generator->set_target_pps(pps);
  std::this_thread::sleep_for(std::chrono::seconds(1));  // give driver time to empty queue
  txrx->tx_reset_stats();
  stream_generator->start();
  std::this_thread::sleep_for(std::chrono::seconds(10));
  const auto txstats = txrx->get_tx_stats();
  auto ret=Validation{txstats.count_tx_injections_error_hint,stream_generator->n_times_cannot_keep_up_wanted_pps};
  if(ret.count_tx_injections_error_hint>0 || ret.n_times_cannot_keep_up_wanted_pps>10){
    m_console->info("MCS {} didn't pass {} measured {}-{}",pps,
                    txstats.curr_packets_per_second,StringHelper::bitrate_readable(txstats.curr_bits_per_second));
  }else{
    m_console->info("MCS {} passed {} measured {}-{}",pps,
                    txstats.curr_packets_per_second,StringHelper::bitrate_readable(txstats.curr_bits_per_second));
  }
  return ret;
}


static void print_test_results_rough(const std::vector<TestResult>& test_results){
  auto m_console=wifibroadcast::log::create_or_get("main");
  for(const auto& result: test_results){
    m_console->debug("MCS {} PASSED: {}-{}-{} FAILED {}-{}-{}",
                     result.mcs_index,
                     result.pass_pps_set,result.pass_pps_measured,StringHelper::bitrate_readable(result.pass_bps_measured),
                     result.fail_pps_set,result.fail_pps_measured,StringHelper::bitrate_readable(result.fail_bps_measured));
  }
}
static void print_test_results_and_theoretical(const std::vector<TestResult>& test_results){
  auto m_console=wifibroadcast::log::create_or_get("main");
  for(const auto& result: test_results){
    const auto theoretical=wifibroadcast::get_theoretical_rate_5G(result.mcs_index);
    m_console->debug("MCS {} PASSED {}--{}",result.mcs_index,
                     StringHelper::bitrate_readable(result.pass_bps_measured),
                     StringHelper::bitrate_readable(theoretical.rate_20mhz_kbits*1000));
  }
}

static std::vector<TestResult> calculate_rough(std::shared_ptr<WBTxRx> txrx){
  std::vector<TestResult> ret;

  auto m_console=wifibroadcast::log::create_or_get("main");
  // Since we use increasing MCS, start where the last measurement failed to speed up testing
  int pps_start=500;

  for(int mcs=0;mcs< 4;mcs++) {
    auto res = increase_pps_until_fail(txrx,mcs, pps_start, 100);
    print_test_results_rough({res});
    pps_start = res.pass_pps_set;
    // at MCS8 we loop around regarding rate
    if(mcs % 8 ==0){
      pps_start=500;
    }
    if(pps_start<=0){
      m_console->warn("Didn't pass a prev. rate");
      pps_start=500;
    }
    ret.push_back(res);
    /*auto res_rough_fine= increase_pps_until_fail_fine_adjust(txrx,mcs,pps_start,400);
    auto rough=res_rough_fine.rough;
    auto fine=res_rough_fine.fine;
    pps_start=rough.pass_pps_set;
    ret.push_back(fine);*/
  }
  return ret;
}

int main(int argc, char *const *argv) {
  std::string card="wlxac9e17596103";
  int opt;
  while ((opt = getopt(argc, argv, "w:agd")) != -1) {
    switch (opt) {
      case 'w':
        card = optarg;
        break;
      default: /* '?' */
      show_usage:
        fprintf(stderr,
                "injection rate test %s [-w wifi card to use]\n",
                argv[0]);
        exit(1);
    }
  }
  std::cout<<"Running on card "<<card<<"\n";

  // Create the Tx-RX
  std::vector<std::string> cards{card};
  WBTxRx::Options options_txrx{};
  options_txrx.rtl8812au_rssi_fixup= true;
  //options_txrx.set_direction= false;
  options_txrx.log_all_received_validated_packets= false;
  options_txrx.disable_encryption= true;

  std::shared_ptr<WBTxRx> txrx=std::make_shared<WBTxRx>(cards,options_txrx);
  // No idea if and what effect stbc and ldpc have on the rate, but openhd enables them if possible by default
  // since they greatly increase range / resiliency
  txrx->tx_update_stbc(true);
  txrx->tx_update_ldpc(true);
  // short GI interval gives slightly higher rates, but also decreases resiliency
  txrx->tx_update_guard_interval(false);

  txrx->start_receiving();

  auto m_console=wifibroadcast::log::create_or_get("main");
  std::vector<TestResult> m_test_results;

  WBTxRx::OUTPUT_DATA_CALLBACK cb=[](uint64_t nonce,int wlan_index,const uint8_t radioPort,const uint8_t *data, const std::size_t data_len){
    //std::string message((const char*)data,data_len);
    //fmt::print("Got packet[{}]\n",message);
  };
  txrx->rx_register_callback(cb);

  /*txrx->tx_update_guard_interval(false);
  const auto res_lgi= calculate_rough(txrx);
  txrx->tx_update_guard_interval(true);
  //const auto res_sgi= calculate_rough(txrx);
  m_console->info("ROUGH TEST RESULTS");
  m_console->info("Long guard");
  print_test_results_rough(res_lgi);*/
  //m_console->info("Short guard");
  //print_test_results_rough(res_sgi);
  txrx->tx_update_channel_width(20);
  const auto res_20mhz= calculate_rough(txrx);
  print_test_results_rough(res_20mhz);
  print_test_results_and_theoretical(res_20mhz);
  /*const auto res_40mhz= calculate_rough(txrx);
  print_test_results_rough(res_40mhz);
  m_console->info("20Mhz:");
  print_test_results_rough(res_20mhz);
  m_console->info("40Mhz:");
  print_test_results_rough(res_40mhz);*/
}