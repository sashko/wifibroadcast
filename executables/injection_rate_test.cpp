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

int main(int argc, char *const *argv) {
  std::string card="wlxac9e17596103";
  bool pcap_setdirection= true;
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
      case 'd':
        pcap_setdirection= false;
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
  options_txrx.set_direction= pcap_setdirection;
  options_txrx.log_all_received_validated_packets= true;

  std::shared_ptr<WBTxRx> txrx=std::make_shared<WBTxRx>(cards,options_txrx);

  txrx->start_receiving();

  auto m_console=wifibroadcast::log::create_or_get("main");

  WBTxRx::OUTPUT_DATA_CALLBACK cb=[](uint64_t nonce,int wlan_index,const uint8_t radioPort,const uint8_t *data, const std::size_t data_len){
    std::string message((const char*)data,data_len);
    fmt::print("Got packet[{}]\n",message);
  };
  txrx->rx_register_callback(cb);

  auto lastLog=std::chrono::steady_clock::now();
  int packet_index=0;

  auto tx_cb=[&txrx](const uint8_t* data,int data_len){
    txrx->tx_inject_packet(10,data,data_len);
  };

  auto stream_generator=std::make_unique<DummyStreamGenerator>(tx_cb,1024);


  for(int mcs=0;mcs< 13;mcs++){
    stream_generator->stop();
    txrx->tx_update_mcs_index(mcs);
    stream_generator->set_target_pps(100);
    stream_generator->start();

    for(int pps=100;pps<5*1000;pps+=100){
      stream_generator->set_target_pps(pps);

      std::this_thread::sleep_for(std::chrono::seconds(10));
      if(txrx->get_tx_stats().count_tx_injections_error_hint>0){
        // TX errors, fine adjust
        m_console->info("Got TX errors at {} pps",pps);
        break ;
      }
    }
  }
}