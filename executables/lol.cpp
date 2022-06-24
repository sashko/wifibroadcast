//
// Created by consti10 on 20.04.22.
// This one just exists to test the compilation with cmake,nothing else.
//

#include "../src/HelperSources/Helper.hpp"
#include "../src/WBReceiver.h"
#include "../src/WBTransmitter.h"
#include "../src/Encryption.hpp"
#include "memory"

static std::unique_ptr<WBReceiver> make_with_out_of_scope() {
  ROptions options;
  options.radio_port = 12;
  auto wb_receiver = std::make_unique<WBReceiver>(options, nullptr);
  return wb_receiver;
}

static std::unique_ptr<WBTransmitter> make_with_out_of_scope2() {
  TOptions options;
  options.radio_port = 12;
  RadiotapHeader::UserSelectableParams params;
  RadiotapHeader radiotap_header{params};
  auto wb_transmitter = std::make_unique<WBTransmitter>(radiotap_header, options);
  return wb_transmitter;
}

static void test() {
  auto wb_receiver = make_with_out_of_scope();
  if (wb_receiver->options.radio_port != 12) {
	throw std::runtime_error("AAERGH");
  }
  /*auto wb_transmitter=make_with_out_of_scope2();
  if(wb_transmitter->options.radio_port!=12){
	throw std::runtime_error("AAERGH2");
  }*/
}

int main(int argc, char *const *argv) {

  WBReceiver wbReceiver(ROptions{}, nullptr);
  Encryptor encryptor{std::nullopt};
  test();
  return 0;
}