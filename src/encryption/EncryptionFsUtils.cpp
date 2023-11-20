//
// Created by consti10 on 13.08.23.
//

#include "EncryptionFsUtils.h"

#include <sodium/crypto_box.h>

#include <cassert>
#include <cstring>
#include <iostream>

#include <spdlog/spdlog.h>
#include "../wifibroadcast_spdlog.h"

int wb::write_keypair_to_file(const wb::KeyPairTxRx& keypair_txrx,
                              const std::string& filename) {
  FILE *fp;
  if ((fp = fopen(filename.c_str(), "w")) == nullptr) {
    std::cerr<<"Unable to save "<<filename<<std::endl;
    assert(false);
    return 1;
  }
  assert(fwrite(keypair_txrx.key_1.secret_key.data(), crypto_box_SECRETKEYBYTES, 1, fp)==1);
  assert(fwrite(keypair_txrx.key_1.public_key.data(), crypto_box_PUBLICKEYBYTES, 1, fp)==1);
  assert(fwrite(keypair_txrx.key_2.secret_key.data(), crypto_box_SECRETKEYBYTES, 1, fp)==1);
  assert(fwrite(keypair_txrx.key_2.public_key.data(), crypto_box_PUBLICKEYBYTES, 1, fp)==1);
  fclose(fp);
  return 0;
}

wb::KeyPairTxRx wb::read_keypair_from_file(const std::string& filename) {
  KeyPairTxRx ret{};
  FILE *fp;
  if ((fp = fopen(filename.c_str(), "r")) == nullptr) {
    std::cerr<<fmt::format("Unable to open {}: {}", filename.c_str(), strerror(errno))<<std::endl;
    assert(false);
  }
  assert(fread(ret.key_1.secret_key.data(), crypto_box_SECRETKEYBYTES, 1, fp)==1);
  assert(fread(ret.key_1.public_key.data(), crypto_box_PUBLICKEYBYTES, 1, fp)==1);
  assert(fread(ret.key_2.secret_key.data(), crypto_box_SECRETKEYBYTES, 1, fp)==1);
  assert(fread(ret.key_2.public_key.data(), crypto_box_PUBLICKEYBYTES, 1, fp)==1);
  fclose(fp);
  return ret;
}