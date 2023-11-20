#ifndef KEY_PAIR_TX_RX_HPP
#define KEY_PAIR_TX_RX_HPP

#include "Key.hpp"

namespace wb {

// A wb keypair are 2 keys, one for transmitting, one for receiving
// (Since both ground and air unit talk bidirectional)
// We use a different key for the down-link / uplink, respective
struct KeyPairTxRx {
  Key key_1;
  Key key_2;
  Key get_tx_key(bool is_air) { return is_air ? key_1 : key_2; }
  Key get_rx_key(bool is_air) { return is_air ? key_2 : key_1; }
};

}  // namespace wb

#endif  //  KEY_PAIR_TX_RX_HPP