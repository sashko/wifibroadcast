//
// Created by consti10 on 17.12.22.
//

#ifndef WIFIBROADCAST_SRC_FOREIGNPACKETSRECEIVER_H_
#define WIFIBROADCAST_SRC_FOREIGNPACKETSRECEIVER_H_

#include <cstdint>
#include <vector>
#include <memory>

#include "RawReceiver.hpp"

class ForeignPacketsReceiver {
 public:
 private:

  std::vector<uint16_t> m_openhd_radio_ports;
};

#endif  // WIFIBROADCAST_SRC_FOREIGNPACKETSRECEIVER_H_
