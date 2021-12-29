//
// Created by consti10 on 28.11.21.
//

#ifndef WIFIBROADCAST_RX2_H
#define WIFIBROADCAST_RX2_H

struct Options{
    // the radio port is what is used as an index to multiplex multiple streams (telemetry,video,...)
    // into the one wfb stream
    uint8_t radio_port = 1;
    // file for encryptor
    std::string keypair="drone.key";
    // wlan interface to send packets with
    std::string wlan;
};

class BidirectionalTransmitter {
public:
    BidirectionalTransmitter(){

    }
    const int maxNumberRetransmissions=5;
};


class BidirectionalReceiver {

};


#endif //WIFIBROADCAST_RX2_H
