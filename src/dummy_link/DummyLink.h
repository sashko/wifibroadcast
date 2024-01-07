//
// Created by consti10 on 07.01.24.
//

#ifndef OPENHD_DUMMYLINK_H
#define OPENHD_DUMMYLINK_H

#include <cstdint>

// TODO: Write something that emulates a wb link (tx, rx)
// using linux shm or similar
class DummyLink {
public:
    void tx_radiotap(const uint8_t* packet_buff, int packet_size);
    void rx_radiotap();
private:
    bool m_is_air;
};


#endif //OPENHD_DUMMYLINK_H
