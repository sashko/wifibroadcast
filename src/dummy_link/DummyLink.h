//
// Created by consti10 on 07.01.24.
//

#ifndef OPENHD_DUMMYLINK_H
#define OPENHD_DUMMYLINK_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <queue>

// TODO: Write something that emulates a wb link (tx, rx)
// using linux shm or similar
class DummyLink {
public:
    explicit DummyLink(bool is_air);
    ~DummyLink();
    void tx_radiotap(const uint8_t* packet_buff, int packet_size);
    std::shared_ptr<std::vector<uint8_t>> rx_radiotap();
private:
    const bool m_is_air;
    int m_fd_tx;
    int m_fd_rx;
    std::string m_fn_tx;
    std::string m_fn_rx;
    std::queue<std::shared_ptr<std::vector<uint8_t>>> m_rx_queue;
    std::mutex m_rx_mutex;
    std::unique_ptr<std::thread> m_receive_thread;
    void loop_rx();
    bool m_keep_receiving= true;
};


#endif //OPENHD_DUMMYLINK_H
