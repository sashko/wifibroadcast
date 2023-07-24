//
// Created by consti10 on 25.07.23.
//

#ifndef WIFIBROADCAST_DUMMYSTREAMGENERATOR_H
#define WIFIBROADCAST_DUMMYSTREAMGENERATOR_H

#include <functional>
#include <thread>
#include <cstdint>

#include "RandomBufferPot.hpp"


class DummyStreamGenerator{
 public:
  typedef std::function<void(const uint8_t* data,int data_len)> OUTPUT_DATA_CALLBACK;

  DummyStreamGenerator(OUTPUT_DATA_CALLBACK cb,int packet_size):
                                                                   m_cb(cb),m_packet_size(packet_size){
    m_random_buffer_pot=std::make_unique<RandomBufferPot>(100,packet_size);
  };

  void set_target_pps(int pps){
    m_target_pps=pps;
  }

  void start(){
    m_terminate= false;
    m_producer_thread=std::make_unique<std::thread>([this](){
      loop_generate_data();
    });
  }
  void stop(){
    m_terminate= true;
    if(m_producer_thread){
      m_producer_thread->join();
      m_producer_thread= nullptr;
    }
  }
  void loop_generate_data(){
    std::chrono::steady_clock::time_point last_packet=std::chrono::steady_clock::now();
    int seq=0;
    while (!m_terminate){
      const auto delay_between_packets=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::seconds(1))/m_target_pps;
      auto buff=m_random_buffer_pot->getBuffer(seq);
      seq++;
      m_cb(buff->data(),buff->size());
      const auto next_packet_tp=last_packet+delay_between_packets;
      while (std::chrono::steady_clock::now()<=next_packet_tp){
        // busy sleep
      }
    }
  }

 private:
  const int m_packet_size=1400;
  const OUTPUT_DATA_CALLBACK m_cb;
  int m_target_pps=100;
  std::unique_ptr<std::thread> m_producer_thread;
  std::unique_ptr<RandomBufferPot> m_random_buffer_pot;
  bool m_terminate= false;
};


#endif  // WIFIBROADCAST_DUMMYSTREAMGENERATOR_H
