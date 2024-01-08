//
// Created by consti10 on 07.01.24.
//

#include "DummyLink.h"

#include <fcntl.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "../HelperSources/SocketHelper.hpp"

// From http://www.atakansarioglu.com/linux-ipc-inter-process-messaging-linux-domain-socket-fifo-pipe-shared-memory-shm-example/

static sockaddr_un create_adr(const std::string& name){
  // Unix domain socket file address.
  struct sockaddr_un address;
  address.sun_family = AF_UNIX;
  strcpy(address.sun_path, name.c_str());
  return address;
}

static int create_socket_read(const std::string& name){
  auto address= create_adr(name);
  // Delete the old socket file.
  unlink(name.c_str());
  // Create a unix domain socket.
  int fd;
  if((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
    std::cout << "Receiver: Cannot create socket" << std::endl;
    return -1;
  }

  // Bind the socket to the address.
  if(bind(fd, (struct sockaddr *)&address, sizeof(sockaddr_un)) != 0) {
    std::cout << "Receiver: Cannot bind socket" << std::endl;
    return -1;
  }
  return fd;
}

static int create_socket_send(){
  // Create a unix domain socket.
  int fd;
  if((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
    std::cout << "Sender: Cannot create socket" << std::endl;
    return -1;
  }
  return fd;
}

static void send_data(int fd,const std::string& name,const uint8_t* data,int data_len){
  auto address= create_adr(name);
  if(sendto(fd, data,data_len, 0, (struct sockaddr *)&address, sizeof(sockaddr_un)) !=data_len) {
    //std::cout << "Client: Cannot send" << std::endl;
  }
  //std::cout<<"Sent:"<<data_len<<std::endl;
}

static constexpr auto MAX_MTU_INCLUDING_HEADER=2000;

static std::shared_ptr<std::vector<uint8_t>> read_data(int fd){
  auto buff=std::make_shared<std::vector<uint8_t>>();
  buff->resize(MAX_MTU_INCLUDING_HEADER);
  auto size=recvfrom(fd, buff->data(), buff->size(), MSG_DONTWAIT, NULL, NULL);
  if(size>0){
    buff->resize(size);
    return buff;
  }
  return nullptr;
}

DummyLink::DummyLink(bool is_air):m_is_air(is_air) {
  if(m_is_air){
    m_fn_tx="air";
    m_fn_rx="gnd";
    //m_fn_rx="air";
  }else{
    m_fn_tx="gnd";
    m_fn_rx="air";
  }
  m_fd_rx=create_socket_read(m_fn_rx);
  //SocketHelper::set_socket_send_rcv_timeout(m_fd_rx,std::chrono::milliseconds(10), true);
  m_fd_tx=create_socket_send();
  m_rx_queue=std::make_unique<moodycamel::BlockingReaderWriterCircularBuffer<std::shared_ptr<DummyLink::RxPacket>>>(
      1000);
  m_keep_receiving= true;
  m_receive_thread=std::make_unique<std::thread>(&DummyLink::loop_rx, this);
}

DummyLink::~DummyLink() {
  m_keep_receiving= false;
  m_receive_thread->join();
  m_receive_thread= nullptr;
}

void DummyLink::tx_radiotap(const uint8_t *packet_buff, int packet_size) {
  //const bool drop=should_drop();
  const bool drop= false;
  if(!should_drop()){
    send_data(m_fd_tx,m_fn_tx,packet_buff,packet_size);
  }
}

std::shared_ptr<std::vector<uint8_t>> DummyLink::rx_radiotap() {
  std::shared_ptr<DummyLink::RxPacket> packet= nullptr;
  static constexpr std::int64_t timeout_usecs=100*1000;
  if(m_rx_queue->wait_dequeue_timed(packet,timeout_usecs)) {
    // dequeued frame
    return packet->buff;
  }
  return nullptr;
}

void DummyLink::loop_rx() {
  while (m_keep_receiving){
    auto packet= read_data(m_fd_rx);
    if(packet!= nullptr){
      //std::cout<<"Got packet"<<packet->size()<<std::endl;
      auto item=std::make_shared<DummyLink::RxPacket>();
      item->buff=packet;
      //auto success=m_rx_queue->try_enqueue(item);
      static constexpr std::int64_t timeout_usecs=100*1000;
      auto success=m_rx_queue->wait_enqueue_timed(item,timeout_usecs);
      if(!success){
        //std::cout<<"Cannot enqueue packet"<<std::endl;
      }
    }
    //std::cout<<"ARGH"<<std::endl;
  }
}

bool DummyLink::should_drop() {
  int rand=next_random_number_0_100();
  if(rand <=5){
    return true;
  }
  return false;
}
