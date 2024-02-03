//
// Created by consti10 on 02.02.24.
//

#ifndef WIFIBROADCAST_FUNKYQUEUE_H
#define WIFIBROADCAST_FUNKYQUEUE_H

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <optional>


template<class T>
class FunkyQueue {
 public:
  explicit FunkyQueue(int capacity):m_capacity(capacity){};
  // Enqueues a new element. Return true on success, false otherwise
  bool try_enqueue(T element){
    std::unique_lock<std::mutex> lk(mtx);
    if(queue.size()>=m_capacity){
      return false;
    }
    queue.push(element);
    cv.notify_one();
  }
  // If there is enough space on the queue, enqueue the given element and return 0;
  // Otherwise, remove all elements currently in the queue, then enqueue the given element,
  // and return the n of removed elements
  int enqueue_or_clear_enqueue(T element){
    std::unique_lock<std::mutex> lk(mtx);
    if(queue.size()>=m_capacity){
      // Not enough space
      const int count_removed=queue.size();
      while (!queue.empty())queue.pop();
      queue.push(element);
      cv.notify_one();
      return count_removed;
    }
    // enough space
    queue.push(element);
    cv.notify_one();
    return 0;
  }
  // Wait up to timeout until element is available.
  std::optional<T> wait_dequeue_timed(std::chrono::nanoseconds timeout){
    std::unique_lock<std::mutex> ul(mtx);
    if(!queue.empty()){
      auto tmp=queue.front();
      queue.pop();
      return tmp;
    }
    const auto res=cv.wait_for(ul,timeout,[this](){
      return !queue.empty();
    });
    if(res== std::cv_status::no_timeout){
      assert(!queue.empty());
      auto tmp=queue.front();
      queue.pop();
      return tmp;
    }
    return std::nullopt;
  }
private:
 const int m_capacity;
 std::queue<T> queue;
 std::mutex mtx;
 std::condition_variable cv;
};

#endif  // WIFIBROADCAST_FUNKYQUEUE_H
