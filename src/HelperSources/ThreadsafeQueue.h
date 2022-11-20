//
// Created by consti10 on 21.11.22.
//

#ifndef WIFIBROADCAST_SRC_HELPERSOURCES_THREADSAFEQUEUE_H_
#define WIFIBROADCAST_SRC_HELPERSOURCES_THREADSAFEQUEUE_H_

#include <queue>
#include <mutex>
#include <memory>

template<typename T>
class ThreadsafeQueue {
  std::queue<std::shared_ptr<T>> queue_;
  mutable std::mutex mutex_;
  // Moved out of public interface to prevent races between this
  // and pop().
  bool empty() const {
    return queue_.empty();
  }
 public:
  ThreadsafeQueue() = default;
  ThreadsafeQueue(const ThreadsafeQueue<T> &) = delete ;
  ThreadsafeQueue& operator=(const ThreadsafeQueue<T> &) = delete ;
  ThreadsafeQueue(ThreadsafeQueue<T>&& other) {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_ = std::move(other.queue_);
  }
  virtual ~ThreadsafeQueue() { }
  unsigned long size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
  }
  // returns the oldest item in the queue if available
  // nullptr otherwise
  std::shared_ptr<T> popIfAvailable() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty()) {
      return std::shared_ptr<T>(nullptr);
    }
    auto tmp = queue_.front();
    queue_.pop();
    return tmp;
  }
  // adds a new item to the queue
  void push(std::shared_ptr<T> item) {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push(std::move(item));
  }
  // returns a list of all buffers currently inside the queue and removes them from the queue
  // The first element in the returned list is the oldest element in the queue
  std::vector<std::shared_ptr<T>> getAllAndClear(){
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<T>> ret;
    while (!queue_.empty()){
      ret.push_back(queue_.front());
      queue_.pop();
    }
    return ret;
  }
};

#endif  // WIFIBROADCAST_SRC_HELPERSOURCES_THREADSAFEQUEUE_H_
