//
// Created by consti10 on 04.03.21.
//

#ifndef WIFIBROADCAST_FIXEDSIZEFIFO_H
#define WIFIBROADCAST_FIXEDSIZEFIFO_H

// A fifo queue with fixed size
// The reason I am not just using std::queue is that for OpenHD,

#include <queue>

template<typename T>
class FixedSizeFIFO{
public:
    static constexpr auto RX_RING_SIZE = 20;
private:
    std::array<std::unique_ptr<T>,RX_RING_SIZE> rx_ring;
    int rx_ring_front = 0; // current packet
    int rx_ring_alloc = 0; // number of allocated entries
public:
    explicit FixedSizeFIFO(){

    }
    static inline int modN(int x, int base) {
        return (base + (x % base)) % base;
    }

    // removes the first (oldest) element
    // returns the index of the removed element
    int rxRingPopFront(){
        const auto ret=rx_ring_front;
        rx_ring_front = modN(rx_ring_front + 1, RX_RING_SIZE);
        rx_ring_alloc -= 1;
        assert(rx_ring_alloc >= 0);
        return ret;
    }
    // makes space for 1 new element
    // return its index (this is now the latest element)
    int rxRingPushBack(){
        int idx = modN(rx_ring_front + rx_ring_alloc, RX_RING_SIZE);
        rx_ring_alloc += 1;
        assert(rx_ring_alloc<=RX_RING_SIZE);
        return idx;
    }
    // returns true if there is space for (at least) one more element
    bool hasSpace()const{
        if (rx_ring_alloc < RX_RING_SIZE) {
            return true;
        }
        return false;
    }
    T& get(const int idx){
        assert(idx<RX_RING_SIZE);
        return *rx_ring[idx];
    }
};

/*// Peek the first (oldest) element of the rx ring
   int rxRingPeekFront()const{
       return rx_ring_front;
   }*/
#endif //WIFIBROADCAST_FIXEDSIZEFIFO_H
