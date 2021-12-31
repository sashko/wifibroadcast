//
// Created by consti10 on 31.12.21.
//

#ifndef WIFIBROADCAST_RANDOMBUFFERPOT_H
#define WIFIBROADCAST_RANDOMBUFFERPOT_H

#include <random>
#include <cassert>
#include <memory>
#include <string>
#include <algorithm>

// holds x buffers with (semi-random) data.
class RandomBufferPot{
public:
    /**
     * Holds @param nBuffers random data buffers of size @param bufferSize
     */
    RandomBufferPot(const std::size_t nBuffers,const std::size_t bufferSize):m_buffers(nBuffers,std::make_unique<std::vector<uint8_t>>(bufferSize)){
        // fill all buffers with random data
        int seqNr=0;
        std::mt19937 random_engine(seqNr);
        for(auto& buffer:m_buffers){
            random_engine.seed(seqNr);
            std::generate(buffer->data(),buffer->data()+buffer->size(),random_engine);
            //std::cout<<StringHelper::vectorAsString(*buffer.get())<<"\n\n";
            seqNr++;
        }
    }
    // get a semi-random data buffer for this sequence number. If the sequence number is higher than the n of allocated buffers,
    // it loops around. As long as this pot is big enough, it should be sufficient to emulate a random data stream
    std::shared_ptr<std::vector<uint8_t>> getBuffer(uint64_t sequenceNumber){
        auto index=sequenceNumber % m_buffers.size();
        return m_buffers.at(index);
    }
private:
    std::vector<std::shared_ptr<std::vector<uint8_t>>> m_buffers;
    //static constexpr const uint32_t SEED=12345;
};

#endif //WIFIBROADCAST_RANDOMBUFFERPOT_H
