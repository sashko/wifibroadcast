//
// Created by consti10 on 02.12.20.
//

#ifndef WIFIBROADCAST_FEC_HPP
#define WIFIBROADCAST_FEC_HPP

#include "wifibroadcast.hpp"
#include "ExternalCSources/fec/fec.h"
#include "HelperSources/TimeHelper.hpp"
#include <cstdint>
#include <cerrno>
#include <string>
#include <utility>
#include <vector>
#include <array>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <functional>
#include <map>


// NOTE: When working with FEC, people seem to use the terms block, fragments and more in different context(s).
// I use (and highly recommend this to anyone else) the following notation:
// A primary fragment is a data packet
// A secondary fragment is a data correction (FEC) packet
// K primary and N-K secondary fragments together form a FEC block,
// On the rx though,for decoding, you don't need to know the n of secondary fragments
// created on the encoder - since it doesn't matter which secondary fragments you get,you either get "enough" for FEC step or "not enough" for FEC step

static_assert(__BYTE_ORDER == __LITTLE_ENDIAN,"This code is written for little endian only !");
// nonce: 64 bit value, consisting of
// 32 bit block idx
// 16 bit fragment idx
// 16 bit "extra data": 1 bit flag and 15 bit number
// flag==0: This is a primary fragment. If it is the last primary fragment for this block, number=n of all primary fragments in this block, else number=0
// flag==1: This is a secondary fragment. Then number== n of all primary fragments in this block
struct FECNonce{
    uint32_t blockIdx;
    uint16_t fragmentIdx;
    uint8_t flag:1;
    uint16_t number:15;
    explicit operator uint64_t()const {
        return *reinterpret_cast<const uint64_t*>(this);
    }
}__attribute__ ((packed));
static_assert(sizeof(FECNonce)==sizeof(uint64_t));
static FECNonce fecNonceFrom(const uint64_t nonce){
    return *reinterpret_cast<const FECNonce*>(&nonce);
}
static constexpr uint64_t MAX_BLOCK_IDX=std::numeric_limits<uint32_t>::max();

// this header is written before the data of each primary FEC fragment
// ONLY for primary FEC fragments though !
// (up to n bytes workaround,in conjunction with zeroing out bytes, but never transmitting the zeroed out bytes)
class FECPayloadHdr {
private:
    // private member to make sure it is always used properly
    uint16_t packet_size;
public:
    explicit FECPayloadHdr(const std::size_t packetSize1){
        assert(packetSize1<=std::numeric_limits<uint16_t>::max());
        // convert to big endian if needed
        packet_size=htobe16(packetSize1);
    }
    // convert from big endian if needed
    std::size_t getPrimaryFragmentSize()const{
        return be16toh(packet_size);
    }
}  __attribute__ ((packed));
static_assert(sizeof(FECPayloadHdr) == 2, "ALWAYS_TRUE");

// 1510-(13+24+9+16+2)
//A: Any UDP with packet size <= 1466. For example x264 inside RTP or Mavlink.
static constexpr const auto FEC_MAX_PACKET_SIZE= WB_FRAME_MAX_PAYLOAD;
static constexpr const auto FEC_MAX_PAYLOAD_SIZE= WB_FRAME_MAX_PAYLOAD - sizeof(FECPayloadHdr);
static_assert(FEC_MAX_PAYLOAD_SIZE == 1446);
// max 255 primary and secondary fragments together for now. Theoretically, this implementation has enough bytes in the header for
// up to 15 bit fragment indices, 2^15=32768
// Note: currently limited by the fec c implementation
static constexpr const uint16_t MAX_N_P_FRAGMENTS_PER_BLOCK=128;
static constexpr const uint16_t MAX_N_S_FRAGMENTS_PER_BLOCK=128;
static constexpr const uint16_t MAX_TOTAL_FRAGMENTS_PER_BLOCK=MAX_N_P_FRAGMENTS_PER_BLOCK+MAX_N_S_FRAGMENTS_PER_BLOCK;

// Takes a continuous stream of packets and
// encodes them via FEC such that they can be decoded by FECDecoder
// The encoding is slightly different from traditional FEC. It
// a) makes sure to send out data packets immediately
// b) Handles packets of size up to N instead of packets of exact size N
// Due to b) the packet size has to be written into the first two bytes of each data packet. See https://github.com/svpcom/wifibroadcast/issues/67
// c) allows ending a block at any time when putting in a new primary fragment
class FECEncoder{
public:
    typedef std::function<void(const uint64_t nonce,const uint8_t* payload,const std::size_t payloadSize)> OUTPUT_DATA_CALLBACK;
    OUTPUT_DATA_CALLBACK outputDataCallback;
    // If you want to use the encoder for a fixed k, just use k for K_MAX and never call
    // encodePacket(...,true).
    // Else, if you want to use the encoder for variable k, just use K_MAX=MAX_N_P_FRAGMENTS_PER_BLOCK and call
    // encodePacket(...,true) as needed.
    explicit FECEncoder(unsigned int K_MAX,unsigned int percentage):mKMax(K_MAX),mPercentage(percentage){
        std::cout<<"FEC with k max:"<<mKMax<<" and percentage:"<<percentage<<"\n";
        const auto tmp_n=calculateN(K_MAX,percentage);
        std::cout << "For a block size of k max this is (" << mKMax << ":" << tmp_n << ") in old (K:N) terms.\n";
        assert(K_MAX>0);
        assert(K_MAX<=MAX_N_P_FRAGMENTS_PER_BLOCK);
        assert(tmp_n <= MAX_TOTAL_FRAGMENTS_PER_BLOCK);
        fec_init();
        blockBuffer.resize(tmp_n);
    }
    FECEncoder(const FECEncoder& other)=delete;
private:
    uint32_t currBlockIdx = 0;
    uint16_t currFragmentIdx = 0;
    size_t currMaxPacketSize = 0;
    // Pre-allocated to hold all primary and secondary fragments
    std::vector<std::array<uint8_t,FEC_MAX_PACKET_SIZE>> blockBuffer;
    const unsigned int mKMax;
    const unsigned int mPercentage;
public:
    // encode packet such that it can be decoded by FECDecoder. Data is forwarded via the callback
    // if @param endBlock=true, the FEC step is applied immediately
    // else, the FEC step is only applied if reaching mKMax
    void encodePacket(const uint8_t *buf,const size_t size,const bool endBlock=false) {
        assert(size <= FEC_MAX_PAYLOAD_SIZE);

        FECPayloadHdr dataHeader(size);
        // write the size of the data part into each primary fragment.
        // This is needed for the 'up to n bytes' workaround
        memcpy(blockBuffer[currFragmentIdx].data(), &dataHeader, sizeof(dataHeader));
        // write the actual data
        memcpy(blockBuffer[currFragmentIdx].data() + sizeof(dataHeader), buf, size);
        // zero out the remaining bytes such that FEC always sees zeroes
        // same is done on the rx. These zero bytes are never transmitted via wifi
        const auto writtenDataSize= sizeof(FECPayloadHdr) + size;
        memset(blockBuffer[currFragmentIdx].data() + writtenDataSize, '\0', FEC_MAX_PACKET_SIZE - writtenDataSize);

        // check if we need to end the block right now (aka do FEC step on tx)
        const int currNPrimaryFragments=currFragmentIdx+1;
        // end block if we either reached mKMax or the caller requested it
        const bool lastPrimaryFragment=(currNPrimaryFragments==mKMax) || endBlock;

        sendPrimaryFragment(sizeof(dataHeader) + size,lastPrimaryFragment);
        // the packet size for FEC encoding is determined by calculating the max of all primary fragments in this block.
        // Since the rest of the bytes are zeroed out we can run FEC with dynamic packet size.
        // As long as the deviation in packet size of primary fragments isn't too high the loss in raw bandwidth is negligible
        // Note,the loss in raw bandwidth comes from the size of the FEC secondary packets, which always has to be the max of all primary fragments
        // Not from the primary fragments, they are transmitted without the "zeroed out" part
        currMaxPacketSize = std::max(currMaxPacketSize, sizeof(dataHeader) + size);
        currFragmentIdx += 1;
        // if this is not the last primary fragment, wo don't need to do anything else
        if(!lastPrimaryFragment){
            return;
        }
        //std::cout<<"Doing FEC step on block size"<<currNPrimaryFragments<<"\n";
        // prepare for the fec step
        const auto nSecondaryFragments=currNPrimaryFragments*mPercentage/100;
        //std::cout<<"Creating block ("<<currNPrimaryFragments<<":"<<currNPrimaryFragments+nSecondaryFragments<<")\n";

        // once enough data has been buffered, create all the secondary fragments
        fecEncode(currMaxPacketSize,blockBuffer,currNPrimaryFragments,nSecondaryFragments);
        // and send them all out
        while (currFragmentIdx<currNPrimaryFragments + nSecondaryFragments){
            sendSecondaryFragment(currMaxPacketSize,currNPrimaryFragments);
            currFragmentIdx += 1;
        }

        currBlockIdx += 1;
        currFragmentIdx = 0;
        currMaxPacketSize = 0;
    }

    // returns true if the block_idx has reached its maximum
    // You want to send a new session key in this case
    bool resetOnOverflow() {
        if (currBlockIdx > MAX_BLOCK_IDX) {
            currBlockIdx = 0;
            currFragmentIdx=0;
            return true;
        }
        return false;
    }
    // returns true if the last block was already fully processed.
    // in this case, you don't need to finish the current block until you put data in the next time
    // also, in the beginning the pipeline is already flushed due to no data packets yet
    bool isAlreadyInFinishedState()const{
        return currFragmentIdx == 0;
    }
    // calculate n from k and percentage as used in FEC terms
    static unsigned int calculateN(const unsigned int k,const unsigned int percentage){
        return k+(k*percentage/100);
    }
private:
    // calculate proper nonce (such that the rx can decode it properly), then forward via callback
    void sendPrimaryFragment(const std::size_t packet_size,const bool isLastPrimaryFragment){
        // remember we start counting from 0 not 1
        const FECNonce nonce{currBlockIdx,currFragmentIdx,false,(uint16_t)(isLastPrimaryFragment ? (currFragmentIdx+1) : 0)};
        const uint8_t *dataP = blockBuffer[currFragmentIdx].data();
        outputDataCallback((uint64_t)nonce,dataP,packet_size);
        //std::cout<<"Lol1"<<(int)nonce.fragmentIdx<<" \n";
    }
    // calculate proper nonce (such that the rx can decode it properly), then forward via callback
    void sendSecondaryFragment(const std::size_t packet_size,const int nPrimaryFragments){
        const FECNonce nonce{currBlockIdx,currFragmentIdx,true,(uint16_t)nPrimaryFragments};
        const uint8_t *dataP = blockBuffer[currFragmentIdx].data();
        outputDataCallback((uint64_t)nonce,dataP,packet_size);
    }
};


// This encapsulates everything you need when working on a single FEC block on the receiver
// for example, addFragment() or pullAvailablePrimaryFragments()
// it also provides convenient methods to query if the block is fully forwarded
// or if it is ready for the FEC reconstruction step.
class RxBlock{
public:
    // @param maxNFragmentsPerBlock max number of primary and secondary fragments for this block.
    // you could just use MAX_TOTAL_FRAGMENTS_PER_BLOCK for that, but if your tx then uses (4:8) for example, you'd
    // allocate much more memory every time for a new RX block than needed.
    explicit RxBlock(const unsigned int maxNFragmentsPerBlock,const uint64_t blockIdx1):
            blockIdx(blockIdx1),
            fragment_map(maxNFragmentsPerBlock, FragmentStatus::UNAVAILABLE), //after creation of the RxBlock every f. is marked as unavailable
            blockBuffer(maxNFragmentsPerBlock){
        creationTime=std::chrono::steady_clock::now();
    }
    // No copy constructor for safety
    RxBlock(const RxBlock&)=delete;
    // two blocks are the same if they refer to the same block idx:
    constexpr bool operator==(const RxBlock& other)const{
        return blockIdx==other.blockIdx;
    }
    // same for not equal operator
    constexpr bool operator!=(const RxBlock& other)const{
        return !(*this==other);
    }
    ~RxBlock()= default;
public:
    // returns true if the fragment at position fragmentIdx has been already received
    bool hasFragment(const uint16_t fragmentIdx)const{
        return fragment_map[fragmentIdx]==AVAILABLE;
    }
    // returns true if we are "done with this block" aka all data has been already forwarded
    bool allPrimaryFragmentsHaveBeenForwarded()const{
        if(fec_k==-1)return false;
        // never send out secondary fragments !
        assert(nAlreadyForwardedPrimaryFragments <= fec_k);
        return nAlreadyForwardedPrimaryFragments == fec_k;
    }
    // returns true if enough FEC secondary fragments are available to replace all missing primary fragments
    bool allPrimaryFragmentsCanBeRecovered()const{
        // return false if k is not known for this block yet
        if(fec_k==-1)return false;
        // ready for FEC step if we have as many secondary fragments as we are missing on primary fragments
        if(nAvailablePrimaryFragments+nAvailableSecondaryFragments>=fec_k)return true;
        return false;
    }
    // returns true if suddenly all primary fragments have become available
    bool allPrimaryFragmentsAreAvailable()const{
        if(fec_k==-1)return false;
        return nAvailablePrimaryFragments==fec_k;
    }
    // copy the fragment data and mark it as available
    // you should check if it is already available with hasFragment() to avoid storing a fragment multiple times
    // when using multiple RX cards
    void addFragment(const FECNonce fecNonce, const uint8_t* data,const std::size_t dataLen){
        assert(fecNonce.blockIdx==blockIdx);
        assert(fragment_map[fecNonce.fragmentIdx]==UNAVAILABLE);
        assert(fecNonce.blockIdx<=MAX_BLOCK_IDX);
        //std::cout<<"LOL "<<(int)fecNonce.fragmentIdx<<"\n";
        assert(fecNonce.fragmentIdx<blockBuffer.size());
        // write the data (doesn't matter if FEC data or correction packet)
        memcpy(blockBuffer[fecNonce.fragmentIdx].data(), data, dataLen);
        // set the rest to zero such that FEC works
        memset(blockBuffer[fecNonce.fragmentIdx].data() + dataLen, '\0', FEC_MAX_PACKET_SIZE - dataLen);
        // mark it as available
        fragment_map[fecNonce.fragmentIdx] = RxBlock::AVAILABLE;
        if(fecNonce.flag==0){
            nAvailablePrimaryFragments++;
            // when we receive the last primary fragment for this block we know the "K" parameter
            if(fecNonce.number!=0 ){
                fec_k=fecNonce.number;
                //std::cout<<"K is known now(P)"<<fec_k<<"\n";
            }
        }else{
            nAvailableSecondaryFragments++;
            // when we receive any secondary fragment we now know k for this block
            if(fec_k==-1){
                fec_k=fecNonce.number;
                //std::cout<<"K is known now(S)"<<fec_k<<"\n";
            }else{
                assert(fec_k==fecNonce.number);
            }
            // and we also know the packet size used for the FEC step
            if(sizeOfSecondaryFragments==-1){
                sizeOfSecondaryFragments=dataLen;
            }else{
                assert(sizeOfSecondaryFragments==dataLen);
            }
        }
        //std::cout<<"D:"<<fecNonce.blockIdx<<" "<<fecNonce.fragmentIdx<<" "<<(int)fecNonce.flag<<" "<<(int)fecNonce.number<<"\n";
    }
    // returns the indices for all primary fragments that have not yet been forwarded and are available (already received or reconstructed). Once an index is returned here, it won't be returned again
    // (Therefore, as long as you immediately forward all primary fragments returned here,everything happens in order)
    // @param breakOnFirstGap : if true (default), stop on the first gap (missing packet). Else, keep going, skipping packets with gaps. Use this parameter if
    // you need to forward everything left on a block before getting rid of it.
    std::vector<uint16_t> pullAvailablePrimaryFragments(const bool breakOnFirstGap= true){
        // note: when pulling the available fragments, we do not need to know how many primary fragments this block actually contains
        std::vector<uint16_t> ret;
        for(int i=nAlreadyForwardedPrimaryFragments; i < nAvailablePrimaryFragments; i++){
            if(!hasFragment(i)){
                if(breakOnFirstGap){
                    break;
                }else{
                    continue;
                }
            }
            ret.push_back(i);
        }
        // make sure these indices won't be returned again
        nAlreadyForwardedPrimaryFragments+=(int)ret.size();
        return ret;
    }
    const uint8_t* getDataPrimaryFragment(const uint16_t fragmentIdx){
        assert(fragment_map[fragmentIdx]==AVAILABLE);
        return blockBuffer[fragmentIdx].data();
    }
    int getNAvailableFragments()const{
        return nAvailablePrimaryFragments+nAvailableSecondaryFragments;
    }
    // make sure to check if enough secondary fragments are available before calling this method !
    // reconstructing only part of the missing data is not supported !
    // return: the n of reconstructed packets
    int reconstructAllMissingData(){
        //std::cout<<"reconstructAllMissingData"<<nAvailablePrimaryFragments<<" "<<nAvailableSecondaryFragments<<" "<<fec.FEC_K<<"\n";
        // NOTE: FEC does only work if nPrimaryFragments+nSecondaryFragments>=FEC_K
        assert(fec_k!=-1);
        assert(nAvailablePrimaryFragments+nAvailableSecondaryFragments>=fec_k);
        // also do not reconstruct if reconstruction is not needed
        assert(nAvailablePrimaryFragments<fec_k);
        assert(nAvailableSecondaryFragments>0);
        assert(sizeOfSecondaryFragments!=-1);
        // now bring it into a format that the c-style fec implementation understands
        std::vector<unsigned int> indicesMissingPrimaryFragments;
        for(int i=0;i<fec_k;i++){
            // if primary fragment is not available,add its index to the list of missing primary fragments
            if(fragment_map[i]!=AVAILABLE){
                indicesMissingPrimaryFragments.push_back(i);
            }
        }
        std::vector<unsigned int> indicesAvailableSecondaryFragments;
        for(int i=0;i<nAvailableSecondaryFragments;i++){
            const auto idx=fec_k+i;
            // if secondary fragment is available,add its index to the list of secondary packets that will be used for reconstruction
            if(fragment_map[idx]==AVAILABLE){
                indicesAvailableSecondaryFragments.push_back(i);
            }
        }
        fecDecode(sizeOfSecondaryFragments, blockBuffer, fec_k, indicesMissingPrimaryFragments, indicesAvailableSecondaryFragments);
        // after the decode step,all previously missing primary fragments have become available - mark them as such
        for(const auto idx:indicesMissingPrimaryFragments){
            fragment_map[idx]=AVAILABLE;
        }
        nAvailablePrimaryFragments+=indicesMissingPrimaryFragments.size();
        // n of reconstructed packets
        return indicesMissingPrimaryFragments.size();
    }
    uint64_t getBlockIdx()const{
        return blockIdx;
    }
private:
    // the block idx marks which block this element refers to
    const uint64_t blockIdx=0;
    // n of primary fragments that are already pulled out
    int nAlreadyForwardedPrimaryFragments=0;
    // for each fragment (via fragment_idx) store if it has been received yet
    enum FragmentStatus{UNAVAILABLE=0,AVAILABLE=1};
    std::vector<FragmentStatus> fragment_map;
    // holds all the data for all received fragments (if fragment_map says UNAVALIABLE at this position, content is undefined)
    std::vector<std::array<uint8_t,FEC_MAX_PACKET_SIZE>> blockBuffer;
    int nAvailablePrimaryFragments=0;
    int nAvailableSecondaryFragments=0;
    std::chrono::steady_clock::time_point creationTime;
    // we don't know how many primary fragments this block contains until we either receive the last primary fragment for this block
    // or receive any secondary fragment.
    int fec_k=-1;
    // for the fec step, we need the size of the fec secondary fragments, which should be equal for all secondary fragments
    int sizeOfSecondaryFragments=-1;
};


// Takes a continuous stream of packets (data and fec correction packets) and
// processes them such that the output is exactly (or as close as possible) to the
// Input stream fed to FECEncoder.
// Most importantly, it also handles re-ordering of packets and packet duplicates due to multiple rx cards
class FECDecoder{
public:
    // Does not need to know k,n or if tx does variable block length or not.
    // If the tx doesn't use the full range of fragment indices (aka K is fixed) use
    // @param maxNFragmentsPerBlock for a more efficient memory usage
    explicit FECDecoder(const unsigned int maxNFragmentsPerBlock=MAX_TOTAL_FRAGMENTS_PER_BLOCK):maxNFragmentsPerBlock(maxNFragmentsPerBlock){
        fec_init();
    }
    FECDecoder(const FECDecoder& other)=delete;
    ~FECDecoder() = default;
    typedef std::function<void(const uint8_t * payload,std::size_t payloadSize)> SEND_DECODED_PACKET;
    // WARNING: Don't forget to register this callback !
    SEND_DECODED_PACKET mSendDecodedPayloadCallback;
    // A value too high doesn't really give much benefit and increases memory usage
    static constexpr auto RX_QUEUE_MAX_SIZE = 20;
    const unsigned int maxNFragmentsPerBlock;
public:
    // returns false if the packet fragment index doesn't match the set FEC parameters (which should never happen !)
    bool validateAndProcessPacket(const uint64_t nonce, const std::vector<uint8_t>& decrypted){
        // normal FEC processing
        const FECNonce fecNonce=fecNonceFrom(nonce);

        // Should never happen due to generating new session key on tx side
        if (fecNonce.blockIdx > MAX_BLOCK_IDX) {
            std::cerr<<"block_idx overflow\n";
            return false;
        }
        if(fecNonce.fragmentIdx>maxNFragmentsPerBlock){
            std::cerr<<"invalid fragment_idx:"<<fecNonce.fragmentIdx<<"\n";
            return false;
        }
        processFECBlockWitRxQueue(fecNonce, decrypted);
        return true;
    }
private:
    /**
     * For this Block,
     * starting at the primary fragment we stopped on last time,
     * forward as many primary fragments as they are available until there is a gap
     * @param breakOnFirstGap : if true, stop on the first gap in all primary fragments. Else, keep going skipping packets with gaps
     */
    void forwardMissingPrimaryFragmentsIfAvailable(RxBlock& block, const bool breakOnFirstGap= true){
        const auto indices=block.pullAvailablePrimaryFragments(breakOnFirstGap);
        for(auto index:indices){
            forwardPrimaryFragment(block, index);
        }
    }
    /**
     * Forward the primary (data) fragment at index fragmentIdx via the output callback
     */
    void forwardPrimaryFragment(RxBlock& block, const uint16_t fragmentIdx)const{
        //std::cout<<"forwardPrimaryFragment("<<(int)block.getBlockIdx()<<","<<(int)fragmentIdx<<")\n";
        assert(block.hasFragment(fragmentIdx));
        const uint8_t* primaryFragment= block.getDataPrimaryFragment(fragmentIdx);
        const FECPayloadHdr &packet_hdr = *(FECPayloadHdr*) primaryFragment;

        const uint8_t *payload = primaryFragment + sizeof(FECPayloadHdr);
        const auto packet_size = packet_hdr.getPrimaryFragmentSize();

        if (packet_size > FEC_MAX_PAYLOAD_SIZE) {
            // this should never happen !
            std::cerr<<"corrupted packet on FECDecoder out ("<<block.getBlockIdx()<<":"<<(int)fragmentIdx<<") : "<<packet_size<<"B\n";
        } else {
            // we use packets of size 0 to flush the tx pipeline
            if(packet_size>0){
                mSendDecodedPayloadCallback(payload, packet_size);
            }
        }
    }
    // since we also need to search this data structure, a std::queue is not enough.
    // since we have an upper limit on the size of this dequeue, it is basically a searchable ring buffer
    std::deque<std::unique_ptr<RxBlock>> rx_queue;
    uint64_t last_known_block = ((uint64_t) -1);  //id of last known block

    // create a new RxBlock for the specified block_idx and push it into the queue
    // NOTE: Checks first if this operation would increase the size of the queue over its max capacity
    // In this case, the only solution is to remove the oldest block before adding the new one
    void rxRingCreateNewSafe(const uint64_t blockIdx){
        // check: make sure to always put blocks into the queue in order !
        if(!rx_queue.empty()){
            // the newest block in the queue should be equal to block_idx -1
            assert(rx_queue.back()->getBlockIdx() == (blockIdx - 1));
        }
        // we can return early if this operation doesn't exceed the size limit
        if(rx_queue.size() < RX_QUEUE_MAX_SIZE){
            rx_queue.push_back(std::make_unique<RxBlock>(maxNFragmentsPerBlock,blockIdx));
            return;
        }
        //Ring overflow. This means that there are more unfinished blocks than ring size
        //Possible solutions:
        //1. Increase ring size. Do this if you have large variance of packet travel time throught WiFi card or network stack.
        //   Some cards can do this due to packet reordering inside, diffent chipset and/or firmware or your RX hosts have different CPU power.
        //2. Reduce packet injection speed or try to unify RX hardware.

        // forward remaining data for the (oldest) block, since we need to get rid of it
        auto& oldestBlock=rx_queue.front();
        std::cerr<<"Forwarding block that is not yet fully finished "<<oldestBlock->getBlockIdx()<<" with n fragments"<<oldestBlock->getNAvailableFragments()<<"\n";
        forwardMissingPrimaryFragmentsIfAvailable(*oldestBlock,false);
        // and remove the block once done with it
        rx_queue.pop_front();

        // now we are guaranteed to have space for one new block
        rx_queue.push_back(std::make_unique<RxBlock>(maxNFragmentsPerBlock,blockIdx));
    }

    // If block is already known and not in the queue anymore return nullptr
    // else if block is inside the ring return pointer to it
    // and if it is not inside the ring add as many blocks as needed, then return pointer to it
    RxBlock* rxRingFindCreateBlockByIdx(const uint64_t blockIdx) {
        // check if block is already in the ring
        auto found=std::find_if(rx_queue.begin(), rx_queue.end(),
                                [&blockIdx](const std::unique_ptr<RxBlock>& block) { return block->getBlockIdx() == blockIdx;});
        if(found != rx_queue.end()){
            return found->get();
        }
        // check if block is already known and not in the ring then it is already processed
        if (last_known_block != (uint64_t) -1 && blockIdx <= last_known_block) {
            return nullptr;
        }

        // add as many blocks as we need ( the rx ring mustn't have any gaps between the block indices).
        // but there is no point in adding more blocks than RX_RING_SIZE
        const int new_blocks = (int) std::min(last_known_block != (uint64_t) -1 ? blockIdx - last_known_block : 1,
                                              (uint64_t) FECDecoder::RX_QUEUE_MAX_SIZE);
        last_known_block = blockIdx;

        for(int i=0;i<new_blocks;i++){
            rxRingCreateNewSafe(blockIdx + i +1 - new_blocks);
        }
        // the new block we've added is now the most recently added element (and since we always push to the back, the "back()" element)
        assert(rx_queue.back()->getBlockIdx()==blockIdx);
        return rx_queue.back().get();
    }


    void processFECBlockWitRxQueue(const FECNonce& fecNonce, const std::vector<uint8_t>& decrypted){
        auto blockP= rxRingFindCreateBlockByIdx(fecNonce.blockIdx);
        //ignore already processed blocks
        if (blockP==nullptr) return;
        // cannot be nullptr
        RxBlock& block = *blockP;
        // ignore already processed fragments
        if(block.hasFragment(fecNonce.fragmentIdx)){
            return;
        }
        block.addFragment(fecNonce, decrypted.data(), decrypted.size());
        if (block == *rx_queue.front()) {
            //std::cout<<"In front\n";
            // we are in the front of the queue (e.g. at the oldest block)
            // forward packets until the first gap
            forwardMissingPrimaryFragmentsIfAvailable(block);
            // We are done with this block if either all fragments have been forwarded or it can be recovered
            if(block.allPrimaryFragmentsHaveBeenForwarded()){
                // remove block when done with it
                rx_queue.pop_front();
                return;
            }
            if(block.allPrimaryFragmentsCanBeRecovered()){
                count_p_fec_recovered+=block.reconstructAllMissingData();
                forwardMissingPrimaryFragmentsIfAvailable(block);
                assert(block.allPrimaryFragmentsHaveBeenForwarded());
                // remove block when done with it
                rx_queue.pop_front();
                return;
            }
            return;
        }else{
            //std::cout<<"Not in front\n";
            // we are not in the front of the queue but somewhere else
            // If this block can be fully recovered or all primary fragments are available this triggers a flush
            if(block.allPrimaryFragmentsAreAvailable() || block.allPrimaryFragmentsCanBeRecovered()){
                // send all queued packets in all unfinished blocks before and remove them
                while(block != *rx_queue.front()){
                    forwardMissingPrimaryFragmentsIfAvailable(*rx_queue.front(), false);
                    rx_queue.pop_front();
                }
                // then process the block who is fully recoverable or has no gaps in the primary fragments
                if(block.allPrimaryFragmentsAreAvailable()){
                    forwardMissingPrimaryFragmentsIfAvailable(block);
                    assert(block.allPrimaryFragmentsHaveBeenForwarded());
                }else{
                    // apply fec for this block
                    count_p_fec_recovered+=block.reconstructAllMissingData();
                    forwardMissingPrimaryFragmentsIfAvailable(block);
                    assert(block.allPrimaryFragmentsHaveBeenForwarded());
                }
                // remove block
                rx_queue.pop_front();
            }
        }
    }
public:
    void decreaseRxRingSize(int newSize){
        std::cout << "Decreasing ring size from " << rx_queue.size() << "to " << newSize << "\n";
        while(rx_queue.size() >newSize){
            forwardMissingPrimaryFragmentsIfAvailable(*rx_queue.front(), false);
            rx_queue.pop_front();
        }
    }
    // By doing so you are telling the pipeline:
    // It makes no sense to hold on to any blocks. Future packets won't help you to recover any blocks that might still be in the pipeline
    // For example, if the RX doesn't receive anything for N ms any data that is going to arrive will not have a smaller or equal block index than the blocks that are currently in the queue
    void flushRxRing(){
       decreaseRxRingSize(0);
    }
public:
    uint64_t count_p_fec_recovered=0;
    uint64_t count_p_lost=0;
    //
    uint64_t count_blocks_lost_full=0;
    uint64_t count_blocks_lost_partial=0;
    uint64_t count_blocks_recovered=0;
};

// quick math regarding sequence numbers:
//uint32_t holds max 4294967295 . At 10 000 pps (packets per seconds) (which is already completely out of reach) this allows the tx to run for 429496.7295 seconds
// 429496.7295 / 60 / 60 = 119.304647083 hours which is also completely overkill for OpenHD (and after this time span, a "reset" of the sequence number happens anyways)
// unsigned 24 bits holds 16777215 . At 1000 blocks per second this allows the tx to create blocks for 16777.215 seconds or 4.6 hours. That should cover a flight (and after 4.6h a reset happens,
// which means you might lose a couple of blocks once every 4.6 h )
// and 8 bits holds max 255.

#endif //WIFIBROADCAST_FEC_HPP
