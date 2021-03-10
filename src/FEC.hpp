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
// K primary and N-K secondary fragments together form a FEC block

// this header is written before the data of each primary FEC fragment
// ONLY for primary FEC fragments though ! (up to n bytes workaround)
class FECPrimaryFragmentHeader {
private:
    // private member to make sure it is always used properly
    uint16_t packet_size;
    //uint16_t packet_size : 15; // big endian | 15 bits packet size
    //bool isSecondaryFragment: 1 ;          //|  1 bit flag, set if this is a secondary (FEC) packet
public:
    explicit FECPrimaryFragmentHeader(const std::size_t packetSize1){
        //std::cout<<"packetS"<<packetSize1<<"\n";
        //assert(packetSize1<=pow(2,15));
        // convert to big endian if needed
        packet_size=htobe16(packetSize1);
        //packet_size=packetSize1;
    }
    // convert from big endian if needed
    std::size_t getPrimaryFragmentSize()const{
        return be16toh(packet_size);
        //return (std::size_t) packet_size;
    }
}  __attribute__ ((packed));
static_assert(sizeof(FECPrimaryFragmentHeader) == 2, "ALWAYS_TRUE");

// c++ wrapper for the FEC library
// If K and N were known at compile time we could make this much cleaner !
class FEC{
public:
    explicit FEC(int k, int n) : FEC_K(k), FEC_N(n){
        assert(n>=k);
        assert(n!=0);
        assert(k!=0);
    }
public:
    const int FEC_K;  // RS number of primary fragments in block default 8
    const int FEC_N;  // RS total number of fragments in block default 12
    const int N_PRIMARY_FRAGMENTS=FEC_K;
    const int N_SECONDARY_FRAGMENTS=FEC_N-FEC_K;
    // Helper functions
    // nonce:  56bit block_idx + 8bit fragment_idx
    static constexpr auto BLOCK_IDX_MASK=((1LLU << 56) - 1);
    static constexpr uint64_t MAX_BLOCK_IDX=((1LLU << 55) - 1);
    // conversion from / to nonce
    static uint64_t calculateNonce(const uint64_t blockIdx, const uint8_t fragmentIdx){
        assert(blockIdx <= MAX_BLOCK_IDX); // should never happen
        return htobe64(((blockIdx & BLOCK_IDX_MASK) << 8) + fragmentIdx);
    }
    static uint64_t calculateBlockIdx(const uint64_t nonce){
        return be64toh(nonce) >> 8;
    }
    static uint8_t calculateFragmentIdx(const uint64_t nonce){
        return (uint8_t) (be64toh(nonce) & 0xff);
    }
};

// 1510-(13+24+9+16+2)
//A: Any UDP with packet size <= 1466. For example x264 inside RTP or Mavlink.
static constexpr const auto FEC_MAX_PACKET_SIZE= WB_FRAME_MAX_PAYLOAD;
static constexpr const auto FEC_MAX_PAYLOAD_SIZE= WB_FRAME_MAX_PAYLOAD - sizeof(FECPrimaryFragmentHeader);
static_assert(FEC_MAX_PAYLOAD_SIZE == 1446);

// Takes a continuous stream of packets and
// encodes them via FEC such that they can be decoded by FECDecoder
// The encoding is slightly different from traditional FEC. It
// a) makes sure to send out data packets immediately
// b) Handles packets of size up to N instead of packets of exact size N
// Due to b) the packet size has to be written into the first two bytes of each data packet. See https://github.com/svpcom/wifibroadcast/issues/67
// use FEC_K==0 to completely skip FEC for the lowest latency possible
class FECEncoder{
public:
    typedef std::function<void(const uint64_t nonce,const uint8_t* payload,const std::size_t payloadSize)> OUTPUT_DATA_CALLBACK;
    OUTPUT_DATA_CALLBACK outputDataCallback;
    // TODO: So we have to be carefully here:
    // 1) If k,n is given: fixed packet size
    // 2) If k,n is not given, but we do variable k,(n) -> what to do ?
    explicit FECEncoder(int k, int n) : fec(k,n){
        fec_init();
        fragments.resize(fec.FEC_N);
        for (int i = 0; i < fec.FEC_N; i++) {
            fragments[i] = new uint8_t[FEC_MAX_PACKET_SIZE];
        }
    }
    ~FECEncoder() {
        for (int i = 0; i < fec.FEC_N; i++) {
            delete fragments[i];
        }
    }
    // K, N is fixed on the encoder side
    const FEC fec;
private:
    uint64_t currBlockIdx = 0; //block_idx << 8 + fragment_idx = nonce (64bit)
    uint8_t currFragmentIdx = 0;
    size_t currMaxPacketSize = 0;
    std::vector<uint8_t*> fragments;
    // Pre-allocated to hold all primary and secondary fragments
    //std::vector<std::array<uint8_t,FEC_MAX_PACKET_SIZE>> blockBuffer;
public:
    void encodePacket(const uint8_t *buf,const size_t size) {
        assert(size <= FEC_MAX_PAYLOAD_SIZE);

        FECPrimaryFragmentHeader dataHeader(size);
        // write the size of the data part into each primary fragment.
        // This is needed for the 'up to n bytes' workaround
        memcpy(fragments[currFragmentIdx], &dataHeader, sizeof(dataHeader));
        // write the actual data
        memcpy(fragments[currFragmentIdx] + sizeof(dataHeader), buf, size);
        // zero out the remaining bytes such that FEC always sees zeroes
        // same is done on the rx. These zero bytes are never transmitted via wifi
        const auto writtenDataSize= sizeof(FECPrimaryFragmentHeader) + size;
        memset(fragments[currFragmentIdx] + writtenDataSize, '\0', FEC_MAX_PACKET_SIZE - writtenDataSize);

        // send primary fragments immediately before calculating the FECs
        send_block_fragment(sizeof(dataHeader) + size);
        // the packet size for FEC encoding is determined by calculating the max of all primary fragments in this block.
        // Since the rest of the bytes are zeroed out we can run FEC with dynamic packet size.
        // As long as the deviation in packet size of primary fragments isn't too high the loss in raw bandwidth is negligible
        // Note,the loss in raw bandwidth comes from the size of the FEC secondary packets, which always has to be the max of all primary fragments
        // Not from the primary fragments, they are transmitted without the "zeroed out" part
        currMaxPacketSize = std::max(currMaxPacketSize, sizeof(dataHeader) + size);
        currFragmentIdx += 1;

        //std::cout<<"Fragment index is "<<(int)fragment_idx<<"FEC_K"<<(int)FEC_K<<"\n";
        if (currFragmentIdx < fec.FEC_K) {
            return;
        }
        // once enough data has been buffered, create all the secondary fragments
        std::vector<uint8_t*> primaryFragmentsList(fec.N_PRIMARY_FRAGMENTS);
        for(int i=0;i<fec.N_PRIMARY_FRAGMENTS;i++){
            primaryFragmentsList[i]=(fragments[i]);
        }
        //fecEncode((const uint8_t **) block, block + FEC_K, max_packet_size);
        fec_encode(currMaxPacketSize, (const unsigned char**)fragments.data(), fec.N_PRIMARY_FRAGMENTS, (unsigned char**)&fragments[fec.FEC_K], fec.N_SECONDARY_FRAGMENTS);
        //fecEncode(max_packet_size,fragments,N_PRIMARY_FRAGMENTS,N_SECONDARY_FRAGMENTS);

        // and send all the secondary fragments one after another
        while (currFragmentIdx < fec.FEC_N) {
            send_block_fragment(currMaxPacketSize);
            currFragmentIdx += 1;
        }
        currBlockIdx += 1;
        currFragmentIdx = 0;
        currMaxPacketSize = 0;
    }

    // returns true if the block_idx has reached its maximum
    // You want to send a new session key in this case
    bool resetOnOverflow() {
        if (currBlockIdx > FEC::MAX_BLOCK_IDX) {
            currBlockIdx = 0;
            currFragmentIdx=0;
            return true;
        }
        return false;
    }
    // add as many "empty packets" as needed until the block is done
    // if the block is already done,return immediately
    void finishCurrentBlock(){
        uint8_t emptyPacket[0];
        while(currFragmentIdx != 0){
            encodePacket(emptyPacket,0);
        }
    }
    // returns true if the last block was already fully processed.
    // in this case, you don't need to finish the current block until you put data in the next time
    // also, in the beginning the pipeline is already flushed due to no data packets yet
    bool isAlreadyInFinishedState()const{
        return currFragmentIdx == 0;
    }
private:
    // construct WB data packet, from either primary or secondary fragment
    // then forward via the callback
    void send_block_fragment(const std::size_t packet_size) const {
        const auto nonce=FEC::calculateNonce(currBlockIdx, currFragmentIdx);
        const uint8_t *dataP = fragments[currFragmentIdx];
        outputDataCallback(nonce,dataP,packet_size);
    }
};


// This encapsulates everything you need when working on a single FEC block on the receiver
// for example, addFragment() or pullAvailablePrimaryFragments()
// it also provides convenient methods to query if the block is fully forwarded
// or if it is ready for the FEC reconstruction step.
class RxBlock{
public:
    explicit RxBlock(const FEC& fec, const uint64_t blockIdx1):
    blockIdx(blockIdx1),fec(fec), fragment_map(fec.FEC_N, FragmentStatus::UNAVAILABLE), fragments(fec.FEC_N), originalSizeOfFragments(fec.FEC_N){
        nAlreadyForwardedPrimaryFragments = 0;
        nAvailablePrimaryFragments=0;
        nAvailableSecondaryFragments=0;
        // mark every fragment as not yet received
        std::fill(fragment_map.begin(),fragment_map.end(),FragmentStatus::UNAVAILABLE);
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
    bool hasFragment(const uint8_t fragmentIdx)const{
        return fragment_map[fragmentIdx]==AVAILABLE;
    }
    // returns true if we are "done with this block" aka all data has been already forwarded
    bool allPrimaryFragmentsHaveBeenForwarded()const{
        // never send out secondary fragments !
        assert(nAlreadyForwardedPrimaryFragments <= fec.FEC_K);
        return nAlreadyForwardedPrimaryFragments == fec.FEC_K;
    }
    // returns true if enough FEC secondary fragments are available to replace all missing primary fragments
    bool allPrimaryFragmentsCanBeRecovered()const{
        if(nAvailablePrimaryFragments+nAvailableSecondaryFragments>=fec.FEC_K)return true;
        return false;
    }
    // returns true if suddenly all primary fragments have become available
    bool allPrimaryFragmentsAreAvailable()const{
        return nAvailablePrimaryFragments==fec.FEC_K;
    }
    // copy the fragment data and mark it as available
    // you should check if it is already available with hasFragment() to avoid storing a fragment multiple times
    // when using multiple RX cards
    void addFragment(const uint8_t fragment_idx, const uint8_t* data,const std::size_t dataLen){
        assert(fragment_map[fragment_idx]==UNAVAILABLE);
        // write the data (doesn't matter if FEC data or correction packet)
        memcpy(fragments[fragment_idx].data(),data,dataLen);
        // set the rest to zero such that FEC works
        memset(fragments[fragment_idx].data()+dataLen, '\0', FEC_MAX_PACKET_SIZE - dataLen);
        // mark it as available
        fragment_map[fragment_idx] = RxBlock::AVAILABLE;
        // store the size of the received fragment for later use in the fec step
        originalSizeOfFragments[fragment_idx]=dataLen;
        if(fragment_idx<fec.FEC_K){
            nAvailablePrimaryFragments++;
        }else{
            nAvailableSecondaryFragments++;
        }
    }
    // returns the indices for all primary fragments that have not yet been forwarded and are available (already received or reconstructed). Once an index is returned here, it won't be returned again
    // (Therefore, as long as you immediately forward all primary fragments returned here,everything happens in order)
    // @param breakOnFirstGap : if true (default), stop on the first gap (missing packet). Else, keep going, skipping packets with gaps. Use this parameter if
    // you need to forward everything left on a block before getting rid of it.
    std::vector<uint8_t> pullAvailablePrimaryFragments(const bool breakOnFirstGap= true){
        std::vector<uint8_t> ret;
        for(int i=nAlreadyForwardedPrimaryFragments; i < fec.FEC_K; i++){
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
    const uint8_t* getDataPrimaryFragment(const uint8_t fragmentIdx){
        assert(fragmentIdx<fec.FEC_K);
        assert(fragment_map[fragmentIdx]==AVAILABLE);
        return fragments[fragmentIdx].data();
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
        assert(nAvailablePrimaryFragments+nAvailableSecondaryFragments>=fec.FEC_K);
        // also do not reconstruct if reconstruction is not needed
        assert(nAvailablePrimaryFragments<fec.FEC_K && nAvailableSecondaryFragments>0);
        // now bring it into a format that the c-style fec implementation understands
        std::vector<uint8_t*> primaryFragmentsData;
        std::vector<unsigned int> indicesMissingPrimaryFragments;
        for(int i=0;i<fec.FEC_K;i++){
            primaryFragmentsData.push_back(fragments[i].data());
            // if primary fragment is not available,add its index to the list of missing primary fragments
            if(fragment_map[i]!=AVAILABLE){
                indicesMissingPrimaryFragments.push_back(i);
            }
        }
        // each FEC packet has the size of max(size of primary fragments)
        std::size_t maxPacketSizeOfThisBlock=0;
        std::vector<uint8_t*> secondaryFragmentsData;
        std::vector<unsigned int> indicesAvailableSecondaryFragments;
        for(int i=0;i<fec.N_SECONDARY_FRAGMENTS;i++){
            const int idx=fec.FEC_K+i;
            secondaryFragmentsData.push_back(fragments[idx].data());
            // if secondary fragment is available,add its index to the list of secondary packets that will be used for reconstruction
            if(fragment_map[idx]==AVAILABLE){
                indicesAvailableSecondaryFragments.push_back(i);
                maxPacketSizeOfThisBlock=originalSizeOfFragments.at(idx);
            }
        }
        fec_decode(maxPacketSizeOfThisBlock, primaryFragmentsData.data(), fec.FEC_K, secondaryFragmentsData.data(), indicesAvailableSecondaryFragments.data(), indicesMissingPrimaryFragments.data(), indicesAvailableSecondaryFragments.size());
        // after the decode step,all previously missing primary fragments have become available - mark them as such
        for(const auto idx:indicesMissingPrimaryFragments){
            fragment_map[idx]=AVAILABLE;
        }
        // n of reconstructed packets
        return indicesMissingPrimaryFragments.size();
    }
    uint64_t getBlockIdx()const{
        return blockIdx;
    }
    uint64_t calculateSequenceNumber(uint8_t fragmentIdx)const{
        return fragmentIdx + blockIdx * fec.FEC_K;
    }
    std::chrono::steady_clock::time_point getCreationTime()const{
        return creationTime;
    }
private:
    //reference to the FEC decoder (needed for k,n). Doesn't change
    const FEC& fec;
    // the block idx marks which block this element refers to
    const uint64_t blockIdx=0;
    // n of primary fragments that are already sent out
    int nAlreadyForwardedPrimaryFragments=0;
    // for each fragment (via fragment_idx) store if it has been received yet
    enum FragmentStatus{UNAVAILABLE=0,AVAILABLE=1};
    // size of all these vectors is always FEC_N
    std::vector<FragmentStatus> fragment_map;
    // holds all the data for all received fragments (if fragment_map says UNAVALIABLE at this position, content is undefined)
    std::vector<std::array<uint8_t,FEC_MAX_PACKET_SIZE>> fragments;
    // holds the original size for all received fragments
    std::vector<std::size_t> originalSizeOfFragments;
    int nAvailablePrimaryFragments=0;
    int nAvailableSecondaryFragments=0;
    std::chrono::steady_clock::time_point creationTime;
};


// Takes a continuous stream of packets (data and fec correction packets) and
// processes them such that the output is exactly (or as close as possible) to the
// Input stream fed to FECEncoder.
// Most importantly, it also handles re-ordering of packets and packet duplicates due to multiple rx cards
class FECDecoder{
public:
    // If K,N is known at construction time
    FECDecoder(int k, int n):fec(k,n){
        fec_init();
    }
    ~FECDecoder() = default;
    typedef std::function<void(const uint8_t * payload,std::size_t payloadSize)> SEND_DECODED_PACKET;
    // WARNING: Don't forget to register this callback !
    SEND_DECODED_PACKET mSendDecodedPayloadCallback;
private:
    //K,N can change on the receiver side !
    //std::unique_ptr<FEC> fec=nullptr;
    const FEC fec;
public:
    // FEC K,N is fixed per session
    void resetNewSession() {
        seq = 0;
        // rx ring part. Remove anything still in the queue
        rx_queue.clear();
        last_known_block = (uint64_t) -1;
    }
    // returns false if the packet fragment index doesn't match the set FEC parameters (which should never happen !)
    bool validateAndProcessPacket(const uint64_t nonce, const std::vector<uint8_t>& decrypted){
        // normal FEC processing
        const uint64_t block_idx=FEC::calculateBlockIdx(nonce);
        const uint8_t fragment_idx=FEC::calculateFragmentIdx(nonce);

        // Should never happen due to generating new session key on tx side
        if (block_idx > FEC::MAX_BLOCK_IDX) {
            std::cerr<<"block_idx overflow\n";
            return false;
        }
        // fragment index must be in the range [0,...,FEC_N[
        if (fragment_idx >= fec.FEC_N) {
            std::cerr<<"invalid fragment_idx:"<<fragment_idx<<"\n";
            return false;
        }
        processFECBlockWitRxQueue(block_idx, fragment_idx, decrypted);
        return true;
    }
private:
    uint64_t seq = 0;
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
    void forwardPrimaryFragment(RxBlock& block, const uint8_t fragmentIdx){
        //std::cout<<"forwardPrimaryFragment("<<(int)block.getBlockIdx()<<","<<(int)fragmentIdx<<")\n";
        assert(block.hasFragment(fragmentIdx));
        const uint8_t* primaryFragment= block.getDataPrimaryFragment(fragmentIdx);
        const FECPrimaryFragmentHeader *packet_hdr = (FECPrimaryFragmentHeader*) primaryFragment;

        const uint8_t *payload = primaryFragment + sizeof(FECPrimaryFragmentHeader);
        const uint16_t packet_size = packet_hdr->getPrimaryFragmentSize();
        const uint64_t packet_seq = block.calculateSequenceNumber(fragmentIdx);

        if (packet_seq > seq + 1) {
            const auto packetsLost=(packet_seq - seq - 1);
            //std::cerr<<packetsLost<<"packets lost\n";
            count_p_lost += packetsLost;
        }
        seq = packet_seq;
        //std::cout<<block.getNAvailableFragments()<<" "<<block.nAvailablePrimaryFragments<<" "<<block.nAvailableSecondaryFragments<<"\n";
        //std::cout<<fec.N_PRIMARY_FRAGMENTS<<" "<<fec.N_SECONDARY_FRAGMENTS<<"\n";

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
public:
    // Here is everything you need when using the RX queue to account for packet re-ordering due to multiple wifi cards
    static constexpr auto RX_QUEUE_MAX_SIZE = 20;
private:
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
            rx_queue.push_back(std::make_unique<RxBlock>(fec, blockIdx));
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
        rx_queue.push_back(std::make_unique<RxBlock>(fec, blockIdx));
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


    void processFECBlockWitRxQueue(const uint64_t block_idx, const uint8_t fragment_idx, const std::vector<uint8_t>& decrypted){
        auto blockP= rxRingFindCreateBlockByIdx(block_idx);
        //ignore already processed blocks
        if (blockP==nullptr) return;
        // cannot be nullptr
        RxBlock& block = *blockP;
        // ignore already processed fragments
        if(block.hasFragment(fragment_idx)){
            return;
        }
        block.addFragment(fragment_idx, decrypted.data(), decrypted.size());
        if (block == *rx_queue.front()) {
            std::cout<<"In front\n";
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
    void forceForwardBlocksOlderThan(const std::chrono::nanoseconds& maxLatency){
        // loop through all blocks in queue. If we find a block that is older than N ms
        // "forward it" even though it is missing packets
        // get the age in nanoseconds of the currently "oldest" block
    }
public:
    uint64_t count_p_fec_recovered=0;
    uint64_t count_p_lost=0;
    //
};

// quick math regarding sequence numbers:
//uint32_t holds max 4294967295 . At 10 000 pps (packets per seconds) (which is already completely out of reach) this allows the tx to run for 429496.7295 seconds
// 429496.7295 / 60 / 60 = 119.304647083 hours which is also completely overkill for OpenHD (and after this time span, a "reset" of the sequence number happens anyways)
// unsigned 24 bits holds 16777215 . At 1000 blocks per second this allows the tx to create blocks for 16777.215 seconds or 4.6 hours. That should cover a flight (and after 4.6h a reset happens,
// which means you might lose a couple of blocks once every 4.6 h )
// and 8 bits holds max 255.

#endif //WIFIBROADCAST_FEC_HPP
