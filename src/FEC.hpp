//
// Created by consti10 on 19.03.21.
//

#ifndef WIFIBROADCAST_FEC_H
#define WIFIBROADCAST_FEC_H

#include <vector>
#include <array>
#include "HelperSources/Helper.hpp"
//#include "ExternalCSources/fecz/fec.h"
#include "ExternalCSources/fec/fec.h"



// c++ wrapper around fec library
// NOTE: When working with FEC, people seem to use the terms block, fragments and more in different context(s).
// To avoid confusion,I decided to use the following notation:
// A block is formed by K primary and N-K secondary fragments. Each of these fragments must have the same size.
// Therefore,
// fragmentSize is the size of each fragment in this block (for some reason, this is called blockSize in the underlying c fec implementation).
// A primary fragment is a data packet
// A secondary fragment is a data correction (FEC) packet
// Note: for the fec_decode() step, it doesn't matter how many secondary fragments were created during the fec_encode() step -
// only thing that matters is how many secondary fragments you received (either enough for fec_decode() or not enough for fec_decode() )
// Also note: you obviously cannot use the same secondary fragment more than once

/**
 * @param fragmentSize size of each fragment in this block
 * @param primaryFragments list of pointers to memory for primary fragments
 * @param secondaryFragments list of pointers to memory for secondary fragments (fec fragments)
 * Using the data from @param primaryFragments constructs as many secondary fragments as @param secondaryFragments holds
 */
void fec_encode(unsigned int fragmentSize,
                std::vector<uint8_t*> primaryFragments,
                std::vector<uint8_t*> secondaryFragments){
    fec_encode(fragmentSize, (unsigned char**)primaryFragments.data(), primaryFragments.size(), (unsigned char**)secondaryFragments.data(), secondaryFragments.size());
}

/**
 * @param fragmentSize size of each fragment in this block
 * @param primaryFragments list of pointers to memory for primary fragments. Must be same size as used for fec_encode()
 * @param indicesMissingPrimaryFragments list of the indices of missing primary fragments.
 * Example: if @param indicesMissingPrimaryFragments contains 2, the 3rd primary fragment is missing
 * @param secondaryFragments list of pointers to memory for secondary fragments (fec fragments). Must not be same size as used for fec_encode(), only MUST contain "enough" secondary fragments
 * @param indicesAvailableSecondaryFragments list of the indices of secondaryFragments that are used to reconstruct missing primary fragments.
 * Example: if @param indicesAvailableSecondaryFragments contains {0,2}, the first secondary fragment has the index 0, and the second secondary fragment has the index 2
 * When this call returns, all missing primary fragments (gaps) have been filled / reconstructed
 */
void fec_decode(unsigned int fragmentSize,
                std::vector<uint8_t*> primaryFragments,
                std::vector<unsigned int> indicesMissingPrimaryFragments,
                std::vector<uint8_t*> secondaryFragments,
                std::vector<unsigned int> indicesAvailableSecondaryFragments,bool fix=false){
    assert(indicesMissingPrimaryFragments.size() <= indicesAvailableSecondaryFragments.size());
    //assert(secondaryFragments.size()==indicesAvailableSecondaryFragments.size());
    std::cout<<"primaryFragmentsS:"<<primaryFragments.size()<<"\n";
    std::cout<<"secondaryFragmentsS:"<<secondaryFragments.size()<<"\n";
    std::cout<<"indicesMissingPrimaryFragments:"<<StringHelper::vectorAsString(indicesMissingPrimaryFragments)<<"\n";
    std::cout<<"indicesAvailableSecondaryFragments:"<<StringHelper::vectorAsString(indicesAvailableSecondaryFragments)<<"\n";
    for(const auto& idx:indicesMissingPrimaryFragments){
        assert(idx<primaryFragments.size());
    }
    if(fix){
        for(const auto& idx:indicesAvailableSecondaryFragments){
            assert(idx<secondaryFragments.size());
        }
        std::vector<uint8_t*> secondaryFragmentsAdj;
        for(const auto & idx:indicesAvailableSecondaryFragments){
            secondaryFragmentsAdj.push_back(secondaryFragments[idx]);
        }
        fec_decode(fragmentSize, (unsigned char**)primaryFragments.data(), primaryFragments.size(), (unsigned char**)secondaryFragmentsAdj.data(),
                   (unsigned int*)indicesAvailableSecondaryFragments.data(), (unsigned int*)indicesMissingPrimaryFragments.data(), indicesMissingPrimaryFragments.size());
    }else{
        assert(indicesMissingPrimaryFragments.size()==secondaryFragments.size());
        assert(secondaryFragments.size()==indicesAvailableSecondaryFragments.size());
        fec_decode(fragmentSize, (unsigned char**)primaryFragments.data(), primaryFragments.size(), (unsigned char**)secondaryFragments.data(),
                   (unsigned int*)indicesAvailableSecondaryFragments.data(), (unsigned int*)indicesMissingPrimaryFragments.data(), indicesMissingPrimaryFragments.size());
    }
}


template<std::size_t S>
void fec_decode2_available(unsigned int fragmentSize,
                           std::vector<std::array<uint8_t,S>>& pf,std::vector<unsigned int> indicesAvailablePrimaryFragments,
                           std::vector<std::array<uint8_t,S>>& sf,std::vector<unsigned int> indicesAvailableSecondaryFragments){
    auto indicesMissingPrimaryFragments=GenericHelper::findMissingIndices(indicesAvailablePrimaryFragments,pf.size());
    fec_decode(fragmentSize, GenericHelper::convertToP(pf),indicesMissingPrimaryFragments, GenericHelper::convertToP(sf), indicesAvailableSecondaryFragments,true);
}



//Note: By using "blockBuffer" as input the fecEncode / fecDecode function(s) don't need to allocate any new memory.
// The "blockBuffer" can be either at least as big as needed or bigger, implementation doesn't care


/**
 * @param packetSize size of each fragment to use for the FEC encoding step. FEC only works on packets the same size
 * @param blockBuffer (big) data buffer. The nth element is to be treated as the nth fragment of the block, either as primary or secondary fragment.
 * During the FEC step, @param nPrimaryFragments fragments are used to calculate nSecondaryFragments FEC blocks.
 * After the FEC step,beginning at position @param nPrimaryFragments ,@param nSecondaryFragments are stored at the following positions, each of size @param fragmentSize
 */
template<std::size_t S>
void fecEncode(unsigned int fragmentSize, std::vector<std::array<uint8_t,S>>& blockBuffer, unsigned int nPrimaryFragments, unsigned int nSecondaryFragments){
    assert(fragmentSize <= S);
    assert(nPrimaryFragments+nSecondaryFragments<=blockBuffer.size());
    auto primaryFragmentsP= GenericHelper::convertToP(blockBuffer,0,nPrimaryFragments);
    auto secondaryFragmentsP=GenericHelper::convertToP(blockBuffer,nPrimaryFragments,blockBuffer.size()-nPrimaryFragments);
    secondaryFragmentsP.resize(nSecondaryFragments);
    fec_encode(fragmentSize, primaryFragmentsP, secondaryFragmentsP);
}

enum FragmentStatus{UNAVAILABLE=0,AVAILABLE=1};

/**
 * @param fragmentSize size of each fragment
 * @param blockBuffer blockBuffer (big) data buffer. The nth element is to be treated as the nth fragment of the block, either as primary or secondary fragment.
 * @param nPrimaryFragments n of primary fragments used during encode step
 * @param fragmentStatusList information which (primary or secondary fragments) were received.
 * values from [0,nPrimaryFragments[ are treated as primary fragments, values from [nPrimaryFragments,size[ are treated as secondary fragments.
 * @return
 */
template<std::size_t S>
std::vector<unsigned int> fecDecode(unsigned int fragmentSize, std::vector<std::array<uint8_t,S>>& blockBuffer, const unsigned int nPrimaryFragments, const std::vector<FragmentStatus>& fragmentStatusList){
    assert(fragmentSize <= S);
    assert(fragmentStatusList.size() <= blockBuffer.size());
    assert(fragmentStatusList.size()==blockBuffer.size());
    std::vector<unsigned int> indicesMissingPrimaryFragments;
    std::vector<uint8_t*> primaryFragmentP(nPrimaryFragments);
    for(unsigned int idx=0;idx<nPrimaryFragments;idx++){
        if(fragmentStatusList[idx] == UNAVAILABLE){
            indicesMissingPrimaryFragments.push_back(idx);
        }
        primaryFragmentP[idx]=blockBuffer[idx].data();
    }
    //
    std::vector<uint8_t*> secondaryFragmentP;
    std::vector<unsigned int> secondaryFragmentIndices;
    for(int i=0; i < fragmentStatusList.size() - nPrimaryFragments; i++) {
        const auto idx = nPrimaryFragments + i;
        if(fragmentStatusList[idx] == AVAILABLE){
            secondaryFragmentP.push_back(blockBuffer[idx].data());
            secondaryFragmentIndices.push_back(i);
        }
    }
    // make sure we got enough secondary fragments
    assert(secondaryFragmentP.size()>=indicesMissingPrimaryFragments.size());
    // assert if fecDecode is called too late (e.g. more secondary fragments than needed for fec
    assert(indicesMissingPrimaryFragments.size()==secondaryFragmentP.size());
    // do fec step
    fec_decode(fragmentSize,primaryFragmentP,indicesMissingPrimaryFragments,secondaryFragmentP,secondaryFragmentIndices);
    return indicesMissingPrimaryFragments;
}

// randomly select a possible combination of received indices (either primary or secondary).
static void testFecCPlusPlusWrapperY(const int nPrimaryFragments,const int nSecondaryFragments){
    std::cout<<"testFecCPlusPlusWrapperX\n";
    fec_init();
    srand (time(NULL));
    constexpr auto FRAGMENT_SIZE=1446;

    auto txBlockBuffer=GenericHelper::createRandomDataBuffers<FRAGMENT_SIZE>(nPrimaryFragments + nSecondaryFragments);
    std::cout<<"XSelected nPrimaryFragments:"<<nPrimaryFragments<<" nSecondaryFragments:"<<nSecondaryFragments<<"\n";

    fecEncode(FRAGMENT_SIZE, txBlockBuffer, nPrimaryFragments, nSecondaryFragments);
    std::cout<<"Encode done\n";

    for(int test=0;test<10;test++) {
        // takes nPrimaryFragments random (possible) indices without duplicates
        // NOTE: Perhaps you could calculate all possible permutations, but these would be quite a lot.
        // Therefore, I just use n random selections of received indices
        auto receivedFragmentIndices= GenericHelper::takeNRandomElements(
                GenericHelper::createIndices(nPrimaryFragments + nSecondaryFragments),
                nPrimaryFragments);
        assert(receivedFragmentIndices.size()==nPrimaryFragments);
        std::cout<<"(Emulated) receivedFragmentIndices"<<StringHelper::vectorAsString(receivedFragmentIndices)<<"\n";

        auto rxBlockBuffer=std::vector<std::array<uint8_t,FRAGMENT_SIZE>>(nPrimaryFragments+nSecondaryFragments);
        std::vector<FragmentStatus> fragmentMap(nPrimaryFragments+nSecondaryFragments,FragmentStatus::UNAVAILABLE);
        for(const auto idx:receivedFragmentIndices){
            rxBlockBuffer[idx]=txBlockBuffer[idx];
            fragmentMap[idx]=FragmentStatus::AVAILABLE;
        }

        fecDecode(FRAGMENT_SIZE, rxBlockBuffer, nPrimaryFragments, fragmentMap);

        for(unsigned int i=0;i<nPrimaryFragments;i++){
            std::cout<<"Comparing fragment:"<<i<<"\n";
            GenericHelper::assertArraysEqual(txBlockBuffer[i], rxBlockBuffer[i]);
        }
    }
}

// Note: This test will take quite a long time !
void testFecCPlusPlusWrapperX(){
    for(int nPrimaryFragments=1;nPrimaryFragments<128;nPrimaryFragments++){
        for(int nSecondaryFragments=0;nSecondaryFragments<128;nSecondaryFragments++){
            testFecCPlusPlusWrapperY(nPrimaryFragments,nSecondaryFragments);
        }
    }
}

#endif //WIFIBROADCAST_FEC_H
