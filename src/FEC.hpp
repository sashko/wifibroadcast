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

// same as above, but different way of passing primary / secondary fragments.
template<std::size_t S>
void fec_encode(unsigned int fragmentSize,std::vector<std::array<uint8_t,S>>& pf,std::vector<std::array<uint8_t,S>>& sf){
    auto pfp=GenericHelper::convertToP(pf);
    auto sfp=GenericHelper::convertToP(sf);
    fec_encode(fragmentSize,pfp,sfp);
}

/**
 * @param fragmentSize size of each fragment in this block
 * @param primaryFragments list of pointers to memory for primary fragments.
 * @param secondaryFragments list of pointers to memory for secondary fragments (fec fragments)
 * @param indicesMissingPrimaryFragments list of the indices of missing primary fragments.
 * Example: if @param indicesMissingPrimaryFragments contains 2, the 3rd primary fragment is missing
 * @param indicesAvailableSecondaryFragments list of the indices of secondaryFragments that are used to reconstruct missing primary fragments
 * Reconstructs all missing primary fragments using the available secondary fragments.
 */
void fec_decode(unsigned int fragmentSize,
                std::vector<uint8_t*> primaryFragments,
                std::vector<uint8_t*> secondaryFragments,
                std::vector<unsigned int> indicesMissingPrimaryFragments,
                std::vector<unsigned int> indicesAvailableSecondaryFragments){
    assert(indicesMissingPrimaryFragments.size() <= indicesAvailableSecondaryFragments.size());
    std::cout<<"primaryFragmentsS:"<<primaryFragments.size()<<"\n";
    std::cout<<"secondaryFragmentsS:"<<secondaryFragments.size()<<"\n";
    std::cout<<"indicesMissingPrimaryFragments:"<<StringHelper::vectorAsString(indicesMissingPrimaryFragments)<<"\n";
    std::cout<<"indicesAvailableSecondaryFragments:"<<StringHelper::vectorAsString(indicesAvailableSecondaryFragments)<<"\n";
    for(const auto& idx:indicesMissingPrimaryFragments){
        assert(idx<primaryFragments.size());
    }
    for(const auto& idx:indicesAvailableSecondaryFragments){
        assert(idx<secondaryFragments.size());
    }
    std::vector<uint8_t*> secondaryFragmentsAdj;
    for(const auto & idx:indicesAvailableSecondaryFragments){
        secondaryFragmentsAdj.push_back(secondaryFragments[idx]);
    }
    fec_decode(fragmentSize, (unsigned char**)primaryFragments.data(), primaryFragments.size(), (unsigned char**)secondaryFragmentsAdj.data(),
               (unsigned int*)indicesAvailableSecondaryFragments.data(), (unsigned int*)indicesMissingPrimaryFragments.data(), indicesMissingPrimaryFragments.size());
}


// same as above, but different way of passing primary / secondary fragments.
template<std::size_t S>
void fec_decode(unsigned int fragmentSize,std::vector<std::array<uint8_t,S>>& pf,std::vector<std::array<uint8_t,S>>& sf,
                std::vector<unsigned int> indicesMissingPrimaryFragments,
                std::vector<unsigned int> indicesAvailableSecondaryFragments){
    auto pfp=GenericHelper::convertToP(pf);
    auto sfp=GenericHelper::convertToP(sf);
    fec_decode(fragmentSize, pfp, sfp, indicesMissingPrimaryFragments, indicesAvailableSecondaryFragments);
}

template<std::size_t S>
void fec_decode2_available(unsigned int fragmentSize, std::vector<std::array<uint8_t,S>>& pf, std::vector<std::array<uint8_t,S>>& sf,
                           std::vector<unsigned int> indicesAvailablePrimaryFragments,
                           std::vector<unsigned int> indicesAvailableSecondaryFragments){

    //std::cout<<"XindicesAvailablePrimaryFragments:"<<StringHelper::vectorAsString(indicesAvailablePrimaryFragments)<<"\n";
    //std::cout<<"XindicesAvailableSecondaryFragments:"<<StringHelper::vectorAsString(indicesAvailableSecondaryFragments)<<"\n";
    auto indicesMissingPrimaryFragments=GenericHelper::findMissingIndices(indicesAvailablePrimaryFragments,pf.size());
    fec_decode2(fragmentSize,pf,sf,indicesMissingPrimaryFragments,indicesAvailableSecondaryFragments);
}



//Note: By using "blockBuffer" as input the fecEncode / fecDecode function(s) don't need to allocate any new memory.
// The "blockBuffer" can be either at least as big as needed or bigger, implementation doesn't care


/**
 * @param packetSize size of each data packet (fragment) to use for the FEC encoding step. FEC only works on packets the same size
 * @param blockBuffer (big) data buffer. The nth element is to be treated as the nth fragment of the block, either as primary or secondary fragment.
 * During the FEC step, @param nPrimaryFragments fragments are used to calculate nSecondaryFragments FEC blocks.
 * After the FEC step,beginning at idx @param nPrimaryFragments ,@param nSecondaryFragments are stored at the following indices, each of size @param packetSize
 */
template<std::size_t S>
void fecEncode(unsigned int packetSize,std::vector<std::array<uint8_t,S>>& blockBuffer,unsigned int nPrimaryFragments,unsigned int nSecondaryFragments){
    assert(packetSize<=S);
    assert(nPrimaryFragments+nSecondaryFragments<=blockBuffer.size());
    auto primaryFragmentsP= GenericHelper::convertToP(blockBuffer,0,nPrimaryFragments);//getPrimaryFragmentPointers(blockBuffer, nPrimaryFragments);
    auto secondaryFragmentsP=GenericHelper::convertToP(blockBuffer,nPrimaryFragments,blockBuffer.size()-nPrimaryFragments); //getPossibleSecondaryFragmentPointers(blockBuffer, nPrimaryFragments);
    secondaryFragmentsP.resize(nSecondaryFragments);
    fec_encode(packetSize,primaryFragmentsP,secondaryFragmentsP);
    //fec_encode(packetSize, (const unsigned char**)primaryFragmentsP.data(), primaryFragmentsP.size(), (unsigned char**)secondaryFragmentsP.data(), nSecondaryFragments);
}

/**
 * @param packetSize size of each data packet (fragment) to use for the FEC encoding step. FEC only works on packets the same size
 * @param blockBuffer (big) data buffer. The nth element is to be treated as the nth fragment of the block, either as primary or secondary fragment.
 * During the FEC step, all missing primary Fragments (indices from @param indicesMissingPrimaryFragments) are reconstructed from the FEC packets,
 * using indices from @param indicesAvailableSecondaryFragments
 * Note: both @param indicesMissingPrimaryFragments and @param indicesAvailableSecondaryFragments refer to a position in @param blockBuffer
 */
template<std::size_t S>
void fecDecode(unsigned int packetSize,std::vector<std::array<uint8_t,S>>& blockBuffer,unsigned int nPrimaryFragments,
               const std::vector<unsigned int>& indicesMissingPrimaryFragments,const std::vector<unsigned int>& indicesAvailableSecondaryFragments){
    // first validate input.
    assert(packetSize<=S);
    assert(indicesMissingPrimaryFragments.size()>=indicesAvailableSecondaryFragments.size());
    // I treat calling fecDecode() with more primary fragments than needed for the reconstruction step as an error here
    // (because it would create unneeded latency) though it would work just fine
    assert(indicesMissingPrimaryFragments.size()==indicesAvailableSecondaryFragments.size());
    // unfortunately the fec implementation needs an array of primary fragments
    // and a different array of secondary fragments where obviously the indices of all primary fragments are the same,
    // but the indices for secondary fragments start at 0 and not fec_k
    // ( in this regard, fec_encode() differs from fec_decode() )
    std::cout<<"blockBufferS:"<<blockBuffer.size()<<"\n";
    auto primaryFragmentsP=GenericHelper::convertToP(blockBuffer,0,nPrimaryFragments);
    auto secondaryFragmentsP=GenericHelper::convertToP(blockBuffer,nPrimaryFragments,blockBuffer.size()-nPrimaryFragments);;
    //secondaryFragmentsP.resize(4);

    std::vector<unsigned int> indicesAvailableSecondaryFragmentsAdjusted(indicesAvailableSecondaryFragments.size());
    for(int i=0;i<indicesAvailableSecondaryFragments.size();i++){
        indicesAvailableSecondaryFragmentsAdjusted[i]=indicesAvailableSecondaryFragments[i]-nPrimaryFragments;
    }
    std::cout<<"indicesMissingPrimaryFragments:"<<StringHelper::vectorAsString(indicesMissingPrimaryFragments)<<"\n";
    std::cout<<"indicesAvailableSecondaryFragmentsAdjusted:"<<StringHelper::vectorAsString(indicesAvailableSecondaryFragmentsAdjusted)<<"\n";

    //fec_decode(packetSize,primaryFragmentsP.data(),primaryFragmentsP.size(),secondaryFragmentsP.data(),indicesAvailableSecondaryFragmentsAdjusted.data(),indicesMissingPrimaryFragments.data(),indicesAvailableSecondaryFragmentsAdjusted.size());
    fec_decode(packetSize,primaryFragmentsP,secondaryFragmentsP,indicesMissingPrimaryFragments,indicesAvailableSecondaryFragmentsAdjusted);
}

template<std::size_t S>
void fecDecode2(unsigned int packetSize, std::vector<std::array<uint8_t,S>>& blockBuffer, unsigned int nPrimaryFragments,
                const std::vector<unsigned int>& indicesAvailablePrimaryFragments, const std::vector<unsigned int>& indicesAvailableSecondaryFragments){
    assert(indicesAvailablePrimaryFragments.size() + indicesAvailableSecondaryFragments.size() == nPrimaryFragments);
    // the fec impl. wants the indices of missing primary fragments, not those ones available
    std::vector<unsigned int> indicesMissingPrimaryFragments;
    for(unsigned int i=0;i<nPrimaryFragments;i++){
        auto found= indicesAvailablePrimaryFragments.end() != std::find(indicesAvailablePrimaryFragments.begin(), indicesAvailablePrimaryFragments.end(), i);
        if(!found){
            indicesMissingPrimaryFragments.push_back(i);
        }
    }
    assert(indicesMissingPrimaryFragments.size()== nPrimaryFragments - indicesAvailablePrimaryFragments.size());
    std::cout<<"indicesMissingPrimaryFragments:"<<StringHelper::vectorAsString(indicesMissingPrimaryFragments)<<"\n";

    //
    auto primaryFragmentP=GenericHelper::convertToP(blockBuffer,0,nPrimaryFragments);
    auto secondaryFragmentP=GenericHelper::convertToP(blockBuffer,nPrimaryFragments,blockBuffer.size()-nPrimaryFragments);

    std::vector<unsigned int> indicesAvailableSecondaryFragmentsAdjusted(indicesAvailableSecondaryFragments.size());
    for(int i=0; i < indicesAvailableSecondaryFragments.size(); i++){
        indicesAvailableSecondaryFragmentsAdjusted[i]= indicesAvailableSecondaryFragments[i] - nPrimaryFragments;
    }
    std::cout<<"indicesAvailableSecondaryFragmentsAdjusted:"<<StringHelper::vectorAsString(indicesAvailableSecondaryFragmentsAdjusted)<<"\n";

    fec_decode(packetSize, primaryFragmentP, secondaryFragmentP, indicesMissingPrimaryFragments, indicesAvailableSecondaryFragmentsAdjusted);

    //fec_decode(packetSize,primaryFragmentPointers.data(),nPrimaryFragments,secondaryFragmentPointers.data(),indicesAvailableSecondaryFragmentsAdjusted.data(),indicesMissingPrimaryFragments.data(),indicesAvailableSecondaryFragmentsAdjusted.size());

}

#endif //WIFIBROADCAST_FEC_H
