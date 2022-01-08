//
// Created by consti10 on 04.01.22.
//

#ifndef WIFIBROADCAST_SIMPLE_INCLUDE_H
#define WIFIBROADCAST_SIMPLE_INCLUDE_H

// By including this file we get all the "galois field math" we need for our FEC implementation
// The mul and addmul methods are highly optimized for each architecture (see Readme.md)

#include "gf256_flat_table.h"
#include "alignment_check.h"

/*#ifdef __x86_64__
#include "gf256_avx2.h"
#endif //__x86_64__

#ifdef __arm__
#include "gf256_neon.h"
#endif //__arm__*/

/*
#ifdef __x86_64__

#endif //__x86_64__

#ifdef __arm__
#endif //__arm__
 */

//#include "gf256_neon.h"
//#include "gf256_avx2.h"
#include "gf256_ssse3.h"

#include <iostream>
#include <cassert>


// computes dst[] = c * src[]
// where '+', '*' are gf256 operations
static void gf256_mul_optimized(uint8_t* dst,const uint8_t* src, gf c,const int sz){
    //mulrc256_flat_table(dst,src,c,sz);
    // We can only do the fast algorithm on multiples of 8
    /*const int sizeSlow = sz % 8;
    const int sizeFast = sz - sizeSlow;
    if(sizeFast>0){
        mulrc256_shuffle_neon_64(dst,src,c,sizeFast);
    }
    if(sizeSlow>0){
        mulrc256_flat_table(&dst[sizeFast],&src[sizeFast],c,sizeSlow);
    }*/
    /*const bool aligned= is_aligned(dst,64) && is_aligned(src,64);
    if(!aligned){
        mulrc256_flat_table(dst,src,c,sz);
        std::cout<<"Not aligned\n";
        return;
    }*/
    //assert(is_aligned(dst,16));
    //assert(is_aligned(src,16));
    //find_alignment(src,dst,16);
    int sizeSlow = sz % 16;
    int sizeFast = sz - sizeSlow;
    if(sizeFast>0){
        mulrc256_shuffle_ssse3(dst,src,c,sizeFast);
    }
    if(sizeSlow>0){
        mulrc256_flat_table(&dst[sizeFast],&src[sizeFast],c,sizeSlow);
    }
}

// computes dst[] = dst[] + c * src[]
// where '+', '*' are gf256 operations
static void gf256_madd_optimized(uint8_t* dst,const uint8_t* src, gf c,const int sz){
    //maddrc256_flat_table(dst,src,c,sz);
    //std::cout<<"c:"<<(int)c<<" sz:"<<sz<<"\n";
    // We can only do the fast algorithm on multiples of 8
    /*const int sizeSlow = sz % 8;
    const int sizeFast = sz - sizeSlow;
    if(sizeFast>0){
        maddrc256_shuffle_neon_64(dst,src,c,sizeFast);
    }
    if(sizeSlow>0){
        maddrc256_flat_table(&dst[sizeFast],&src[sizeFast],c,sizeSlow);
    }*/
    /*const bool aligned= is_aligned(dst,64) && is_aligned(src,64);
    if(!aligned){
        maddrc256_flat_table(dst,src,c,sz);
        std::cout<<"Not aligned\n";
        return;
    }*/
    const int sizeSlow = sz % 16;
    const int sizeFast = sz - sizeSlow;
    if(sizeFast>0){
        maddrc256_shuffle_ssse3(dst,src,c,sizeFast);
    }
    if(sizeSlow>0){
        maddrc256_flat_table(&dst[sizeFast],&src[sizeFast],c,sizeSlow);
    }
}

static const uint8_t inverses[MOEPGF256_SIZE] = MOEPGF256_INV_TABLE;

// for the inverse of a number we don't have a highly optimized method
// since it is never done on big chunks of memory anyways
static uint8_t gf256_inverse(uint8_t value){
    return inverses[value];
}

// and sometimes the FEC code needs to just multiply two uint8_t values (not a memory region)
static uint8_t gf256_mul(uint8_t x,uint8_t y){
    uint8_t ret;
    mulrc256_flat_table(&ret,&x,y,1);
    return ret;
}


#endif //WIFIBROADCAST_SIMPLE_INCLUDE_H
