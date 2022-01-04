//
// Created by consti10 on 04.01.22.
//

#ifndef WIFIBROADCAST_SIMPLE_INCLUDE_H
#define WIFIBROADCAST_SIMPLE_INCLUDE_H

// selects the right methods depending on hardware availability

#include "gf256_flat_table.h"

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

#include "gf256_neon.h"

// computes dst[] = c * src[]
// where '+', '*' are gf256 operations
static void gf256_mul_optimized(uint8_t* dst,const uint8_t* src, gf c,const int sz){
    // We can only do the fast algorithm on multiples of 8
    const int sizeFast=sz - (sz % 8);
    const int sizeSlow= sz-sizeFast;
    if(sizeFast>0){
        mulrc256_shuffle_neon_64(dst,src,c,sizeFast);
    }
    if(sizeSlow>0){
        mulrc256_flat_table(&dst[sizeFast],&src[sizeFast],c,sizeSlow);
    }
}

// computes dst[] = dst[] + c * src[]
// where '+', '*' are gf256 operations
static void gf256_madd_optimized(uint8_t* dst,const uint8_t* src, gf c,const int sz){
    // We can only do the fast algorithm on multiples of 8
    const int sizeFast=sz - (sz % 8);
    const int sizeSlow= sz-sizeFast;
    if(sizeFast>0){
        maddrc256_shuffle_neon_64(dst,src,c,sizeFast);
    }
    if(sizeSlow>0){
        maddrc256_flat_table(&dst[sizeFast],&src[sizeFast],c,sizeSlow);
    }
}


#endif //WIFIBROADCAST_SIMPLE_INCLUDE_H
