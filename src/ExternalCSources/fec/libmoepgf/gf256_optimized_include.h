//
// Created by consti10 on 04.01.22.
//

#ifndef WIFIBROADCAST_SIMPLE_INCLUDE_H
#define WIFIBROADCAST_SIMPLE_INCLUDE_H

// By including this file we get all the "galois field math" we need for our FEC implementation
// The mul and addmul methods are highly optimized for each architecture (see Readme.md)

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

//#include "gf256_neon.h"
//#include "gf256_avx2.h"

#include <iostream>


/*static void test(){
    static int X_SIZE=8;
    const uint8_t buf1[X_SIZE]{
        18,1,2,3,4,5,6,7
    };
    uint8_t res1[X_SIZE]{
            36,1,2,3,4,5,6,7
    };
    uint8_t res2[X_SIZE];
    memcpy(res2,res1,X_SIZE);

    xorr_scalar(res1,buf1,X_SIZE);
    xorr_neon_64(res2,buf1,X_SIZE);

    for(int i=0;i<X_SIZE;i++){
        assert(res1[i]==res2[i]);
    }

    std::cout<<"XXX\n";

}*/

//static inline bool is_aligned(const void * pointer, size_t byte_count)
//{ return (uintptr_t)pointer % byte_count == 0; }


// computes dst[] = c * src[]
// where '+', '*' are gf256 operations
static void gf256_mul_optimized(uint8_t* dst,const uint8_t* src, gf c,const int sz){
    mulrc256_flat_table(dst,src,c,sz);
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
    /*const int sizeSlow = sz % 32;
    const int sizeFast = sz - sizeSlow;
    if(sizeFast>0){
        mulrc256_shuffle_avx2(dst,src,c,sizeFast);
    }
    if(sizeSlow>0){
        mulrc256_flat_table(&dst[sizeFast],&src[sizeFast],c,sizeSlow);
    }*/
}

// computes dst[] = dst[] + c * src[]
// where '+', '*' are gf256 operations
static void gf256_madd_optimized(uint8_t* dst,const uint8_t* src, gf c,const int sz){
    maddrc256_flat_table(dst,src,c,sz);
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
    /*const int sizeSlow = sz % 32;
    const int sizeFast = sz - sizeSlow;
    if(sizeFast>0){
        maddrc256_shuffle_avx2(dst,src,c,sizeFast);
    }
    if(sizeSlow>0){
        maddrc256_flat_table(&dst[sizeFast],&src[sizeFast],c,sizeSlow);
    }*/
}

static const uint8_t inverses[MOEPGF256_SIZE] = MOEPGF256_INV_TABLE;

// for the inverse of a number we don't have a highly optimized method
// since it is never done on big chunks of memory anyways
static uint8_t gf256_inverse(uint8_t value){
    return inverses[value];
}

static uint8_t gf256_mul(uint8_t x,uint8_t y){
    uint8_t ret;
    mulrc256_flat_table(&ret,&x,y,1);
    return ret;
}


#endif //WIFIBROADCAST_SIMPLE_INCLUDE_H
