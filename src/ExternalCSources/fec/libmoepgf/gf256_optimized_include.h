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
    /*const int sizeFast=sz - (sz % 32);
    const int sizeSlow= sz-sizeFast;
    if(sizeFast>0){
        mulrc256_shuffle_avx2_2(dst,src,c,sizeFast);
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
    //const int sizeFast=sz - (sz % 8);
    //const int sizeSlow= sz-sizeFast;
    if(sizeFast>0){
        maddrc256_shuffle_neon_64(dst,src,c,sizeFast);
    }
    if(sizeSlow>0){
        maddrc256_flat_table(&dst[sizeFast],&src[sizeFast],c,sizeSlow);
    }*/
    /*const int sizeFast=sz - (sz % 32);
    const int sizeSlow= sz % 32;
    if(sizeFast>0){
        maddrc256_shuffle_avx2(dst,src,c,sizeFast);
    }
    if(sizeSlow>0){
        maddrc256_flat_table(&dst[sizeFast],&src[sizeFast],c,sizeSlow);
    }*/
}


#endif //WIFIBROADCAST_SIMPLE_INCLUDE_H
