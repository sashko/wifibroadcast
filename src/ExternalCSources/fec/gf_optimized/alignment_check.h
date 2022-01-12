//
// Created by consti10 on 08.01.22.
//

#ifndef WIFIBROADCAST_ALIGNMENT_CHECK_H
#define WIFIBROADCAST_ALIGNMENT_CHECK_H

// NEON / SSSE3 only work on aligned data ?!
// THIS STUFF REALLY SUCKS -
// WELL LOOKS AS IF USING "u" everywhere in ssse3 did the trick
// NOTE: This file is now obsolete, but I keep it in here in case someone wants to add AVX2 ;)

#include <iostream>

static inline bool is_aligned(const void * pointer, size_t byte_count)
{ return (uintptr_t)pointer % byte_count == 0; }

static inline bool are_aligned(const void * pointer1,const void* pointer2,size_t byte_count)
{ return is_aligned(pointer1,byte_count) && is_aligned(pointer2,byte_count);}


// Not guaranteed that a value exists that has the proper alignment for both input arrays -
// well i was able to fix it otherwise
static inline int find_alignment(const uint8_t * pointer1,const uint8_t * pointer2, size_t byte_count){
    int ret=0;
    while (! ( is_aligned(&pointer1[ret],byte_count) && is_aligned(&pointer2[ret],byte_count) ) ) {
        ret+=8;
    }
    if(ret!=0){
        std::cout<<"Alignment okay after "<<ret<<"bytes\n";
    }
    return ret;
}

//if(!are_aligned(src,dst,16)){
//std::cout<<"Cannot do fast due to alignment\n";
//sizeSlow=sz;
//sizeFast=0;
//}

#endif //WIFIBROADCAST_ALIGNMENT_CHECK_H
