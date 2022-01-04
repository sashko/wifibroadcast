//
// Created by consti10 on 04.01.22.
//

#ifndef LIBMOEPGF_GF256_AVX2_H
#define LIBMOEPGF_GF256_AVX2_H

#include <immintrin.h>
#include "gf256tables285.h"
#include <stdint.h>

static const uint8_t pt[MOEPGF256_SIZE][MOEPGF256_EXPONENT] = MOEPGF256_POLYNOMIAL_DIV_TABLE;
static const uint8_t tl[MOEPGF256_SIZE][16] = MOEPGF256_SHUFFLE_LOW_TABLE;
static const uint8_t th[MOEPGF256_SIZE][16] = MOEPGF256_SHUFFLE_HIGH_TABLE;

void
xorr_avx2(uint8_t *region1, const uint8_t *region2, size_t length)
{
    uint8_t *end;
    register __m256i in, out;

    for (end=region1+length; region1<end; region1+=32, region2+=32) {
        in  = _mm256_load_si256((void *)region2);
        out = _mm256_load_si256((void *)region1);
        out = _mm256_xor_si256(in, out);
        _mm256_store_si256((void *)region1, out);
    }
}

void
maddrc256_shuffle_avx2(uint8_t *region1, const uint8_t *region2,
                       uint8_t constant, size_t length)
{
    uint8_t *end;
    register __m256i t1, t2, m1, m2, in1, in2, out, l, h;
    register __m128i bc;

    if (constant == 0)
        return;

    if (constant == 1) {
        xorr_avx2(region1, region2, length);
        return;
    }

    bc = _mm_load_si128((void *)tl[constant]);
    t1 = __builtin_ia32_vbroadcastsi256(bc);
    bc = _mm_load_si128((void *)th[constant]);
    t2 = __builtin_ia32_vbroadcastsi256(bc);
    m1 = _mm256_set1_epi8(0x0f);
    m2 = _mm256_set1_epi8(0xf0);

    for (end=region1+length; region1<end; region1+=32, region2+=32) {
        in2 = _mm256_load_si256((void *)region2);
        in1 = _mm256_load_si256((void *)region1);
        l = _mm256_and_si256(in2, m1);
        l = _mm256_shuffle_epi8(t1, l);
        h = _mm256_and_si256(in2, m2);
        h = _mm256_srli_epi64(h, 4);
        h = _mm256_shuffle_epi8(t2, h);
        out = _mm256_xor_si256(h, l);
        out = _mm256_xor_si256(out, in1);
        _mm256_store_si256((void *)region1, out);
    }
}


#endif //LIBMOEPGF_GF256_AVX2_H
