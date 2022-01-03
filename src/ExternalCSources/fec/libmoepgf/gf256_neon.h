//
// Created by consti10 on 02.01.22.
//

#include <arm_neon.h>
#include "gf256tables285.h"


static const uint8_t pt[MOEPGF256_SIZE][MOEPGF256_EXPONENT] = MOEPGF256_POLYNOMIAL_DIV_TABLE;
static const uint8_t tl[MOEPGF256_SIZE][16] = MOEPGF256_SHUFFLE_LOW_TABLE;
static const uint8_t th[MOEPGF256_SIZE][16] = MOEPGF256_SHUFFLE_HIGH_TABLE;

void
xorr_neon_128(uint8_t *region1, const uint8_t *region2, size_t length)
{
    uint8_t *end;
    register uint64x2_t in, out;

    for (end=region1+length; region1<end; region1+=16, region2+=16) {
        in  = vld1q_u64((const uint64_t *)region2);
        out = vld1q_u64((const uint64_t *)region1);
        out = veorq_u64(in, out);
        vst1q_u64((const uint64_t *)region1, out);
    }
}
/*
static void
maddrc256_shuffle_neon_64(uint8_t *region1, const uint8_t *region2,
                          uint8_t constant, size_t length)
{
    uint8_t *end;
    register uint8x8x2_t t1, t2;
    register uint8x8_t m1, m2, in1, in2, out, l, h;

    if (constant == 0)
        return;

    if (constant == 1) {
        xorr_neon_128(region1, region2, length);
        return;
    }

    t1 = vld2_u8((void *)tl[constant]);
    t2 = vld2_u8((void *)th[constant]);
    m1 = vdup_n_u8(0x0f);
    m2 = vdup_n_u8(0xf0);

    for (end=region1+length; region1<end; region1+=8, region2+=8) {
        in2 = vld1_u8((void *)region2);
        in1 = vld1_u8((void *)region1);
        l = vand_u8(in2, m1);
        l = vtbl2_u8(t1, l);
        h = vand_u8(in2, m2);
        h = vshr_n_u8(h, 4);
        h = vtbl2_u8(t2, h);
        out = veor_u8(h, l);
        out = veor_u8(out, in1);
        vst1_u8(region1, out);
    }
}*/