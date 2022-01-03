//
// Created by consti10 on 02.01.22.
//

#include <arm_neon.h>
#include "gf256tables285.h"


static const uint8_t pt[MOEPGF256_SIZE][MOEPGF256_EXPONENT] = MOEPGF256_POLYNOMIAL_DIV_TABLE;

void
xorr_neon_64(uint8_t *region1, const uint8_t *region2, size_t length)
{
    uint8_t *end;
    register uint64x1_t in, out;

    for (end=region1+length; region1<end; region1+=8, region2+=8) {
        in  = vld1_u64((void *)region2);
        out = vld1_u64((void *)region1);
        out = veor_u64(in, out);
        vst1_u64((void *)region1, out);
    }
}

void
xorr_neon_128(uint8_t *region1, const uint8_t *region2, size_t length)
{
    uint8_t *end;
    register uint64x2_t in, out;

    for (end=region1+length; region1<end; region1+=16, region2+=16) {
        in  = vld1q_u64((void *)region2);
        out = vld1q_u64((void *)region1);
        out = veorq_u64(in, out);
        vst1q_u64((void *)region1, out);
    }
}

void
maddrc256_imul_neon_128(uint8_t *region1, const uint8_t *region2,
                        uint8_t constant, size_t length)
{
    uint8_t *end;
    const uint8_t *p = pt[constant];
    register uint8x16_t mi[8], sp[8], ri[8], reg1, reg2;

    if (constant == 0)
        return;

    if (constant == 1) {
        xorr_neon_128(region1, region2, length);
        return;
    }

    mi[0] = vdupq_n_u8(0x01);
    mi[1] = vdupq_n_u8(0x02);
    mi[2] = vdupq_n_u8(0x04);
    mi[3] = vdupq_n_u8(0x08);
    mi[4] = vdupq_n_u8(0x10);
    mi[5] = vdupq_n_u8(0x20);
    mi[6] = vdupq_n_u8(0x40);
    mi[7] = vdupq_n_u8(0x80);

    sp[0] = vdupq_n_u8(p[0]);
    sp[1] = vdupq_n_u8(p[1]);
    sp[2] = vdupq_n_u8(p[2]);
    sp[3] = vdupq_n_u8(p[3]);
    sp[4] = vdupq_n_u8(p[4]);
    sp[5] = vdupq_n_u8(p[5]);
    sp[6] = vdupq_n_u8(p[6]);
    sp[7] = vdupq_n_u8(p[7]);

    for (end=region1+length; region1<end; region1+=16, region2+=16) {
        reg2 = vld1q_u8(region2);
        reg1 = vld1q_u8(region1);

        ri[0] = vandq_u8(reg2, mi[0]);
        ri[1] = vandq_u8(reg2, mi[1]);
        ri[2] = vandq_u8(reg2, mi[2]);
        ri[3] = vandq_u8(reg2, mi[3]);
        ri[4] = vandq_u8(reg2, mi[4]);
        ri[5] = vandq_u8(reg2, mi[5]);
        ri[6] = vandq_u8(reg2, mi[6]);
        ri[7] = vandq_u8(reg2, mi[7]);

        ri[1] = vshrq_n_u8(ri[1], 1);
        ri[2] = vshrq_n_u8(ri[2], 2);
        ri[3] = vshrq_n_u8(ri[3], 3);
        ri[4] = vshrq_n_u8(ri[4], 4);
        ri[5] = vshrq_n_u8(ri[5], 5);
        ri[6] = vshrq_n_u8(ri[6], 6);
        ri[7] = vshrq_n_u8(ri[7], 7);

        ri[0] = vmulq_u8(ri[0], sp[0]);
        ri[1] = vmulq_u8(ri[1], sp[1]);
        ri[2] = vmulq_u8(ri[2], sp[2]);
        ri[3] = vmulq_u8(ri[3], sp[3]);
        ri[4] = vmulq_u8(ri[4], sp[4]);
        ri[5] = vmulq_u8(ri[5], sp[5]);
        ri[6] = vmulq_u8(ri[6], sp[6]);
        ri[7] = vmulq_u8(ri[7], sp[7]);

        ri[0] = veorq_u8(ri[0], ri[1]);
        ri[2] = veorq_u8(ri[2], ri[3]);
        ri[4] = veorq_u8(ri[4], ri[5]);
        ri[6] = veorq_u8(ri[6], ri[7]);
        ri[0] = veorq_u8(ri[0], ri[2]);
        ri[4] = veorq_u8(ri[4], ri[6]);
        ri[0] = veorq_u8(ri[0], ri[4]);
        ri[0] = veorq_u8(ri[0], reg1);

        vst1q_u8(region1, ri[0]);
    }
}