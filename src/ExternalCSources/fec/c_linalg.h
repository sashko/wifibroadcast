//
// Created by consti10 on 02.01.22.
//

#ifndef WIFIBROADCAST_C_LINALG_H
#define WIFIBROADCAST_C_LINALG_H

typedef unsigned char gf;

static void consti_mul(gf *dst1,const gf *src1, gf c,const int sz){
    for(int i=0;i<sz;i++){
        dst1[i]=(gf)src1[i]*c;
    }
}

static void consti_addmul(gf *dst1,const gf *src1, gf c, int sz) {
    for(int i=0;i<sz;i++){
        dst1[i]+=(gf)src1[i]*c;
    }
}
#endif //WIFIBROADCAST_C_LINALG_H
