#ifndef FEC_2_H
#define FEC_2_H

//#ifdef __cplusplus
//extern "C" {
//#endif

//#define PROFILE

#include <stdint.h>

typedef uint8_t gf;

/*
 * create a new encoder, returning a descriptor. This contains k,n and
 * the encoding matrix.
 * n is the number of data blocks + fec blocks (matrix height)
 * k is just the data blocks (matrix width)
 * NOTE: Since k,n are variable this call is still required to setup the lookup tables
 * But k,n don't have to be specified at creation time
 */
void fec_init(void);

/**
 * @param blockSize size of each block (all blocks must have the same size)
 * @param data_blocks array of pointers to the memory of the data blocks
 * @param nrDataBlocks how many data blocks
 * @param fec_blocks array of pointers to the memory of the fec blocks (generated)
 * @param nrFecBlocks how many fec blocks to generate
 */
void fec_encode(unsigned int blockSize,
                const gf **data_blocks,
                unsigned int nrDataBlocks,
                gf **fec_blocks,
                unsigned int nrFecBlocks);

/**
 *
 * @param blockSize size of each block
 * @param data_blocks array of pointers to the memory of the data blocks. Missing areas will be filled
 * @param nr_data_blocks how many data blocks (available and missing)
 * @param fec_blocks array of pointers to the memory of the fec blocks
 * @param fec_block_nos indices of the received fec blocks
 * @param erased_blocks indices of the erased / missing data blocks that will be reconstructed
 * @param nr_fec_blocks how many data blocks are missing
 */
void fec_decode(unsigned int blockSize,
                gf **data_blocks,
                unsigned int nr_data_blocks,
                gf **fec_blocks,
                const unsigned int fec_block_nos[],
                const unsigned int erased_blocks[],
                unsigned short nr_fec_blocks  /* how many blocks per stripe */);

void fec_license(void);

void test_gf();

#ifdef PROFILE
void printDetail(void);
#endif

//#ifdef __cplusplus
//}
//#endif

#endif //FEC_2_H