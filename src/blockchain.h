#ifndef _BLOCKCHAIN_H
#define _BLOCKCHAIN_H

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

struct block {
    unsigned int index;
    time_t timestamp;
    unsigned char *data;
    uint64_t nonce;
    unsigned int data_len;
    void *previous_block;
    unsigned char hash[32];
};

struct block *block_new(struct block *previous_block, const unsigned char *data, unsigned int data_len);
void block_free(struct block *block);
int block_mine(struct block *newblock, int zero_bits);
int block_verify(struct block *newblock, int zero_bits);
void blockchain_free(struct block *block);

#endif

