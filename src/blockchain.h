#ifndef _BLOCKCHAIN_H
#define _BLOCKCHAIN_H

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

struct block {
    uint64_t index;
    uint64_t timestamp;
    unsigned char *data;
    uint64_t nonce;
    unsigned int data_len;
    void *previous_block;
    unsigned char hash[32];
};

struct block *block_new(struct block *previous_block, const unsigned char *data, unsigned int data_len);
void block_free(struct block *block);
int block_mine_with_copy(struct block *newblock, int zero_bits, unsigned char previous_hash[32]);
int block_mine(struct block *newblock, int zero_bits);
int block_verify(struct block *newblock, int zero_bits);
int blockchain_verify(struct block *newblock, int zero_bits);
int block_save(struct block *newblock, const char *path);
struct block *block_load(const char *path, uint64_t index);
struct block *blockchain_load(const char *path);
unsigned char *block_save_buffer(struct block *newblock, int *size);
struct block *block_load_buffer(const unsigned char *buffer, int size);
void blockchain_free(struct block *block);

#endif

