#include "blockchain.h"
#include "sha3.h"
#include "base64.h"
#ifdef _WIN32
    #include <windows.h>
#else
    #include <arpa/inet.h>
#endif

uint64_t block_switchorder(uint64_t input) {
    uint64_t rval;
    uint8_t *data = (uint8_t *)&rval;

    data[0] = input >> 56;
    data[1] = input >> 48;
    data[2] = input >> 40;
    data[3] = input >> 32;
    data[4] = input >> 24;
    data[5] = input >> 16;
    data[6] = input >> 8;
    data[7] = input >> 0;
    return rval;
}

#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : block_switchorder(x))
#endif

#ifndef ntohll
#define ntohll(x) ((1==ntohl(1)) ? (x) : block_switchorder(x))
#endif

struct block *block_new(struct block *previous_block, const unsigned char *data, unsigned int data_len) {
    struct block *newblock = (struct block *)malloc(sizeof(struct block));
    if (!newblock)
        return NULL;

    newblock->timestamp = time(NULL);
    newblock->index = previous_block ? (previous_block->index + 1) : 0;
    newblock->previous_block = (void *)previous_block;
    newblock->nonce = 0;
    memset(newblock->hash, 0, 32);
    if ((data) && (data_len)) {
        newblock->data = (unsigned char *)malloc(data_len + 1);
        if (data) {
            memcpy(newblock->data, data, data_len);
            newblock->data[data_len] = 0;
            newblock->data_len = data_len;
        } else {
            free(newblock);
            return NULL;
        }
    } else {
        newblock->data = NULL;
        newblock->data_len = 0;
    }
    return newblock;
}

void block_free(struct block *block) {
    if (!block)
        return;

    free(block->data);
    free(block);
}

int block_mine(struct block *newblock, int zero_bits) {
    sha3_context ctx;
    const unsigned char *hash;
    char proof_of_work[0x100];
    static unsigned char ref_hash[32];
    char in[16];
    char out[32];
    int len;

    if (!newblock)
        return 0;

    if ((zero_bits < 0) || (zero_bits > 64))
        return 0;

    proof_of_work[0] = 0;

    int proof_len = snprintf((char *)proof_of_work, 0x100, "edblock:1:%i:%i:%.*s::", zero_bits, (int)newblock->timestamp, (int)newblock->data_len, (const char *)newblock->data);
    if (proof_len >= 0x100 - 10)
        return 0;

    uint64_t counter = 0;
    unsigned char *ptr = proof_of_work + proof_len;

    int bytes = zero_bits / 8;
    int mbits = zero_bits % 8;

    if (mbits)
        mbits = 8 - mbits;

    // seems faster to just increment count instead of randomizing it
    while (1) {
        sha3_Init256(&ctx);

        uint64_t counter_be = htonll(counter);
#ifdef BLOCKCHAIN_HASHCASH_ASCII_STRING
        const BYTE *counter_ptr = (const BYTE *)&counter_be;
        int offset = 0;
        do {
            if (counter_ptr[offset])
                break;
            offset ++;
        } while (offset < 7);

        len = base64_encode(counter_ptr + offset, (BYTE *)ptr, 8 - offset, 0);
        sha3_Update(&ctx, proof_of_work, proof_len + len);
#else
        len = 8;
        sha3_Update(&ctx, proof_of_work, proof_len);
        sha3_Update(&ctx, (unsigned char *)&counter_be, 8);
#endif
        if (newblock->previous_block)
            sha3_Update(&ctx, (struct block *)newblock->previous_block, 32);
        else
            sha3_Update(&ctx, ref_hash, 32);

        hash = (const unsigned char *)sha3_Finalize(&ctx);

        if (!memcmp(hash, ref_hash, bytes)) {
            if ((!mbits) || ((hash[bytes] >> mbits) == (ref_hash[bytes] >> mbits))) {
                newblock->nonce = counter;
                memcpy(newblock->hash, hash, 32);
                return 1;
            }
        }
        counter++;

        // not found
        if (counter == 0)
            return 0;
    }
    return 0;
}

int block_verify(struct block *newblock, int zero_bits) {
    static unsigned char ref_hash[32];
    char proof_of_work[0x100];
    sha3_context ctx;
    const unsigned char *hash;
    int bytes;
    int mbits;
    int len;

    if (!newblock)
        return 0;

    int proof_len = snprintf((char *)proof_of_work, 0x100, "edblock:1:%i:%i:%.*s::", zero_bits, (int)newblock->timestamp, (int)newblock->data_len, (const char *)newblock->data);
    sha3_Init256(&ctx);

    uint64_t counter_be = ntohll(newblock->nonce);
#ifdef BLOCKCHAIN_HASHCASH_ASCII_STRING
    const BYTE *counter_ptr = (const BYTE *)&counter_be;
    int offset = 0;
    do {
        if (counter_ptr[offset])
            break;
        offset ++;
    } while (offset < 7);

    len = base64_encode(counter_ptr + offset, (BYTE *)ptr, 8 - offset, 0);
    sha3_Update(&ctx, proof_of_work, proof_len + len);
#else
    len = 8;
    sha3_Update(&ctx, proof_of_work, proof_len);
    sha3_Update(&ctx, (unsigned char *)&counter_be, 8);
#endif
    if (newblock->previous_block)
        sha3_Update(&ctx, (struct block *)newblock->previous_block, 32);
    else
        sha3_Update(&ctx, ref_hash, 32);

    hash = (const unsigned char *)sha3_Finalize(&ctx);
    bytes = zero_bits / 8;
    mbits = zero_bits % 8;
    if ((memcmp(hash, ref_hash, bytes)) || ((mbits) && ((hash[bytes] >> mbits) != (ref_hash[bytes] >> mbits))))
        return 0;

    return 1;
}

int blockchain_verify(struct block *newblock, int zero_bits) {
    if (!newblock)
        return 0;

    while (newblock) {
        if (!block_verify(newblock, zero_bits))
            return 0;

        newblock = (struct block *)newblock->previous_block;
    }
    return 1;
}

void blockchain_free(struct block *newblock) {
    while (newblock) {
        struct block *prev = (struct block *)newblock->previous_block;
        block_free(prev);
        newblock = prev;
    }
}
