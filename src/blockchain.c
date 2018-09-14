#include "blockchain.h"
#include "sha3.h"
#include "base64.h"
#include "inttypes.h"
#include "log.h"

#ifdef _WIN32
    #include <windows.h>
#else
    #include <arpa/inet.h>
#endif

uint64_t switchorder(uint64_t input);
uint64_t microseconds();

#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : switchorder(x))
#endif

#ifndef ntohll
#define ntohll(x) ((1==ntohl(1)) ? (x) : switchorder(x))
#endif

struct block *block_new(struct block *previous_block, const unsigned char *data, unsigned int data_len) {
    struct block *newblock = (struct block *)malloc(sizeof(struct block));
    if (!newblock)
        return NULL;

    newblock->timestamp = microseconds();
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

int block_mine_with_copy(struct block *newblock, int zero_bits, unsigned char *previous_hash) {
    sha3_context ctx;
    static unsigned char ref_hash[32];
    const unsigned char *hash;
    char proof_of_work[0x100];
    char in[16];
    char out[32];
    int len;

    if (!newblock)
        return 0;

    if ((zero_bits < 0) || (zero_bits > 64))
        return 0;

    if (!previous_hash)
        previous_hash = ref_hash;

    proof_of_work[0] = 0;

    int proof_len = snprintf((char *)proof_of_work, 0x100, "edblock:1:%i:%i:%.*s::%" PRIu64 ":", zero_bits, (int)(newblock->timestamp / 1000000UL), (int)newblock->data_len, (const char *)newblock->data, newblock->index);
    if (proof_len >= 0x100 - 10)
        return 0;

    uint64_t counter = 0;
    unsigned char *ptr = (unsigned char *)proof_of_work + proof_len;

    int bytes = zero_bits / 8;
    int mbits = zero_bits % 8;

    if (mbits)
        mbits = 8 - mbits;

    // seems faster to just increment count instead of randomizing it
    while (1) {
        sha3_Init256(&ctx);

        uint64_t counter_be = htonll(counter);
#ifdef BLOCKCHAIN_HASHCASH_ASCII_STRING
        const unsigned char *counter_ptr = (const unsigned char *)&counter_be;
        int offset = 0;
        do {
            if (counter_ptr[offset])
                break;
            offset ++;
        } while (offset < 7);

        len = base64_decode(8 - offset, (const char *)counter_ptr + offset, sizeof(proof_of_work) - proof_len, (char *)ptr);
        sha3_Update(&ctx, proof_of_work, proof_len + len);
#else
        len = 8;
        sha3_Update(&ctx, proof_of_work, proof_len);
        sha3_Update(&ctx, (unsigned char *)&counter_be, 8);
#endif
        sha3_Update(&ctx, previous_hash, 32);

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

int block_mine(struct block *newblock, int zero_bits) {
    if (!newblock)
        return 0;

    return block_mine_with_copy(newblock, zero_bits, newblock->previous_block ? ((struct block *)newblock->previous_block)->hash : NULL);
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

    int proof_len = snprintf((char *)proof_of_work, 0x100, "edblock:1:%i:%i:%.*s::%" PRIu64 ":", zero_bits, (int)(newblock->timestamp / 1000000UL), (int)newblock->data_len, (const char *)newblock->data, newblock->index);
    sha3_Init256(&ctx);

    uint64_t counter_be = ntohll(newblock->nonce);
#ifdef BLOCKCHAIN_HASHCASH_ASCII_STRING
    const unsigned char *counter_ptr = (const unsigned char *)&counter_be;
    int offset = 0;
    do {
        if (counter_ptr[offset])
            break;
        offset ++;
    } while (offset < 7);

    unsigned char *ptr = (unsigned char *)proof_of_work + proof_len;
    len = base64_encode(8 - offset, counter_ptr + offset, sizeof(proof_of_work) - proof_len, (char *)ptr);
    sha3_Update(&ctx, proof_of_work, proof_len + len);
#else
    len = 8;
    sha3_Update(&ctx, proof_of_work, proof_len);
    sha3_Update(&ctx, (unsigned char *)&counter_be, 8);
#endif
    if (newblock->previous_block)
        sha3_Update(&ctx, ((struct block *)newblock->previous_block)->hash, 32);
    else
        sha3_Update(&ctx, ref_hash, 32);

    hash = (const unsigned char *)sha3_Finalize(&ctx);
    bytes = zero_bits / 8;
    mbits = zero_bits % 8;
    if ((memcmp(hash, ref_hash, bytes)) || ((mbits) && ((hash[bytes] >> mbits) != (ref_hash[bytes] >> mbits)))) {
        log_error("error in hash verify, block %i", (int)newblock->index);
        return 0;
    }

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
        block_free(newblock);
        newblock = prev;
    }
}

int block_save(struct block *newblock, const char *path) {
    char fullpath[4096];
    char out[32];

    if (!newblock)
        return -1;

    fullpath[0] = 0;

    uint64_t index = htonll(newblock->index);

    size_t len = base64_encode(sizeof(uint64_t), (const unsigned char *)&index, sizeof(out) - 1, (char *)out);
    out[len] = 0;

    snprintf(fullpath, sizeof(fullpath), "%s/%s", path, out);

    FILE *f = fopen(fullpath, "wb");
    if (!f)
        return -1;

    uint64_t timestamp = htonll(newblock->timestamp);
    uint64_t nonce = htonll(newblock->nonce);
    unsigned int data_len = htonl(newblock->data_len);

    fwrite("EDB0100", 1, 7, f);
    fwrite(&index, 1, sizeof(uint64_t), f);
    fwrite(&timestamp, 1, sizeof(uint64_t), f);
    fwrite(&nonce, 1, sizeof(uint64_t), f);
    fwrite(&newblock->hash, 1, 32, f);
    fwrite(&data_len, 1, sizeof(unsigned int), f);
    if (newblock->data_len)
        fwrite(newblock->data, 1, newblock->data_len, f);
    fclose(f);

    return 0;
}

unsigned char *block_save_buffer(struct block *newblock, int *size) {
    uint64_t index = htonll(newblock->index);
    uint64_t timestamp = htonll(newblock->timestamp);
    uint64_t nonce = htonll(newblock->nonce);
    unsigned int data_len = htonl(newblock->data_len);
    *size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t) + 32 + sizeof(unsigned int) + newblock->data_len;
    unsigned char *buffer = (unsigned char *)malloc(*size);
    unsigned char *ptr = buffer;

    memcpy(ptr, &index, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    memcpy(ptr, &timestamp, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    memcpy(ptr, &nonce, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    memcpy(ptr, newblock->hash, 32);
    ptr += 32;
    memcpy(ptr, &data_len, sizeof(unsigned int));
    ptr += sizeof(unsigned int);
    if (newblock->data_len) {
        memcpy(ptr, newblock->data, newblock->data_len);
        ptr += newblock->data_len;
    }
    return buffer;
}

struct block *block_load_buffer(const unsigned char *buffer, int size) {
    int min_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t) + 32 + sizeof(unsigned int);
    if ((!buffer) || (size < min_size))
        return NULL;

    uint64_t index;
    uint64_t timestamp;
    uint64_t nonce;
    unsigned int data_len;
    const unsigned char *ptr = buffer;

    struct block *newblock = block_new(NULL, NULL, 0);

    memcpy(&index, ptr, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    memcpy(&timestamp, ptr, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    memcpy(&nonce, ptr, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    memcpy(newblock->hash, ptr, 32);
    ptr += 32;
    memcpy(&data_len, ptr, sizeof(unsigned int));
    ptr += sizeof(unsigned int);

    newblock->index = ntohll(index);
    newblock->timestamp = ntohll(timestamp);
    newblock->nonce = ntohll(nonce);
    newblock->data_len = ntohl(data_len);

    if (newblock->data_len) {
        newblock->data = (unsigned char *)malloc(newblock->data_len + 1);
        if (!newblock->data) {
            block_free(newblock);
            return NULL;
        }
        memcpy(newblock->data, ptr, newblock->data_len);
        newblock->data[newblock->data_len] = 0;
        ptr += newblock->data_len;
    }
    return newblock;
}

struct block *block_load(const char *path, uint64_t index) {
    char fullpath[4096];
    char out[32];
    struct block *newblock = NULL;

    fullpath[0] = 0;

    uint64_t index_be = htonll(index);

    size_t len = base64_encode(sizeof(uint64_t), (const unsigned char *)&index_be, sizeof(out) - 1, (char *)out);
    out[len] = 0;

    snprintf(fullpath, sizeof(fullpath), "%s/%s", path, out);

    FILE *f = fopen(fullpath, "rb");
    if (!f)
        return NULL;

    uint64_t timestamp;
    unsigned char *data;
    uint64_t nonce;
    unsigned int data_len;
    void *previous_block;
    unsigned char hash[32];

    char version_buffer[7];
    if ((fread(version_buffer, 1, 7, f) < 7) || (memcmp(version_buffer, "EDB0100", 7))) {
        // unsupported version
        fclose(f);
        return 0;
    }
    fread(&index, 1, sizeof(uint64_t), f);
    fread(&timestamp, 1, sizeof(uint64_t), f);
    fread(&nonce, 1, sizeof(uint64_t), f);
    newblock = block_new(NULL, NULL, 0);
    if (newblock) {
        newblock->index = ntohll(index);
        newblock->timestamp = ntohl(timestamp);
        newblock->nonce = ntohll(nonce);
        fread(&newblock->hash, 1, 32, f);
        fread(&data_len, 1, sizeof(unsigned int), f);
        newblock->data_len = ntohl(data_len);
        if (newblock->data_len) {
            newblock->data = (unsigned char *)malloc(newblock->data_len + 1);
            if (data) {
                newblock->data[newblock->data_len] = 0;
            } else {
                fclose(f);
                block_free(newblock);
                return NULL;
            }
            fread(newblock->data, 1, newblock->data_len, f);
        }
    }
    fclose(f);

    return newblock;
}

struct block *blockchain_load(const char *path) {
    uint64_t i = 0;
    struct block *newblock = NULL;
    struct block *top_block;
    do {
        top_block = newblock;
        newblock = block_load(path, i ++);
        if (newblock)
            newblock->previous_block = top_block;
    } while (newblock);
    return top_block;
}
