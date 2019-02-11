#include <string.h>
#include <stdlib.h>
#include "sha3.h"
#include "poa.h"
#ifdef POA_DEBUG
    #include <stdio.h>
#endif

int poa_init(struct poa_context *poa) {
    if (!poa)
        return -1;

    memset(poa, 0, sizeof(struct poa_context));
    return 0;
}

void poa_done(struct poa_context *poa) {
    if (!poa)
        return;

    free(poa->hashes);
}

int poa_add(struct poa_context *poa, const unsigned char *hash, poa_verify verify_hash, void *userdata) {
    if ((!poa) || (!hash))
        return -1;

    if ((verify_hash) && (verify_hash(hash, userdata) != 1))
        return -1;

    int write_at_pos = poa->hash_len;
    int start = 0;
    int end = poa->hash_len - 1;
    int middle = end / 2;

    int order = 0;
    int i = 0;
    while (start <= end) {
        i ++;
        order = memcmp(poa->hashes[middle], hash, POA_HASH_SIZE) * -1;
        write_at_pos = middle;
        if (order > 0)
            start = middle + 1;
        else
        if (!order)
            return -1;
        else
            end = middle - 1;
        middle = (start + end) / 2;
    }
    if (order > 0)
        write_at_pos ++;

    if (poa->hash_len >= poa->hash_allocated_size - 1) {
        poa->hash_allocated_size += POA_HASH_INCREMENT;
        poa->hashes = (poa_hash *)realloc(poa->hashes, poa->hash_allocated_size * sizeof(poa_hash));
        if (!poa->hashes) {
            poa->hash_allocated_size = 0;
            poa->hash_len = 0;
            return -1;
        }
    }

    if (write_at_pos != poa->hash_len)
        memmove(&poa->hashes[write_at_pos + 1], poa->hashes[write_at_pos], (poa->hash_len - write_at_pos + 1) * sizeof(poa_hash));

    poa->hash_len ++;
    memcpy(poa->hashes[write_at_pos], hash, POA_HASH_SIZE);

    return 0;
}

int poa_compute(struct poa_context *poa, unsigned int winner_bytes) {
    if ((!poa) || (poa->hash_len <= 0) || (!poa->hashes))
        return -1;

    sha3_context ctx;
    int i;

    sha3_Init256(&ctx);
    for (i = 0; i < poa->hash_len; i ++)    
        sha3_Update(&ctx, poa->hashes[i], POA_HASH_SIZE);

    const unsigned char *data = (const unsigned char *)sha3_Finalize(&ctx);
    
    int byte_1 = 0;
    int byte_2 = 7;
    int byte_3 = 15;
    int byte_4 = 31;

    if (winner_bytes) {
        unsigned long use_bytes = (unsigned long)winner_bytes;
        byte_1 = use_bytes / 0x1000000UL % POA_HASH_SIZE;
        use_bytes %= 0x1000000UL;

        byte_2 = use_bytes / 0x10000UL % POA_HASH_SIZE;
        use_bytes %= 0x10000UL;

        byte_3 = use_bytes / 0x100UL % POA_HASH_SIZE;
        use_bytes %= 0x100UL;

        byte_4 = winner_bytes % POA_HASH_SIZE;
    }

    unsigned long modulo = (unsigned long)poa->hash_len;
    unsigned int winner = (data[byte_1] * 0x1000000UL + data[byte_2] * 0x10000UL + data[byte_3] * 0x100UL + data[byte_4]) % modulo;
    poa->hash_len = 0;
    poa->hash_allocated_size = 0;
    free(poa->hashes);
    poa->hashes = NULL;

    return winner;
}

#ifdef POA_DEBUG
void poa_debug(struct poa_context *poa) {
    if (!poa)
        return;

    int i;
    int j;
    for (i = 0; i < poa->hash_len; i ++) {
        fprintf(stderr, "hash[%06i]: ", i);
        for (j = 0; j < POA_HASH_SIZE; j ++) {
            fprintf(stderr, "%02x", (int)poa->hashes[i][j]);
        }
        fprintf(stderr, "\n");
    }
}
#endif
