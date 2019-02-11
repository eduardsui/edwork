#ifndef __POA_H
#define __POA_H

#define POA_HASH_INCREMENT  1024
#define POA_HASH_SIZE       32

typedef unsigned char poa_hash[POA_HASH_SIZE];
typedef int (*poa_verify)(const unsigned char *hash, void *userdata);

struct poa_context {
    poa_hash *hashes;
    int hash_allocated_size;
    int hash_len;
};


int poa_init(struct poa_context *poa);
void poa_done(struct poa_context *poa);
int poa_add(struct poa_context *poa, const unsigned char *hash, poa_verify verify_hash, void *userdata);
int poa_compute(struct poa_context *poa, unsigned int winner_bytes);
#ifdef POA_DEBUG
    void poa_debug(struct poa_context *poa)
#endif

#endif
