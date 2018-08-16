/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>
#include "edfs_types.h"
/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned int  SHA_WORD;         // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	SHA_WORD datalen;
	unsigned long long bitlen;
	SHA_WORD state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);

void sha256(const BYTE in[], size_t len, BYTE hash[]);
void hmac_sha256(const BYTE key_gc[], size_t key_len, const BYTE data[], size_t data_len, BYTE hash[]);

#endif   // SHA256_H
