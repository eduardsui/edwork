/* base64.c : base-64 / MIME encode/decode */
/* PUBLIC DOMAIN - Jon Mayo - November 13, 2003 */
/* $Id: base64.c 156 2007-07-12 23:29:10Z orange $ */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include "base64.h"

static const uint8_t base64enc_tab[]= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static const uint8_t base64dec_tab[256]= {
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255, 62,255,255,
	 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,  0,255,255,
	255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255, 63,
	255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
};

/* decode a base64 string in one shot */
int base64_decode(size_t in_len, const char *in, size_t out_len, unsigned char *out) {
	unsigned ii, io;
	uint_least32_t v;
	unsigned rem;

	for (io = 0, ii = 0,v = 0, rem = 0; ii < in_len; ii ++) {
		unsigned char ch;
		if (isspace(in[ii]))
            continue;
		if ((in[ii]=='=') || (!in[ii]))
            break; /* stop at = or null character*/
		ch = base64dec_tab[(unsigned)in[ii]];
		if (ch == 255)
            break; /* stop at a parse error */
		v = (v<<6) | ch;
		rem += 6;
		if (rem >= 8) {
			rem -= 8;
			if (io >= out_len)
                return -1; /* truncation is failure */
			out[io ++] = (v >> rem) & 255;
		}
	}
	if (rem >= 8) {
		rem -= 8;
		if (io >= out_len)
            return -1; /* truncation is failure */
		out[io ++] = (v >> rem) & 255;
	}
	return io;
}

int base64_encode(size_t in_len, const unsigned char *in, size_t out_len, char *out) {
	unsigned ii, io;
	uint_least32_t v;
	unsigned rem;

	for(io = 0, ii = 0, v = 0, rem = 0; ii < in_len; ii ++) {
		unsigned char ch;
		ch = in[ii];
		v = (v << 8) | ch;
		rem += 8;
		while (rem >= 6) {
			rem -= 6;
			if (io >= out_len)
                return -1; /* truncation is failure */
			out[io ++] = base64enc_tab[(v >> rem) & 63];
		}
	}
	if (rem) {
		v <<= (6 - rem);
		if (io >= out_len)
            return -1; /* truncation is failure */
		out[io ++] = base64enc_tab[v & 63];
	}
	if (io < out_len)
	    out[io] = 0;

	return io;
}
