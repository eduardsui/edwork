/* base64.h : base-64 / MIME encode/decode */
/* PUBLIC DOMAIN - Jon Mayo - November 13, 2003 */
/* $Id: base64.h 128 2007-04-20 08:20:40Z orange $ */
#ifndef BASE64_H
#define BASE64_H
#include <stddef.h>


int base64_encode(size_t in_len, const unsigned char *in, size_t out_len, char *out);
int base64_decode(size_t in_len, const char *in, size_t out_len, unsigned char *out);

#endif /* BASE64_H */
