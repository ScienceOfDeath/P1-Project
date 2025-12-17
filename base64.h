#include <stdint.h>
#ifndef BASE64_H
#define BASE64_H

int base64_encode(const uint8_t *in, int in_len, char *out);
int base64_decode(const char *in, uint8_t *out);

#endif
