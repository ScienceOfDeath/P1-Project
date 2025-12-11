#ifndef BASE64_H
#define BASE64_H

int base64_encode(const unsigned char *in, int in_len, char *out);
int base64_decode(const char *in, unsigned char *out);

#endif
