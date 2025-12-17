#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "base64.h"

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_encode(const uint8_t *in, int in_len, char *out) {
    int i, j = 0;
    uint8_t a3[3];
    uint8_t a4[4];

    for (i = 0; i < in_len;) {
        int k;
        for (k = 0; k < 3; k++) {
            if (i < in_len) a3[k] = in[i++];
            else a3[k] = 0;
        }

        a4[0] = (a3[0] & 0xfc) >> 2;
        a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
        a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
        a4[3] = a3[2] & 0x3f;

        for (k = 0; k < 4; k++) {
            if (i - k > in_len) out[j++] = '=';
            else out[j++] = b64_table[a4[k]];
        }
    }

    out[j] = '\0';
    return j;
}

int base64_decode(const char *in, uint8_t *out) {
    int in_len = strlen(in);
    int i = 0, j = 0;
    uint8_t a3[3], a4[4];
    int k;

    while (i < in_len) {
        int pad = 0;
        for (k = 0; k < 4; k++) {
            if (in[i] == '=') { a4[k] = 0; pad++; i++; }
            else {
                const char *p = strchr(b64_table, in[i++]);
                if (p) a4[k] = p - b64_table;
                else a4[k] = 0;
            }
        }

        a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
        a3[1] = ((a4[1] & 0x0f) << 4) + ((a4[2] & 0x3c) >> 2);
        a3[2] = ((a4[2] & 0x03) << 6) + a4[3];

        for (k = 0; k < 3 - pad; k++)
            out[j++] = a3[k];
    }

    return j;
}
