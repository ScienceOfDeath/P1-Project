#ifndef AES_H
#define AES_H

#include <stdint.h>

/* ===== Constants ===== */
#define AES_128_KEY 16
#define AES_192_KEY 24
#define AES_256_KEY 32

#define ROWS 4
#define COLUMNS 4
#define BLOCK_SIZE (ROWS * COLUMNS)

/* ===== Context ===== */
typedef struct 
{   
    int blocks;
    int rounds;
    int length;
    int key_len;

    uint8_t key[AES_256_KEY];
    uint8_t aes_blocks[256][ROWS][COLUMNS];
    uint8_t round_keys[15][ROWS][COLUMNS];
} aes_context;

/* ===== Core AES ===== */
void setKey(aes_context *context, const uint8_t *key);
void keySchedule(aes_context *context);

void aesEncryptBlock(aes_context *context, uint8_t block[BLOCK_SIZE]);
void aesDecryptBlock(aes_context *context, uint8_t block[BLOCK_SIZE]);

/* ===== Helpers used in tests ===== */
uint8_t galoisMultiplication(uint8_t a, uint8_t b);
void mixColumn(uint8_t col[ROWS], const uint8_t gf[ROWS][COLUMNS]);
void shiftRow(uint8_t state[ROWS][COLUMNS]);
void inverseShiftRow(uint8_t state[ROWS][COLUMNS]);
int padPlainText(uint8_t *data, int len);
int removePadding(uint8_t *data, int len);

#endif
