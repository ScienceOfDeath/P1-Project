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

void printState(uint8_t state[ROWS][COLUMNS])
{
    
    for (int column = 0; column < COLUMNS; column++) 
    {
        for (int row = 0; row < ROWS; row++) 
        {
            printf("%02X ", state[row][column]);
        }
        printf("\n");
    }
    printf("\n");
}

void printBlocksColumn(aes_context *context)
{
    for (int i = 0; i < context->blocks; i++)
    {
        printState(context->aes_blocks[i]);
    }
}


void printBlocksRow(aes_context *context)
{
    for (int i = 0; i < context->blocks; i++)
    {
        printf("Block %d:\n", i);
        for (int row = 0; row < ROWS; row++) 
        {
            for (int column = 0; column < COLUMNS; column++) 
            {
                printf("%02X ", context->aes_blocks[i][row][column]);
            }
            printf("\n");
        }
        printf("\n");
    }
}