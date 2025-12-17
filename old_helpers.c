#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// MESSAGE SIZES
#define MAX_NUMBER_OF_BLOCKS 256
#define BLOCK_SIZE (ROWS * COLUMNS)
#define MAX_MESSAGE_LENGTH (MAX_NUMBER_OF_BLOCKS * BLOCK_SIZE)

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


void printHex(uint8_t hex[], int len)
{
    for (int i = 0; i < len ; i++)
    {
        printf("%02X ", hex[i]);
    }
    printf("\n");
}


void hexToBlock(const uint8_t hex[MAX_MESSAGE_LENGTH], aes_context *context)
{
    int counter = 0;
    for (int block = 0; block < context->blocks; block++)
    {
        for (int column = 0; column < COLUMNS; column++)
        {
            for (int row = 0; row < ROWS; row++)
            {
                context->aes_blocks[block][row][column] = hex[counter++];
            }
        }
    }
    
}

void blockToHex(uint8_t hex[MAX_MESSAGE_LENGTH], const aes_context *context)
{
    int counter = 0;
    for (int block = 0; block < context->blocks; block++)
    {
        for (int column = 0; column < COLUMNS; column++)
        {
            for (int row = 0; row < ROWS; row++)
            {
                hex[counter++] = context->aes_blocks[block][row][column];
            }
        }
    }
}


void hexStringToBytes(const char *hex, uint8_t *bytes, int *len) {
    int hex_len = strlen(hex);
    if (hex_len % 2 != 0) 
    {
        printf("Invalid hex key length.\n");
        exit(EXIT_FAILURE);
    }
    *len = hex_len / 2;
    for (int i = 0; i < *len; i++) 
    {
        unsigned int temp;
        sscanf(hex + 2 * i, "%2x", &temp);
        bytes[i] = (uint8_t)temp;
    }
}


int main(void)
{
    char input_text[MAX_MESSAGE_LENGTH];
    char base64_text[MAX_MESSAGE_LENGTH * 4];
    uint8_t hex_text[MAX_MESSAGE_LENGTH * 2];

    char input_key[AES_256_KEY * 2 + 1];
    uint8_t key[AES_256_KEY];

    aes_context context;   

    // Key Handling
    printf("Input key (hex): ");
    scanf("\n %[^\n]s", input_key);

    hexStringToBytes(input_key, key, &context.key_len);
    setKey(&context, key);
    keySchedule(&context);
    // EO Key handling

    // Choose an action to perform
    int choice = 0;
    int valid = 0;

    while (1)
    {
        do {
            printf("\n---= Choose action =---\n[1] Encrypt\n[2] Decrypt\n[3] Exit\n");
            valid = scanf("%d", &choice);
        } while (valid != 1 && (choice != 1 || choice != 2 || choice != 3));

        switch (choice)
        {
        case 1:
            printf("Input plain text: ");
            scanf("\n %[^\n]s", input_text);

            encrypt(&context, input_text, hex_text);
            base64_encode(hex_text, context.length, base64_text);
            printf("Encrypted (Base64): %s\n", base64_text);
            break;
        
        case 2:
            
            printf("Input encrypted text (base64): ");
            scanf("\n %[^\n]s", input_text);
            
            int hex_len = base64_decode(input_text, hex_text);
            decrypt(&context, hex_text, hex_len, hex_text);
            break;
            
        case 3:
            printf("Exiting program!\n");
            exit(EXIT_SUCCESS);

        default:
            printf("Choice invalid!\nExiting program!\n");
            exit(EXIT_FAILURE);
            break;
        }
    }
    

    return EXIT_SUCCESS;
}