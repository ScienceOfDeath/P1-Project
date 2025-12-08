#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define AES_128 10

#define BITS_PER_BYTE 8

#define ROWS 4
#define COLUMNS 4

#define MAX_NUMBER_OF_BLOCKS 256
#define BLOCK_SIZE ROWS * COLUMNS
#define MAX_MESSAGE_LENGTH MAX_NUMBER_OF_BLOCKS * BLOCK_SIZE


// The AES Substitution Box (S-Box)
static const unsigned char sbox[256] = {
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16   // F
};

// The AES Inverse Substitution Box (InvS-Box)
static const unsigned char rsbox[256] = {
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, // 0
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, // 1
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, // 2
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, // 3
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, // 4
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, // 5
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, // 6
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, // 7
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, // 8
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, // 9
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, // A
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, // B
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, // C
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, // D
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, // E
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d  // F
};

// 00000000 - 11111111

/*
    [0,0,0,0]
    [1,1,1,1]
    [2,2,2,2]
    [3,3,3,3]
*/

static const unsigned char rijndael_galois_field[ROWS][COLUMNS] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};

static const unsigned char inverse_rijndael_galois_field[ROWS][COLUMNS] = {
    {0x0E, 0x0B, 0x0D, 0x09},
    {0x09, 0x0E, 0x0B, 0x0D},
    {0x0D, 0x09, 0x0E, 0x0B},
    {0x0B, 0x0D, 0x09, 0x0E}
};


int stringToHex(const char string[], unsigned char hex[])
{
    int i = 0;
    while (string[i] != '\0')
    {
        hex[i] = (unsigned char)string[i];  // store numeric (hex) value
        i++;
    }

    // AES requires exactly 16 bytes -= Move to parsing function =-
    while (i % 16 != 0)
    {
        hex[i++] = '\0';
    }
    return i;
}

void printHex(unsigned char hex[], int len)
{
    for (int i = 0; i < len ; i++)
    {
        printf("%02X ", hex[i]);
    }
    printf("\n");
}

void substite(unsigned char aes_block[MAX_MESSAGE_LENGTH][ROWS][COLUMNS], const unsigned char sbox[256], const int blocks)
{
    for (int block = 0; block < blocks; block++)
    {
        for (int column = 0; column < COLUMNS; column++)
        {
            for (int row = 0; row < ROWS; row++)
            {
                aes_block[block][row][column] = sbox[aes_block[block][row][column]];
            }
        }
    }
}


void hexToBlock(const unsigned char hex[MAX_MESSAGE_LENGTH], unsigned char aes_block[MAX_NUMBER_OF_BLOCKS][ROWS][COLUMNS], const int blocks)
{
    int counter = 0;
    for (int block = 0; block < blocks; block++)
    {
        for (int column = 0; column < COLUMNS; column++)
        {
            for (int row = 0; row < ROWS; row++)
            {
                aes_block[block][row][column] = hex[counter++];
            }
        }
    }
    
}

void blockToHex(unsigned char hex[MAX_MESSAGE_LENGTH], const unsigned char aes_block[MAX_NUMBER_OF_BLOCKS][ROWS][COLUMNS], const int blocks)
{
    int counter = 0;
    for (int block = 0; block < blocks; block++)
    {
        for (int column = 0; column < COLUMNS; column++)
        {
            for (int row = 0; row < ROWS; row++)
            {
                hex[counter++] = aes_block[block][row][column];
            }
        }
    }
    hex[counter] = '\0';
}


unsigned char galoisMultiplication(unsigned char multiplicand, unsigned char multiplier)
{
    unsigned char product = 0;

    for (int i = 0; i < BITS_PER_BYTE; i++)
    {
        if (multiplier & 1)
        {
            product = product ^ multiplicand;
        }

        unsigned char overflow = multiplicand & 0x80;

        multiplicand = multiplicand << 1;

        if (overflow != 0)
        {
            multiplicand = multiplicand ^ 0x1B;
        }

        multiplier = multiplier >> 1;
    }

    return product;
}


void mixColumn(unsigned char column[ROWS], const unsigned char galois_field[ROWS][COLUMNS])
{
    unsigned char result[ROWS];

    for (int i = 0; i < COLUMNS; i++)
    {
        result[i] =
        galoisMultiplication(column[0], galois_field[i][0]) ^
        galoisMultiplication(column[1], galois_field[i][1]) ^
        galoisMultiplication(column[2], galois_field[i][2]) ^
        galoisMultiplication(column[3], galois_field[i][3]);
    }

    for (int i = 0; i < COLUMNS; i++)
    {
        column[i] = result[i];
    }
}


void mixColumns(unsigned char state[ROWS][COLUMNS], const unsigned char gf[ROWS][COLUMNS])
{

    unsigned char state_column[ROWS];
    for (int column = 0; column < COLUMNS; column++)
    {
        for (int row = 0; row < ROWS; row++)
        {
            state_column[row] = state[row][column];
        }
        
        mixColumn(state_column, gf);

        for (int row = 0; row < ROWS; row++)
        {
            state[row][column] = state_column[row];
        }
    }
}

void mixColumnBlocks(unsigned char aes_block[MAX_NUMBER_OF_BLOCKS][ROWS][COLUMNS], int blocks)
{
    for (int block = 0; block < blocks; block++)
    {        
        mixColumns(aes_block[block], rijndael_galois_field);       
    }
}


void inverseMixColumnBlocks(unsigned char aes_block[MAX_NUMBER_OF_BLOCKS][ROWS][COLUMNS], int blocks)
{
    for (int block = 0; block < blocks; block++)
    {        
        mixColumns(aes_block[block], inverse_rijndael_galois_field);       
    }
}



void shiftRow(unsigned char state[ROWS][COLUMNS])
{   

    unsigned char tmp;

    tmp         = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = tmp;

    for (int i = 0; i < 2; i++)
    {
        tmp         = state[2][0];
        state[2][0] = state[2][1];
        state[2][1] = state[2][2];
        state[2][2] = state[2][3];
        state[2][3] = tmp;
    }
    
    for (int i = 0; i < 3; i++)
    {
        tmp         = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = tmp;
    }
        
    
}

void inverseShiftRow(unsigned char state[ROWS][COLUMNS])
{   

    unsigned char tmp;

    tmp         = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = tmp;

    for (int i = 0; i < 2; i++)
    {
        tmp         = state[2][3];
        state[2][3] = state[2][2];
        state[2][2] = state[2][1];
        state[2][1] = state[2][0];
        state[2][0] = tmp;
    }
    
    for (int i = 0; i < 3; i++)
    {
        tmp         = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = tmp;
    }
        
    
}


void shiftRows(unsigned char aes_block[MAX_NUMBER_OF_BLOCKS][ROWS][COLUMNS], int blocks)
{
    for (int block = 0; block < blocks; block++)
    {
        shiftRow(aes_block[block]);
    }
}

void inverseShiftRows(unsigned char aes_block[MAX_NUMBER_OF_BLOCKS][ROWS][COLUMNS], int blocks)
{
    for (int block = 0; block < blocks; block++)
    {
        inverseShiftRow(aes_block[block]);
    }
}


void printBlocksColumn(unsigned char aes_block[MAX_NUMBER_OF_BLOCKS][ROWS][COLUMNS], int blocks)
{
    for (int block = 0; block < blocks; block++)
    {
        printf("Block %d:\n", block);
        for (int column = 0; column < COLUMNS; column++) 
        {
            for (int row = 0; row < ROWS; row++) 
            {
                printf("%02X ", aes_block[block][row][column]);
            }
            printf("\n");
        }
        printf("\n");
    }
}


void printBlocksRow(unsigned char aes_block[MAX_NUMBER_OF_BLOCKS][ROWS][COLUMNS], int blocks)
{
    for (int block = 0; block < blocks; block++)
    {
        printf("Block %d:\n", block);
        for (int row = 0; row < ROWS; row++) 
        {
            for (int column = 0; column < COLUMNS; column++) 
            {
                printf("%02X ", aes_block[block][row][column]);
            }
            printf("\n");
        }
        printf("\n");
    }
}


void encrypt(char *plain_text, char *encrypted_text, int blocks)
{
    
}

void decrypt()
{

}


int main(void)
{
    char plain_text[MAX_MESSAGE_LENGTH];
    unsigned char hex_text[MAX_MESSAGE_LENGTH];
    unsigned char aes_block[MAX_NUMBER_OF_BLOCKS][ROWS][COLUMNS];
    int len, blocks;

    printf("Input plain text: ");
    scanf("\n %[^\n]s", plain_text);

    len = stringToHex(plain_text, hex_text);
    blocks = len / 16;

    hexToBlock(hex_text, aes_block, blocks);

    printBlocksRow(aes_block, blocks);

    printf("Substituted:\n");
    substite(aes_block, sbox, blocks);
    printBlocksRow(aes_block, blocks);

    printf("Shifted Rows:\n");
    shiftRows(aes_block, blocks);
    printBlocksRow(aes_block, blocks);


    printf("Mixed Columns:\n");
    mixColumnBlocks(aes_block, blocks);
    printBlocksRow(aes_block, blocks);
    
    blockToHex(hex_text, aes_block, blocks);
    printf("Encrypted: %s\n", hex_text);

    
    inverseMixColumnBlocks(aes_block, blocks);
    printBlocksRow(aes_block, blocks);

    inverseShiftRows(aes_block, blocks);
    printBlocksRow(aes_block, blocks);

    substite(aes_block, rsbox, blocks);
    printBlocksRow(aes_block, blocks);

    blockToHex(hex_text, aes_block, blocks);

    printHex(hex_text, strlen(hex_text));

    printf("\nPlain: %s\n", hex_text);


    return 0;

}
