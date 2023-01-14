#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>


void decrypt(unsigned char*, unsigned char*);
void encrypt(unsigned char*, unsigned char*);
unsigned char ffAdd(unsigned char, unsigned char);
unsigned char ffMultiply(unsigned char, unsigned char);
unsigned char xtime(unsigned char);
u_int32_t rotWord(u_int32_t);
u_int32_t subWord(u_int32_t);
u_int32_t* keyExpansion(u_int8_t*, u_int32_t*, unsigned int);
void subBytes(unsigned int**);
void shiftRows(unsigned int**);
void cipher(u_int8_t*, u_int8_t*,u_int32_t*);
void testArithmetic();
void testSubAndRot();
void testKeyExpansion();

int keyLength = 4;
int blockSize = 4;
int numRounds = 10;

 unsigned char Sbox[16][16] = {
    { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 } ,
    { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 } ,
    { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 } ,
    { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 } ,
    { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 } ,
    { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf } ,
    { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 } ,
    { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 } ,
    { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 } ,
    { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb } ,
    { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 } ,
    { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 } ,
    { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a } ,
    { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e } ,
    { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf } ,
    { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
    };


int main(int argc, char** argv) {

    //testArithmetic();
    //testSubAndRot();
    testKeyExpansion();
    /*if (strcmp(argv[1], "-d")) {
        decrypt(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "-e")) {
        encrypt(argv[2], argv[3]);
    }*/

    return 0;
}

/** finite field arithmetic functions **/
unsigned char ffAdd(unsigned char x, unsigned char y) {
    return x ^ y;
}

unsigned char xtime(unsigned char x) {

    if ((x & 0x80) == 0x80) {
        return (x << 1) ^ 0x1b;
    }
    return x << 1;

}

unsigned char ffMultiply(unsigned char x, unsigned char y) {
    
    char total = 0;
    char possibleX[8];
    bzero(possibleX, 8);
    possibleX[0] = x;
    for (int i = 1; i < 8; ++i) {
        possibleX[i] = xtime(possibleX[i - 1]);
    }

    int i = 0;
    while (y != 0) {
        if ((y & 0x01) == 1) {
            total = ffAdd(total, possibleX[i]);
        }
        y = y >> 1;
        ++i;
    }

   return total;

}

u_int32_t rotWord(u_int32_t x) {
    return (x << 8) | (x >> 24);
} 

u_int32_t subWord(u_int32_t x) {

    unsigned int result = 0;

    for (int i = 0; i < 4; ++i ) {
        unsigned char byte = (x >> (8 * (3 - i))) & 0xff;
        unsigned char row = (byte & 0xf0) >> 4;
        unsigned char col = byte & 0x0f;
        byte = Sbox[row][col];
        x = (x & ~(0xff << (8 * (3 - i)))) | (byte << (8 * (3 - i)));
    }
    
    return x;
}

u_int32_t* keyExpansion(u_int8_t key[4*keyLength], u_int32_t word[blockSize*(numRounds+1)], unsigned int keyLength) {
    
    unsigned char temp[4];
    unsigned int rcon[] = { 0x00000000, 
           0x01000000, 0x02000000, 0x04000000, 0x08000000, 
           0x10000000, 0x20000000, 0x40000000, 0x80000000, 
           0x1B000000, 0x36000000, 0x6C000000, 0xD8000000, 
           0xAB000000, 0x4D000000, 0x9A000000, 0x2F000000, 
           0x5E000000, 0xBC000000, 0x63000000, 0xC6000000, 
           0x97000000, 0x35000000, 0x6A000000, 0xD4000000, 
           0xB3000000, 0x7D000000, 0xFA000000, 0xEF000000, 
           0xC5000000, 0x91000000, 0x39000000, 0x72000000, 
           0xE4000000, 0xD3000000, 0xBD000000, 0x61000000, 
           0xC2000000, 0x9F000000, 0x25000000, 0x4A000000, 
           0x94000000, 0x33000000, 0x66000000, 0xCC000000, 
           0x83000000, 0x1D000000, 0x3A000000, 0x74000000, 
           0xE8000000, 0xCB000000, 0x8D000000 };

    unsigned int i = 0;

    while (i < keyLength) {
        word[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3];
        i++;
    }

    i = keyLength;

    while (i < blockSize * (numRounds + 1)) {
        u_int32_t temp = word[i-1];
        if (i % keyLength == 0) {
            temp = subWord(rotWord(temp)) ^ rcon[i/keyLength];
        } else if (keyLength > 6 && i % keyLength == 4) {
            temp = subWord(temp);
        }
        word[i] = word[i-keyLength] ^ temp;
        i++;
    }

    return word;
    
}

void subBytes(unsigned int** state) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            subWord(state[i][j]);
        }
    }

}

void shiftRows(unsigned int** state) {

}

void mixColumns(unsigned int** state) {
    unsigned char fixedPolynomial
    //for (int i = 0; i < )
}

void cipher(u_int8_t in[blockSize], u_int8_t out[blockSize], u_int32_t w[blockSize*(numRounds+1)]) {
    unsigned int state[4][4];
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[j][i] = in[i*4 + j];
        }
    }

    addRoundKey(state, w);

    for (int round = 1; round < numRounds; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, w + round * blockSize);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, w + numRounds * blockSize);

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            out[i*4 + j] = state[j][i];
        }
    }
}

void testKeyExpansion() {
    u_int8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    u_int32_t w[44];

    for (int i = 0; i < 10; ++i) {
        int nextKey = keyExpansion(key, w, keyLength);
    }

    for (int i = 0; i < 44; ++i) {
        printf("w[%d] = %x\n", i, w[i]);
    }

}

void testSubAndRot() {
    unsigned int sub1 = subWord(0x00102030);
    printf("sub1 = %x\n", sub1);

    unsigned int sub2 = subWord(0x40506070);
    printf("sub2 = %x\n", sub2);

    unsigned int sub3 = subWord(0x8090a0b0);
    printf("sub3 = %x\n", sub3);

    unsigned int sub4 = subWord(0xc0d0e0f0);
    printf("sub4 = %x\n", sub4);

    unsigned int rot1 = rotWord(0x09cf4f3c);
    printf("rot1 = %x\n", rot1);

    unsigned int rot2 = rotWord(0x2a6c7605);
    printf("rot2 = %x\n", rot2);

}

void testArithmetic() {
    unsigned char add = ffAdd(0x57, 0x83);
    printf("ffAdd = %x\n", add);

    unsigned char x1 = xtime(0x57);
    printf("x1 = %x\n", x1);

    unsigned char x2 = xtime(0xae);
    printf("x2 = %x\n", x2);

    unsigned char x3 = xtime(0x47);
    printf("x3 = %x\n", x3);

    unsigned char x4 = xtime(0x8e);
    printf("x4 = %x\n", x4);

    unsigned char multiply = ffMultiply(0x57, 0x13);
    printf("ffMult = %x\n", multiply);
    
}