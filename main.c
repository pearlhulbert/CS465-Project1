#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>


void decrypt(unsigned char*, unsigned char*);
void encrypt(unsigned char*, unsigned char*);
u_int8_t ffAdd(u_int8_t, u_int8_t);
u_int8_t ffMultiply(u_int8_t, u_int8_t);
u_int8_t  xtime(u_int8_t);
u_int32_t rotWord(u_int32_t);
u_int32_t subWord(u_int32_t);
u_int32_t* keyExpansion(u_int8_t*, u_int32_t*, unsigned int);
void subBytes(u_int8_t(*state)[4]);
void shiftRows(u_int8_t(*state)[4]);
void mixColumns(u_int8_t(*state)[4]);
void addRoundKey(u_int8_t(*state)[4], u_int32_t*, unsigned int);
void cipher(u_int8_t*, u_int8_t*, u_int32_t*);
void testArithmetic();
void testSubAndRot();
void testKeyExpansion();
void testCipherFunctions();

int keyLength = 4;
int blockSize = 4;
int numRounds = 10;

 u_int8_t Sbox[16][16] = {
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
    //testKeyExpansion();
    testCipherFunctions();
    /*if (strcmp(argv[1], "-d")) {
        decrypt(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "-e")) {
        encrypt(argv[2], argv[3]);
    }*/

    return 0;
}

/** finite field arithmetic functions **/
u_int8_t ffAdd(u_int8_t  x, u_int8_t y) {
    return x ^ y;
}

u_int8_t xtime(u_int8_t x) {

    if ((x & 0x80) == 0x80) {
        return (x << 1) ^ 0x1b;
    }
    return x << 1;

}

u_int8_t ffMultiply(u_int8_t x, u_int8_t y) {
    
    char total = 0;
    u_int8_t possibleX[8];
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
    //printf("x in rotWord: %d\n", x);
    return (x << 8) | (x >> 24);
} 

u_int32_t subWord(u_int32_t x) {

    unsigned int result = 0;

    //printf("x before sub %d\n", x);

    for (int i = 0; i < 4; ++i ) {
        u_int8_t byte = (x >> (8 * (3 - i))) & 0xff;
        u_int8_t row = (byte & 0xf0) >> 4;
        u_int8_t col = byte & 0x0f;
        byte = Sbox[row][col];
        x = (x & ~(0xff << (8 * (3 - i)))) | (byte << (8 * (3 - i)));
    }
    //printf("x after sub = %d\n", x);
    return x;
}

u_int32_t* keyExpansion(u_int8_t key[4*keyLength], u_int32_t word[blockSize*(numRounds+1)], unsigned int keyLength) {
    
    u_int8_t temp[4];
    u_int32_t rcon[] = { 0x00000000, 
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

    u_int32_t keySchedule[numRounds];

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

void subBytes(u_int8_t(*state)[4]) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = subWord(state[i][j]);
        }
    }

}

void shiftRows(u_int8_t(*state)[4]) {

    //printf("in shiftRows\n");
    u_int8_t temp;
    u_int8_t newState[4][4];

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            newState[i][j] = state[i][(j+i) % 4];
        }
    }

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = newState[i][j];
        }
    }
}

 void mixColumns(u_int8_t(*state)[4]) {
    u_int8_t fixedPolynomial[4][4] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}
    };

    u_int8_t result[4][4];

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            result[i][j] = 0;

            for (int k = 0; k < 4; ++k) {
                result[i][j] = ffAdd(result[i][j], ffMultiply(fixedPolynomial[i][k], state[k][j]));
            }
        }
        
    }

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = result[i][j];
        }
    }

}

void addRoundKey(u_int8_t(*state)[4], u_int32_t w[blockSize*(numRounds+1)], unsigned int numRounds) {

    u_int8_t newState[4][4];

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            newState[i][j] = ffAdd(state[i][j], w[i]);
        }
    }

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = newState[i][j];
        }
    }
}

void cipher(u_int8_t in[blockSize], u_int8_t out[blockSize], u_int32_t w[blockSize*(numRounds+1)]) {
    u_int8_t state[4][4];
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[j][i] = in[i*4 + j];
        }
    }

    addRoundKey(state, w, 4);

    for (int round = 1; round < numRounds; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, w + round * blockSize, 4);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, w + numRounds * blockSize, 4);

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
        u_int32_t* nextKey = keyExpansion(key, w, keyLength);
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

void testCipherFunctions() {
    u_int8_t state[4][4] =  { {0x19,0xa0,0x9a,0xe9},
                         {0x3d,0xf4,0xc6,0xf8},
                         {0xe3,0xe2,0x8d,0x48},
                         {0xbe,0x2b,0x2a,0x08}};

    subBytes(state);
    printf("after subBytes:\n");
    for (int i = 0; i < 4; ++i) {
         printf("sub[%d] = ", i);
        for (int j = 0; j < 4; ++j) {
            printf("%x, ", state[i][j]);
        }
        printf("\n");
    }

    printf("\n");

    u_int8_t state1[4][4] =  { {0x19,0xa0,0x9a,0xe9},
                         {0x3d,0xf4,0xc6,0xf8},
                         {0xe3,0xe2,0x8d,0x48},
                         {0xbe,0x2b,0x2a,0x08}};


    shiftRows(state);
    printf("after shiftRows:\n");
    for (int i = 0; i < 4; ++i) {
         printf("shift[%d] = ", i);
        for (int j = 0; j < 4; ++j) {
            printf("%x, ", state[i][j]);
        }
        printf("\n");
    }

    printf("\n");

    u_int8_t state2[4][4] =  { {0x19,0xa0,0x9a,0xe9},
                         {0x3d,0xf4,0xc6,0xf8},
                         {0xe3,0xe2,0x8d,0x48},
                         {0xbe,0x2b,0x2a,0x08}};


    mixColumns(state);
    printf("after mixColumns: \n");
   for (int i = 0; i < 4; ++i) {
         printf("mix[%d] = ", i);
        for (int j = 0; j < 4; ++j) {
            printf("%x, ", state[i][j]);
        }
        printf("\n");
    }

    printf("\n");

    u_int8_t state3[4][4] =  { {0x19,0xa0,0x9a,0xe9},
                         {0x3d,0xf4,0xc6,0xf8},
                         {0xe3,0xe2,0x8d,0x48},
                         {0xbe,0x2b,0x2a,0x08} };

    uint32_t w[44] = { 0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
                              0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,
                              0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
                              0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,
                              0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
                              0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
                              0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
                              0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
                              0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
                              0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
                              0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6 };



    addRoundKey(state, w, 4);
    printf("after addRoundKey:\n");
    for (int i = 0; i < 4; ++i) {
         printf("add[%d] = ", i);
         for (int j = 0; j < 4; ++j) {
             printf("%x, ", state[i][j]);
         }
         printf("\n");
    }


}