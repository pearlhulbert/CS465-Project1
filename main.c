#include <stdlib.h>
#include <stdio.h>
#include <string.h>


void decrypt(unsigned char*, unsigned char*);
void encrypt(unsigned char*, unsigned char*);
unsigned char ffAdd(unsigned char, unsigned char);
unsigned char ffMultiply(unsigned char, unsigned char);
unsigned char xtime(unsigned char);
void testArithmetic();

int main(int argc, char** argv) {

    testArithmetic();
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