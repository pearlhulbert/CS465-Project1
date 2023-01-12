#include <stdlib.h>
#include <stdio.h>
#include <string.h>


void decrypt(char*, char*);
void encrypt(char*, char*);
char ffAdd(char, char);
char ffMultiply(char, char);
char xtime(char);
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
char ffAdd(char x, char y) {
    return x ^ y;
}

char xtime(char x) {

    if ((x & 0x80) == 0x80) {
        return (x << 1) ^ 0x1b;
    }
    return x << 1;

}

char ffMultiply(char x, char y) {
    
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
    char add = ffAdd(0x57, 0x83);
    printf("ffAdd = %x\n", add);

    char x1 = xtime(0x57);
    printf("x1 = %x\n", x1);

    char x2 = xtime(0xae);
    printf("x2 = %x\n", x2);

    char x3 = xtime(0x47);
    printf("x3 = %x\n", x3);

    char x4 = xtime(0x8e);
    printf("x4 = %x\n", x4);

    char multiply = ffMultiply(0x57, 0x13);
    printf("ffMult = %x\n", multiply);

}