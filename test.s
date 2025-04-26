do_nothing:
	mov rax, msg
	ret
	; Write to stdout
	; mov rax, 1 ; syscall number for sys_write
	; mov rdi, 1 ; file descriptor 1 is stdout
	; mov rsi, msg ; address of string to output
	; mov rdx, 4 ; number of bytes to write
	; syscall

	; Exit program
	; mov rax, 60 ; syscall number for sys_exit
	; xor rdi, rdi ; exit code 0
	; syscall
	; ret

msg:
	; db 104, 101, 121, 10
	@bytes(104, 101, 121, 10)
