@section(".text")
do_nothing:
	; Write to stdout
	mov rax, 1 ; syscall number for sys_write
	mov rdi, 1 ; file descriptor 1 is stdout
	mov rsi, msg ; address of string to output
	mov rdx, 4 ; number of bytes to write
	syscall

	call do_exit

@section(".data")
msg:
	@ascii("hey\n")

@section(".text")
do_exit:
	; Exit program
	mov rax, 60 ; syscall number for sys_exit
	xor rdi, rdi ; exit code 0
	syscall
	ret
