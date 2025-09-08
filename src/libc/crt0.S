.intel_syntax noprefix

.section .text
.globl _start

_start:
    # The x86-64 System V ABI requires the stack to be 16-byte aligned before a call
    # instruction. The entry point is not guaranteed to be aligned.
    # We clear the direction flag and align the stack.
    cld
    and rsp, ~0xf

    # Per the ABI, the frame pointer should be 0 to terminate the stack frame chain.
    xor rbp, rbp

    # TODO: Eventually, pop argc, argv, and envp from the stack here
    # --- GET argc & argv ---
    # pop rdi        # Pop argc into RDI (1st argument to main)
    # mov rsi, rsp   # RSP now points to argv[0], so RSI gets argv (2nd argument to main)
    # --- END GET argc & argv ---

    # TODO: Eventually support envp from the stack here
    # and pass them to main in RDI and RSI. For now, we call main with no args.
    call main

    # main has returned. The return value is in RAX.
    # We need to call the exit syscall. The syscall number is in RAX
    # and the first argument (the exit code) is in RDI.
    mov rdi, rax                # Move main's return value to rdi for the exit syscall
    mov rax, 51                 # 51 is the syscall number for exit (from unistd.h)
    syscall

    # The program should never reach here.
    hlt
