.intel_syntax noprefix

.section .text
.globl _start

_start:
    # The x86-64 System V ABI requires the stack to be 16-byte aligned before a call
    # instruction. The entry point is not guaranteed to be aligned.
    # The kernel sets up the stack so that RSP points to argc.
    cld                   # Clear direction flag
    # RSP already points to argc

    # Per the ABI, the frame pointer should be 0 to terminate the stack frame chain.
    xor rbp, rbp

    # --- GET argc & argv & envp ---
    # Stack layout at _start (RSP points here):
    # [argc]              # 8 bytes
    # [argv[0]]           # 8 bytes
    # ...
    # [argv[argc-1]]      # 8 bytes
    # [NULL]              # 8 bytes (terminator for argv)
    # [envp[0]]           # 8 bytes
    # ...
    # [envp[n-1]]         # 8 bytes
    # [NULL]              # 8 bytes (terminator for envp)
    # [strings...]        # Variable size

    mov rdi, [rsp]        # Pop argc into RDI (1st argument to main)
    lea rsi, [rsp+8]      # RSI gets argv (2nd argument to main) - address of argv[0]
    # Calculate envp: RSI points to argv array. argv array has (argc + 1) pointers.
    # So, envp array starts at RSI + (argc + 1) * 8
    mov rax, rdi          # rax = argc
    inc rax               # rax = argc + 1
    shl rax, 3            # rax = (argc + 1) * 8 (bit shift for multiplication by 8)
    lea rdx, [rsi + rax]  # RDX gets envp (3rd argument to main) - address of envp[0]

    # --- END GET argc & argv & envp ---

    # Call main with argc (rdi), argv (rsi), envp (rdx)
    call main

    # main has returned. The return value is in RAX.
    # We need to call the exit syscall. The syscall number is in RAX
    # and the first argument (the exit code) is in RDI.
    mov rdi, rax                # Move main's return value to rdi for the exit syscall
    mov rax, 51                 # 51 is the syscall number for exit (from unistd.h)
    syscall

    # The program should never reach here.
    hlt
