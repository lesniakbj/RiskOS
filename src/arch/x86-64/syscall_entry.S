.intel_syntax noprefix

.section .text
.global syscall_entry

.equ REGS_GS,                   0
.equ REGS_FS,                   8
.equ REGS_R15,                  16
.equ REGS_R14,                  24
.equ REGS_R13,                  32
.equ REGS_R12,                  40
.equ REGS_R11,                  48
.equ REGS_R10,                  56
.equ REGS_R9,                   64
.equ REGS_R8,                   72
.equ REGS_RBP,                  80
.equ REGS_RDI,                  88
.equ REGS_RSI,                  96
.equ REGS_RDX,                  104
.equ REGS_RCX,                  112
.equ REGS_RBX,                  120
.equ REGS_RAX,                  128
.equ REGS_INTERRUPT_NUMBER,     136
.equ REGS_ERROR_CODE,           144
.equ REGS_RIP,                  152
.equ REGS_CS,                   160
.equ REGS_RFLAGS,               168
.equ REGS_USER_RSP,             176
.equ REGS_SS,                   184
.equ REGS_SIZE,                 192

syscall_entry:
    # CPU State on entry:
    # RCX = User RIP (return address)
    # R11 = User RFLAGS
    # RAX = Syscall number
    # RSP = User stack pointer

    # First... save the rsp, then set new tss
    mov r8, rsp
    mov rsp, [tss_entry + 4]

    # Allocate space for registers_t structure on stack
    sub rsp, REGS_SIZE

    # Manually construct a registers_t structure to match interrupt handler format
    # Segment registers (we'll fake these since we can't read them directly)
    mov qword ptr [rsp + REGS_GS], 0              # GS - not typically used in x86-64
    mov qword ptr [rsp + REGS_FS], 0              # FS - not typically used in x86-64
    # General purpose registers
    mov [rsp + REGS_R15], r15
    mov [rsp + REGS_R14], r14
    mov [rsp + REGS_R13], r13
    mov [rsp + REGS_R12], r12
    mov [rsp + REGS_R11], r11                     # User RFLAGS
    mov [rsp + REGS_R10], r10
    mov [rsp + REGS_R9], r9
    mov [rsp + REGS_R8], r8                       # RSP
    mov [rsp + REGS_RBP], rbp
    mov [rsp + REGS_RDI], rdi
    mov [rsp + REGS_RSI], rsi
    mov [rsp + REGS_RDX], rdx
    mov [rsp + REGS_RCX], rcx                     # User RIP
    mov [rsp + REGS_RBX], rbx
    mov [rsp + REGS_RAX], rax                     # Syscall number

    # Interrupt-related fields
    mov qword ptr [rsp + REGS_INTERRUPT_NUMBER], 0x80   # Fake syscall interrupt number
    mov qword ptr [rsp + REGS_ERROR_CODE], 0            # No error code for syscalls

    # CPU-pushed fields
    mov [rsp + REGS_RIP], rcx                     # User RIP (same as RCX)
    mov qword ptr [rsp + REGS_CS], 0x18           # User code segment (adjust if needed)
    mov [rsp + REGS_RFLAGS], r11                  # User RFLAGS (same as R11)
    mov r8, rsp
    add r8, REGS_SIZE                             # Calculate what user RSP was
    mov [rsp + REGS_USER_RSP], r8                 # Approximate user RSP
    mov qword ptr [rsp + REGS_SS], 0x20           # User data segment (adjust if needed)

    # Pass pointer to syscall_args_t as first argument
    mov rdi, rsp

    # Call C handler
    call syscall_handler

    # Handler can modify registers as needed
    # Restore registers from the structure
    mov r15, [rsp + REGS_R15]
    mov r14, [rsp + REGS_R14]
    mov r13, [rsp + REGS_R13]
    mov r12, [rsp + REGS_R12]
    mov r11, [rsp + REGS_R11]           # User RFLAGS
    mov r10, [rsp + REGS_R10]
    mov r9, [rsp + REGS_R9]
    mov r8, [rsp + REGS_R8]
    mov rbp, [rsp + REGS_RBP]
    mov rdi, [rsp + REGS_RDI]
    mov rsi, [rsp + REGS_RSI]
    mov rdx, [rsp + REGS_RDX]
    mov rcx, [rsp + REGS_RCX]           # User RIP
    mov rbx, [rsp + REGS_RBX]
    mov rax, [rsp + REGS_RAX]           # Return value (could be modified by handler)

    # Clean up the stack
    add rsp, REGS_SIZE

    # Restore rsp
    mov rsp, r8

    # Return to user space
    # RCX = user RIP, R11 = user RFLAGS
    sysretq