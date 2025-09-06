.intel_syntax noprefix

.global isr_common_stub

# Macro to define an ISR that does NOT push an error code
.macro ISR_NOERRCODE isr_num
.global isr\isr_num
isr\isr_num:
    push 0 # Push a dummy error code (0) for consistency
    push \isr_num
    jmp isr_common_stub
.endm

# Macro to define an ISR that DOES push an error code
.macro ISR_ERRCODE isr_num
.global isr\isr_num
isr\isr_num:
    # Error code is already on stack, just push the ISR number
    push \isr_num
    jmp isr_common_stub
.endm

# CPU Exceptions (0x00-0x1F)
ISR_NOERRCODE 0   # Division By Zero Exception
ISR_NOERRCODE 1   # Debug Exception
ISR_NOERRCODE 2   # Non Maskable Interrupt Exception
ISR_NOERRCODE 3   # Breakpoint Exception
ISR_NOERRCODE 4   # Overflow Exception
ISR_NOERRCODE 5   # Bound Range Exceeded Exception
ISR_NOERRCODE 6   # Invalid Opcode Exception
ISR_NOERRCODE 7   # Device Not Available Exception
ISR_ERRCODE   8   # Double Fault Exception
ISR_NOERRCODE 9   # Coprocessor Segment Overrun
ISR_ERRCODE   10  # Invalid TSS Exception
ISR_ERRCODE   11  # Segment Not Present Exception
ISR_ERRCODE   12  # Stack-Segment Fault Exception
ISR_ERRCODE   13  # General Protection Fault Exception
ISR_ERRCODE   14  # Page Fault Exception
ISR_NOERRCODE 15  # Reserved
ISR_NOERRCODE 16  # x87 FPU Floating-Point Error
ISR_ERRCODE   17  # Alignment Check Exception
ISR_NOERRCODE 18  # Machine Check Exception
ISR_NOERRCODE 19  # SIMD Floating-Point Exception
ISR_NOERRCODE 20  # Virtualization Exception
ISR_NOERRCODE 21  # Control Protection Exception
ISR_NOERRCODE 22  # Reserved
ISR_NOERRCODE 23  # Reserved
ISR_NOERRCODE 24  # Reserved
ISR_NOERRCODE 25  # Reserved
ISR_NOERRCODE 26  # Reserved
ISR_NOERRCODE 27  # Reserved
ISR_NOERRCODE 28  # Hypervisor Injection Exception
ISR_NOERRCODE 29  # VMM Communication Exception
ISR_ERRCODE   30  # Security Exception
ISR_NOERRCODE 31  # Reserved

# IRQs (remapped to 0x20-0x2F)
ISR_NOERRCODE 32  # IRQ0 (Timer)
ISR_NOERRCODE 33  # IRQ1 (Keyboard)
ISR_NOERRCODE 34  # IRQ2
ISR_NOERRCODE 35  # IRQ3
ISR_NOERRCODE 36  # IRQ4
ISR_NOERRCODE 37  # IRQ5
ISR_NOERRCODE 38  # IRQ6
ISR_NOERRCODE 39  # IRQ7
ISR_NOERRCODE 40  # IRQ8 (RTC)
ISR_NOERRCODE 41  # IRQ9 (ACPI System Control Interrupt)
ISR_NOERRCODE 42  # IRQ10
ISR_NOERRCODE 43  # IRQ11
ISR_NOERRCODE 44  # IRQ12 (Mouse)
ISR_NOERRCODE 45  # IRQ13
ISR_NOERRCODE 46  # IRQ14
ISR_NOERRCODE 47  # IRQ15

# Syscall interrupt
ISR_NOERRCODE 128 # Interrupt 0x80

# Common entry point for all ISRs
isr_common_stub:
    # Save all general purpose registers.
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    # Save special segement registers used in 64 bit mode
    push fs
    push gs

    # Set up data segments for kernel
    mov ax, 0x10    # Kernel data segment selector
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    # Call the C handler. The 'regs' argument is a pointer to the current ESP.
    mov rdi, rsp
    call isr_handler_c

    # Restore segment registers
    pop gs
    pop fs

    # Restore general purpose registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    # Pop the interrupt number and error code.
    add rsp, 16

    iretq

.global context_switch
context_switch:
    # RDI: address of prev_process->kstack_ptr
    # RSI: next_proc->kstack_ptr (new RSP to load)
    # Save current RSP
    # mov [rdi], rsp

    # Load new RSP
    mov rsp, rsi

    # Restore segment registers
    pop gs
    pop fs

    # Restore general purpose registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    # Pop the interrupt number and error code.
    add rsp, 16 # 2 * 8 bytes

    # Now, the stack is set up for iretq.
    iretq

.global first_time_user_switch
first_time_user_switch:
    # RDI: new_rsp (kstack_ptr for the new user process)
    mov rsp, rdi
    iretq
