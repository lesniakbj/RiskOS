.intel_syntax noprefix

.global gdt_load
.type gdt_load, @function
gdt_load:
    # The first argument (gdt_ptr_t* ptr) is in RDI.
    lgdt [rdi]

    # Reload all data segment registers with the kernel data selector (0x10).
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax

    # It's good practice to zero out fs and gs if they are not being used.
    xor rax, rax
    mov fs, ax
    mov gs, ax

    # Reload the CS register to use the new GDT.
    # We do this with a far return (retfq).
    # Push the kernel code selector (0x08) onto the stack.
    push 0x08
    # Push the address of the next instruction onto the stack.
    lea rax, [rip + flush_cs]
    push rax
    # Far return. This will pop RIP, then CS.
    retfq

flush_cs:
    ret

.global tss_flush
.type tss_flush, @function
tss_flush:
    # Load the Task Register (ltr) with the TSS selector.
    # Our TSS is the 6th entry in the GDT (index 5).
    # The selector is therefore 5 * 8 = 40 = 0x28.
    mov ax, 0x28
    ltr ax
    ret
