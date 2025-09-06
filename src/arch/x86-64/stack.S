.intel_syntax noprefix

.section .bss
.align 16

.global kernel_stack
kernel_stack:
    .skip 16384  # Reserve 16 KiB for the stack

.global stack_top
stack_top: