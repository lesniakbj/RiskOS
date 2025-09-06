#ifndef ARCH_X86_64_INTERRUPTS_H
#define ARCH_X86_64_INTERRUPTS_H

#include <stdint.h>

// Defines the structure of the registers pushed to the stack during an interrupt.
typedef struct registers {
    // Pushed manually by our common stub in isr_handlers.S
     uint64_t gs, fs;
     uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
     uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;

    // Pushed by our ISR macros
    uint64_t interrupt_number;
    uint64_t error_code;

    // Pushed by the CPU automatically
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t user_rsp;
    uint64_t ss;
} __attribute__((packed)) registers_t;

// Defines the function signature for a C-level interrupt handler.
typedef void (*interrupt_handler_t)(registers_t* regs);

// Sets the C handler for a given interrupt vector.
void register_interrupt_handler(uint8_t n, interrupt_handler_t handler);

// The main C-level entry point for all interrupts.
// This is called by the assembly stub in isr_handlers.S.
void isr_handler_c(registers_t *regs);

// extern void context_switch(uint64_t new_esp);

#endif
