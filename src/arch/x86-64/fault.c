#include <kernel/log.h>
#include <arch/x86-64/fault.h>
#include <arch/x86-64/interrupts.h>

// Helper function to read the CR2 register, which contains the faulting address in a page fault.
static inline uint64_t read_cr2(void) {
    uint64_t val;
    asm volatile ("mov %%cr2, %0" : "=r" (val));
    return val;
}

void general_protection_fault_handler(registers_t* regs) {
    LOG_ERR("--- GENERAL PROTECTION FAULT ---");
    LOG_ERR("  Interrupt: 0x%llx, Error Code: 0x%llx", regs->interrupt_number, regs->error_code);
    LOG_ERR("  CS:  0x%llx, RIP: 0x%llx, RFLAGS: 0x%llx", regs->cs, regs->rip, regs->rflags);
    LOG_ERR("  SS:  0x%llx, RSP: 0x%llx", regs->ss, regs->user_rsp);
    LOG_ERR("  RAX: 0x%llx, RBX: 0x%llx, RCX: 0x%llx", regs->rax, regs->rbx, regs->rcx);
    LOG_ERR("  RDX: 0x%llx, RSI: 0x%llx, RDI: 0x%llx", regs->rdx, regs->rsi, regs->rdi);
    LOG_ERR("  RBP: 0x%llx, R8:  0x%llx, R9:  0x%llx", regs->rbp, regs->r8, regs->r9);
    LOG_ERR("  R10: 0x%llx, R11: 0x%llx, R12: 0x%llx", regs->r10, regs->r11, regs->r12);
    LOG_ERR("  R13: 0x%llx, R14: 0x%llx, R15: 0x%llx", regs->r13, regs->r14, regs->r15);
    LOG_ERR("  FS:  0x%llx, GS:  0x%llx", regs->fs, regs->gs);

    if(regs->error_code) {
        LOG_ERR("  Selector Error Code: 0x%llx", regs->error_code);
    }

    LOG_ERR("--- SYSTEM HALTED ---");
    for(;;);
}

void page_fault_handler(registers_t *regs) {
    uint64_t faulting_address = read_cr2();

    // The error code gives us details about the fault.
    int present = !(regs->error_code & 0x1);
    int rw = regs->error_code & 0x2;
    int us = regs->error_code & 0x4;
    int reserved = regs->error_code & 0x8;
    int id = regs->error_code & 0x10;

    LOG_ERR("--- PAGE FAULT ---");
    LOG_ERR("  Faulting Address: 0x%llx", faulting_address);
    LOG_ERR("  At RIP: 0x%llx", regs->rip);
    LOG_ERR("  RSP: 0x%llx", regs->user_rsp);
    LOG_ERR("  Error Code: 0x%llx", regs->error_code);
    LOG_ERR("  Reason: %s, %s access, while in %s mode.",
        present ? "Supervisory page violation" : "Page not present",
        rw ? "write" : "read",
        us ? "user" : "supervisor");

    if (reserved) {
        LOG_ERR("  A reserved bit was set in a page table entry.");
    }
    if (id) {
        LOG_ERR("  The fault was caused by an instruction fetch.");
    }

    LOG_ERR("--- SYSTEM HALTED ---");
    for(;;);
}

void double_fault_handler(registers_t* regs) {
    LOG_ERR("--- DOUBLE FAULT ---");
    LOG_ERR("  Interrupt: 0x%llx, Error Code: 0x%llx", regs->interrupt_number, regs->error_code);
    LOG_ERR("  CS:  0x%llx, RIP: 0x%llx, RFLAGS: 0x%llx", regs->cs, regs->rip, regs->rflags);
    LOG_ERR("  SS:  0x%llx, RSP: 0x%llx", regs->ss, regs->user_rsp);
    LOG_ERR("  This is a critical system error - two exceptions occurred simultaneously.");
    LOG_ERR("--- SYSTEM HALTED ---");
    for(;;);
}

void invalid_opcode_handler(registers_t* regs) {
    LOG_ERR("--- INVALID OPCODE EXCEPTION ---");
    LOG_ERR("  Interrupt: 0x%llx", regs->interrupt_number);
    LOG_ERR("  CS:  0x%llx, RIP: 0x%llx, RFLAGS: 0x%llx", regs->cs, regs->rip, regs->rflags);
    LOG_ERR("  SS:  0x%llx, RSP: 0x%llx", regs->ss, regs->user_rsp);
    LOG_ERR("  The processor encountered an invalid or undefined opcode.");
    LOG_ERR("--- SYSTEM HALTED ---");
    for(;;);
}

void divide_by_zero_handler(registers_t* regs) {
    LOG_ERR("--- DIVIDE BY ZERO EXCEPTION ---");
    LOG_ERR("  Interrupt: 0x%llx", regs->interrupt_number);
    LOG_ERR("  CS:  0x%llx, RIP: 0x%llx, RFLAGS: 0x%llx", regs->cs, regs->rip, regs->rflags);
    LOG_ERR("  SS:  0x%llx, RSP: 0x%llx", regs->ss, regs->user_rsp);
    LOG_ERR("  A division by zero operation was attempted.");
    LOG_ERR("--- SYSTEM HALTED ---");
    for(;;);
}

void stack_segment_fault_handler(registers_t* regs) {
    LOG_ERR("--- STACK SEGMENT FAULT ---");
    LOG_ERR("  Interrupt: 0x%llx, Error Code: 0x%llx", regs->interrupt_number, regs->error_code);
    LOG_ERR("  CS:  0x%llx, RIP: 0x%llx, RFLAGS: 0x%llx", regs->cs, regs->rip, regs->rflags);
    LOG_ERR("  SS:  0x%llx, RSP: 0x%llx", regs->ss, regs->user_rsp);
    LOG_ERR("  Stack segment error occurred.");
    LOG_ERR("--- SYSTEM HALTED ---");
    for(;;);
}

void alignment_check_handler(registers_t* regs) {
    LOG_ERR("--- ALIGNMENT CHECK EXCEPTION ---");
    LOG_ERR("  Interrupt: 0x%llx, Error Code: 0x%llx", regs->interrupt_number, regs->error_code);
    LOG_ERR("  CS:  0x%llx, RIP: 0x%llx, RFLAGS: 0x%llx", regs->cs, regs->rip, regs->rflags);
    LOG_ERR("  SS:  0x%llx, RSP: 0x%llx", regs->ss, regs->user_rsp);
    LOG_ERR("  Unaligned memory access detected (alignment checking enabled).");
    LOG_ERR("--- SYSTEM HALTED ---");
    for(;;);
}