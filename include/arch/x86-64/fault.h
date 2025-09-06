#ifndef ARCH_I386_FAULT_H
#define ARCH_I386_FAULT_H

#include <arch/x86-64/interrupts.h>

void general_protection_fault_handler(registers_t* regs);
void page_fault_handler(registers_t *regs);
void double_fault_handler(registers_t* regs);
void invalid_opcode_handler(registers_t* regs);
void divide_by_zero_handler(registers_t* regs);
void stack_segment_fault_handler(registers_t* regs);
void alignment_check_handler(registers_t* regs);

#endif