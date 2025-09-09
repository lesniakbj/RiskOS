#ifndef KERNEL_SYSCALL_Hvmm
#define KERNEL_SYSCALL_H

#include <stdint.h>
#include <arch/x86-64/interrupts.h>

// The C-level syscall handler, to be called from the assembly wrapper.
int64_t syscall_handler(registers_t* args);

// The assembly-level entry point that the CPU jumps to.
void syscall_entry();

#endif