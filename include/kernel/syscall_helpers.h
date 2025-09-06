#ifndef KERNEL_SYSCALL_HELPERS_H
#define KERNEL_SYSCALL_HELPERS_H

#include <stdint.h>
#include <arch/x86-64/gdt.h>

// Global variables accessible from assembly
extern uint64_t kernel_pml4;
extern tss_entry_t* tss_instance_ptr;

// Initializes the helper variables.
void syscall_helpers_init();

#endif
