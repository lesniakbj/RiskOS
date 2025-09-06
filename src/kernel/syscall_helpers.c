#include <kernel/syscall_helpers.h>
#include <arch/x86-64/vmm.h>

// Define the global variables
uint64_t kernel_pml4;
tss_entry_t* tss_instance_ptr;

// Extern the tss_entry from gdt.c
extern tss_entry_t tss_entry;

void syscall_helpers_init() {
    kernel_pml4 = vmm_get_kernel_pml4();
    tss_instance_ptr = &tss_entry;
}
