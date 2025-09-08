#ifndef KERNEL_PROC_H
#define KERNEL_PROC_H

#include <stdint.h>
#include <stddef.h>
#include <drivers/fs/vfs.h>
#include <arch/x86-64/interrupts.h>
#include <arch/x86-64/vmm.h>

#define MAX_PROCESSES 256
#define MAX_FD_PER_PROCESS 16

// Process states
typedef enum {
    PROC_STATE_UNUSED = 0,   // Process slot is free
    PROC_STATE_INIT,         // Process is being initialized
    PROC_STATE_READY,        // Process is ready to run
    PROC_STATE_RUNNING,      // Process is currently running
    PROC_STATE_SLEEPING,     // Process is sleeping/blocking
    PROC_STATE_ZOMBIE,       // Process has exited but not waited on
    PROC_STATE_EXIT,         // Process has exited but not waited on
    PROC_STATE_INIT_WAIT     // Process is waiting for children to exit
} proc_state_t;

// Process types
typedef enum {
    PROC_TYPE_KERNEL = 0,   // Kernel process (runs in ring 0)
    PROC_TYPE_USER          // User process (runs in ring 3)
} proc_type_t;

// File descriptor structure
typedef struct file_desc {
    vfs_node_t* node;       // VFS node this FD points to
    uint32_t flags;         // Flags (read/write/append, etc.)
    uint64_t offset;        // Current file offset
} file_desc_t;

// Process control block
typedef struct process {
    uint8_t used;               // Is this process slot in use?
    uint64_t pid;               // Process ID
    proc_state_t state;         // Current state of the process
    proc_type_t type;           // Type of process (kernel or user)
    uint64_t pml4_phys;         // Physical address of the process's page table (PML4)
    void* kernel_stack;         // Pointer to the kernel stack for this process
    size_t kernel_stack_size;   // Size of the kernel stack
    uint64_t kstack_ptr;        // Current kernel stack pointer (used for context switches)
    void* entry_point;          // Entry point of the process
    struct process* parent;     // Pointer to the parent process
    uint64_t exit_code;         // Exit code if the process has exited
    vfs_node_t* working_dir;    // Working dir of this process
    uint64_t program_break;
    uint64_t program_break_start;
    
    // File descriptors
    file_desc_t file_descriptors[MAX_FD_PER_PROCESS];
} process_t;

// --- Process Manager Functions ---

// Initialize the process manager. This must be called before any other proc_* functions.
void proc_init();

// Create a new process of the specified type.
process_t* proc_create(proc_type_t proc_type);

// Execute a process (set its state to READY).
void proc_exec(process_t* process);
void proc_terminate(process_t* proc);

// Run the process scheduler. This will switch to the next runnable process.
void proc_scheduler_run(registers_t *regs);
void proc_scheduler_run_special(registers_t *regs, bool is_exit);

// Get the current process
process_t* proc_get_current();

#endif