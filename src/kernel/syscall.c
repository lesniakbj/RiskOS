#include <kernel/syscall.h>
#include <kernel/log.h>
#include <kernel/proc.h>
#include <kernel/heap.h>
#include <drivers/fb_console.h>
#include <drivers/fs/vfs.h>
#include <arch/x86-64/vmm.h>
#include <arch/x86-64/pmm.h>
#include <libc/unistd.h>
#include <libc/string.h>
#include <lib/elf.h>

#define USERSPACE_TOP (0x7000000000ULL)
#define MAX_WRITE_SIZE 1024
#define MAX_SYSCALLS 61

#define USER_STACK_TOP 0x7000000000
#define USER_STACK_SIZE 0x4000 // 16KB


// Define the syscall function pointer type
typedef int64_t (*syscall_func_t)(registers_t* regs);

// Forward declarations for syscall handlers
static int64_t sys_exit(registers_t* regs);
static int64_t sys_fork(registers_t* parent_regs);
static int64_t sys_read(registers_t* regs);
static int64_t sys_write(registers_t* regs);
static int64_t sys_open(registers_t* regs);
static int64_t sys_close(registers_t* regs);
static int64_t sys_lseek(registers_t* regs);
static int64_t sys_brk(registers_t* regs);
static int64_t sys_yield(registers_t* regs);
static int64_t sys_getpid(registers_t* regs);

// Syscall table
static syscall_func_t syscall_table[MAX_SYSCALLS] = {
    [SYS_READ]          = sys_read,
    [SYS_WRITE]         = sys_write,
    [SYS_OPEN]          = sys_open,
    [SYS_CLOSE]         = sys_close,
    [SYS_LSEEK]         = sys_lseek,
    [SYS_BRK]           = sys_brk,
    [SYS_PROC_YIELD]    = sys_yield,
    [SYS_PROC_EXIT]     = sys_exit,
    [SYS_PROC_PID]      = sys_getpid,
    [SYS_PROC_FORK]     = sys_fork,
};


// Helper to find the next available file descriptor for the current process
static int get_next_fd() {
    process_t* current_proc = proc_get_current();
    for (int i = 0; i < MAX_FD_PER_PROCESS; ++i) {
        if (current_proc->file_descriptors[i].node == NULL) {
            return i;
        }
    }
    return -1; // No available file descriptors
}

// Safely copies a string from userspace to a kernel buffer.
// Returns 0 on success, -EFAULT on failure.
static int copy_from_user(char *kbuf, const char *ubuf, size_t max_len) {
    if ((uint64_t)ubuf >= USERSPACE_TOP) {
        return -1;
    }
    // TODO: We should validate the entire range, not just the start.
    memcpy(kbuf, ubuf, max_len);
    return 0;
}


int64_t syscall_handler(registers_t* regs) {
    LOG_DEBUG("  SYSCALL REGS:");
    LOG_DEBUG("  Interrupt: 0x%llx, Error Code: 0x%llx", regs->interrupt_number, regs->error_code);
    LOG_DEBUG("  CS:  0x%llx, RIP: 0x%llx, RFLAGS: 0x%llx", regs->cs, regs->rip, regs->rflags);
    LOG_DEBUG("  SS:  0x%llx, RSP: 0x%llx", regs->ss, regs->user_rsp);
    LOG_DEBUG("  RAX: 0x%llx, RBX: 0x%llx, RCX: 0x%llx", regs->rax, regs->rbx, regs->rcx);
    LOG_DEBUG("  RDX: 0x%llx, RSI: 0x%llx, RDI: 0x%llx", regs->rdx, regs->rsi, regs->rdi);
    LOG_DEBUG("  RBP: 0x%llx, R8:  0x%llx, R9:  0x%llx", regs->rbp, regs->r8, regs->r9);
    LOG_DEBUG("  R10: 0x%llx, R11: 0x%llx, R12: 0x%llx", regs->r10, regs->r11, regs->r12);
    LOG_DEBUG("  R13: 0x%llx, R14: 0x%llx, R15: 0x%llx", regs->r13, regs->r14, regs->r15);
    LOG_DEBUG("  FS:  0x%llx, GS:  0x%llx", regs->fs, regs->gs);

    uint64_t syscall_num = regs->rax;

    if (syscall_num >= MAX_SYSCALLS || syscall_table[syscall_num] == NULL) {
        LOG_DEBUG("Unknown or unimplemented syscall number: %llu", syscall_num);
        return -1; // Corresponds to -ENOSYS
    }

    return syscall_table[syscall_num](regs);
}

static int64_t sys_exit(registers_t* regs) {
    int64_t exit_code = regs->rdi; // First argument
    LOG_INFO("Process %d exiting with code %d", proc_get_current()->pid, exit_code);
    proc_terminate(proc_get_current());
    proc_scheduler_run_special(NULL, true);
    LOG_PANIC("No processes to run after exit! Halting.");
    for (;;) { asm("hlt"); }
    return -1; // Should be unreachable
}

static int64_t sys_write(registers_t* regs) {
    uint64_t fd = regs->rdi;
    const char* buf = (const char*)regs->rsi;
    size_t count = regs->rdx;

    if (fd >= MAX_FD_PER_PROCESS) {
        LOG_ERR("sys_write: ERROR: fd %llu is out of bounds (MAX_FD_PER_PROCESS=%d)", fd, MAX_FD_PER_PROCESS);
        return -1;
    }

    process_t* current_proc = proc_get_current();
    file_desc_t* file = &current_proc->file_descriptors[fd];

    if (file->node == NULL) {
        LOG_ERR("sys_write: ERROR: file->node is NULL for fd %llu", fd);
        return -1;
    }

    char kbuf[MAX_WRITE_SIZE + 1];
    size_t write_count = count > MAX_WRITE_SIZE ? MAX_WRITE_SIZE : count;
    if (copy_from_user(kbuf, buf, write_count) != 0) {
        LOG_ERR("sys_write: ERROR: copy_from_user failed for fd %llu", fd);
        return -2;
    }
    kbuf[write_count] = '\0'; // Ensure null termination for logging/printing

    int64_t bytes_written = vfs_write(file->node, file->offset, write_count, kbuf);
    if (bytes_written > 0) {
        file->offset += bytes_written;
    }

    return bytes_written;
}


static int64_t sys_close(registers_t* regs) {
    uint64_t fd = regs->rdi;

    if (fd >= MAX_FD_PER_PROCESS || proc_get_current()->file_descriptors[fd].node == NULL) {
        return -1;
    }

    process_t* current = proc_get_current();
    file_desc_t* file = &current->file_descriptors[fd];
    // TODO: vfs_close(file); // This function would handle reference counting and resource cleanup.
    file->node = NULL;
    file->offset = 0;
    file->flags = 0;
    return 0;
}

static int64_t sys_fork(registers_t* parent_regs) {
    LOG_DEBUG("Forking!");

    // Create a new child process of this current process..
    process_t* parent = proc_get_current();
    process_t* child = proc_create(parent->type);
    if (child == NULL) {
        LOG_ERR("SYSCALL: Failed to create new process struct.");
        return -1;
    }

    // Copy the virtual address space from the current to the new
    child->pml4_phys = vmm_create_address_space();
    if (child->pml4_phys == 0) {
        LOG_ERR("SYSCALL: Failed to create new address space for child.");
        // TODO: Need a `proc_free(child)` function to clean up the process struct
        return -1;
    }

    // Iterate through the parent's user-space virtual memory and copy it page by page.
    // NOTE: This is a simplified implementation. It assumes a contiguous user space
    // up to the program break and doesn't handle mmap'd regions above it.
    // It also assumes a function `vmm_get_hhdm_offset()` exists to get the HHDM base.
    uint64_t hhdm_offset = vmm_get_hhdm_offset();
    for (uint64_t vaddr = 0; vaddr < parent->program_break; vaddr += PAGE_SIZE) {
        uint64_t parent_phys_addr = vmm_get_physical_addr_from(parent->pml4_phys, vaddr);
        if (parent_phys_addr == 0) {
            continue; // This page isn't mapped in the parent, so we skip it.
        }

        // Allocate a new physical page for the child.
        void* child_phys_page = pmm_alloc_block();
        if (child_phys_page == NULL) {
            LOG_ERR("sys_fork: pmm_alloc_block failed. Cannot complete address space copy.");
            // In a real implementation, we would need to unmap all pages mapped so far
            // for the child and free their physical frames before terminating it.
            return -1; // ENOMEM
        }

        // Copy the page content from parent to child using the HHDM mapping.
        void* parent_page_content = (void*)(parent_phys_addr + hhdm_offset);
        void* child_page_dest = (void*)((uint64_t)child_phys_page + hhdm_offset);
        memcpy(child_page_dest, parent_page_content, PAGE_SIZE);

        // Map the new page in the child's address space.
        // TODO: We should get the flags from the parent's PTE instead of hardcoding them.
        uint64_t flags = PAGE_PRESENT | PAGE_READ_WRITE | PAGE_USER;
        if (!vmm_map_page_to(child->pml4_phys, vaddr, (uint64_t)child_phys_page, flags)) {
            LOG_ERR("sys_fork: vmm_map_page_to failed for child.");
            pmm_free_block(child_phys_page);
            // TODO: Full cleanup required here.
            return -1;
        }
    }

    // --- FIX: Explicitly copy the user-mode stack pages ---
    for (uint64_t vaddr = USER_STACK_TOP - USER_STACK_SIZE; vaddr < USER_STACK_TOP; vaddr += PAGE_SIZE) {
        uint64_t parent_phys_addr = vmm_get_physical_addr_from(parent->pml4_phys, vaddr);
        if (parent_phys_addr == 0) {
            continue; // This part of the stack was never touched/mapped, so skip it.
        }

        void* child_phys_page = pmm_alloc_block();
        if (child_phys_page == NULL) {
            LOG_ERR("sys_fork: pmm_alloc_block failed for stack pages.");
            return -1; // ENOMEM
        }

        void* parent_page_content = (void*)(parent_phys_addr + hhdm_offset);
        void* child_page_dest = (void*)((uint64_t)child_phys_page + hhdm_offset);
        memcpy(child_page_dest, parent_page_content, PAGE_SIZE);

        uint64_t flags = PAGE_PRESENT | PAGE_READ_WRITE | PAGE_USER;
        if (!vmm_map_page_to(child->pml4_phys, vaddr, (uint64_t)child_phys_page, flags)) {
            LOG_ERR("sys_fork: vmm_map_page_to failed for stack pages.");
            pmm_free_block(child_phys_page);
            return -1;
        }
    }

    // Copy the program break information.
    child->program_break = parent->program_break;
    child->program_break_start = parent->program_break_start;

    // Copy the registers from the parent...
    uint64_t child_regs_addr = (uint64_t)child->kernel_stack + child->kernel_stack_size - sizeof(registers_t);
    registers_t* child_regs = (registers_t*)child_regs_addr;
    memcpy(child_regs, parent_regs, sizeof(registers_t));
    child->kstack_ptr = child_regs_addr;
    child_regs->rax = 0;

    // Duplicate the parent file descriptors...
    for(int i = 0; i < MAX_FD_PER_PROCESS; i++) {
        child->file_descriptors[i] = parent->file_descriptors[i];
    }

    proc_exec(child);
    return child->pid;
}

static int64_t sys_open(registers_t* regs) {
    const char* path = (const char*)regs->rdi;
    uint16_t flags = (uint16_t)regs->rsi;

    int fd = get_next_fd();
    if (fd < 0) {
        return -1;
    }

    char kpath[256];
    if (copy_from_user(kpath, path, sizeof(kpath)) != 0) {
        return -2;
    }

    vfs_node_t* node = vfs_open(kpath);
    if (node == NULL) {
        return -3;
    }

    process_t* current_proc = proc_get_current();
    current_proc->file_descriptors[fd].node = node;
    current_proc->file_descriptors[fd].offset = 0;
    current_proc->file_descriptors[fd].flags = flags;

    LOG_INFO("Process %d opened \"%s\" as fd %d", current_proc->pid, kpath, fd);
    return fd;
}

static int64_t sys_lseek(registers_t* regs) {
    uint64_t fd = regs->rdi;
    int64_t offset = regs->rsi;
    uint8_t wence = regs->rdx;

    process_t* proc = proc_get_current();

    // TODO: Check with the VFS if this file is seekable, otherwise return an error
    if(fd >= MAX_FD_PER_PROCESS || proc->file_descriptors[fd].node == NULL) {
        return -1;
    }

    // Update the offset in the file
    file_desc_t* file = &proc->file_descriptors[fd];
    uint64_t sz = file->node->length;
    uint64_t new_off;
    switch(wence) {
        case SEEK_SET:
            new_off = offset;
            break;
        case SEEK_CUR:
            new_off = file->offset + offset;
            break;
        case SEEK_END:
            new_off = sz + offset;
            break;
        default:
            return -2;
    }

    file->offset = new_off;
    return new_off;
}

static int64_t sys_brk(registers_t* regs) {
    uint64_t addr = regs->rdi;
    process_t* current_proc = proc_get_current();
    uint64_t old_program_break = current_proc->program_break;

    if (addr == 0) {
        return old_program_break;
    }

    // Align the requested address to page boundary
    uint64_t new_program_break_aligned = (addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    uint64_t old_program_break_aligned = (old_program_break + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    if (new_program_break_aligned < current_proc->program_break_start) {
        LOG_ERR("SYSCALL: brk(0x%llx) failed: cannot shrink below initial break 0x%llx", addr, current_proc->program_break_start);
        return -1;
    }

    if (new_program_break_aligned > old_program_break_aligned) {
        // Expand heap
        for (uint64_t page = old_program_break_aligned; page < new_program_break_aligned; page += PAGE_SIZE) {
            void* phys_page = pmm_alloc_block();
            if (phys_page == NULL) {
                LOG_ERR("SYSCALL: brk failed to allocate physical page for 0x%llx", page);
                // Rollback any pages already mapped in this call
                for (uint64_t p = old_program_break_aligned; p < page; p += PAGE_SIZE) {
                    vmm_unmap_page_from(current_proc->pml4_phys, p);
                    pmm_free_block((void*)vmm_get_physical_addr_from(current_proc->pml4_phys, p));
                }
                return -1;
            }
            if (!vmm_map_page_to(current_proc->pml4_phys, page, (uint64_t)phys_page, PAGE_PRESENT | PAGE_READ_WRITE | PAGE_USER)) {
                LOG_ERR("SYSCALL: brk failed to map virtual page 0x%llx to physical 0x%llx", page, (uint64_t)phys_page);
                pmm_free_block(phys_page);
                // Rollback
                for (uint64_t p = old_program_break_aligned; p < page; p += PAGE_SIZE) {
                    vmm_unmap_page_from(current_proc->pml4_phys, p);
                    pmm_free_block((void*)vmm_get_physical_addr_from(current_proc->pml4_phys, p));
                }
                return -1;
            }
        }
    } else if (new_program_break_aligned < old_program_break_aligned) {
        // Shrink heap
        for (uint64_t page = new_program_break_aligned; page < old_program_break_aligned; page += PAGE_SIZE) {
            uint64_t phys_addr = vmm_get_physical_addr_from(current_proc->pml4_phys, page);
            if (phys_addr != 0) {
                vmm_unmap_page_from(current_proc->pml4_phys, page);
                pmm_free_block((void*)phys_addr);
            }
        }
    }

    current_proc->program_break = addr; // Store the unaligned address
    LOG_INFO("SYSCALL: Process %llu brk changed from 0x%llx to 0x%llx (requested 0x%llx)",
             current_proc->pid, old_program_break, current_proc->program_break, addr);
    return 0; // Return 0 on success for non-zero addr
}

static int64_t sys_read(registers_t* regs) {
    uint64_t fd = regs->rdi;
    void* buf = (void*)regs->rsi;
    size_t count = regs->rdx;

    process_t* proc = proc_get_current();

    if (fd >= MAX_FD_PER_PROCESS || proc->file_descriptors[fd].node == NULL) {
        return -1; // EBADF
    }

    char* kbuf = kmalloc(count);
    if (!kbuf) {
        return -1; // ENOMEM
    }

    file_desc_t* file = &proc->file_descriptors[fd];
    vfs_node_t* node = file->node;

    int64_t bytes_read = node->fops->read(node, file->offset, count, kbuf);

    if (bytes_read > 0) {
        // Copy the data from the kernel buffer to the user's buffer.
        memcpy(buf, kbuf, bytes_read);
        file->offset += bytes_read;
    }

    kfree(kbuf);
    return bytes_read;
}

static int64_t sys_yield(registers_t* regs) {
    proc_scheduler_run(regs);
    return -1; // Should not be reached in the same context
}

static int64_t sys_getpid(registers_t* regs) {
    (void)regs; // Unused
    return proc_get_current()->pid;
}
