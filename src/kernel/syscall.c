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
#define MAX_SYSCALLS 512

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
static int64_t sys_waitid(registers_t* regs);
static int64_t sys_exec(registers_t* regs);
static int64_t sys_stat(registers_t* regs);

// Syscall table
static syscall_func_t syscall_table[MAX_SYSCALLS] = {
    [SYS_READ]          = sys_read,
    [SYS_WRITE]         = sys_write,
    [SYS_OPEN]          = sys_open,
    [SYS_CLOSE]         = sys_close,
    [SYS_STAT]          = sys_stat,
    [SYS_LSEEK]         = sys_lseek,
    [SYS_BRK]           = sys_brk,
    [SYS_PROC_YIELD]    = sys_yield,
    [SYS_PROC_EXIT]     = sys_exit,
    [SYS_PROC_PID]      = sys_getpid,
    [SYS_PROC_FORK]     = sys_fork,
    [SYS_WAITID]        = sys_waitid,
    [SYS_EXEC]          = sys_exec,
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
    uint64_t syscall_num = regs->rax;

    if (syscall_num >= MAX_SYSCALLS || syscall_table[syscall_num] == NULL) {
        LOG_DEBUG("Unknown or unimplemented syscall number: %llu", syscall_num);
        return -1; // Corresponds to -ENOSYS
    }

    return syscall_table[syscall_num](regs);
}

static int64_t sys_exit(registers_t* regs) {
    int64_t exit_code = regs->rdi;
    process_t* current = proc_get_current();

    // Turn the process into a zombie and wake the parent.
    proc_free(current, exit_code);

    // Yield to the scheduler. This process will not run again.
    proc_scheduler_run(regs);

    LOG_PANIC("Zombie process %d ran again!", current->pid);
    for (;;) { asm("hlt"); }
    return -1;
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
//        LOG_ERR("sys_write: ERROR: file->node is NULL for fd %llu", fd);
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

static int64_t sys_stat(registers_t* regs) {
    char* filepath = (char*)regs->rdi;
    file_stats_t* buf = (file_stats_t*)regs->rsi;

    char kpath[256];
    if (copy_from_user(kpath, filepath, sizeof(kpath)) != 0) {
        return -2;
    }

    vfs_node_t* node = vfs_open(kpath);
    if (node == NULL) {
        return -3;
    }

    file_stats_t file_stats;
    if (node->fops && node->fops->stat) {
        if (node->fops->stat(node, &file_stats) != 0) {
            LOG_ERR("sys_exec: Failed to get file stats for '%s'", kpath);
            return -5; // EIO
        }
    }

    memcpy(buf, &file_stats, sizeof(file_stats_t));
    return 0;
}

static int64_t sys_fork(registers_t* parent_regs) {
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
        proc_free(child, -1);
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

    // Make sure we set the parent of this child correctly
    child->parent = parent;
    child->pgid = parent->pgid;

    proc_make_ready(child);
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

static int64_t sys_waitid(registers_t* regs) {
    uint64_t idtype = regs->rdi;
    uint64_t id = regs->rsi;
    void* info = (void*)regs->rdx;
    int options = regs->r10;

    if(idtype != 0) { // Corresponds to P_PID
        LOG_ERR("  Unsupported idtype: %llu. Only P_PID (0) is supported.", idtype);
        return -1;
    }

    process_t* parent = proc_get_current();
    for (;;) {
        process_t* child_to_reap = find_zombie_child(parent->pid, id);

        if (child_to_reap != NULL) {
            // TODO: Copy exit information to the user-space `info` struct.

            uint64_t child_pid = child_to_reap->pid;
            proc_free(child_to_reap, child_to_reap->exit_code); // proc_free should turn it into a zombie
            return child_pid;
        }

        if (options & WNOHANG) {
            LOG_ERR("  WNOHANG option is set, returning 0.");
            LOG_ERR("--- sys_waitid EXIT (WNOHANG) ---");
            return 0;
        }

        parent->state = PROC_STATE_BLOCKED;
        proc_scheduler_run(regs);
    }
}

static int64_t sys_exec(registers_t* regs) {
    const char* filename = (const char*)regs->rdi;
    char** argv = (char**)regs->rsi;
    char** envp = (char**)regs->rdx;

    // Copy the filename from user space
    char kfilename[256];
    if (copy_from_user(kfilename, filename, sizeof(kfilename)) != 0) {
        LOG_ERR("sys_exec: Failed to copy filename from user space");
        return -1; // EFAULT
    }

    // Open the file using VFS
    vfs_node_t* file_node = vfs_open(kfilename);
    if (file_node == NULL) {
        LOG_ERR("sys_exec: Failed to open file '%s'", kfilename);
        return -2; // ENOENT
    }
    
    // Get the correct file size using stat
    file_stats_t file_stats;
    if (file_node->fops && file_node->fops->stat) {
        if (file_node->fops->stat(file_node, &file_stats) != 0) {
            LOG_ERR("sys_exec: Failed to get file stats for '%s'", kfilename);
            return -5; // EIO
        }
    } else {
        // Fallback to node length if no stat function
        file_stats.size_bytes = file_node->length;
    }

    // Check if the file is executable
    if (!(file_node->flags & VFS_EXEC)) {
        LOG_ERR("sys_exec: File '%s' is not executable", kfilename);
        return -3; // EACCES
    }

    // Read the file into kernel memory
    char* file_buffer = kmalloc(file_stats.size_bytes);
    if (file_buffer == NULL) {
        LOG_ERR("sys_exec: Failed to allocate memory for file buffer, size=%llu", file_stats.size_bytes);
        return -4; // ENOMEM
    }

    int64_t bytes_read = vfs_read(file_node, 0, file_stats.size_bytes, file_buffer);
    if (bytes_read <= 0) {
        LOG_ERR("sys_exec: Failed to read file, bytes_read=%lld", bytes_read);
        kfree(file_buffer);
        return -5; // EIO
    }

    // Validate it's an ELF file
    elf_header_t* elf_header = (elf_header_t*)file_buffer;
    if (elf_header->ident[0] != 0x7F || 
        elf_header->ident[1] != 'E' || 
        elf_header->ident[2] != 'L' || 
        elf_header->ident[3] != 'F') {
        LOG_ERR("sys_exec: File is not a valid ELF file");
        kfree(file_buffer);
        return -6; // ENOEXEC
    }

    // Count argc and copy argv to kernel space
    int argc = 0;
    char** kargv = NULL;
    
    if (argv) {
        // First count the arguments
        for (argc = 0; argc < 63; argc++) {  // Limit to 63 arguments for safety
            if (argv[argc] == NULL) break;
        }
        
        // Allocate kernel space for argv array
        kargv = kmalloc((argc + 1) * sizeof(char*));  // +1 for NULL terminator
        if (kargv == NULL) {
            LOG_ERR("sys_exec: Failed to allocate memory for argv array");
            kfree(file_buffer);
            return -4; // ENOMEM
        }
        
        // Copy each argument string
        for (int i = 0; i < argc; i++) {
            kargv[i] = kmalloc(256); // Assume max 256 chars per arg
            if (kargv[i] == NULL) {
                LOG_ERR("sys_exec: Failed to allocate memory for argument %d", i);
                // Free previously allocated args
                for (int j = 0; j < i; j++) {
                    kfree(kargv[j]);
                }
                kfree(kargv);
                kfree(file_buffer);
                return -4; // ENOMEM
            }
            
            if (copy_from_user(kargv[i], argv[i], 256) != 0) {
                LOG_ERR("sys_exec: Failed to copy argument %d from user space", i);
                // Free previously allocated args
                for (int j = 0; j <= i; j++) {
                    kfree(kargv[j]);
                }
                kfree(kargv);
                kfree(file_buffer);
                return -1; // EFAULT
            }
        }
        kargv[argc] = NULL;  // NULL terminate
    }

    // Kernel envp
    int envc = 0;
    if (envp) {
        for (; envp[envc] != NULL; envc++) {}
    }
    char** kenvp = NULL;
    if (envc > 0) {
        kenvp = kmalloc((envc + 1) * sizeof(char*));
        if (!kenvp) { /* cleanup and return ENOMEM */ }
        for (int i = 0; i < envc; ++i) {
            kenvp[i] = kmalloc(256); // or allocate exact length after measuring
            if (!kenvp[i]) { /* cleanup */ }
            if (copy_from_user(kenvp[i], envp[i], 256) != 0) { /* cleanup */ }
        }
        kenvp[envc] = NULL;
    }
    
    // Load the ELF with or without arguments
    process_t* new_proc = NULL;
    if (argc > 0) {
        new_proc = elf_load_process_with_args(file_buffer, argc, kargv, kenvp);
    } else {
        new_proc = elf_load_process(file_buffer);
    }

    // Clean up kernel argv copies
    if (kargv) {
        for (int i = 0; i < argc; i++) {
            if (kargv[i]) {
                kfree(kargv[i]);
            }
        }
        kfree(kargv);
    }

    if (kenvp) {
        for (int i = 0; i < envc; ++i) {
            kfree(kenvp[i]);
        }
        kfree(kenvp);
    }

    if (new_proc == NULL) {
        LOG_ERR("sys_exec: Failed to load ELF");
        kfree(file_buffer);
        return -7; // ENOEXEC
    }

    // Replace the current process with the new one
    process_t* current_proc = proc_get_current();

    // Copy the new process data to the current process

    current_proc->pml4_phys = new_proc->pml4_phys;
    current_proc->program_break = new_proc->program_break;
    current_proc->program_break_start = new_proc->program_break_start;
    current_proc->entry_point = new_proc->entry_point;
    current_proc->kstack_ptr = new_proc->kstack_ptr;
    current_proc->pgid = new_proc->pgid;

    // Get the new process's initial register state
    registers_t* new_regs = (registers_t*)new_proc->kstack_ptr;

    // Update the register state that will be restored when returning to userspace
    // We need to be very careful about which fields we update:

    // For sysretq, we need to set:
    // rcx = new RIP (entry point)
    // r11 = new RFLAGS
    // r8 = new RSP (stack pointer)
    regs->rcx = new_regs->rip;           // This will become RCX, which sysretq uses as RIP
    regs->r11 = new_regs->rflags;        // This will become R11, which sysretq uses as RFLAGS
    regs->r8 = new_regs->user_rsp;       // This will become the new RSP after sysretq
    new_regs->r8 = new_regs->user_rsp;       // This will become the new RSP after sysretq

    // Also update the fields in the register structure that correspond to these registers
    regs->rip = new_regs->rip;           // For consistency in the structure
    regs->user_rsp = new_regs->user_rsp; // The user stack pointer
    regs->rflags = new_regs->rflags;     // The flags
    regs->cs = new_regs->cs;             // Code segment
    regs->ss = new_regs->ss;             // Stack segment

    // Syscall return value should be 0 for success
    regs->rax = 0;

    // Free the temporary new process structure (but not its address space)
    // We zero out the pml4_phys so vmm_free_address_space doesn't free it again
    proc_free(new_proc, 0);

    kfree(file_buffer);
    vmm_load_pml4(current_proc->pml4_phys);

    // The sys_exec call should not return on success
    // Instead, we return to userspace with the new process's registers
    return 0;
}