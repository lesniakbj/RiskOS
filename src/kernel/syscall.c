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

#define USERSPACE_TOP (0x7000000000ULL)
#define MAX_WRITE_SIZE 1024

static int64_t sys_exit_proc(registers_t* regs);
static int64_t sys_fork_proc(registers_t* parent_regs);

static int64_t sys_read(uint64_t fd, void* buf, size_t count);
static int64_t sys_write(uint64_t fd, const char* buf, size_t count);
static int64_t sys_open(const char* path, uint16_t flags);
static int64_t sys_close(uint64_t fd);
static int64_t sys_lseek(uint64_t fd, int64_t offset, uint8_t wence);
static int64_t sys_brk(uint64_t addr);

// Helper to find the next available file descriptor for the current process
static int get_next_fd() {
    process_t* current_proc = proc_get_current();
    for (int i = 0; i < MAX_FD_PER_PROCESS; ++i) {
        if (&(current_proc->file_descriptors[i]) == NULL) {
            // TODO: We need to properly create the fd struct
        } else if(current_proc->file_descriptors[i].node == NULL) {
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

    switch (regs->rax) {
        case SYSCALL_READ:
            return sys_read(regs->rdi, (void*)regs->rsi, regs->rdx);
        case SYSCALL_WRITE:
            return sys_write(regs->rdi, (const char*)regs->rsi, regs->rdx);
        case SYSCALL_OPEN:
            return sys_open((const char*)regs->rdi, (uint16_t)regs->rsi);
        case SYSCALL_CLOSE:
            return sys_close(regs->rdi);
        case SYSCALL_LSEEK:
            return sys_lseek(regs->rdi, regs->rsi, regs->rdx);
        case SYSCALL_PROC_YIELD:
            proc_scheduler_run(regs);
            return -1;
        case SYSCALL_PROC_EXIT:
            sys_exit_proc(regs);
            return -1; // Should not be reached
        case SYSCALL_PROC_PID:
            return proc_get_current()->pid;
        case SYSCALL_PROC_FORK:
            return sys_fork_proc(regs);
        case SYS_BRK:
            return sys_brk(regs->rdi);
        default:
            LOG_DEBUG("Unknown syscall number: %llu", regs->rax);
            return -1; // Error code
    }
}

static int64_t sys_exit_proc(registers_t* regs) {
    int64_t exit_code = regs->rdi; // First argument
    LOG_INFO("Process %d exiting with code %d", proc_get_current()->pid, exit_code);
    proc_terminate(proc_get_current());
    proc_scheduler_run_special(NULL, true);
    LOG_PANIC("No processes to run after exit! Halting.");
    for (;;) { asm("hlt"); }
    return -1; // Should be unreachable
}

static int64_t sys_write(uint64_t fd, const char* buf, size_t count) {
    process_t* p = proc_get_current();

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


static int64_t sys_close(uint64_t fd) {
    if (fd >= MAX_FD_PER_PROCESS || proc_get_current()->file_descriptors[fd].node == NULL) {
        return -1;
    }

    process_t* current = proc_get_current();
    file_desc_t* file = &current->file_descriptors[fd];
    // TODO: vfs_close(file); // This function would handle reference counting and resource cleanup.
    current->file_descriptors[fd].node = NULL;
    current->file_descriptors[fd].offset = 0;
    current->file_descriptors[fd].flags = 0;
    return 0;
}

static int64_t sys_fork_proc(registers_t* parent_regs) {
    (void)parent_regs; // Will be used when fork is fully implemented
    LOG_DEBUG("Forking!");
    // TODO: Actually fork the process correctly...
    return proc_get_current()->pid;
}

static int64_t sys_open(const char* path, uint16_t flags) {
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

static int64_t sys_lseek(uint64_t fd, int64_t offset, uint8_t wence) {
    process_t* proc = proc_get_current();

    // TODO: Check with the VFS if this file is seekable, otherwise return an error
    if(fd < 0 || fd >= MAX_FD_PER_PROCESS || proc->file_descriptors[fd].node == NULL) {
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

static int64_t sys_brk(uint64_t addr) {
    process_t* current_proc = proc_get_current();
    uint64_t old_program_break = current_proc->program_break;

    if (addr == 0) {
        // brk(0) returns the current program break.
        // This is a non-standard Linux behavior for the syscall,
        // but it's what sbrk(0) would internally do.
        // For the actual brk() syscall, it should return 0 on success.
        // We'll return the current break here, and the libc wrapper will handle it.
        return old_program_break;
    }

    // Align the requested address to page boundary
    uint64_t new_program_break_aligned = (addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    uint64_t old_program_break_aligned = (old_program_break + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    if (new_program_break_aligned < current_proc->program_break_start) {
        // Cannot shrink below initial program break
        LOG_ERR("SYSCALL: brk(0x%llx) failed: cannot shrink below initial break 0x%llx", addr, current_proc->program_break_start);
        return -1; // Return -1 on error
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
                return -1; // Return -1 on failure
            }
            if (!vmm_map_page_to(current_proc->pml4_phys, page, (uint64_t)phys_page, PAGE_PRESENT | PAGE_READ_WRITE | PAGE_USER)) {
                LOG_ERR("SYSCALL: brk failed to map virtual page 0x%llx to physical 0x%llx", page, (uint64_t)phys_page);
                pmm_free_block(phys_page);
                // Rollback
                for (uint64_t p = old_program_break_aligned; p < page; p += PAGE_SIZE) {
                    vmm_unmap_page_from(current_proc->pml4_phys, p);
                    pmm_free_block((void*)vmm_get_physical_addr_from(current_proc->pml4_phys, p));
                }
                return -1; // Return -1 on failure
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

static int64_t sys_read(uint64_t fd, void* buf, size_t count) {
    process_t* proc = proc_get_current();

    if (fd >= MAX_FD_PER_PROCESS || proc->file_descriptors[fd].node == NULL) {
        return -1; // EBADF
    }

    // Allocate a temporary buffer from the kernel heap.
    // This is much safer than using a fixed-size stack buffer.
    char* kbuf = kmalloc(count);
    if (!kbuf) {
        return -1; // ENOMEM
    }

    file_desc_t* file = &proc->file_descriptors[fd];
    vfs_node_t* node = file->node;

    // 1. Read from the file into our temporary kernel buffer
    int64_t bytes_read = node->fops->read(node, file->offset, count, kbuf);

    if (bytes_read > 0) {
        // 2. Copy the data from the kernel buffer to the user's buffer.
        memcpy(buf, kbuf, bytes_read);

        // 3. Update the file offset
        uint64_t old_offset = file->offset;
        file->offset += bytes_read;
    }

    // 4. Free the temporary kernel buffer
    kfree(kbuf);

    return bytes_read;
}