#include <kernel/syscall.h>
#include <kernel/log.h>
#include <kernel/proc.h>
#include <drivers/fb_console.h>
#include <drivers/fs/vfs.h>
#include <arch/x86-64/vmm.h>
#include <arch/x86-64/pmm.h>
#include <libc/unistd.h>
#include <libc/string.h>

#define USERSPACE_TOP (0x000080000000ULL)
#define MAX_WRITE_SIZE 256

static int64_t sys_exit_proc(registers_t* regs);
static int64_t sys_fork_proc(registers_t* parent_regs);
static int64_t sys_write(uint64_t fd, const char* buf, size_t count);
static int64_t sys_open(const char* path, uint16_t flags);
static int64_t sys_close(uint64_t fd);

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
    strncpy(kbuf, ubuf, max_len);
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
            return 0;
        case SYSCALL_WRITE:
            return sys_write(regs->rdi, (const char*)regs->rsi, regs->rdx);
        case SYSCALL_OPEN:
            return sys_open((const char*)regs->rdi, (uint16_t)regs->rsi);
        case SYSCALL_CLOSE:
            return sys_close(regs->rdi);
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
    LOG_DEBUG("--- sys_write called with fd=%llu ---", fd);
    LOG_DEBUG("Buf: '%s', Count: %d", buf, count);
    process_t* p = proc_get_current();
    for (int i = 0; i < MAX_FD_PER_PROCESS; i++) {
        if (p->file_descriptors[i].node != NULL) {
            LOG_DEBUG("  FD %d: node=0x%llx, name='%s'", i,
                      (uint64_t)p->file_descriptors[i].node,
                      p->file_descriptors[i].node->name);
        }
    }

    if (fd >= MAX_FD_PER_PROCESS) {
        return -1;
    }

    process_t* current_proc = proc_get_current();
    file_desc_t* file = &current_proc->file_descriptors[fd];

    if (file->node == NULL) {
        return -1;
    }

    char kbuf[MAX_WRITE_SIZE + 1];
    size_t write_count = count > MAX_WRITE_SIZE ? MAX_WRITE_SIZE : count;
    if (copy_from_user(kbuf, buf, write_count) != 0) {
        return -2;
    }
    kbuf[write_count] = '\0'; // Ensure null termination for logging/printing

    LOG_DEBUG("SYSCALL: Writing to VFS file '%s' '%llu' '%llu' '%s'", file->node->name, file->offset, write_count, kbuf);
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
