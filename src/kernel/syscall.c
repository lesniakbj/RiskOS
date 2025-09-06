#include <kernel/syscall.h>
#include <kernel/log.h>
#include <kernel/proc.h>
#include <drivers/fb_console.h>
#include <arch/x86-64/vmm.h>
#include <arch/x86-64/pmm.h>
#include <libc/unistd.h>
#include <libc/string.h>

#define USERSPACE_TOP (0x0000800000ULL)
#define MAX_WRITE_SIZE 256

static int64_t sys_exit_proc(registers_t* regs);
static int64_t sys_fork_proc(registers_t* parent_regs);
static int64_t sys_write(uint64_t fd, const char* buf, size_t count);

int64_t syscall_handler(registers_t* regs) {
    // Log user registers...
//    LOG_DEBUG("  SYSCALL REGS:");
//    LOG_DEBUG("  Interrupt: 0x%llx, Error Code: 0x%llx", regs->interrupt_number, regs->error_code);
//    LOG_DEBUG("  CS:  0x%llx, RIP: 0x%llx, RFLAGS: 0x%llx", regs->cs, regs->rip, regs->rflags);
//    LOG_DEBUG("  SS:  0x%llx, RSP: 0x%llx", regs->ss, regs->user_rsp);
//    LOG_DEBUG("  RAX: 0x%llx, RBX: 0x%llx, RCX: 0x%llx", regs->rax, regs->rbx, regs->rcx);
//    LOG_DEBUG("  RDX: 0x%llx, RSI: 0x%llx, RDI: 0x%llx", regs->rdx, regs->rsi, regs->rdi);
//    LOG_DEBUG("  RBP: 0x%llx, R8:  0x%llx, R9:  0x%llx", regs->rbp, regs->r8, regs->r9);
//    LOG_DEBUG("  R10: 0x%llx, R11: 0x%llx, R12: 0x%llx", regs->r10, regs->r11, regs->r12);
//    LOG_DEBUG("  R13: 0x%llx, R14: 0x%llx, R15: 0x%llx", regs->r13, regs->r14, regs->r15);
//    LOG_DEBUG("  FS:  0x%llx, GS:  0x%llx", regs->fs, regs->gs);

    switch (regs->rax) {
        case SYSCALL_WRITE:
            LOG_DEBUG("Handling write syscall. Current proc pid: %llu", proc_get_current()->pid);
            return sys_write(regs->rdi, (const char*)regs->rsi, regs->rdx);
        case SYSCALL_PROC_YIELD:
            LOG_DEBUG("Handling yield syscall");
            // TODO: We need to properly save the stackframe here before we run proc run, or we will get a Page Fault/GPF later
            proc_scheduler_run(regs);
            return -1;
        case SYSCALL_PROC_EXIT:
            LOG_DEBUG("Handling exit syscall with code %d", regs->rdi);
            sys_exit_proc(regs);
            return regs->rdi;
        case SYSCALL_PROC_PID:
            LOG_DEBUG("Handling PID syscall. Current proc pid: %llu", proc_get_current()->pid);
            regs->rax = proc_get_current()->pid;
            return -1;
        case SYSCALL_PROC_FORK:
            LOG_DEBUG("Handling fork syscall. Current proc pid: %llu", proc_get_current()->pid);
            return sys_fork_proc(regs);
        default:
            LOG_DEBUG("Unknown syscall number: %llu", regs->rax);
            return -1; // Error code
    }
}

static int64_t sys_exit_proc(registers_t* regs) {
    int64_t exit_code = regs->rdi; // First argument
    LOG_DEBUG("Handling exit syscall with code %d", exit_code);

    // Set the return value (even though we won't return)
    regs->rax = exit_code;

    // TERMINATE THE PROCESS HERE - DON'T RETURN TO USER SPACE
    LOG_INFO("Process exiting with code %d", exit_code);
    proc_terminate(proc_get_current());

    // The scheduler should never return from here when exiting a process.
    // If it does, it means there are no other runnable processes (not even the idle task),
    // which is a critical error.
    // Pass NULL to indicate this is not a regular scheduler invocation
    // Use the special scheduler with is_exit=true to avoid saving the current process state
    proc_scheduler_run_special(NULL, true);

    // If we reach here, it means there are no other processes to run
    LOG_PANIC("No processes to run after exit! Halting.");
    for (;;) {
        asm("hlt");
    }
}

static int64_t sys_write(uint64_t fd, const char* buf, size_t count) {
    if (buf == NULL) {
        return -1;
    }
    framebuffer_writestring(buf);
    LOG_DEBUG(buf);
    return count;
}

static int64_t sys_fork_proc(registers_t* parent_regs) {
    LOG_DEBUG("Forking!");
    LOG_DEBUG("Done forking!");
    return proc_get_current()->pid;
}