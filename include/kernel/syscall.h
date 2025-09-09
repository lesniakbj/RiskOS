#ifndef KERNEL_SYSCALL_Hvmm
#define KERNEL_SYSCALL_H

#include <stdint.h>
#include <arch/x86-64/interrupts.h>

// Syscall numbers
#define SYSCALL_READ            0
#define SYSCALL_WRITE           1
#define SYSCALL_OPEN            2
#define SYSCALL_CLOSE           3

#define SYSCALL_LSEEK           8
#define     SEEK_SET            0
#define     SEEK_CUR            1
#define     SEEK_END            2

#define SYSCALL_PROC_YIELD      24
#define SYSCALL_PROC_EXIT       60
#define SYSCALL_PROC_PID        39
#define SYSCALL_PROC_FORK       57

#define SYSCALL_WAITID          247
#define     P_PID               0
#define     P_PIDFD             1
#define     P_PGID              2
#define     P_ALL               3
#define     WNOHANG             (1 << 0)
#define     WUNTRACED           (1 << 1)
#define     WCONTINUED          (1 << 2)

// The C-level syscall handler, to be called from the assembly wrapper.
int64_t syscall_handler(registers_t* args);

// The assembly-level entry point that the CPU jumps to.
void syscall_entry();

#endif