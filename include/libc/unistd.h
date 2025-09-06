#ifndef LIBC_UNISTD_H
#define LIBC_UNISTD_H

#include <stdint.h>

// --- Process IPC/Control Syscalls ---
#define SYSCALL_PROC_YIELD      50
#define SYSCALL_PROC_EXIT       51
#define SYSCALL_PROC_FORK       52
#define SYSCALL_PROC_WAIT       53
#define SYSCALL_PROC_WAIT_PID   54
#define SYSCALL_PROC_PID        55

// TODO: Move to Syscall lib
// --- VFS (IO, File, Device) Syscalls ---
#define SYSCALL_VFS_WRITE       60


#define ERR_NOPROC              -1

// --- Process Syscalls ---
void yield();
void exit(int status);
int64_t fork();
void wait();
void wait_pid();
uint64_t pid();

// --- VFS File Syscalls ---
int64_t write(uint8_t* bytes);


#endif