#ifndef LIBC_UNISTD_H
#define LIBC_UNISTD_H

#include <stdint.h>
#include <stddef.h>

// Standard file descriptors
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

// Syscall numbers
#define SYS_READ                0
#define SYS_WRITE               1
#define SYS_OPEN                2
#define SYS_CLOSE               3

#define SYS_LSEEK               8
#define     SEEK_SET            0
#define     SEEK_CUR            1
#define     SEEK_END            2

#define SYS_BRK                 12

#define SYS_PROC_YIELD          24
#define SYS_PROC_EXIT           60
#define SYS_PROC_PID            39
#define SYS_PROC_FORK           57

// --- Process Syscalls ---
void yield();
int64_t fork();
int64_t pid();

// --- Process memory requests ---
int64_t brk(void* addr);

// --- VFS File Syscalls ---
int64_t read(uint64_t fd, void* buf, size_t count);
int64_t write(uint64_t fd, const char* buf, size_t count);
int64_t open(const char* path, uint16_t flags);
int64_t close(uint64_t fd);
void exit(int64_t status);
int64_t lseek(uint64_t fd, int64_t offset, uint8_t wence);


#endif