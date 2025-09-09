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

#define SYS_WAITID              247
#define     P_PID               0
#define     P_PIDFD             1
#define     P_PGID              2
#define     P_ALL               3
#define     WNOHANG             (1 << 0)
#define     WUNTRACED           (1 << 1)
#define     WCONTINUED          (1 << 2)

// --- Syscall macro wrappers ---
#define _SYSCALL0_NO_RET(syscall_num) \
    ({ \
        asm volatile ( \
            "syscall" \
            : /* no output */ \
            : "a"(syscall_num) \
            : "rcx", "r11", "memory" \
        ); \
    })

#define _SYSCALL0(syscall_num) \
    ({ \
        int64_t ret; \
        asm volatile ( \
            "syscall" \
            : "=a"(ret) \
            : "a"(syscall_num) \
            : "rcx", "r11", "memory" \
        ); \
        ret; \
    })

#define _SYSCALL1_NO_RET(syscall_num, param1) \
    ({ \
        asm volatile ( \
            "syscall" \
            : /* no output */ \
            : "a"(syscall_num), "D"(param1) \
            : "rcx", "r11", "memory" \
        ); \
    })

#define _SYSCALL1(syscall_num, param1) \
    ({ \
        int64_t ret; \
        asm volatile ( \
            "syscall" \
            : /* no output */ \
            : "a"(syscall_num), "D"(param1) \
            : "rcx", "r11", "memory" \
        ); \
        ret; \
    })

#define _SYSCALL2(syscall_num, param1, param2) \
    ({ \
        int64_t ret; \
        asm volatile ( \
            "syscall" \
            : "=a"(ret) \
            : "a" (syscall_num), "D" (param1), "S" (param2) \
            : "rcx", "r11", "memory" \
        ); \
        ret; \
    })

#define _SYSCALL3(syscall_num, param1, param2, param3) \
    ({ \
        int64_t ret; \
        asm volatile ( \
            "syscall" \
            : "=a"(ret) \
            : "a" (syscall_num), "D" (param1), "S" (param2), "d" (param3) \
            : "rcx", "r11", "memory" \
        ); \
        ret; \
    })

#define _SYSCALL4(syscall_num, param1, param2, param3, param4) \
    ({ \
        int64_t ret; \
        register int64_t r10 asm("r10") = (int64_t)(param4); \
        asm volatile ( \
            "syscall" \
            : "=a"(ret) \
            : "a" (syscall_num), "D" (param1), "S" (param2), "d" (param3), "r"(r10) \
            : "rcx", "r11", "memory" \
        ); \
        ret; \
    })

// --- Process Syscalls ---
void yield();
int64_t fork();
int64_t pid();

// --- Process memory requests ---
int64_t brk(void* addr);
void* sbrk(int64_t increment);

// --- VFS File Syscalls ---
int64_t read(uint64_t fd, void* buf, size_t count);
int64_t write(uint64_t fd, const char* buf, size_t count);
int64_t open(const char* path, uint16_t flags);
int64_t close(uint64_t fd);
void exit(int64_t status);
int64_t lseek(uint64_t fd, int64_t offset, uint8_t wence);


#endif