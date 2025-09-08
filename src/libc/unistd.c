#include <libc/unistd.h>

void yield() {
    asm volatile (
        "syscall"
        :
        : "a"(SYS_PROC_YIELD)
        : "rcx", "r11", "memory"
    );
}

int64_t fork() {
    int64_t pid;
    asm volatile (
        "syscall"
        : "=a"(pid)
        : "a"(SYS_PROC_FORK)
        : "rcx", "r11", "memory"
    );
    return pid;
}

void exit(int status) {
    asm volatile (
        "syscall"
        :
        : "a"(SYS_PROC_EXIT), "D"(status)
        : "rcx", "r11", "memory"
    );
}

int64_t getpid() {
    int64_t pid;
    asm volatile (
        "syscall"
        : "=a"(pid)
        : "a"(SYS_PROC_PID)
        : "rcx", "r11", "memory"
    );
    return pid;
}

int64_t write(uint64_t fd, const char* buf, size_t count) {
    int64_t bytes_written;
    asm volatile (
        "syscall"
        : "=a" (bytes_written)
        : "a" (SYS_WRITE), "D" (fd), "S" (buf), "d" (count)
        : "rcx", "r11", "memory"
    );
    return bytes_written;
}

int64_t open(const char* path, uint16_t flags) {
    int fd;
    asm volatile (
        "syscall"
        : "=a" (fd)
        : "a" (SYS_OPEN), "D" (path), "S" (flags)
        : "rcx", "r11", "memory"
    );
    return fd;
}