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

void exit(int64_t status) {
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
    int64_t fd;
    asm volatile (
        "syscall"
        : "=a" (fd)
        : "a" (SYS_OPEN), "D" (path), "S" (flags)
        : "rcx", "r11", "memory"
    );
    return fd;
}

int64_t read(uint64_t fd, void* buf, size_t count) {
    int64_t bytes_read;
    asm volatile (
        "syscall"
        : "=a" (bytes_read)
        : "a" (SYS_READ), "D" (fd), "S" (buf), "d" (count)
        : "rcx", "r11", "memory"
    );
    return bytes_read;
}

int64_t close(uint64_t fd) {
    int64_t status;
    asm volatile (
        "syscall"
        : "=a" (status)
        : "a" (SYS_CLOSE), "D" (fd)
        : "rcx", "r11", "memory"
    );
    return status;
}

int64_t brk(void* addr) {
    int64_t ret;
    asm volatile (
        "syscall"
        : "=a" (ret)
        : "a" (SYS_BRK), "D" (addr)
        : "rcx", "r11", "memory"
    );
    return ret;
}

void* sbrk(int64_t increment) {
    static void* program_break = NULL;

    if (program_break == NULL) {
        // Initialize program_break by calling brk(0) to get the current break
        program_break = (void*)brk(0);
        if ((int64_t)program_break == -1) {
            return (void*)-1; // brk(0) failed
        }
    }

    void* old_program_break = program_break;
    void* new_program_break = (void*)((uint64_t)program_break + increment);

    if (brk(new_program_break) == -1) {
        return (void*)-1; // brk failed
    }

    program_break = new_program_break;
    return old_program_break;
}