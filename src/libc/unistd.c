#include <libc/unistd.h>

void yield() {
    asm volatile (
        "syscall"
        :                               // No return
        : "a"(50)                       // Yield == Syscall 50
    );
}

void exit(int status) {
    asm volatile (
        "syscall"
        :
        : "a"(51)
    );
}