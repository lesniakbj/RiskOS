#include <libc/unistd.h>

uint64_t counter = 0;
int main() {
    write(0, "Starting init...\n", sizeof("Starting init...\n"));
    uint64_t pid = getpid();

    int64_t fork_pid = fork();
    if(fork_pid == 0) {
        write(0, "I am the child!", sizeof("I am the child!"));
    } else {
        write(0, "I am the parent!", sizeof("I am the parent!"));
    }

    for(;;) {
        counter++;

        if(counter % 500 == 0) {
            yield();
        }

        if(counter > 1000) {
            exit(pid + 100);    // Exit with the PID so we can test we receive it correctly.
        }
    }
}