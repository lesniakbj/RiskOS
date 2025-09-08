#include <libc/unistd.h>
#include <libc/stdio.h>                                                                                                                                                                                                                          │
#include <libc/string.h>

static void mux_puts(int64_t fd, const char* str) {
    puts(str);
    write(fd, str, strlen(str));
    write(fd, "\n", 1);
}

uint64_t counter = 0;
int main() {
    int64_t fd = open("/dev/serial01", 1); // TODO: Define read, write, exec flags
    mux_puts(fd, "Starting init...");

    uint64_t pid = getpid();
    int64_t fork_pid = fork();
    if(fork_pid == 0) {
        mux_puts(fd, "I am the child!");
    } else {
        mux_puts(fd, "I am the parent!");
    }

    for(;;) {
        counter++;

        if(counter % 500 == 0) {
            yield();
            mux_puts(fd, "I just did a yield!");
        }

        if(counter > 1000) {
            mux_puts(fd, "Time for me to exit!");
            exit(pid + 100);    // Exit with the PID so we can test we receive it correctly.
        }
    }
}