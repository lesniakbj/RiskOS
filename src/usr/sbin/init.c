#include <libc/unistd.h>
#include <libc/stdio.h>                                                                                                                                                                                                                          │
#include <libc/string.h>
#include <libc/stdlib.h>

static uint64_t counter = 0;
static int64_t serio_fd;

static void mux_puts(const char* str) {
    puts(str);
    write(serio_fd, str, strlen(str));
    write(serio_fd, "\n", 1);
}

static void test_write() {
    serio_fd = open("/dev/serial01", 1); // TODO: Define read, write, exec flags
    mux_puts("Starting init...");
}

static int64_t test_fork() {
    int64_t fork_pid = fork();
    if(fork_pid == 0) {
        mux_puts("I am the child!");
    } else {
        mux_puts("I am the parent!");
    }
    return fork_pid;
}

static void test_read() {
    // Lets try to read some bytes from a file...
    uint64_t linker_fd = open("/init/user.lds", 1);
    char buf[533];
    int64_t bytes_read = read(linker_fd, buf, 532);
    buf[bytes_read] = '\0';
    mux_puts("I read the following number of bytes:");

    // Convert bytes_read to a string for printing.
    char str[21];
    itoa(bytes_read, str, 10);
    mux_puts(str);

    if(bytes_read == 532) {
        mux_puts("I read 532 bytes! yay!");
        mux_puts("Those UTF-8 bytes yield:");
        mux_puts(buf);

        char ascii_buf[533];
        utf8_to_ascii_safe(ascii_buf, buf, 533);
        mux_puts("Those ASCII bytes yield:");
        mux_puts(ascii_buf);
    }
}

static void test_brk() {
    // Testing
    mux_puts("  Lets test brk() while we're here...");
    int64_t status = brk((void*)0x802000);
    if(status == 0) {
        mux_puts("  We set our brk to 0x802000");
        mux_puts("  But wait! I wanna see what our break is...");
        int64_t current_brk_val = (int64_t)brk(0);
        if(current_brk_val > 0) {
            char brk_str[21];
            itoa(current_brk_val, brk_str, 16);
            mux_puts("  Current break is: ");
            mux_puts(brk_str);
            mux_puts("  Requesting addition of 0x100000");
            void* sbrk_ret = sbrk(0x100000);
            if ((int64_t)sbrk_ret != -1) {
                int64_t new_brk_val = (int64_t)brk(0);
                if(new_brk_val > 0) {
                    char new_brk_str[21];
                    itoa(new_brk_val, new_brk_str, 16);
                    mux_puts("  New break is: ");
                    mux_puts(new_brk_str);
                }
            } else {
                mux_puts("  sbrk failed!");
            }
        }
    } else {
        mux_puts("  brk(0x802000) failed!");
    }
}

int main() {
    test_write();
    int64_t fork_pid = test_fork();
    // test_read();

    uint64_t pid = getpid();
    if(fork_pid == 0) {
        mux_puts("I am the child so I am going to do more work...");
        for(;;) {
            counter++;

            if(counter % 500 == 0) {
                yield();
                mux_puts("I just did a yield!");
                // test_brk();
            }

            if(counter > 1000) {
                mux_puts("Time for me to exit!");
                int64_t status = close(serio_fd);
                if(!status) {
                    mux_puts("I just closed a file descriptor for serial! I shouldn't see this on serial!");
                }
                char buf[21];
                itoa(pid + 100, buf, 10);
                mux_puts(buf);

                exit(pid + 100);    // Exit with the PID so we can test we receive it correctly.
            }
        }
    } else {
        mux_puts("I am the parent and I am tired... exiting...");
        exit(pid + 100);
    }
}