#include <libc/unistd.h>
#include <libc/stdio.h>                                                                                                                                                                                                                          │
#include <libc/string.h>
#include <libc/stdlib.h>

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

    // Lets try to read some bytes from a file...
    uint64_t linker_fd = open("/init/user.lds", 1);
    char buf[533];
    int64_t bytes_read = read(linker_fd, buf, 532);
    buf[bytes_read] = '\0';
    mux_puts(fd, "I read the following number of bytes:");

    // Convert bytes_read to a string for printing.
    char str[21];
    itoa(bytes_read, str, 10);
    mux_puts(fd, str);

    if(bytes_read == 532) {
        mux_puts(fd, "I read 532 bytes! yay!");
        mux_puts(fd, "Those UTF-8 bytes yield:");
        mux_puts(fd, buf);

        char ascii_buf[533];
        utf8_to_ascii_safe(ascii_buf, buf, 533);
        mux_puts(fd, "Those ASCII bytes yield:");
        mux_puts(fd, ascii_buf);
    }

    for(;;) {
        counter++;

        if(counter % 500 == 0) {
            yield();
            mux_puts(fd, "I just did a yield!");

            // Testing
            mux_puts(fd, "  Lets test brk() while we're here...");
            int64_t status = brk((void*)0x802000);
            if(status == 0) {
                mux_puts(fd, "  We set our brk to 0x802000");
                mux_puts(fd, "  But wait! I wanna see what our break is...");
                int64_t current_brk_val = (int64_t)brk(0);
                if(current_brk_val > 0) {
                    char brk_str[21];
                    itoa(current_brk_val, brk_str, 16);
                    mux_puts(fd, "  Current break is: ");
                    mux_puts(fd, brk_str);
                    mux_puts(fd, "  Requesting addition of 0x100000");
                    void* sbrk_ret = sbrk(0x100000);
                    if ((int64_t)sbrk_ret != -1) {
                        int64_t new_brk_val = (int64_t)brk(0);
                        if(new_brk_val > 0) {
                            char new_brk_str[21];
                            itoa(new_brk_val, new_brk_str, 16);
                            mux_puts(fd, "  New break is: ");
                            mux_puts(fd, new_brk_str);
                        }
                    } else {
                        mux_puts(fd, "  sbrk failed!");
                    }
                }
            } else {
                mux_puts(fd, "  brk(0x802000) failed!");
            }
        }

        if(counter > 1000) {
            mux_puts(fd, "Time for me to exit!");
            int64_t status = close(fd);
            if(!status) {
                mux_puts(fd, "I just closed a file descriptor for serial! I shouldn't see this on serial!");
            }
            exit(pid + 100);    // Exit with the PID so we can test we receive it correctly.
        }
    }
}