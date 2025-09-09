#include <libc/stdio.h>
#include <libc/unistd.h>

uint64_t serio_fd;

void mux_printf(const char* format, ...) {
    va_list args;

    // Print to standard output (the console)
    va_start(args, format);
    vdprintf(STDOUT_FILENO, format, args);
    va_end(args);

    // Print to the serial port
    va_start(args, format);
    vdprintf(serio_fd, format, args);
    va_end(args);
}

int main(int argc, char** argv, char** envp) {
    serio_fd = open("/dev/serial01", 1);
    mux_printf("We made it to cat!\n");
    for(int i = 0; i < argc; i++) {
        mux_printf("%s\n", argv[i]);
    }
    for (int i = 0; envp[i] != NULL; i++) {
        mux_printf("%s\n", envp[i]);
    }
    exit(0);
}