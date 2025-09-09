#include <libc/string.h>
#include <libc/unistd.h>
#include <libc/stdio.h>
#include <libc/stdlib.h>
#include <stdarg.h>

int64_t puts(const char *s) {
    size_t len = strlen(s);
    if (write(STDOUT_FILENO, s, len) != (int64_t)len) {
        return EOF;
    }
    if (write(STDOUT_FILENO, "\n", 1) != 1) {
        return EOF;
    }
    return 0;
}

int putchar(int c) {
    char ch = (char)c;
    return write(STDOUT_FILENO, &ch, 1);
}

// Core helper to print a string to a specific file descriptor
static int fd_print_string(int fd, const char* s) {
    if (!s) s = "(null)";
    return write(fd, s, strlen(s));
}

// Core helper to print a number to a specific file descriptor
static int fd_print_num(int fd, int64_t n, int base) {
    char buf[21];
    itoa(n, buf, base);
    return fd_print_string(fd, buf);
}

// The core implementation that all other printf functions will use.
int vdprintf(int fd, const char *format, va_list args) {
    int count = 0;
    char ch;

    for (const char* p = format; *p != '\0'; p++) {
        if (*p != '%') {
            ch = *p;
            write(fd, &ch, 1);
            count++;
            continue;
        }

        p++; // Move past the '%'

        switch (*p) {
            case 'd': {
                int64_t val = va_arg(args, int64_t);
                count += fd_print_num(fd, val, 10);
                break;
            }
            case 's': {
                const char* str = va_arg(args, const char*);
                count += fd_print_string(fd, str);
                break;
            }
            case 'x': {
                uint64_t val = va_arg(args, uint64_t);
                count += fd_print_num(fd, val, 16);
                break;
            }
            case 'u': {
                uint64_t val = va_arg(args, uint64_t);
                count += fd_print_num(fd, val, 10);
                break;
            }
            case 'c': { // Handle single character
                char val = (char)va_arg(args, int);
                write(fd, &val, 1);
                count++;
                break;
            }
            case '%': {
                write(fd, "%%", 1);
                count++;
                break;
            }
            default: {
                write(fd, "%", 1);
                write(fd, p, 1);
                count += 2;
                break;
            }
        }
    }
    return count;
}

int dprintf(int fd, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int count = vdprintf(fd, format, args);
    va_end(args);
    return count;
}

int printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int count = vdprintf(STDOUT_FILENO, format, args);
    va_end(args);
    return count;
}