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

// Core helper to print a signed number to a specific file descriptor
static int fd_print_signed_num(int fd, int64_t n, int base) {
    char buf[21];
    itoa(n, buf, base);
    return fd_print_string(fd, buf);
}

// Core helper to print an unsigned number to a specific file descriptor
static int fd_print_unsigned_num(int fd, uint64_t n, int base) {
    char buf[21]; // Max for uint64_t in base 10 is 20 chars + null
    utoa(n, buf, base);
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

        // Handle length modifiers
        int long_flag = 0; // 0: none, 1: l, 2: ll
        if (*p == 'l') {
            p++;
            if (*p == 'l') {
                long_flag = 2; // 'll'
                p++;
            } else {
                long_flag = 1; // 'l'
            }
        }

        switch (*p) {
            case 'd': {
                int64_t val;
                if (long_flag == 2) { // 'lld'
                    val = va_arg(args, long long);
                } else if (long_flag == 1) { // 'ld'
                    val = va_arg(args, long);
                } else { // 'd'
                    val = va_arg(args, int);
                }
                count += fd_print_signed_num(fd, val, 10);
                break;
            }
            case 's': {
                const char* str = va_arg(args, const char*);
                count += fd_print_string(fd, str);
                break;
            }
            case 'x': {
                uint64_t val;
                if (long_flag == 2) { // 'llx'
                    val = va_arg(args, unsigned long long);
                } else if (long_flag == 1) { // 'lx'
                    val = va_arg(args, unsigned long);
                } else { // 'x'
                    val = va_arg(args, unsigned int);
                }
                count += fd_print_unsigned_num(fd, val, 16);
                break;
            }
            case 'u': {
                uint64_t val;
                if (long_flag == 2) { // 'llu'
                    val = va_arg(args, unsigned long long);
                } else if (long_flag == 1) { // 'lu'
                    val = va_arg(args, unsigned long);
                } else { // 'u'
                    val = va_arg(args, unsigned int);
                }
                count += fd_print_unsigned_num(fd, val, 10);
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
            case 'p': {
                uint64_t val = va_arg(args, uint64_t); // Pointers are always uint64_t
                fd_print_string(fd, "0x");
                count += 2;
                // Print pointer value as hex
                char buf[17]; // 16 hex chars + null terminator
                utoa(val, buf, 16);
                // Pad with leading zeros to make it 16 characters
                int len = strlen(buf);
                for (int i = 0; i < 16 - len; i++) {
                    write(fd, "0", 1);
                    count++;
                }
                count += fd_print_string(fd, buf);
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
