#ifndef LIBC_STDIO_H
#define LIBC_STDIO_H

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h> // For va_list

#define EOF -1

int64_t puts(const char *s);
int putchar(int c);
int printf(const char *format, ...);
int dprintf(int fd, const char *format, ...);
int vdprintf(int fd, const char *format, va_list args);

#endif