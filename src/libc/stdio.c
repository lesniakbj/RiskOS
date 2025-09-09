#include <libc/string.h>
#include <libc/unistd.h>
#include <libc/stdio.h>
#include <stdint.h>

int64_t puts(const char *s) {
    size_t len = strlen(s);
    if (write(1, s, len) != (int64_t)len) {
        return EOF;
    }
    if (write(1, "\n", 1) != 1) {
        return EOF;
    }
    return 0;
}
