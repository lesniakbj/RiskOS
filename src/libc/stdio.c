#include <string.h>
#include <unistd.h>
#include <stdio.h>

int puts(const char *s) {
    size_t len = strlen(s);
    if (write(1, s, len) != len) {
        return EOF;
    }
    if (write(1, "\n", 1) != 1) {
        return EOF;
    }
    return 0;
}
