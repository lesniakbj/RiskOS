#include <lib/octal.h>

int64_t octal_to_int(char *str, size_t size) {
    int64_t n = 0;
    char *c = str;

    // Only try to convert characters between 0-7 (valid oct values)
    while(size-- > 0 && *c >= '0' && *c <= '7') {
        n *= 8;
        n += *c - '0';
        c++;
    }
    return n;
}