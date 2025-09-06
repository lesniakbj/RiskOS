#include <libc/stdlib.h>
#include <libc/string.h>

// Helper to reverse a string in place
static void reverse(char* str) {
    int i = 0;
    int j = strlen(str) - 1;
    while (i < j) {
        char c = str[i];
        str[i] = str[j];
        str[j] = c;
        i++;
        j--;
    }
}

// Converts an unsigned 64-bit integer to a null-terminated string.
void utoa(uint64_t value, char* buf, int base) {
    if (base < 2 || base > 36) {
        *buf = '\0';
        return;
    }

    int i = 0;
    if (value == 0) {
        buf[i++] = '0';
        buf[i] = '\0';
        return;
    }

    while (value > 0) {
        uint64_t remainder = value % base;
        buf[i++] = (remainder < 10) ? (remainder + '0') : (remainder - 10 + 'a');
        value /= base;
    }

    buf[i] = '\0';
    reverse(buf);
}

// Converts a signed 64-bit integer to a null-terminated string.
void itoa(int64_t value, char* buf, int base) {
    if (base != 10) {
        // For non-decimal bases, treat as unsigned
        utoa((uint64_t)value, buf, base);
        return;
    }

    int i = 0;
    if (value < 0) {
        buf[i++] = '-';
        value = -value;
    }

    utoa((uint64_t)value, buf + i, base);
}
