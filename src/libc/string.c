#include <libc/string.h>
#include <stdbool.h>

size_t strlen(const char *str) {
    size_t len = 0;
    while(str[len] != '\0') {
        len++;
    }
    return len;
}

char* strchr(const char* str, int64_t c) {
    // Cast c to unsigned char to match standard behavior for comparison
    unsigned char target = (unsigned char)c;

    // Iterate through the string
    while (*str != '\0') {
        if (*str == target) {
            return (char*)str; // Keep track of the last found position
        }
        str++;
    }

    // Check if the null terminator itself matches (c == '\0')
    // This is part of the standard behavior.
    if (target == '\0') {
         // The end of the string is the last occurrence of '\0'
        return (char*)str;
    }

    return NULL;
}

char* strrchr(const char* str, int64_t c) {
    char* last_occurrence = NULL;
    // Cast c to unsigned char to match standard behavior for comparison
    unsigned char target = (unsigned char)c;

    // Iterate through the string
    while (*str != '\0') {
        if (*str == target) {
            last_occurrence = (char*)str; // Keep track of the last found position
        }
        str++;
    }

    // Check if the null terminator itself matches (c == '\0')
    // This is part of the standard behavior.
    if (target == '\0') {
         // The end of the string is the last occurrence of '\0'
        return (char*)str;
    }

    // Return the pointer to the last occurrence found, or NULL if not found
    return last_occurrence;
}

char* strcpy(char* dest, const char* src) {
    char* original_dest = dest;
    while (*src != '\0') {
        *dest = *src;
        dest++;
        src++;
    }
    *dest = '\0';
    return original_dest;
}

void *memcpy(void *restrict dest, const void *restrict src, size_t n) {
    uint8_t *restrict pdest = (uint8_t *restrict)dest;
    const uint8_t *restrict psrc = (const uint8_t *restrict)src;

    for (size_t i = 0; i < n; i++) {
        pdest[i] = psrc[i];
    }

    return dest;
}

void *memset(void *s, int c, size_t n) {
    uint8_t *p = (uint8_t *)s;

    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)c;
    }

    return s;
}

void *memmove(void *dest, const void *src, size_t n) {
    uint8_t *pdest = (uint8_t *)dest;
    const uint8_t *psrc = (const uint8_t *)src;

    if (src > dest) {
        for (size_t i = 0; i < n; i++) {
            pdest[i] = psrc[i];
        }
    } else if (src < dest) {
        for (size_t i = n; i > 0; i--) {
            pdest[i-1] = psrc[i-1];
        }
    }

    return dest;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    const uint8_t *p1 = (const uint8_t *)s1;
    const uint8_t *p2 = (const uint8_t *)s2;

    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] < p2[i] ? -1 : 1;
        }
    }

    return 0;
}

int strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

char* strtok(char* str, const char* delim) {
    static char* static_str = NULL;
    if (str != NULL) {
        static_str = str;
    }

    if (static_str == NULL || *static_str == '\0') {
        return NULL;
    }

    char* token_start = static_str;
    while (*static_str != '\0') {
        const char* d = delim;
        while (*d != '\0') {
            if (*static_str == *d) {
                *static_str = '\0'; // Null-terminate the token
                static_str++;
                // Skip multiple delimiters
                while (*static_str != '\0') {
                    const char* d2 = delim;
                    bool is_delim = false;
                    while (*d2 != '\0') {
                        if (*static_str == *d2) {
                            is_delim = true;
                            break;
                        }
                        d2++;
                    }
                    if (!is_delim) break;
                    static_str++;
                }
                return token_start;
            }
            d++;
        }
        static_str++;
    }

    return token_start;
}

char* strncpy(char* dest, const char* src, size_t n) {
    size_t i;
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    for ( ; i < n; i++) {
        dest[i] = '\0';
    }
    return dest;
}

// Converts a UTF-8 string to an ASCII-safe string, replacing non-ASCII characters with '?'.
// dest_size is the maximum size of the destination buffer, including the null terminator.
void utf8_to_ascii_safe(char* dest, const char* src, size_t dest_size) {
    if (dest == NULL || src == NULL || dest_size == 0) {
        return;
    }

    size_t src_idx = 0;
    size_t dest_idx = 0;

    while (src[src_idx] != '\0' && dest_idx < dest_size - 1) {
        unsigned char c = (unsigned char)src[src_idx];

        if (c < 0x80) { // ASCII character (0xxxxxxx)
            dest[dest_idx++] = c;
            src_idx++;
        } else if ((c & 0xE0) == 0xC0) { // 2-byte UTF-8 sequence (110xxxxx 10xxxxxx)
            dest[dest_idx++] = '?'; // Replace with placeholder
            src_idx += 2; // Skip 2 bytes
        } else if ((c & 0xF0) == 0xE0) { // 3-byte UTF-8 sequence (1110xxxx 10xxxxxx 10xxxxxx)
            dest[dest_idx++] = '?'; // Replace with placeholder
            src_idx += 3; // Skip 3 bytes
        } else if ((c & 0xF8) == 0xF0) { // 4-byte UTF-8 sequence (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
            dest[dest_idx++] = '?'; // Replace with placeholder
            src_idx += 4; // Skip 4 bytes
        } else { // Invalid UTF-8 start byte or continuation byte
            dest[dest_idx++] = '?'; // Replace with placeholder
            src_idx++; // Advance by one byte
        }
    }
    dest[dest_idx] = '\0'; // Null-terminate the destination string
}
