#ifndef LIBC_STRING_H
#define LIBC_STRING_H

#include <stddef.h>
#include <stdint.h>

size_t strlen(const char *str);
char* strchr(const char* str, int c);
char* strrchr(const char* str, int c);
char* strcpy(char* dest, const char* src);
char* strncpy(char* dest, const char* src, size_t n);
int strcmp(const char* s1, const char* s2);
char* strtok(char* str, const char* delim);
char* strcat(char* dest, const char* src);

void utf8_to_ascii_safe(char* dest, const char* src, size_t dest_size);

void *memcpy(void *restrict dest, const void *restrict src, size_t n);
void *memset(void *s, int c, size_t n);
void *memmove(void *dest, const void *src, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);

#endif
