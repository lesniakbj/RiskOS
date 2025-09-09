#ifndef LIB_OCTAL_H
#define LIB_OCTAL_H

#include <stdint.h>
#include <stddef.h>

int64_t octal_to_int(char *str, size_t size);
uint64_t octal_to_uint64(const char *str, size_t size);

#endif