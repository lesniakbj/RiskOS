#ifndef KERNEL_STD_LIB_H
#define KERNEL_STD_LIB_H

#include <stdint.h>

// Converts a signed 64-bit integer to a string.
void itoa(int64_t value, char* buf, int base);

// Converts an unsigned 64-bit integer to a string.
void utoa(uint64_t value, char* buf, int base);

#endif
