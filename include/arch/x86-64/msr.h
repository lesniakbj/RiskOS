#ifndef MSR_H
#define MSR_H

#include <stdint.h>

// MSR addresses
#define MSR_EFER                0xC0000080  // Extended Feature Enable Register
#define MSR_STAR                0xC0000081  // System Call Target Address Register
#define MSR_LSTAR               0xC0000082  // Long Mode System Call Target Address
#define MSR_FMASK               0xC0000084  // System Call Flag Mask
#define MSR_FS_BASE             0xC0000100  // FS Base Address
#define MSR_GS_BASE             0xC0000101  // GS Base Address
#define MSR_KERNEL_GS_BASE      0xC0000102  // Kernel GS Base Address

static inline void wrmsr(uint32_t msr, uint64_t value) {
    uint32_t low = value & 0xFFFFFFFF;
    uint32_t high = value >> 32;
    asm volatile ("wrmsr" : : "c"(msr), "a"(low), "d"(high));
}

static inline uint64_t rdmsr(uint32_t msr) {
    uint32_t low, high;
    asm volatile ("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((uint64_t)high << 32) | low;
}

#endif // MSR_H
