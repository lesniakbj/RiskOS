#ifndef ARCH_X86_64_GDT_H
#define ARCH_X86_64_GDT_H

#define GDT_ENTRIES 7

#include <stdint.h>

typedef struct gdt_entry {
    uint16_t limit_low;        // The lower 16 bits of the limit.
    uint16_t base_low;         // The lower 16 bits of the base.
    uint8_t base_middle;       // The next 8 bits of the base
    uint8_t access;            // Access flags, determine ring level, type, etc.
    uint8_t granularity;       // Upper 4 bits of limit, plus granularity and size flags.
    uint8_t base_high;         // The last 8 bits of the base.
} __attribute__((packed)) gdt_entry_t;

typedef struct gdt_ptr {
    uint16_t limit;
    uint64_t address;
} __attribute__((packed)) gdt_ptr_t;

// Defines the structure of a Task State Segment
typedef struct tss_entry {
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved1;
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iomap_base;
} __attribute__((packed)) tss_entry_t;

// Struct for the 16-byte TSS GDT entry
typedef struct gdt_tss_entry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t  base_middle;
    uint8_t  access;
    uint8_t  limit_high_and_flags;
    uint8_t  base_high;
    uint32_t base_upper;
    uint32_t reserved;
} __attribute__((packed)) gdt_tss_entry_t;

void gdt_init();
extern void gdt_load(gdt_ptr_t* gdt_ptr);

void tss_init();
void tss_set_stack(uint64_t kernel_rsp);
uint64_t tss_get_stack_ptr();

void dump_gdt_fixed();
void dump_tss_info_fixed();

extern void tss_flush();

#endif