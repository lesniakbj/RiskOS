#ifndef ARCH_X86_64_IDT_H
#define ARCH_X86_64_IDT_H

#define IDT_ENTRIES 256

// --- Gate Attributes ---
// Bit 47: Present (P)
#define IDT_ATTR_PRESENT 0x80
// Bits 46-45: Descriptor Privilege Level (DPL)
#define IDT_ATTR_DPL0    0x00
#define IDT_ATTR_DPL3    0x60
// Bits 44-40: Gate Type
#define IDT_TYPE_INT     0x0E  // 64-bit Interrupt Gate
#define IDT_TYPE_TRAP    0x0F  // 64-bit Trap Gate


#include <stdint.h>

typedef struct idt_gate_descriptor {
    uint16_t isr_addr_low;
    uint16_t kernel_cs;
    uint8_t ist;
    uint8_t attributes;
    uint16_t isr_addr_middle;
    uint32_t isr_addr_high;
    uint32_t reserved;
} __attribute__((packed)) idt_gate_descriptor_t;

typedef struct idt_ptr_entry {
    uint16_t limit;     // Size of IDT in bytes, minus 1
    uint64_t base;       // Linear address where IDT starts
} __attribute__((packed)) idt_ptr_entry_t;

void idt_init();
extern void idt_load(idt_ptr_entry_t* idt_ptr);

#endif
