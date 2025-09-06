#include <kernel/log.h>
#include <arch/x86-64/idt.h>

// ISR stubs defined in isr_handlers.s
extern void isr0(), isr1(), isr2(), isr3(), isr4(), isr5(), isr6(), isr7();
extern void isr8(), isr9(), isr10(), isr11(), isr12(), isr13(), isr14(), isr15();
extern void isr16(), isr17(), isr18(), isr19(), isr20(), isr21(), isr22(), isr23();
extern void isr24(), isr25(), isr26(), isr27(), isr28(), isr29(), isr30(), isr31();
extern void isr32(), isr33(), isr34(), isr35(), isr36(), isr37(), isr38(), isr39();
extern void isr40(), isr41(), isr42(), isr43(), isr44(), isr45(), isr46(), isr47();
extern void isr128(); // Syscall

static idt_gate_descriptor_t idt_entries[IDT_ENTRIES];
static idt_ptr_entry_t idt_ptr;

static void idt_set_descriptor(uint8_t vector, uint64_t isr, uint8_t flags) {
    idt_gate_descriptor_t* descriptor = &idt_entries[vector];

    descriptor->isr_addr_low    = isr & 0xFFFF;
    descriptor->kernel_cs       = 0x08;             // Kernel Code Segment selector from GDT
    descriptor->ist             = 0;                // We are not using the Interrupt Stack Table for now
    descriptor->attributes      = flags;
    descriptor->isr_addr_middle = (isr >> 16) & 0xFFFF;
    descriptor->isr_addr_high   = (isr >> 32) & 0xFFFFFFFF;
    descriptor->reserved        = 0;
}

void idt_init(void) {
    idt_ptr.limit = sizeof(idt_entries) - 1;
    idt_ptr.base = (uint64_t)&idt_entries;

    // Clear the entire IDT to a known state.
    memset(&idt_entries, 0, sizeof(idt_entries));

    // Create a table of our ISR stubs.
    void* isr_stub_table[] = {
        isr0, isr1, isr2, isr3, isr4, isr5, isr6, isr7,
        isr8, isr9, isr10, isr11, isr12, isr13, isr14, isr15,
        isr16, isr17, isr18, isr19, isr20, isr21, isr22, isr23,
        isr24, isr25, isr26, isr27, isr28, isr29, isr30, isr31,
        isr32, isr33, isr34, isr35, isr36, isr37, isr38, isr39,
        isr40, isr41, isr42, isr43, isr44, isr45, isr46, isr47
    };

    // Loop through the table to populate the IDT for exceptions and IRQs.
    // These are kernel-level interrupts, so DPL is 0.
    size_t num_stubs = sizeof(isr_stub_table) / sizeof(void*);
    const uint8_t kernel_int_attr = IDT_ATTR_PRESENT | IDT_ATTR_DPL0 | IDT_TYPE_INT;
    for (uint8_t i = 0; i < num_stubs; i++) {
        idt_set_descriptor(i, (uint64_t)isr_stub_table[i], kernel_int_attr);
    }

    // -- Syscall --
    // The syscall interrupt must be callable from user-mode, so DPL is 3.
    const uint8_t syscall_attr = IDT_ATTR_PRESENT | IDT_ATTR_DPL3 | IDT_TYPE_INT;
    idt_set_descriptor(128, (uint64_t)isr128, syscall_attr);

    idt_load(&idt_ptr);
    LOG_INFO("IDT Initialized...");
}

