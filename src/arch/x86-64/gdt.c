#include <kernel/log.h>
#include <arch/x86-64/gdt.h>

extern void tss_flush();
extern uint8_t stack_top[];

static struct {
    gdt_entry_t null;
    gdt_entry_t kernel_code;
    gdt_entry_t kernel_data;
    gdt_entry_t user_data;
    gdt_entry_t user_code;
    gdt_tss_entry_t tss;
} __attribute__((packed)) gdt_table;

static gdt_ptr_t gdt_ptr;
tss_entry_t tss_entry;

static void gdt_set_tss(gdt_tss_entry_t* entry, uint64_t base, uint32_t limit) {
    entry->limit_low = limit & 0xFFFF;
    entry->base_low = base & 0xFFFF;
    entry->base_middle = (base >> 16) & 0xFF;
    entry->access = 0x89;  // P=1, type=9 (TSS)
    entry->limit_high_and_flags = ((limit >> 16) & 0x0F);
    entry->base_high = (base >> 24) & 0xFF;
    entry->base_upper = (base >> 32) & 0xFFFFFFFF;
    entry->reserved = 0;
}

void gdt_init() {
    gdt_ptr.limit = sizeof(gdt_table) - 1;
    gdt_ptr.address = (uint64_t)&gdt_table;

    // Clear the GDT to start.
    memset(&gdt_table, 0, sizeof(gdt_table));

    // Kernel Code Segment (Ring 0)
    // Access: P=1, DPL=0, S=1, E=1, RW=1 -> 0x9A
    // Granularity: G=1, L=1 -> 0xA0 (D/B bit is 0 for 64-bit code)
    gdt_table.kernel_code = (gdt_entry_t){
        .limit_low = 0,
        .base_low = 0,
        .base_middle = 0,
        .access = 0x9A,
        .granularity = 0xA0,
        .base_high = 0
    };

    // Kernel Data Segment (Ring 0)
    // Access: P=1, DPL=0, S=1, E=0, RW=1 -> 0x92
    // Granularity: G=1, D/B=1 -> 0xC0 (L bit must be 0 for data segments)
    gdt_table.kernel_data = (gdt_entry_t){
        .limit_low = 0,
        .base_low = 0,
        .base_middle = 0,
        .access = 0x92,
        .granularity = 0xC0,
        .base_high = 0
    };

    // User Code Segment (Ring 3)
    // Access: P=1, DPL=3, S=1, E=1, RW=1 -> 0xFA
    // Granularity: G=1, L=1 -> 0xA0
    // User code
    gdt_table.user_code = (gdt_entry_t){
        .limit_low = 0,
        .base_low = 0,
        .base_middle = 0,
        .access = 0xFA,   // P=1, DPL=3, code, exec, readable
        .granularity = 0xA0, // L=1, G=1
        .base_high = 0
    };

    // User data
    gdt_table.user_data = (gdt_entry_t){
        .limit_low = 0,
        .base_low = 0,
        .base_middle = 0,
        .access = 0xF2,   // P=1, DPL=3, data, writable
        .granularity = 0x00, // G=0, L=0
        .base_high = 0
    };

    // TSS Segment
    gdt_set_tss(&gdt_table.tss, (uint64_t)&tss_entry, sizeof(tss_entry) - 1);

    // Load the GDT
    gdt_load(&gdt_ptr);
    LOG_INFO("GDT Initialized...");
}

void tss_init() {
    memset(&tss_entry, 0, sizeof(tss_entry));

    // Set the kernel stack segment selector
    tss_entry.rsp0 = (uint64_t)stack_top;              // Kernel Stack pointer set on privilege change
    tss_entry.iomap_base = sizeof(tss_entry);

    // Load the TSS selector (0x28) into the Task Register
    tss_flush();
    LOG_INFO("TSS Initialized...");
}

// This function will be called by the scheduler on a context switch
void tss_set_stack(uint64_t kernel_rsp) {
    tss_entry.rsp0 = kernel_rsp;
}

// This function returns the current kernel stack pointer from the TSS
uint64_t tss_get_stack_ptr() {
    return tss_entry.rsp0;
}

static void print_descriptor_fields(uint64_t desc, int idx) {
    // Descriptor layout in a single 64-bit qword when read as little-endian:
    // bits 0..15   : limit_low
    // bits 16..39  : base_low + base_middle (split across fields in struct)
    // bits 40..47  : access
    // bits 48..51  : limit_high (bits 16..19 of limit)
    // bits 52..55  : flags (L, D/B, G)
    // bits 56..63  : base_high (bits 24..31)
    uint16_t limit_low = desc & 0xffff;
    uint8_t base_lo_middle = (desc >> 16) & 0xff;
    uint8_t base_high = (desc >> 56) & 0xff;
    uint8_t access = (desc >> 40) & 0xff;
    uint8_t limit_high = (desc >> 48) & 0x0f;
    uint8_t flags = (desc >> 52) & 0x0f;

    uint32_t base = ((uint32_t)base_high << 24) | (((uint32_t)(desc >> 16) & 0xff) << 16) | 0; // partial but okay for checks

    LOG_INFO("GDT slot %d: raw=0x%016llx limit_low=0x%04x access=0x%02x flags=0x%01x limit_high=0x%01x base_high=0x%02x",
             idx, (unsigned long long)desc, (unsigned)limit_low, (unsigned)access, (unsigned)flags, (unsigned)limit_high, (unsigned)base_high);
}

void dump_gdt_fixed(void) {
    uintptr_t base = (uintptr_t)gdt_ptr.address;
    uint16_t limit = gdt_ptr.limit;
    LOG_INFO("DEBUG GDT: location=0x%lx, limit=%u", (unsigned long)base, (unsigned)limit);

    uint64_t *entries = (uint64_t*)base;
    int n = (limit + 1) / 8;
    LOG_INFO("DEBUG GDT: entries count = %d", n);

    int upto = n < 8 ? n : 8;
    for (int i = 0; i < upto; ++i) {
        uint64_t desc = entries[i];
        LOG_INFO("DEBUG GDT [%d] raw=0x%lx", i, (unsigned long)desc);

        uint16_t limit_low = desc & 0xFFFF;
        uint8_t access = (desc >> 40) & 0xFF;
        uint8_t flags  = (desc >> 52) & 0x0F;
        uint8_t limit_high = (desc >> 48) & 0x0F;
        uint8_t base_high  = (desc >> 56) & 0xFF;

        LOG_INFO("  limit_low=0x%x access=0x%x flags=0x%x limit_high=0x%x base_high=0x%x",
                 limit_low, access, flags, limit_high, base_high);
    }

    if (n > 6) {
        uint64_t desc_low = entries[5];
        uint64_t desc_high = entries[6];
        LOG_INFO("DEBUG GDT TSS pair idx=5 low=0x%lx high=0x%lx",
                 (unsigned long)desc_low, (unsigned long)desc_high);

        uint64_t base_low = (desc_low >> 16) & 0xFFFFFF;
        uint64_t base_mid = (desc_high & 0xFFFFFFFFULL);
        uint64_t tss_base = (base_mid << 32) | base_low;
        uint32_t tss_limit = (uint32_t)((desc_low & 0xFFFF) | (((desc_low >> 48) & 0x0F) << 16));

        LOG_INFO("DEBUG TSS: decoded base=0x%lx limit=0x%x",
                 (unsigned long)tss_base, tss_limit);
    }
}

void dump_tss_info_fixed(void) {
    uint16_t tr;
    asm volatile("str %0" : "=r"(tr));
    LOG_INFO("DEBUG TSS: TR selector=0x%x", tr);
    LOG_INFO("DEBUG TSS: rsp0=0x%lx", (unsigned long)tss_entry.rsp0);
}
