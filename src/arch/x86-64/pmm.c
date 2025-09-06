#include <arch/x86-64/pmm.h>
#include <kernel/log.h>
#include <libc/string.h>
#include <libc/stdlib.h>

// Bitmap allocator, backed by static ints
static uint64_t *alloc_map = 0;
static size_t max_blocks = 0;
static size_t used_blocks = 0;

// Statically allocated data
static pmm_status_t pmm_status;

static char* mem_type_names[] = {
    [LIMINE_MEMMAP_USABLE] = "Usable",
    [LIMINE_MEMMAP_RESERVED] = "Reserved",
    [LIMINE_MEMMAP_ACPI_RECLAIMABLE] = "ACPI Reclaimable",
    [LIMINE_MEMMAP_ACPI_NVS] = "ACPI NVS",
    [LIMINE_MEMMAP_BAD_MEMORY] = "Bad Memory",
    [LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE] = "Boot Reclaimable",
    [LIMINE_MEMMAP_EXECUTABLE_AND_MODULES] = "Kern/Exec + Modules",
    [LIMINE_MEMMAP_FRAMEBUFFER] = "Framebuffer",
};

static void pmm_set_bit(uint64_t);
static void pmm_clear_bit(uint64_t);
static bool pmm_test_bit(uint64_t);
static int64_t pmm_find_first_free();
static void log_mmap_regions(struct limine_memmap_response *mmap_resp);

// Defined in linker.ld
extern uint64_t _kernel_start;
extern uint64_t _kernel_end;

void pmm_init(struct limine_memmap_response *mmap_resp, struct limine_executable_address_response *kernel_addr_resp, struct limine_hhdm_response *hhdm_resp) {
    // Sanity checks
    if (mmap_resp == NULL) {
        LOG_ERR("Memory map request not honored! Halting...");
        for (;;) { asm volatile ("hlt"); }
    }
    if (kernel_addr_resp == NULL) {
        LOG_ERR("Kernel address request not honored! Halting...");
        for (;;) { asm volatile ("hlt"); }
    }
    if (hhdm_resp == NULL) {
        LOG_ERR("Kernel HHDM request not honored! Halting...");
        for (;;) { asm volatile ("hlt"); }
    }

    // Copy some data out so we can reclaim it later
    pmm_status.hhdm_mapping = hhdm_resp->offset;

    // Log the initial memory map and kernel mappings
    log_mmap_regions(mmap_resp);
    LOG_INFO("Kernel Start Phys (Addr Response): 0x%llx", kernel_addr_resp->physical_base);
    LOG_INFO("Kernel Start Virt (Addr Response): 0x%llx", kernel_addr_resp->virtual_base);
    pmm_status.kernel_start = kernel_addr_resp->physical_base;
    pmm_status.kernel_start_virt = kernel_addr_resp->virtual_base;

    // Find the highest usable physical address
    uint64_t highest_usable_addr = 0;
    for(uint64_t i = 0; i < mmap_resp->entry_count; i++) {
        struct limine_memmap_entry *entry = mmap_resp->entries[i];
        if(entry->type == LIMINE_MEMMAP_USABLE) {
            uint64_t end = entry->base + entry->length;
            if(end > highest_usable_addr) {
                highest_usable_addr = end;
            }
        }
    }
    LOG_INFO("Found highest address at: 0x%llx (%s)", highest_usable_addr, format_size(highest_usable_addr));
    pmm_status.highest_addr = highest_usable_addr;

    // Calculate the number of blocks needed and bitmap size
    max_blocks = highest_usable_addr / PMM_BLOCK_SIZE;
    size_t bitmap_size_bytes = max_blocks / BITS_PER_BYTE;
    if(max_blocks % BITS_PER_BYTE) {
        bitmap_size_bytes++;
    }
    LOG_INFO("Max blocks: %llu", max_blocks);
    LOG_INFO("Bitmap size: %s", format_size(bitmap_size_bytes));
    pmm_status.max_blocks = max_blocks;
    pmm_status.used_blocks = 0;
    pmm_status.bitmap_size = bitmap_size_bytes;

    // Find a place for our bitmap to live
    uint64_t placement_addr = 0;
    for(uint64_t i = 0; i < mmap_resp->entry_count; i++) {
        struct limine_memmap_entry *entry = mmap_resp->entries[i];
        if(entry->type == LIMINE_MEMMAP_USABLE) {
            if(entry->length >= bitmap_size_bytes){
                placement_addr = entry->base;
                break;
            }
        }
    }
    alloc_map = (uint64_t*)(placement_addr + hhdm_resp->offset);
    LOG_INFO("Bitmap allocator located at physical addr: 0x%llx", placement_addr);
    LOG_INFO("Bitmap allocator located at virtual addr: 0x%llx", (uint64_t)alloc_map);
    pmm_status.placement_address = placement_addr;

    // Calculate the total usable memory
    uint64_t total_memory = 0;
    for (uint64_t i = 0; i < mmap_resp->entry_count; i++) {
        struct limine_memmap_entry *entry = mmap_resp->entries[i];
        if (entry->type == LIMINE_MEMMAP_USABLE || entry->type == LIMINE_MEMMAP_ACPI_RECLAIMABLE || entry->type == LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE) {
            total_memory += entry->length;
        }
    }
    LOG_INFO("Total usable memory: %s", format_size(total_memory));
    pmm_status.total_memory = total_memory;

    // Mark everything as used to start
    memset(alloc_map, 0xFF, bitmap_size_bytes);

    // Mark all usable sections as free
    for(uint64_t i = 0; i < mmap_resp->entry_count; i++) {
        struct limine_memmap_entry *entry = mmap_resp->entries[i];
        if(entry->type == LIMINE_MEMMAP_USABLE) {
            for(uint64_t j = 0; j < entry->length / PMM_BLOCK_SIZE; j++) {
                pmm_clear_bit((entry->base / PMM_BLOCK_SIZE) + j);
            }
        }
    }

    // Re-mark the kernel as used.
    uint64_t kernel_size = (uintptr_t)&_kernel_end - (uintptr_t)&_kernel_start;
    uint64_t kernel_start_block = pmm_status.kernel_start / PMM_BLOCK_SIZE;
    uint64_t kernel_end_block = (pmm_status.kernel_start + kernel_size + PMM_BLOCK_SIZE - 1) / PMM_BLOCK_SIZE;
    for (uint64_t i = kernel_start_block; i < kernel_end_block; i++) {
        pmm_set_bit(i);
    }

    // Re-mark the bitmap as used.
    uint64_t bitmap_start_block = pmm_status.placement_address / PMM_BLOCK_SIZE;
    uint64_t bitmap_end_block = (pmm_status.placement_address + pmm_status.bitmap_size + PMM_BLOCK_SIZE - 1) / PMM_BLOCK_SIZE;
    for (uint64_t i = bitmap_start_block; i < bitmap_end_block; i++) {
        pmm_set_bit(i);
    }

    // Count used blocks
    used_blocks = 0;
    for (uint64_t i = 0; i < max_blocks; i++) {
        if (pmm_test_bit(i)) {
            used_blocks++;
        }
    }
    pmm_status.used_blocks = used_blocks;

    // Final log
    uint64_t free_mem = (max_blocks - used_blocks) * PMM_BLOCK_SIZE;
    LOG_INFO("PMM initialized... Free Mem: %s", format_size(free_mem));
}

void* pmm_alloc_block() {
    // Find the first free block.
    uint64_t frame = pmm_find_first_free();
    if (frame == PMM_NO_FREE_BLOCKS) {
        return 0; // Out of memory
    }

    // Mark the block as used.
    pmm_set_bit(frame);
    used_blocks++;

    // Calculate and return the physical address.
    return (void*)(frame * PMM_BLOCK_SIZE);
}

void pmm_free_block(void *p) {
    // Calculate the block index from the address.
    uint64_t frame = (uint64_t)p / PMM_BLOCK_SIZE;

    // Mark the block as free.
    pmm_clear_bit(frame);
    used_blocks--;
}

// Helper to find the first free block of memory and returns its index.
static int64_t pmm_find_first_free() {
    for (uint64_t i = 0; i < max_blocks / PMM_BITS_PER_ENTRY; i++) {
        // If the dword is all 1's, there are no free blocks in this chunk.
        if (alloc_map[i] != PMM_ENTRY_FULL) {
            // Use the bit index to find exactly which of the 32 memory blocks represented by that integer is the first one that's free
            for (uint64_t j = 0; j < PMM_BITS_PER_ENTRY; j++) {
                uint64_t bit = 1 << j;
                if (!(alloc_map[i] & bit)) {
                    return i * PMM_BITS_PER_ENTRY + j;
                }
            }
        }
    }
    return PMM_NO_FREE_BLOCKS; // No free blocks found
}


// Helper function to set a bit in the bitmap.
static void pmm_set_bit(uint64_t bit) {
    alloc_map[bit / PMM_BITS_PER_ENTRY] |= (1ULL << (bit % PMM_BITS_PER_ENTRY));
}

// Helper function to clear a bit in the bitmap.
static void pmm_clear_bit(uint64_t bit) {
    alloc_map[bit / PMM_BITS_PER_ENTRY] &= ~(1ULL << (bit % PMM_BITS_PER_ENTRY));
}

// Helper function to test if a bit is set.
static bool pmm_test_bit(uint64_t bit) {
    return alloc_map[bit / PMM_BITS_PER_ENTRY] & (1ULL << (bit % PMM_BITS_PER_ENTRY));
}

static void log_mmap_regions(struct limine_memmap_response *mmap_resp) {
    LOG_INFO("Memory Map:");
    for (uint64_t i = 0; i < mmap_resp->entry_count; i++) {
        struct limine_memmap_entry *entry = mmap_resp->entries[i];

        char base_size_str[40];
        strcpy(base_size_str, format_size(entry->base));

        char length_size_str[40];
        strcpy(length_size_str, format_size(entry->length));

        char type_str_buf[22];
        char* type_str;
        if (entry->type < (sizeof(mem_type_names)/sizeof(char*)) && mem_type_names[entry->type] != NULL) {
            type_str = mem_type_names[entry->type];
        } else {
            utoa(entry->type, type_str_buf, 10);
            type_str = type_str_buf;
        }

        LOG_INFO("  base: 0x%llx (%s), length: 0x%llx (%s), type: %s",
            entry->base,
            base_size_str,
            entry->length,
            length_size_str,
            type_str
        );
    }
}