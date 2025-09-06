#ifndef ARCH_X86_64_PMM_H
#define ARCH_X86_64_PMM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <kernel/limine.h>

// The size of a single physical memory block (page). 4KB is standard for x86.
#define PMM_BLOCK_SIZE 4096
#define BITS_PER_BYTE 8
#define BYTES_PER_KB 1024

// The number of bits in an entry of the memory map.
#define PMM_BITS_PER_ENTRY 64
#define PMM_ENTRY_FULL 0xFFFFFFFFFFFFFFFF

// Return value from pmm_find_first_free when no free blocks are found.
#define PMM_NO_FREE_BLOCKS -1

// Structure to hold PMM information
typedef struct {
    uint64_t hhdm_mapping;
    uint64_t kernel_start, kernel_start_virt;
    uint64_t highest_addr;
    uint64_t total_memory;
    uint64_t max_blocks;
    uint64_t used_blocks;
    size_t bitmap_size;
    uint64_t kernel_end, kernel_end_virt;
    uint64_t placement_address;
    int64_t error;
} pmm_status_t;

void pmm_init(struct limine_memmap_response *mmap_resp, struct limine_executable_address_response *kernel_addr_resp, struct limine_hhdm_response *hhdm_resp);
void* pmm_alloc_block();
void* pmm_alloc_blocks(size_t num_blocks);
void* pmm_alloc_aligned_block(size_t alignment);
void pmm_alloc_aligned_blocks(size_t num_blocks, size_t alignment);
void pmm_free_block(void* p);
void pmm_free_blocks(void* p, size_t num_blocks);
pmm_status_t* pmm_stats();


#endif