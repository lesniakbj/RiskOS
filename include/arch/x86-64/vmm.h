#ifndef ARCH_X86_64_VMM_H
#define ARCH_X86_64_VMM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <kernel/limine.h>

#define PAGE_SIZE 4096

#define PAGE_PRESENT        (1 << 0)
#define PAGE_READ_WRITE     (1 << 1)
#define PAGE_USER           (1 << 2)
#define PAGE_WRITE_THROUGH  (1 << 3)
#define PAGE_CACHE_DISABLE  (1 << 4)
#define PAGE_ACCESSED       (1 << 5)
#define PAGE_DIRTY          (1 << 6)
#define PAGE_HUGE           (1 << 7) // For PD or PDPT entries
#define PAGE_NO_EXECUTE     (1UL << 63)

#define PAGE_ADDR_MASK      0x000FFFFFFFFFF000

#define PML4_INDEX(addr) ((((uint64_t)(addr)) >> 39) & 0x1FF)
#define PDPT_INDEX(addr) ((((uint64_t)(addr)) >> 30) & 0x1FF)
#define PD_INDEX(addr)   ((((uint64_t)(addr)) >> 21) & 0x1FF)
#define PT_INDEX(addr)   ((((uint64_t)(addr)) >> 12) & 0x1FF)

typedef uint64_t pt_entry_t;

typedef struct {
    pt_entry_t entries[512];
} __attribute__((aligned(PAGE_SIZE))) pt_t; // Page Table

typedef struct {
    pt_entry_t entries[512];
} __attribute__((aligned(PAGE_SIZE))) pd_t; // Page Directory

typedef struct {
    pt_entry_t entries[512];
} __attribute__((aligned(PAGE_SIZE))) pdpt_t; // Page Directory Pointer Table

typedef struct {
    pt_entry_t entries[512];
} __attribute__((aligned(PAGE_SIZE))) pml4_t; // Page Map Level 4


void vmm_init(struct limine_memmap_response *mmap_resp, struct limine_hhdm_response *hhdm_resp);

bool vmm_map_page(uint64_t virt_addr, uint64_t phys_addr, uint64_t flags);
bool vmm_map_page_to(uint64_t pml4_phys, uint64_t virt_addr, uint64_t phys_addr, uint64_t flags);

void vmm_unmap_page(uint64_t virt_addr);
void vmm_unmap_page_from(uint64_t pml4_phys, uint64_t virt_addr);

void* physical_to_virtual(uint64_t physical_addr);
uint64_t vmm_get_physical_addr(uint64_t virt_addr);
uint64_t vmm_get_physical_addr_from(uint64_t pml4_phys, uint64_t virt_addr);

void vmm_load_pml4(uint64_t pml4_phys);
uint64_t vmm_get_kernel_pml4();
uint64_t vmm_get_current_pml4();

uint64_t vmm_create_address_space();
uint64_t vmm_clone_address_space(uint64_t pml4_phys_src);

uint64_t vmm_get_hhdm_offset();

#endif