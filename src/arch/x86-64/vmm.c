#include <arch/x86-64/vmm.h>
#include <arch/x86-64/pmm.h>
#include <kernel/log.h>
#include <libc/string.h>

// Pointer to the kernel's top-level page table (PML4)
static pml4_t *kernel_pml4_virt = NULL;
static uint64_t kernel_pml4_phys = 0;
static uint64_t current_pml4_phys = 0;

// The higher-half direct map offset
static uint64_t hhdm_offset = 0;

// Helper function to flush a single page from the TLB
static inline void flush_tlb_single(uint64_t addr) {
    asm volatile ("invlpg (%0)" :: "r"(addr) : "memory");
}

// Helper function to get the virtual address of a physical address using the HHDM
static void* physical_to_virtual(uint64_t physical_addr) {
    return (void*)(physical_addr + hhdm_offset);
}

static pt_entry_t* vmm_walk_to_pte_from(pml4_t* pml4_virt, uint64_t virt_addr, bool create_if_missing) {
    if (pml4_virt == NULL) return NULL;

    uint64_t pml4_index = PML4_INDEX(virt_addr);
    pt_entry_t* pml4e = &pml4_virt->entries[pml4_index];

    if (!(*pml4e & PAGE_PRESENT)) {
        if (!create_if_missing) return NULL;
        void* new_pdpt_phys = pmm_alloc_block();
        if (!new_pdpt_phys) return NULL;
        memset(physical_to_virtual((uint64_t)new_pdpt_phys), 0, PAGE_SIZE);
        *pml4e = (uint64_t)new_pdpt_phys | PAGE_PRESENT | PAGE_READ_WRITE | PAGE_USER;
    }

    pdpt_t* pdpt = physical_to_virtual(*pml4e & PAGE_ADDR_MASK);
    uint64_t pdpt_index = PDPT_INDEX(virt_addr);
    pt_entry_t* pdpte = &pdpt->entries[pdpt_index];

    if (!(*pdpte & PAGE_PRESENT)) {
        if (!create_if_missing) return NULL;
        void* new_pd_phys = pmm_alloc_block();
        if (!new_pd_phys) return NULL;
        memset(physical_to_virtual((uint64_t)new_pd_phys), 0, PAGE_SIZE);
        *pdpte = (uint64_t)new_pd_phys | PAGE_PRESENT | PAGE_READ_WRITE | PAGE_USER;
    }

    pd_t* pd = physical_to_virtual(*pdpte & PAGE_ADDR_MASK);
    uint64_t pd_index = PD_INDEX(virt_addr);
    pt_entry_t* pde = &pd->entries[pd_index];

    if (!(*pde & PAGE_PRESENT)) {
        if (!create_if_missing) return NULL;
        void* new_pt_phys = pmm_alloc_block();
        if (!new_pt_phys) return NULL;
        memset(physical_to_virtual((uint64_t)new_pt_phys), 0, PAGE_SIZE);
        *pde = (uint64_t)new_pt_phys | PAGE_PRESENT | PAGE_READ_WRITE | PAGE_USER;
    }

    pt_t* pt = physical_to_virtual(*pde & PAGE_ADDR_MASK);
    uint64_t pt_index = PT_INDEX(virt_addr);
    return &pt->entries[pt_index];
}


// This is the old function, now wrapping the new one for the kernel's address space.
static pt_entry_t* vmm_walk_to_pte(uint64_t virt_addr, bool create_if_missing) {
    return vmm_walk_to_pte_from(kernel_pml4_virt, virt_addr, create_if_missing);
}

void vmm_init(struct limine_memmap_response *mmap_resp, struct limine_hhdm_response *hhdm_resp) {
    if (hhdm_resp == NULL) {
        LOG_ERR("VMM Error: HHDM response is required.");
        for (;;) { asm("hlt"); }
    }
    hhdm_offset = hhdm_resp->offset;

    // Read the physical address of the PML4 from the CR3 register and save it.
    asm volatile ("mov %%cr3, %0" : "=r" (kernel_pml4_phys));

    // Also save the virtual address for the VMM's internal use.
    kernel_pml4_virt = (pml4_t*)physical_to_virtual(kernel_pml4_phys);

    LOG_INFO("VMM initialized. Kernel PML4 is at physical address 0x%llx", kernel_pml4_phys);
}

uint64_t vmm_get_kernel_pml4() {
    return kernel_pml4_phys;
}

uint64_t vmm_create_address_space() {
    // Allocate space for a new PML4 Table
    void* new_pml4_phys = pmm_alloc_block();
    if(new_pml4_phys == NULL) {
        LOG_ERR("VMM: Failed to allocate page for new address space");
        return 0;
    }

    // Get the virtual address and clear the table
    pml4_t* new_pml4_virt = (pml4_t*)physical_to_virtual((uint64_t)new_pml4_phys);
    memset(new_pml4_virt, 0, PAGE_SIZE);

    // Copy kernel mappings into the PML4
    for(uint16_t i = 256; i < 512; i++) {
        new_pml4_virt->entries[i] = kernel_pml4_virt->entries[i];
    }

    return (uint64_t)new_pml4_phys;
}

void vmm_load_pml4(uint64_t pml4_phys) {
    asm volatile("mov %0, %%cr3" :: "r"(pml4_phys) : "memory");
}

bool vmm_map_page(uint64_t virt_addr, uint64_t phys_addr, uint64_t flags) {
    pt_entry_t* pte = vmm_walk_to_pte(virt_addr, true);
    if (pte == NULL) {
        return false; // Failed to allocate a table
    }

    *pte = phys_addr | flags;
    return true;
}

bool vmm_map_page_to(uint64_t pml4_phys, uint64_t virt_addr, uint64_t phys_addr, uint64_t flags) {
    pml4_t* pml4_virt = (pml4_t*)physical_to_virtual(pml4_phys);
    pt_entry_t* pte = vmm_walk_to_pte_from(pml4_virt, virt_addr, true);
    if (pte == NULL) {
        return false; // Failed to allocate a table
    }

    *pte = phys_addr | flags;
    // No need to flush TLB here, as this address space is not yet active.
    return true;
}

void vmm_unmap_page(uint64_t virt_addr) {
    pt_entry_t* pte = vmm_walk_to_pte(virt_addr, false);
    if (pte != NULL) {
        *pte = 0;
        flush_tlb_single(virt_addr);
    }
}

uint64_t vmm_get_physical_addr(uint64_t virt_addr) {
    pt_entry_t* pte = vmm_walk_to_pte(virt_addr, false);
    if (pte == NULL || !(*pte & PAGE_PRESENT)) {
        return 0; // Not mapped
    }

    return (*pte & PAGE_ADDR_MASK) + (virt_addr & 0xFFF);
}

uint64_t vmm_get_current_pml4() {
    uint64_t pml4_phys;
    asm volatile ("mov %%cr3, %0" : "=r" (pml4_phys));
    return pml4_phys;
}
