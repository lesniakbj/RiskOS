#include <lib/elf.h>
#define USER_STACK_TOP 0x7000000000
#define USER_STACK_SIZE 0x4000 // 16KB

#include <kernel/log.h>
#include <arch/x86-64/vmm.h>
#include <arch/x86-64/pmm.h>

#define USER_STACK_TOP 0x7000000000
#define USER_STACK_SIZE 0x4000 // 16KB

static bool validate_elf_header(elf_header_t* header);
static void map_segment_pages(uint64_t size, uint64_t virt_addr, uint64_t pml4);

static bool little_endian = true;

process_t* elf_load_process(void* file_ptr) {
    elf_header_t* header = (elf_header_t*)file_ptr;
    if(!validate_elf_header(header)) {
        LOG_ERR("ELF: Invalid file");
        return NULL;
    }
    LOG_DEBUG("ELF: Found ELF file. Entry point: 0x%llx, Program headers: %d at 0x%llx",
      header->entry_point_addr, header->num_program_entries, header->prog_header_offset);

    // Allocate a new process in the process table for this ELF
    process_t* proc = proc_create(PROC_TYPE_USER);
    if(proc == NULL) {
        LOG_DEBUG("Error attempting to create ELF proc");
        return NULL;
    }

    // Create a new virtual address space for the process
    proc->pml4_phys = vmm_create_address_space();
    if (proc->pml4_phys == 0) {
        LOG_ERR("ELF: Failed to create new address space for PID %llu", proc->pid);
        return NULL;
    }

    // Parse the program headers
    uint8_t* starting_addr = (uint8_t*)file_ptr + header->prog_header_offset;
    for(uint16_t n = 0; n < header->num_program_entries; n++) {
        elf_program_header_t* prog_header = &((elf_program_header_t*)starting_addr)[n];
        if(prog_header->entry_type != 0x01) {
            continue; // If its not a loadable segment, skip it
        }
        LOG_DEBUG("ELF: Loadable segment found: VAddr: 0x%llx, Bytes: %llu bytes, Offset: 0x%llx, Filesize: %llu bytes",
                  prog_header->virtual_addr, prog_header->mem_used, prog_header->file_offest, prog_header->file_size);

        map_segment_pages(prog_header->mem_used, prog_header->virtual_addr, proc->pml4_phys);

        // To copy the data, we must temporarily switch to the new process's address space
        uint64_t old_pml4 = vmm_get_current_pml4();
        vmm_load_pml4(proc->pml4_phys);
        memcpy((void*)prog_header->virtual_addr, (uint8_t*)file_ptr + prog_header->file_offest, prog_header->file_size);

        // If mem_used > file_size, it means we have a .bss section that needs to be zeroed
        if (prog_header->mem_used > prog_header->file_size) {
            uint64_t bss_start = prog_header->virtual_addr + prog_header->file_size;
            uint64_t bss_size = prog_header->mem_used - prog_header->file_size;
            memset((void*)bss_start, 0, bss_size);
        }

        // Switch back to the kernel's address space
        vmm_load_pml4(old_pml4);

        // Set the initial program break for the process
        if (prog_header->entry_type == 0x01) { // PT_LOAD
            uint64_t segment_end = prog_header->virtual_addr + prog_header->mem_used;
            if (segment_end > proc->program_break) {
                proc->program_break = segment_end;
                if (proc->program_break_start == 0) {
                    proc->program_break_start = segment_end;
                }
            }
        }
    }

    // Align the program break to the next page boundary
    proc->program_break = (proc->program_break + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    proc->program_break_start = proc->program_break;

    // Stage 4: Allocate and map a user-mode stack
    for (uint64_t i = 0; i < USER_STACK_SIZE; i += PAGE_SIZE) {
        void* phys_page = pmm_alloc_block();
        if(phys_page == NULL) {
           LOG_ERR("ELF: Failed to allocate page for new segment mappings");
           return NULL;
        }
        uint64_t vaddr = USER_STACK_TOP - USER_STACK_SIZE + i;
        vmm_map_page_to(proc->pml4_phys, vaddr, (uint64_t)phys_page, PAGE_PRESENT | PAGE_READ_WRITE | PAGE_USER);
    }

    // Stage 5: Craft the initial register frame on the process's KERNEL stack.
    // The ELF loader is still responsible for setting rip, cs, rsp, ss, and rflags correctly.
    uint64_t* stack_ptr = (uint64_t*)((uint64_t)proc->kernel_stack + proc->kernel_stack_size - sizeof(registers_t));
    registers_t* regs_frame = (registers_t*)stack_ptr;
    memset(regs_frame, 0, sizeof(registers_t));
    regs_frame->rip = header->entry_point_addr;
    regs_frame->cs = 0x23;                      // 0x20 | 3; // User code selector (0x20) with RPL 3
    regs_frame->rflags = 0x246;                 // Enable interrupts (IF) and set bit 1 (always 1)
    regs_frame->user_rsp = USER_STACK_TOP;
    regs_frame->ss = 0x1b;                      //0x18 | 3; // User data selector (0x18) with RPL 3

    // Tell the scheduler where to find this register frame
    proc->kstack_ptr = (uint64_t)regs_frame;
    proc->entry_point = (void*)header->entry_point_addr;
    LOG_INFO("ELF: Successfully loaded PID %llu.", proc->pid);
    return proc;
}

bool validate_elf_header(elf_header_t* header) {
    // Check the magic number
    if(header->ident[0] == 0x7F && memcmp(header->ident + 1, "ELF", 3)) {
        LOG_ERR("ELF: Invalid magic number. Not an ELF file.");
        return false;
    }

    // Ensure we have a 64bit ELF
    if(header->ident[4] == 1) {
        LOG_ERR("ELF: Invalid bit format; must be compiled as 64-bit ELF.");
        return false;
    }

    // Check the endianess of the file
    little_endian = header->ident[5] == 1;

    // Check the ABI (ensure its SYS-V)
    if(header->ident[7] != 0x00) {
        LOG_ERR("ELF: Invalid ABI format; must be compiled for 64-bit SysV.");
        return false;
    }
    return true;
}

void map_segment_pages(uint64_t size, uint64_t virt_addr, uint64_t pml4) {
    for (uint64_t i = 0; i < size; i += PAGE_SIZE) {
        void* phys_page = pmm_alloc_block();
        if(phys_page == NULL) {
            LOG_ERR("ELF: Failed to allocate page for new segment mappings");
            return;
        }
        uint64_t segment_vaddr = virt_addr + i;
        vmm_map_page_to(pml4, segment_vaddr, (uint64_t)phys_page, PAGE_PRESENT | PAGE_READ_WRITE | PAGE_USER);
    }
}