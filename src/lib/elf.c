#include <lib/elf.h>
#include <kernel/log.h>
#include <arch/x86-64/vmm.h>
#include <arch/x86-64/pmm.h>
#include <libc/string.h>

#define USER_STACK_TOP 0x7000000000
#define USER_STACK_SIZE 0x4000 // 16KB

static bool validate_elf_header(elf_header_t* header);
static void map_segment_pages(uint64_t size, uint64_t virt_addr, uint64_t pml4);

// Helper functions for stack setup
static bool calculate_stack_layout(int argc, char** argv, int envc, char** envp,
                                   uint64_t* total_size, uint64_t* argv_offset,
                                   uint64_t* envp_offset, uint64_t* strings_offset);
static void populate_stack(uint64_t stack_top_vaddr, int argc, char** argv, int envc, char** envp,
                           uint64_t total_size, uint64_t argv_offset, uint64_t envp_offset, uint64_t strings_offset);

static bool little_endian = true;

/**
 * Calculates the total size needed on the user stack for argc, argv, envp,
 * and the actual strings they point to, ensuring proper alignment.
 *
 * @param argc: Number of arguments
 * @param argv: Array of argument strings
 * @param envc: Number of environment variables
 * @param envp: Array of environment variable strings (key=value)
 * @param[out] total_size: Pointer to store the calculated total size.
 * @param[out] argv_offset: Pointer to store the offset from stack top where argv array starts.
 * @param[out] envp_offset: Pointer to store the offset from stack top where envp array starts.
 * @param[out] strings_offset: Pointer to store the offset from stack top where the actual strings start.
 * @return: True on success, false if calculation fails (e.g., overflow).
 */
static bool calculate_stack_layout(int argc, char** argv, int envc, char** envp,
                                   uint64_t* total_size, uint64_t* argv_offset,
                                   uint64_t* envp_offset, uint64_t* strings_offset) {
    *total_size = 0;
    *argv_offset = 0;
    *envp_offset = 0;
    *strings_offset = 0;

    // Account for argc (int64_t)
    *total_size += sizeof(int64_t);

    // Account for argv array pointers (argc + 1 NULL terminator)
    *total_size += (argc + 1) * sizeof(char*);

    // Account for envp array pointers (envc + 1 NULL terminator)
    *total_size += (envc + 1) * sizeof(char*);

    // Account for argument strings and environment strings, plus null terminators
    size_t strings_size = 0;
    for (int i = 0; i < argc; i++) {
        if (argv[i]) {
            strings_size += strlen(argv[i]) + 1; // +1 for null terminator
        }
    }
    for (int i = 0; i < envc; i++) {
        if (envp[i]) {
            strings_size += strlen(envp[i]) + 1; // +1 for null terminator
        }
    }

    // Align total size to 16 bytes (ABI requirement)
    *strings_offset = (*total_size + 0xF) & ~0xF;
    *total_size = *strings_offset + strings_size;
    // Ensure final size is also 16-byte aligned
    *total_size = (*total_size + 0xF) & ~0xF;

    // Calculate offsets for argv and envp arrays within the stack layout
    *argv_offset = sizeof(int64_t); // argc is first
    *envp_offset = *argv_offset + (argc + 1) * sizeof(char*); // envp follows argv array

    return true; // Add error checking for overflow if needed
}

/**
 * Copies argc, argv, envp, and their associated strings onto the user stack
 * at the specified virtual address, following the System V ABI layout.
 *
 * @param stack_top_vaddr: Virtual address of the top of the user stack page.
 * @param argc: Number of arguments.
 * @param argv: Array of argument strings.
 * @param envc: Number of environment variables.
 * @param envp: Array of environment variable strings.
 * @param total_size: Total size calculated by calculate_stack_layout.
 * @param argv_offset: Offset for argv array.
 * @param envp_offset: Offset for envp array.
 * @param strings_offset: Offset for the actual strings.
 */
static void populate_stack(uint64_t stack_top_vaddr, int argc, char** argv, int envc, char** envp,
                           uint64_t total_size, uint64_t argv_offset, uint64_t envp_offset, uint64_t strings_offset) {
    // Calculate the base address where we start placing data
    uint64_t stack_base_vaddr = stack_top_vaddr - total_size;
    uint64_t current_string_vaddr = stack_base_vaddr + strings_offset;

    // 1. Place argc
    *(int64_t*)stack_base_vaddr = (int64_t)argc;

    // 2. Place argv array and strings
    char** argv_array_loc = (char**)(stack_base_vaddr + argv_offset);
    for (int i = 0; i < argc; i++) {
        if (argv[i]) {
            strcpy((char*)current_string_vaddr, argv[i]);
            argv_array_loc[i] = (char*)current_string_vaddr;
            current_string_vaddr += strlen(argv[i]) + 1;
        } else {
            argv_array_loc[i] = NULL;
        }
    }
    argv_array_loc[argc] = NULL; // Null terminate argv array

    // 3. Place envp array and strings
    char** envp_array_loc = (char**)(stack_base_vaddr + envp_offset);
    for (int i = 0; i < envc; i++) {
        if (envp[i]) {
            strcpy((char*)current_string_vaddr, envp[i]);
            envp_array_loc[i] = (char*)current_string_vaddr;
            current_string_vaddr += strlen(envp[i]) + 1;
        } else {
            envp_array_loc[i] = NULL;
        }
    }
    envp_array_loc[envc] = NULL; // Null terminate envp array

    // Ensure the final stack pointer is 16-byte aligned
    // The stack pointer should point just *above* the argc value.
    // The ABI requires RSP+8 to be 16-byte aligned *before* a `call` instruction.
    // Since `_start` does `call main`, the RSP here (pointing to argc) must satisfy this.
    // This means the address of argc (stack_base_vaddr) + 8 must be 16-byte aligned.
    // Therefore, stack_base_vaddr should be 8-byte aligned (since 8 % 16 = 8).
    // Our calculation should already handle this with the initial alignment of total_size.
    // LOG_DEBUG("Stack populated. Final user RSP will be: 0x%llx", stack_base_vaddr);
}

/**
 * Loads an ELF file into a new process and prepares its initial user stack
 * with argc, argv, and envp according to the System V ABI.
 *
 * @param file_ptr: Pointer to the ELF file in memory.
 * @param argc: Number of arguments for the new process.
 * @param argv: Array of argument strings.
 * @param envp: Array of environment variable strings.
 * @return: Pointer to the newly created process_t on success, NULL on failure.
 */
process_t* elf_load_process_with_args(void* file_ptr, int argc, char** argv, char** envp) {
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
        // TODO: cleanup proc
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

    // Allocate and map a user-mode stack
    for (uint64_t i = 0; i < USER_STACK_SIZE; i += PAGE_SIZE) {
        void* phys_page = pmm_alloc_block();
        if(phys_page == NULL) {
           LOG_ERR("ELF: Failed to allocate page for new segment mappings");
           // TODO: cleanup allocated pages and process
           return NULL;
        }
        uint64_t vaddr = USER_STACK_TOP - USER_STACK_SIZE + i;
        vmm_map_page_to(proc->pml4_phys, vaddr, (uint64_t)phys_page, PAGE_PRESENT | PAGE_READ_WRITE | PAGE_USER);
    }

    // Stack Population with argc/argv/envp
    int envc = 0;
    if (envp) {
        while(envp[envc]) envc++;
    }

    uint64_t total_stack_size, argv_off, envp_off, strings_off;
    if (!calculate_stack_layout(argc, argv, envc, envp, &total_stack_size, &argv_off, &envp_off, &strings_off)) {
        LOG_ERR("ELF: Failed to calculate initial stack layout");
        // TODO: cleanup
        return NULL;
    }

    // Temporarily switch to the new process's address space to populate the stack
    uint64_t old_pml4 = vmm_get_current_pml4();
    vmm_load_pml4(proc->pml4_phys);

    populate_stack(USER_STACK_TOP, argc, argv, envc, envp, total_stack_size, argv_off, envp_off, strings_off);

    // Switch back to the kernel's address space
    vmm_load_pml4(old_pml4);

    // Craft the initial register frame on the process's KERNEL stack.
    // The ELF loader is still responsible for setting rip, cs, rsp, ss, and rflags correctly.
    uint64_t final_user_rsp = USER_STACK_TOP - total_stack_size; // Points just above argc
    
    uint64_t* stack_ptr = (uint64_t*)((uint64_t)proc->kernel_stack + proc->kernel_stack_size - sizeof(registers_t));
    registers_t* regs_frame = (registers_t*)stack_ptr;
    memset(regs_frame, 0, sizeof(registers_t));
    regs_frame->rip = header->entry_point_addr;
    regs_frame->cs = 0x23;                      // 0x20 | 3; // User code selector (0x20) with RPL 3
    regs_frame->rflags = 0x246;                 // Enable interrupts (IF) and set bit 1 (always 1)
    regs_frame->user_rsp = final_user_rsp;      // Set to the calculated stack pointer
    regs_frame->ss = 0x1b;                      //0x18 | 3; // User data selector (0x18) with RPL 3

    // Tell the scheduler where to find this register frame
    proc->kstack_ptr = (uint64_t)regs_frame;
    proc->entry_point = (void*)header->entry_point_addr;

    // By convention, a new process loaded from an executable starts its own process group.
    proc->pgid = proc->pid;

    LOG_INFO("ELF: Successfully loaded PID %llu with args.", proc->pid);
    return proc;
}

process_t* elf_load_process(void* file_ptr) {
   // Provide default empty args and env
   int argc = 0;
   char* argv[] = { NULL };
   char* envp[] = { NULL };
   return elf_load_process_with_args(file_ptr, argc, argv, envp);
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