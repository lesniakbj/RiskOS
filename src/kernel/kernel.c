#include <stddef.h>
#include <stdbool.h>
#include <kernel/kernel.h>
#include <kernel/time.h>
#include <kernel/heap.h>
#include <kernel/log.h>
#include <kernel/syscall.h>
#include <kernel/limine.h>
#include <kernel/limreq.h>
#include <kernel/syscall.h>
#include <drivers/fb_console.h>
#include <drivers/serio.h>
#include <drivers/pit.h>
#include <drivers/disk.h>
#include <drivers/fs/vfs.h>
#include <drivers/fs/tarfs.h>
#include <drivers/fs/devfs.h>
#include <drivers/fs/fat32.h>
#include <arch/x86-64/gdt.h>
#include <arch/x86-64/idt.h>
#include <arch/x86-64/pic.h>
#include <arch/x86-64/pci.h>
#include <arch/x86-64/pmm.h>
#include <arch/x86-64/vmm.h>
#include <arch/x86-64/io.h>
#include <arch/x86-64/interrupts.h>
#include <arch/x86-64/fault.h>
#include <lib/tar.h>
#include <lib/elf.h>
#include <libc/string.h>

static void early_logging_init();
static void arch_init();
static void memory_init();
static void device_init();
static void register_interrupt_handlers();
static void register_syscall_vector();
static struct limine_file* load_initramfs();

#define KERNEL_HEAP_START 0xffffc90000000000
#define KERNEL_HEAP_INITIAL_SIZE 0x1000

static uint64_t rdmsr_u64(uint32_t msr) {
    uint32_t lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

void dump_syscall_msrs() {
    uint64_t star = rdmsr_u64(0xC0000081);
    uint64_t lstar = rdmsr_u64(0xC0000082);
    uint64_t fmask = rdmsr_u64(0xC0000084);
    LOG_INFO("MSR IA32_STAR = 0x%llx", star);
    LOG_INFO("MSR IA32_LSTAR = 0x%llx", lstar);
    LOG_INFO("MSR IA32_FMASK = 0x%llx", fmask);
}

// Kernel Entry...
void kernel_main() {
    // Ensure that we start with interrupts disabled (I believe limine does this but... lets be sure...)
    asm volatile ("cli");

    // Exit early if we weren't booted correctly...
    if (LIMINE_BASE_REVISION_SUPPORTED == false) {
        for (;;) {
            asm volatile ("hlt");
        }
    }

    early_logging_init();
    arch_init();
    memory_init();
    device_init();
    proc_init();
    syscall_helpers_init();
    register_interrupt_handlers();
    register_syscall_vector();

    // Phase 5: VFS init and Initramfs
    // TODO: Instead of attaching the node directly to the VFS, add a delegation layer
    // so that when the VFS encounters nodes not in its own tree it delegates to another driver
    vfs_init();
    tarfs_init(load_initramfs(), "init");

    print_vfs_tree(vfs_root_node(), 0);

    // Test opening a file in the initramfs
    vfs_node_t* test_node = vfs_open("/init/sbin/init");
    if (test_node) {
        LOG_INFO("Successfully opened /init/sbin/init");
        // You can now read from this node using vfs_read
        if(test_node->flags & VFS_EXEC) {
            LOG_INFO("File is an exec!");
            proc_exec(elf_load_process(((tar_file_data_t*)(test_node->private_data))->data));
        } else {
            LOG_INFO("File is a regular file!");
        }
    } else {
        LOG_ERR("Failed to open /init/sbin/init");
    }

    // Phase 6: Init then VFS (DevFS, Fat32, etc)
    // devfs_init();
    // vfs_create_directory("dev");
    // vfs_create_directory("hda1");
    // vfs_mount(NULL, "devfs", "/dev");
    // framebuffer_console_register();
    // serial_register();
    // fat32_init();
    // disk_system_init();

    // TODO: Screen init first, then screen->attach_console(console_init());
    // TODO: Get active console via screen->active_console
    // TODO: log_init(screen->active_console);

    // TODO: Launch user mode PID 1, which is the system idle thread

    // Enable interrupts before starting the scheduler.
    asm volatile ("sti");

    // The scheduler will pick PID 0 (or PID 1 if created and ready).
    proc_scheduler_run(NULL);   // Pass NULL for regs, as it's the first switch.

    LOG_PANIC("We returned from the scheduler!!!");
    for(;;);
}

static struct limine_file* load_initramfs() {
    struct limine_file* init_tar_module = NULL;
    for (uint64_t i = 0; i < module_request.response->module_count; i++) {
        if(strcmp(module_request.response->modules[i]->path, "/boot/initramfs.tar") == 0) {
            init_tar_module = module_request.response->modules[i];
            break;
        }
    }
    if (init_tar_module == NULL) {
        LOG_ERR("FATAL: Could not find init.tar module!");
        for (;;) {
            asm volatile ("hlt");
        }
    }
    LOG_DEBUG("Initramfs found: Rev: %llu, Addr: 0x%llx, Size: %llu, Path: %s, CmdLine: %s, Type: %u, Partition: %u, Disk: %u",
                init_tar_module->revision, init_tar_module->address, init_tar_module->size, init_tar_module->path, init_tar_module->string,
                init_tar_module->media_type, init_tar_module->partition_index, init_tar_module->mbr_disk_id);
    return init_tar_module;
}

static void register_syscall_vector() {
    // Get the address of the handler
    uint64_t addr = (uint64_t)syscall_entry;
    uint32_t lstar_addr = 0xC0000082;
    uint32_t star_addr = 0xC0000081;
    uint32_t fmask_addr = 0xC0000084;
    uint32_t efer_addr = 0xC0000080;

    // Set up the MSRs for syscall/sysret
    // IA32_LSTAR: syscall entry point
    uint32_t low = (uint32_t)addr;
    uint32_t high = (uint32_t)(addr >> 32);
    asm volatile (
        "wrmsr"
        : // No output
        : "c"(lstar_addr), "a"(low), "d"(high)  // IA32_LSTAR MSR
    );
    
    // IA32_STAR: syscall CS/SS selectors
    // bits 63-48: kernel CS, bits 47-32: kernel SS
    // For our GDT: kernel CS = 0x08, kernel data = 0x10, user data = 0x18, user code = 0x20
    // SYSRET will set user SS to (STAR[63:48] + 8) and user CS to (STAR[63:48] + 16)
    // We set STAR[63:48] to 0x10 (kernel data) to get user SS=0x18 and CS=0x20.
    uint64_t star = (((uint64_t)0x08) << 32) | (((uint64_t)0x10) << 48);
    //uint64_t star = (((uint64_t)0x18) << 48) | (((uint64_t)0x08) << 32);
    uint32_t star_low = (uint32_t)star;           // likely 0
    uint32_t star_high = (uint32_t)(star >> 32);  // contains 0x00180008
    asm volatile (
        "wrmsr"
        : // No output
        : "c"(star_addr), "a"(star_low), "d"(star_high)  // IA32_STAR MSR
    );
    
    // IA32_FMASK: flags mask (clear interrupt flag when entering syscall)
    uint64_t fmask = (1ULL << 9); // IF (bit 9)
    asm volatile ("wrmsr" : : "c"(fmask_addr), "a"((uint32_t)fmask), "d"((uint32_t)(fmask>>32)));

    // Enable SYSCALL/SYSRET instructions
    uint32_t eax, edx;
    asm volatile (
        "rdmsr"
        : "=a"(eax), "=d"(edx)
        : "c"(efer_addr)
    );
    eax |= 1;
    asm volatile (
        "wrmsr"
        : // No output
        : "c"(efer_addr), "a"(eax), "d"(edx)
    );

    dump_syscall_msrs();
}

static void early_logging_init() {
    serial_init(SERIAL_COM1);
    log_init();
}

static void arch_init() {
    framebuffer_init(framebuffer_request.response);
    gdt_init();
    tss_init();
    asm volatile(
        ".intel_syntax noprefix\n"
        "mov ax, 0x10\n"
        "mov ds, ax\n"
        "mov es, ax\n"
        "mov ss, ax\n"
        ".att_syntax prefix\n"
        ::: "ax"
    );
    idt_init();
    pic_remap(0x20, 0x28);
    dump_gdt_fixed();
    dump_tss_info_fixed();
    // TODO: Do we init SMP here?
}

static void memory_init() {
    pmm_init(mmap_request.response, kernel_address_request.response, hhdm_request.response);
    vmm_init(mmap_request.response, hhdm_request.response);
    heap_init(KERNEL_HEAP_START, KERNEL_HEAP_INITIAL_SIZE);
}

static void device_init() {
    pci_init();
    if (pit_init(1000) == 0) {
        system_time_init(date_at_boot_request.response);
    } else {
        LOG_ERR("FATAL: No timer available!");
        return; // Halt if no timer
    }
}

static void register_interrupt_handlers() {
    register_interrupt_handler(0x20, pit_handler);
    register_interrupt_handler(0x0E, page_fault_handler);
    register_interrupt_handler(0x0D, general_protection_fault_handler);
    register_interrupt_handler(0x00, divide_by_zero_handler);
    register_interrupt_handler(0x06, invalid_opcode_handler);
    register_interrupt_handler(0x08, double_fault_handler);
    register_interrupt_handler(0x0C, stack_segment_fault_handler);
    register_interrupt_handler(0x11, alignment_check_handler);
    // register_interrupt_handler(0x21, keyboard_handler);
    // register_interrupt_handler(0x2C, mouse_handler);
    // register_interrupt_handler(0x28, rtc_handler);
    // register_interrupt_handler(0x80, syscall_handler);
}