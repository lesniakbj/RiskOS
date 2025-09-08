#include <stddef.h>
#include <stdbool.h>
#include <kernel/kernel.h>
#include <kernel/time.h>
#include <kernel/heap.h>
#include <kernel/log.h>
#include <kernel/syscall.h>
#include <kernel/limine.h>
#include <kernel/limreq.h>
#include <drivers/fb_console.h>
#include <drivers/serio.h>
#include <drivers/pit.h>
#include <drivers/disk.h>
#include <drivers/device.h>
#include <drivers/devdisc.h>
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
#include <arch/x86-64/msr.h>
#include <lib/tar.h>
#include <lib/elf.h>
#include <libc/string.h>

// This structure will be pointed to by the KERNEL_GS_BASE MSR.
// It holds data that is private to each CPU.
// For now, we only have one CPU.
typedef struct {
    uint64_t kernel_stack;
    uint64_t user_stack;
} per_cpu_data_t;

static per_cpu_data_t cpu0_data;

static void early_logging_init();
static void arch_init();
static void memory_init();
static void kdevice_init();
static void register_interrupt_handlers();
static void register_syscall_vector();
static struct limine_file* load_initramfs();

#define KERNEL_HEAP_START 0xffffc90000000000
#define KERNEL_HEAP_INITIAL_SIZE 0x1000

void dump_syscall_msrs() {
    uint64_t star = rdmsr(MSR_STAR);
    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t fmask = rdmsr(MSR_FMASK);
    LOG_INFO("MSR IA32_STAR = 0x%llx", star);
    LOG_INFO("MSR IA32_LSTAR = 0x%llx", lstar);
    LOG_INFO("MSR IA32_FMASK = 0x%llx", fmask);
}

// Kernel Entry...
void kernel_main() {
    asm volatile ("cli");

    if (LIMINE_BASE_REVISION_SUPPORTED == false) {
        for (;;) { asm volatile ("hlt"); }
    }

    early_logging_init();
    arch_init();
    memory_init();
    kdevice_init();
    proc_init();
    syscall_helpers_init();
    register_interrupt_handlers();
    register_syscall_vector();

    vfs_init();
    device_manager_init();
    devdisc_discover_devices();
    tarfs_init(load_initramfs(), "init");
    fat32_init();
    disk_system_init();
    devfs_init();
    vfs_create_directory("dev");
    vfs_mount(NULL, "devfs", "/dev");
    framebuffer_console_register();
    serial_register();

    print_vfs_tree(vfs_root_node(), 0);

    vfs_node_t* test_node = vfs_open("/init/sbin/init");
    if (test_node) {
        LOG_INFO("Successfully opened /init/sbin/init");
        if(test_node->flags & VFS_EXEC) {
            LOG_INFO("File is an exec!");
            process_t* init_proc = elf_load_process(((tar_file_data_t*)(test_node->private_data))->data);
            if (init_proc != NULL) {
                if (proc_setup_std_fds(init_proc) == 0) {
                    LOG_INFO("Successfully set up stdio for init process");
                    proc_exec(init_proc);
                } else {
                    LOG_ERR("Failed to set up stdio for init process");
                }
            } else {
                LOG_ERR("Failed to load init process");
            }
        } else {
            LOG_INFO("File is a regular file!");
        }
    } else {
        LOG_ERR("Failed to open /init/sbin/init");
    }

    asm volatile ("sti");

    proc_scheduler_run(NULL);

    LOG_PANIC("We returned from the scheduler!!!");
    for(;;);
}

static struct limine_file* load_initramfs() {
    // ... (implementation is the same)
    struct limine_file* init_tar_module = NULL;
    for (uint64_t i = 0; i < module_request.response->module_count; i++) {
        if(strcmp(module_request.response->modules[i]->path, "/boot/initramfs.tar") == 0) {
            init_tar_module = module_request.response->modules[i];
            break;
        }
    }
    if (init_tar_module == NULL) {
        LOG_ERR("FATAL: Could not find init.tar module!");
        for (;;) { asm volatile ("hlt"); }
    }
    LOG_DEBUG("Initramfs found: Rev: %llu, Addr: 0x%llx, Size: %llu, Path: %s, CmdLine: %s, Type: %u, Partition: %u, Disk: %u",
                init_tar_module->revision, init_tar_module->address, init_tar_module->size, init_tar_module->path, init_tar_module->string,
                init_tar_module->media_type, init_tar_module->partition_index, init_tar_module->mbr_disk_id);
    return init_tar_module;
}

static void register_syscall_vector() {
    wrmsr(MSR_LSTAR, (uint64_t)syscall_entry);
    uint64_t star = (((uint64_t)0x08) << 32) | (((uint64_t)0x10) << 48);
    wrmsr(MSR_STAR, star);
    wrmsr(MSR_FMASK, (1ULL << 9)); // Clear IF flag

    uint64_t efer = rdmsr(MSR_EFER);
    efer |= 1; // Enable SCE (Syscall Enable)
    wrmsr(MSR_EFER, efer);

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

    // Set up the GS base for the kernel
    cpu0_data.kernel_stack = tss_get_stack_ptr();
    wrmsr(MSR_KERNEL_GS_BASE, (uint64_t)&cpu0_data);

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
}

static void memory_init() {
    pmm_init(mmap_request.response, kernel_address_request.response, hhdm_request.response);
    vmm_init(mmap_request.response, hhdm_request.response);
    heap_init(KERNEL_HEAP_START, KERNEL_HEAP_INITIAL_SIZE);
}

static void kdevice_init() {
    pci_init();
    if (pit_init(1000) == 0) {
        system_time_init(date_at_boot_request.response);
    } else {
        LOG_ERR("FATAL: No timer available!");
        return;
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
}
