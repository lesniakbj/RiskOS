#include <kernel/proc.h>
#include <kernel/heap.h>
#include <kernel/log.h>
#include <arch/x86-64/vmm.h>
#include <libc/string.h> // For memset
#include <arch/x86-64/gdt.h> // For tss_set_stack
#include <drivers/fs/vfs.h>

// Symbols from stack.S, defining the bounds of the bootstrap stack.
extern uint8_t kernel_stack[];
extern uint8_t stack_top[];

// Assembly context switch functions
extern void context_switch(uint64_t* current_kstack_ptr_addr, uint64_t next_kstack_ptr_val);
extern void first_time_user_switch(uint64_t new_rsp);

static process_t process_table[MAX_PROCESSES];
static process_t* current_process = NULL;
static uint64_t next_pid = 0;
static bool scheduler_initialized = false;

static void kernel_idle_process();

process_t* proc_get_current() {
    return current_process;
}

void proc_init() {
    // Clear the entire process table to a known state.
    memset(process_table, 0, sizeof(process_table));

    // Initialize PID 0, the kernel's idle task.
    // This process "adopts" the state the kernel is already running in.
    process_t* kernel_proc = &process_table[0];
    kernel_proc->used = true;
    kernel_proc->pid = next_pid++;
    kernel_proc->state = PROC_STATE_RUNNING;    // It's the currently running process.
    kernel_proc->type = PROC_TYPE_KERNEL;
    kernel_proc->parent = NULL;                 // The kernel has no parent.
    kernel_proc->exit_code = 0;
    kernel_proc->working_dir = vfs_root_node();

    // Initialize file descriptors (stdin, stdout, stderr)
    for (int i = 0; i < MAX_FD_PER_PROCESS; i++) {
        kernel_proc->file_descriptors[i].node = NULL;
        kernel_proc->file_descriptors[i].flags = 0;
        kernel_proc->file_descriptors[i].offset = 0;
    }

    // For x86-64, we need the physical address of the top-level page table (PML4).
    // The kernel process uses the initial page tables set up by the VMM.
    kernel_proc->pml4_phys = vmm_get_kernel_pml4();

    // The kernel stack is already allocated in stack.S and is currently in use.
    // We just record its location and size.
    kernel_proc->kernel_stack = (void*)kernel_stack;
    kernel_proc->kernel_stack_size = (size_t)(stack_top - kernel_stack);

    // --- Craft the initial stack frame for PID 0 ---
    // This stack frame will be used when the scheduler first switches TO PID 0.
    // It needs to look like an interrupt return frame (registers_t).
    // We place it at the top of PID 0's kernel stack.
    uint64_t* stack_ptr = (uint64_t*)((uint64_t)stack_top - sizeof(registers_t));
    registers_t* regs_frame = (registers_t*)stack_ptr;
    memset(regs_frame, 0, sizeof(registers_t)); // Clear the frame

    // Set the values that iretq will pop to start kernel_idle_process
    regs_frame->rip = (uint64_t)kernel_idle_process; // Jump to kernel_idle_process
    regs_frame->cs = 0x08; // Kernel Code Segment Selector
    regs_frame->rflags = 0x246; // Enable interrupts (IF flag) and set bit 1 (always 1)
    regs_frame->user_rsp = (uint64_t)stack_top; // This is the RSP that iretq will pop. It should be the top of the stack.
    regs_frame->ss = 0x10; // Kernel Data Segment Selector

    // The kstack_ptr for PID 0 should point to this crafted registers_t struct.
    kernel_proc->kstack_ptr = (uint64_t)regs_frame;
    kernel_proc->entry_point = kernel_idle_process;

    // Set the initial running process.
    current_process = kernel_proc;

    scheduler_initialized = true;
    LOG_INFO("Process manager initialized. PID 0 (kernel idle task) is running.");

    LOG_INFO("--- PID 0 (Kernel Idle Task) Details ---");
    LOG_INFO("  PID: %llu", kernel_proc->pid);
    LOG_INFO("  State: %d (2=Running)", kernel_proc->state);
    LOG_INFO("  Type: %d (0=Kernel)", kernel_proc->type);
    LOG_INFO("  PML4 Address (Phys): 0x%llx", kernel_proc->pml4_phys);
    LOG_INFO("  Kernel Stack Base: 0x%llx", (uint64_t)kernel_proc->kernel_stack);
    LOG_INFO("  Kernel Stack Size: %llu bytes", (uint64_t)kernel_proc->kernel_stack_size);
    LOG_INFO("  Parent: %s", (kernel_proc->parent == NULL) ? "None" : "Error");
}

process_t* proc_create(proc_type_t proc_type) {
    // Find a free process in the process table
    for (uint16_t i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].used == false) {
            process_t* new_proc = &process_table[i];

            // Fill in the process with some of the basic metadata
            new_proc->used = true;
            new_proc->pid = next_pid++;
            new_proc->state = PROC_STATE_INIT;
            new_proc->type = proc_type;
            new_proc->exit_code = 0;
            new_proc->working_dir = vfs_root_node();

            // Initialize file descriptors
            for (int j = 0; j < MAX_FD_PER_PROCESS; j++) {
                new_proc->file_descriptors[j].node = NULL;
                new_proc->file_descriptors[j].flags = 0;
                new_proc->file_descriptors[j].offset = 0;
            }

            // Allocate a new kernel stack for this process
            new_proc->kernel_stack_size = 0x4000; // 16KB kernel stack
            new_proc->kernel_stack = kmalloc(new_proc->kernel_stack_size);
            SAFE_ALLOCZ(new_proc->kernel_stack, void*, new_proc->kernel_stack_size, "PROC: Failed to allocate kernel stack for PID %llu", new_proc->pid, {new_proc->used = false; return NULL;};);

            return new_proc;
        }
    }

    LOG_ERR("PROC: Error attempting to create proc! No free slots!");
    return NULL;
}

void proc_make_ready(process_t* process) {
    process->state = PROC_STATE_READY;
    return;
}

// Helper function to set up standard file descriptors for a process
int64_t proc_setup_std_fds(process_t* proc) {
    if (proc == NULL) {
        return -1;
    }

    // Each standard FD needs its own file description, so we open the device for each one.

    // stdin (FD 0)
    vfs_node_t* stdin_node = vfs_open("/dev/console");
    if (stdin_node == NULL) {
        LOG_ERR("PROC: Failed to open /dev/console for stdin");
        return -1;
    }
    proc->file_descriptors[0].node = stdin_node;
    proc->file_descriptors[0].flags = 0; // Or your specific read-only flag
    proc->file_descriptors[0].offset = 0;

    // stdout (FD 1)
    vfs_node_t* stdout_node = vfs_open("/dev/console");
    if (stdout_node == NULL) {
        LOG_ERR("PROC: Failed to open /dev/console for stdout");
        // Clean up already opened node
        kfree(stdin_node);
        proc->file_descriptors[0].node = NULL;
        return -1;
    }
    proc->file_descriptors[1].node = stdout_node;
    proc->file_descriptors[1].flags = 1; // Or your specific write-only flag
    proc->file_descriptors[1].offset = 0;

    // stderr (FD 2)
    vfs_node_t* stderr_node = vfs_open("/dev/console");
    if (stderr_node == NULL) {
        LOG_ERR("PROC: Failed to open /dev/console for stderr");
        // Clean up already opened nodes
        kfree(stdin_node);
        kfree(stdout_node);
        proc->file_descriptors[0].node = NULL;
        proc->file_descriptors[1].node = NULL;
        return -1;
    }
    proc->file_descriptors[2].node = stderr_node;
    proc->file_descriptors[2].flags = 1; // Or your specific write-only flag
    proc->file_descriptors[2].offset = 0;

    LOG_INFO("PROC: Standard file descriptors set up for PID %llu", proc->pid);
    return 0;
}

process_t* find_zombie_child(uint64_t parent_pid, int64_t child_pid_to_find) {
    LOG_ERR("find_zombie_child: Searching for child of parent %llu. Specific child PID to find: %lld", parent_pid, child_pid_to_find);
    for(int i = 0; i < MAX_PROCESSES; i++) {
        process_t* current_proc = &process_table[i];
        if (!current_proc->used) {
            continue; // Skip unused slots
        }

        LOG_ERR("  -> Checking PID %llu: ParentPID=%llu, State=%d", current_proc->pid, current_proc->parent ? current_proc->parent->pid : (uint64_t)-1, current_proc->state);

        if(current_proc->parent == NULL || current_proc->parent->pid != parent_pid) {
            continue;
        }
        LOG_ERR("    -> Match: Is a child of parent %llu", parent_pid);

        if (current_proc->state != PROC_STATE_ZOMBIE) {
            continue;
        }
        LOG_ERR("    -> Match: Is a zombie.");

        if (child_pid_to_find > 0) {
            if (current_proc->pid == child_pid_to_find) {
                LOG_ERR("      -> Match: Found specific PID %lld. Returning.", child_pid_to_find);
                return current_proc;
            }
        } else {
            LOG_ERR("      -> Match: Looking for any child. Returning PID %llu.", current_proc->pid);
            return current_proc;
        }
    }

    LOG_ERR("find_zombie_child: No matching zombie child found for parent %llu.", parent_pid);
    return NULL;
}

void proc_terminate(process_t* proc) {
    if(proc) {
        proc->used = false;  // Mark the slot as free
        proc->state = PROC_STATE_UNUSED;
        // In a more advanced kernel, we would free memory, close files, etc...
    }
}

void proc_free(process_t* proc, int64_t exit_code) {
    // Become a zombie
    proc->state = PROC_STATE_ZOMBIE;
    proc->exit_code = exit_code;

    // TODO:  Free the user address space (page tables and physical pages)
    // Free the kernel stack
    // Close all file descriptors
    //
    if (proc->parent) {
        proc_wakeup(proc->parent->pid);
    }
}

process_t* proc_get_by_pid(uint64_t pid) {
    if (pid >= MAX_PROCESSES || !process_table[pid].used) {
        return NULL;
    }
    return &process_table[pid];
}

void proc_wakeup(uint64_t pid) {
    process_t* proc_to_wake = proc_get_by_pid(pid);
    if (proc_to_wake != NULL && proc_to_wake->state == PROC_STATE_BLOCKED) {
        LOG_ERR("Waking up blocked process %d", pid);
        proc_to_wake->state = PROC_STATE_READY;
    }
}

void proc_scheduler_run(registers_t *regs) {
    proc_scheduler_run_special(regs, false);
}

void proc_scheduler_run_special(registers_t *regs, bool is_exit) {
    asm volatile ("cli");
    if(!scheduler_initialized) {
        return; // Scheduler not ready yet.
    }

    // --- Save the state of the current process ---
    // If this is the very first call from kernel_main(), regs will be NULL.
    // In that case, we need to capture the current RSP from kernel_main's context.
    process_t* prev_process = NULL;
    process_t* next_proc = NULL;
    if (regs == NULL && !is_exit) {
        // This is the first time the scheduler is called from kernel_main.
        // The current_process (PID 0) is already running. Its kstack_ptr was
        // already set to the crafted frame in proc_init. So, we don't save anything here.
        // The context switch will just jump to that crafted frame.
        prev_process = current_process;
        next_proc = current_process;
        LOG_DEBUG("--- KERNEL FIRST SWITCH ---");
        LOG_DEBUG("  Jumping to idle process (PID 0)");
        LOG_DEBUG("  kstack_ptr value: 0x%llx", next_proc->kstack_ptr);
        goto skip_scheduler;
    } else {
        // This is a regular scheduler invocation (e.g., from a timer interrupt).
        // Save the RSP of the current process. 'regs' points to the saved registers on the stack.
        if(!is_exit)
            current_process->kstack_ptr = (uint64_t)regs;
    }

    // --- Find the next runnable process ---
    prev_process = current_process;  // Save current process for comparison
    uint64_t start_idx = prev_process->pid;     // Start search from current PID
    for (uint64_t i = 0; i < MAX_PROCESSES; i++) {
        uint64_t idx = (start_idx + 1 + i) % MAX_PROCESSES; // Simple round-robin
        if (process_table[idx].used &&
            (process_table[idx].state == PROC_STATE_READY || process_table[idx].state == PROC_STATE_RUNNING)) {
            next_proc = &process_table[idx];
            break;
        }
    }

    // If no runnable process found, or the next process is the same as current, return.
    // This means the current process (likely the idle task) continues to run.
    if (next_proc == NULL || next_proc == prev_process) {
        return;
    }

    // --- Perform Context Switch ---
//    LOG_DEBUG("--- CONTEXT SWITCH ---");
//    LOG_DEBUG("  Scheduler invoked. is_exit=%d, regs=0x%llx", is_exit, (uint64_t)regs);
//    LOG_DEBUG("  From: PID %d, Type %d, State %d", prev_process->pid, prev_process->type, prev_process->state);
//    LOG_DEBUG("    Old kstack_ptr value:      0x%llx", prev_process->kstack_ptr);
//    LOG_DEBUG("    Old PML4: 0x%llx", prev_process->pml4_phys);
//    LOG_DEBUG("  To:   PID %d, Type %d, State %d", next_proc->pid, next_proc->type, next_proc->state);
//    LOG_DEBUG("    New kstack_ptr value:      0x%llx", next_proc->kstack_ptr);
//    LOG_DEBUG("    New PML4: 0x%llx", next_proc->pml4_phys);
//
//    if (regs) {
//        LOG_DEBUG("  Register state at switch (from interrupt/syscall):");
//        LOG_DEBUG("    RAX: 0x%llx, RBX: 0x%llx, RCX: 0x%llx, RDX: 0x%llx", regs->rax, regs->rbx, regs->rcx, regs->rdx);
//        LOG_DEBUG("    RSI: 0x%llx, RDI: 0x%llx, RBP: 0x%llx", regs->rsi, regs->rdi, regs->rbp);
//        LOG_DEBUG("    R8:  0x%llx, R9:  0x%llx, R10: 0x%llx, R11: 0x%llx", regs->r8, regs->r9, regs->r10, regs->r11);
//        LOG_DEBUG("    R12: 0x%llx, R13: 0x%llx, R14: 0x%llx, R15: 0x%llx", regs->r12, regs->r13, regs->r14, regs->r15);
//        LOG_DEBUG("    RIP: 0x%llx, RFLAGS: 0x%llx, RSP: 0x%llx", regs->rip, regs->rflags, regs->user_rsp);
//        LOG_DEBUG("    CS: 0x%llx, SS: 0x%llx", regs->cs, regs->ss);
//    }

    // Update global current_process pointer
    current_process = next_proc;

    // Update the TSS with the new process's kernel stack pointer.
    // This is crucial for handling interrupts that occur while in user mode.
    uint64_t new_rsp0 = (uint64_t)next_proc->kernel_stack + next_proc->kernel_stack_size;
    // LOG_DEBUG("  Setting TSS RSP0 to: 0x%llx", new_rsp0);
    tss_set_stack(new_rsp0);

    // Switch page tables if necessary.
    if (next_proc->pml4_phys != prev_process->pml4_phys) {
        // LOG_DEBUG("  Switching page tables (PML4).");
        vmm_load_pml4(next_proc->pml4_phys);
    } else {
        // LOG_DEBUG("  Page tables are the same, not switching.");
    }

    // Perform the assembly context switch.
    // This function will not return. It will jump to the new process's context.
    // It needs to save the current RSP (which is the RSP of proc_scheduler_run) into
    // prev_process->kstack_ptr, and then load next_proc->kstack_ptr and iretq.
skip_scheduler:
    // LOG_DEBUG("Switching context to PID %d (%d): 0x%llx", next_proc->pid, next_proc->type, next_proc->kstack_ptr);
    LOG_INFO("Next proc kstack_ptr=0x%llx, type=%d, pid=%llu", next_proc->kstack_ptr, next_proc->type, next_proc->pid);
    registers_t* saved = (registers_t*) next_proc->kstack_ptr;
    LOG_INFO("Saved frame: RIP=0x%llx CS=0x%llx RFLAGS=0x%llx RSP=0x%llx SS=0x%llx",
             saved->rip, saved->cs, saved->rflags, saved->user_rsp, saved->ss);
    context_switch((uint64_t*)&prev_process->kstack_ptr, next_proc->kstack_ptr);
}

static void kernel_idle_process() {
    LOG_WARN("PID 0: Starting kernel idle process.");
    while(1) {
        asm volatile ("hlt");
    }
}

//void cpu_idle(void)
//{
//	current_thread_info()->status |= TS_POLLING;
//
//	/*
//	 * If we're the non-boot CPU, nothing set the stack canary up
//	 * for us.  CPU0 already has it initialized but no harm in
//	 * doing it again.  This is a good place for updating it, as
//	 * we wont ever return from this function (so the invalid
//	 * canaries already on the stack wont ever trigger).
//	 */
//	boot_init_stack_canary();
//
//	/* endless idle loop with no priority at all */
//	while (1) {
//		tick_nohz_stop_sched_tick(1);
//		while (!need_resched()) {
//
//			rmb();
//
//			if (cpu_is_offline(smp_processor_id()))
//				play_dead();
//			/*
//			 * Idle routines should keep interrupts disabled
//			 * from here on, until they go to idle.
//			 * Otherwise, idle callbacks can misfire.
//			 */
//			local_irq_disable();
//			enter_idle();
//			/* Don't trace irqs off for idle */
//			stop_critical_timings();
//			if (cpuidle_idle_call())
//				pm_idle();
//			start_critical_timings();
//
//			/* In many cases the interrupt that ended idle
//			   has already called exit_idle. But some idle
//			   loops can be woken up without interrupt. */
//			__exit_idle();
//		}
//
//		tick_nohz_restart_sched_tick();
//		preempt_enable_no_resched();
//		schedule();
//		preempt_disable();
//	}
//}
