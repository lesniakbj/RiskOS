#include <kernel/proc.h>
#include <kernel/heap.h>
#include <kernel/log.h>
#include <arch/x86-64/vmm.h>
#include <libc/string.h> // For memset
#include <arch/x86-64/gdt.h> // For tss_set_stack

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
    regs_frame->rflags = 0x202; // Enable interrupts (IF flag) and set bit 1 (always 1)
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

            // Allocate a new kernel stack for this process
            new_proc->kernel_stack_size = 0x4000; // 16KB kernel stack
            new_proc->kernel_stack = kmalloc(new_proc->kernel_stack_size);
            if (new_proc->kernel_stack == NULL) {
                LOG_ERR("PROC: Failed to allocate kernel stack for PID %llu", new_proc->pid);
                new_proc->used = false; // Free the slot
                return NULL;
            }

            return new_proc;
        }
    }

    LOG_ERR("PROC: Error attempting to create proc! No free slots!");
    return NULL;
}

void proc_exec(process_t* process) {
    process->state = PROC_STATE_READY;
    return;
}

void proc_terminate(process_t* proc) {
    if(proc) {
        proc->used = false;  // Mark the slot as free
        proc->state = PROC_STATE_UNUSED;
        // In a more advanced kernel, we would free memory, close files, etc...
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
    LOG_DEBUG("--- CONTEXT SWITCH ---");
    LOG_DEBUG("  Scheduler invoked. is_exit=%d, regs=0x%llx", is_exit, (uint64_t)regs);
    LOG_DEBUG("  From: PID %d, Type %d, State %d", prev_process->pid, prev_process->type, prev_process->state);
    LOG_DEBUG("    Old kstack_ptr value:      0x%llx", prev_process->kstack_ptr);
    LOG_DEBUG("    Old PML4: 0x%llx", prev_process->pml4_phys);
    LOG_DEBUG("  To:   PID %d, Type %d, State %d", next_proc->pid, next_proc->type, next_proc->state);
    LOG_DEBUG("    New kstack_ptr value:      0x%llx", next_proc->kstack_ptr);
    LOG_DEBUG("    New PML4: 0x%llx", next_proc->pml4_phys);

    if (regs) {
        LOG_DEBUG("  Register state at switch (from interrupt/syscall):");
        LOG_DEBUG("    RAX: 0x%llx, RBX: 0x%llx, RCX: 0x%llx, RDX: 0x%llx", regs->rax, regs->rbx, regs->rcx, regs->rdx);
        LOG_DEBUG("    RSI: 0x%llx, RDI: 0x%llx, RBP: 0x%llx", regs->rsi, regs->rdi, regs->rbp);
        LOG_DEBUG("    R8:  0x%llx, R9:  0x%llx, R10: 0x%llx, R11: 0x%llx", regs->r8, regs->r9, regs->r10, regs->r11);
        LOG_DEBUG("    R12: 0x%llx, R13: 0x%llx, R14: 0x%llx, R15: 0x%llx", regs->r12, regs->r13, regs->r14, regs->r15);
        LOG_DEBUG("    RIP: 0x%llx, RFLAGS: 0x%llx, RSP: 0x%llx", regs->rip, regs->rflags, regs->user_rsp);
        LOG_DEBUG("    CS: 0x%llx, SS: 0x%llx", regs->cs, regs->ss);
    }

    // Update global current_process pointer
    current_process = next_proc;

    // Update the TSS with the new process's kernel stack pointer.
    // This is crucial for handling interrupts that occur while in user mode.
    uint64_t new_rsp0 = (uint64_t)next_proc->kernel_stack + next_proc->kernel_stack_size;
    LOG_DEBUG("  Setting TSS RSP0 to: 0x%llx", new_rsp0);
    tss_set_stack(new_rsp0);

    // Switch page tables if necessary.
    if (next_proc->pml4_phys != prev_process->pml4_phys) {
        LOG_DEBUG("  Switching page tables (PML4).");
        vmm_load_pml4(next_proc->pml4_phys);
    } else {
        LOG_DEBUG("  Page tables are the same, not switching.");
    }

    // Perform the assembly context switch.
    // This function will not return. It will jump to the new process's context.
    // It needs to save the current RSP (which is the RSP of proc_scheduler_run) into
    // prev_process->kstack_ptr, and then load next_proc->kstack_ptr and iretq.
skip_scheduler:
    LOG_DEBUG("Switching context to PID %d (%d): 0x%llx", next_proc->pid, next_proc->type, next_proc->kstack_ptr);
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
