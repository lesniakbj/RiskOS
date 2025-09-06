#include <kernel/log.h>
#include <arch/x86-64/interrupts.h>
#include <arch/x86-64/pic.h>

interrupt_handler_t interrupt_handlers[256];

void register_interrupt_handler(uint8_t n, interrupt_handler_t handler) {
    // TODO: Make sure that we either aren't trashing other handlers, or chain
    // multiple handlers if we try to re-regiser
    interrupt_handlers[n] = handler;
    LOG_INFO("Registering interrupt handler %d, with handler 0x%x", n, handler);
}

// Generic C handler for all interrupts and exceptions
void isr_handler_c(registers_t *regs) {
    // For IRQs, we need to send an End-of-Interrupt (EOI) to the PIC *before*
    // calling the handler, as the handler might switch context and not return.
    if (regs->interrupt_number >= 32 && regs->interrupt_number <= 47) {
        // The mouse handler (IRQ 12, vector 44) and RTC handler (IRQ 8, vector 40)
        // are responsible for their own EOI, so we don't send it for them here.
        if (regs->interrupt_number != 44 && regs->interrupt_number != 40) {
            if (regs->interrupt_number >= 40) {
                outb(0xA0, PIC_EOI); // EOI for slave PIC
            }
            outb(0x20, PIC_EOI); // EOI for master PIC
        }
    }

    if (interrupt_handlers[regs->interrupt_number] != 0) {
        interrupt_handlers[regs->interrupt_number](regs);
    }
}
