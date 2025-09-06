#ifndef DRIVERS_PIT_H
#define DRIVERS_PIT_H

#define PIT_CHANNEL_0_DATA_PORT     0x40
#define PIT_COMMAND_PORT            0x43

#define PIT_MODE_3                  0x06     // Square Wave Mode
#define PIT_CHANNEL_0               0x00
#define PIT_ACCESS_LOBYTE_HIBYTE    0x30

#define PIT_BASE_FREQUENCY          1193182

#define CONSOLE_CLOCK_UPDATE_INTERVAL   100
#define SCHEDULER_UPDATE_INTERVAL       10

#include <stdint.h>
#include <arch/x86-64/interrupts.h>

int64_t pit_init(uint64_t frequency_hz);
void pit_handler(registers_t *regs);
uint64_t pit_get_tick_count();

#endif // DRIVERS_PIT_H