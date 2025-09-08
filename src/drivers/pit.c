// #include <kernel/proc.h>
#include <kernel/log.h>
#include <kernel/time.h>
#include <kernel/proc.h>
#include <drivers/pit.h>
#include <arch/x86-64/io.h>

// Global variables to track PIT state
static uint64_t pit_tick_count = 0;
static uint64_t pit_frequency = 0;
static uint64_t pit_divisor = 0;

// Counter for console clock updates
static uint64_t schedule_counter = 0;
static uint64_t console_clock_counter = 0;

extern volatile uint64_t system_ticks;

int64_t pit_init(uint64_t frequency_hz) {
    // Ensure the requested frequency for the PIT is in bounds
    if (frequency_hz == 0 || frequency_hz > PIT_BASE_FREQUENCY) {
        LOG_ERR("Invalid frequency requested: %llu Hz", frequency_hz);
        return -1;
    }

    pit_frequency = frequency_hz;
    pit_divisor = PIT_BASE_FREQUENCY / frequency_hz;

    // Check for potential precision loss
    if (PIT_BASE_FREQUENCY % frequency_hz != 0) {
        // The actual frequency will be slightly different
        uint64_t actual_freq = PIT_BASE_FREQUENCY / pit_divisor;
        LOG_WARN("Requested freq %llu Hz, actual freq approx %llu Hz due to integer division.",
                 frequency_hz, actual_freq);
    }

    // Prepare the command byte: Channel 0, Access Mode Low/High, Mode 3 (Square Wave)
    uint8_t command = PIT_CHANNEL_0 | PIT_ACCESS_LOBYTE_HIBYTE | PIT_MODE_3;

    // Send the command byte to the PIT command port
    outb(PIT_COMMAND_PORT, command);

    // Send the divisor (low byte, then high byte) to Channel 0 data port
    outb(PIT_CHANNEL_0_DATA_PORT, (uint8_t)(pit_divisor & 0xFF));          // Low byte
    outb(PIT_CHANNEL_0_DATA_PORT, (uint8_t)((pit_divisor >> 8) & 0xFF));   // High byte

    // Reset tick counter
    pit_tick_count = 0;

    LOG_INFO("PIT initialized: Frequency=%llu Hz, Divisor=%llu", pit_frequency, pit_divisor);
    return 0;
}

// Interrupt handler for the PIT triggered interrupts
void pit_handler(registers_t *regs) {
    // Increment the global tick counter
    pit_tick_count++;

    // --- System Clock Update Logic ---
    system_ticks++;

    // --- Process Scheduler Logic ---
    schedule_counter++;
    if (schedule_counter >= SCHEDULER_UPDATE_INTERVAL) {
        schedule_counter = 0;
        proc_scheduler_run(regs);
    }
}

uint64_t pit_get_tick_count() {
    return pit_tick_count;
}

uint64_t pit_get_frequency() {
    return pit_frequency;
}