#include <drivers/keyboard.h>
#include <kernel/log.h>
#include <arch/x86-64/io.h>
#include <arch/x86-64/interrupts.h>
#include <libc/string.h>
#include <drivers/input.h> // Include the generic input header

// Function to send a command to the PS/2 controller
static void ps2_controller_send_command(uint8_t command) {
    // Wait for input buffer to be empty
    while (inb(PS2_STATUS_PORT) & PS2_STATUS_INPUT_BUFFER_FULL);
    outb(PS2_COMMAND_PORT, command);
}

// Function to send data to the PS/2 data port
static void ps2_data_send(uint8_t data) {
    // Wait for input buffer to be empty
    while (inb(PS2_STATUS_PORT) & PS2_STATUS_INPUT_BUFFER_FULL);
    outb(PS2_DATA_PORT, data);
}

// Function to read data from the PS/2 data port
static uint8_t ps2_data_read() {
    // Wait for output buffer to be full
    while (!(inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_BUFFER_FULL));
    return inb(PS2_DATA_PORT);
}

// Basic scan code to ASCII conversion (very simplified for now)
static char scancode_to_ascii(uint8_t scancode) {
    // This is a highly simplified mapping for QWERTY layout.
    // A real keyboard driver would use a scancode set, shift states, etc.
    switch (scancode) {
        case 0x02: return '1';
        case 0x03: return '2';
        case 0x04: return '3';
        case 0x05: return '4';
        case 0x06: return '5';
        case 0x07: return '6';
        case 0x08: return '7';
        case 0x09: return '8';
        case 0x0A: return '9';
        case 0x0B: return '0';
        case 0x10: return 'q';
        case 0x11: return 'w';
        case 0x12: return 'e';
        case 0x13: return 'r';
        case 0x14: return 't';
        case 0x15: return 'y';
        case 0x16: return 'u';
        case 0x17: return 'i';
        case 0x18: return 'o';
        case 0x19: return 'p';
        case 0x1E: return 'a';
        case 0x1F: return 's';
        case 0x20: return 'd';
        case 0x21: return 'f';
        case 0x22: return 'g';
        case 0x23: return 'h';
        case 0x24: return 'j';
        case 0x25: return 'k';
        case 0x26: return 'l';
        case 0x2C: return 'z';
        case 0x2D: return 'x';
        case 0x2E: return 'c';
        case 0x2F: return 'v';
        case 0x30: return 'b';
        case 0x31: return 'n';
        case 0x32: return 'm';
        case 0x39: return ' '; // Spacebar
        case 0x1C: return '\n'; // Enter key
        case 0x0E: return '\b'; // Backspace
        // Add more mappings as needed
        default: return 0; // Unhandled scancode
    }
}

// Keyboard Interrupt Handler
void keyboard_handler(registers_t* regs) {
    (void)regs; // Unused for now

    uint8_t status = inb(PS2_STATUS_PORT);
    if (status & PS2_STATUS_OUTPUT_BUFFER_FULL) {
        uint8_t scancode = inb(PS2_DATA_PORT);

        // Check if it's a key release event (most significant bit set)
        if (scancode & 0x80) {
            // Key released, ignore for now
        } else {
            char ascii_char = scancode_to_ascii(scancode);
            if (ascii_char != 0) {
                // Call the generic input handler if one is registered
                if (g_char_input_handler != NULL) {
                    g_char_input_handler(ascii_char);
                } else {
                    LOG_WARN("Keyboard: No character input handler registered. Dropping char %c (scancode: 0x%x)", ascii_char, scancode);
                }
            }
        }
    }
}

void keyboard_init() {
    // Disable keyboard (Port 1)
    ps2_controller_send_command(PS2_CMD_DISABLE_KEYBOARD);

    // Flush output buffer
    // Read any pending data to clear the buffer
    while (inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_BUFFER_FULL) {
        inb(PS2_DATA_PORT);
    }

    // Read Controller Configuration Byte
    ps2_controller_send_command(PS2_CMD_READ_CONFIG_BYTE);
    uint8_t config_byte = ps2_data_read();

    // Enable keyboard interrupt (bit 0) and disable translation (bit 6)
    config_byte |= 0x01; // Enable IRQ1
    config_byte &= ~0x40; // Disable translation

    // Write Controller Configuration Byte
    ps2_controller_send_command(PS2_CMD_WRITE_CONFIG_BYTE);
    ps2_data_send(config_byte);

    // Enable keyboard (Port 1)
    ps2_controller_send_command(PS2_CMD_ENABLE_KEYBOARD);

    // Register keyboard interrupt handler (IRQ1, remapped to 0x21)
    register_interrupt_handler(0x21, keyboard_handler);

    LOG_INFO("Keyboard driver initialized.");
}
