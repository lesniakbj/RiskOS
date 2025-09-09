#ifndef DRIVERS_KEYBOARD_H
#define DRIVERS_KEYBOARD_H

#include <stdint.h>

// PS/2 Controller I/O Ports
#define PS2_DATA_PORT   0x60
#define PS2_STATUS_PORT 0x64
#define PS2_COMMAND_PORT 0x64

// PS/2 Controller Status Register Bits
#define PS2_STATUS_OUTPUT_BUFFER_FULL 0x01
#define PS2_STATUS_INPUT_BUFFER_FULL  0x02
#define PS2_STATUS_KEYBOARD_LOCKED    0x10
#define PS2_STATUS_TRANSMIT_TIMEOUT   0x20
#define PS2_STATUS_RECEIVE_TIMEOUT    0x40
#define PS2_STATUS_PARITY_ERROR       0x80

// PS/2 Controller Commands
#define PS2_CMD_READ_CONFIG_BYTE    0x20
#define PS2_CMD_WRITE_CONFIG_BYTE   0x60
#define PS2_CMD_DISABLE_KEYBOARD    0xAD
#define PS2_CMD_ENABLE_KEYBOARD     0xAE
#define PS2_CMD_TEST_PS2_PORT1      0xAB
#define PS2_CMD_TEST_PS2_PORT2      0xA9
#define PS2_CMD_TEST_CONTROLLER     0xAA

// Keyboard Commands
#define KB_CMD_SET_LEDS             0xED
#define KB_CMD_ECHO                 0xEE
#define KB_CMD_SCAN_CODE_SET        0xF0
#define KB_CMD_IDENTIFY             0xF2
#define KB_CMD_ENABLE_SCANNING      0xF4
#define KB_CMD_DISABLE_SCANNING     0xF5
#define KB_CMD_SET_DEFAULT_PARAMS   0xF6
#define KB_CMD_RESEND               0xFE
#define KB_CMD_RESET                0xFF

// Keyboard Responses
#define KB_ACK                      0xFA
#define KB_RESEND                   0xFE
#define KB_ERROR                    0xFF

// Function prototypes
void keyboard_init();

#endif // DRIVERS_KEYBOARD_H