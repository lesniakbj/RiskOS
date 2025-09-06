#ifndef DRIVER_SERIALIO_H
#define DRIVER_SERIALIO_H

#include <stdint.h>

// Serial port addresses
#define SERIAL_COM1 0x3F8
#define SERIAL_COM2 0x2F8
#define SERIAL_COM3 0x3E8
#define SERIAL_COM4 0x2E8

// Serial port offsets
#define SERIAL_DATA_REG         0    // Data register (read/write)
#define SERIAL_INTERRUPT_REG    1    // Interrupt enable register (write)
#define SERIAL_FIFO_REG         2    // FIFO control register (write)
#define SERIAL_LINE_REG         3    // Line control register (write)
#define SERIAL_MODEM_REG        4    // Modem control register (write)
#define SERIAL_LINE_STATUS_REG  5    // Line status register (read)
#define SERIAL_MODEM_STATUS_REG 6    // Modem status register (read)

// Line status flags
#define SERIAL_LINE_STATUS_DATA_READY     0x01
#define SERIAL_LINE_STATUS_OVERRUN_ERROR  0x02
#define SERIAL_LINE_STATUS_PARITY_ERROR   0x04
#define SERIAL_LINE_STATUS_FRAMING_ERROR  0x08
#define SERIAL_LINE_STATUS_BREAK_SIGNAL   0x10
#define SERIAL_LINE_STATUS_TRANSMIT_EMPTY 0x20
#define SERIAL_LINE_STATUS_TRANSMIT_IDLE  0x40
#define SERIAL_LINE_STATUS_FIFO_ERROR     0x80

// Baud rate divisors
#define SERIAL_BAUD_115200 1
#define SERIAL_BAUD_57600  2
#define SERIAL_BAUD_38400  3
#define SERIAL_BAUD_19200  6
#define SERIAL_BAUD_9600   12

// Commands
#define DISABLE_INTERRUPTS 0x00
#define ENABLE_INTERRUPTS 0x01
#define ENABLE_BAUD_DIVISOR 0x80 // DLAB bit

// Line Control Register Flags
#define SERIAL_LINE_DATA_BITS_5   0x00
#define SERIAL_LINE_DATA_BITS_6   0x01
#define SERIAL_LINE_DATA_BITS_7   0x02
#define SERIAL_LINE_DATA_BITS_8   0x03

#define SERIAL_LINE_STOP_BIT_1    0x00
#define SERIAL_LINE_STOP_BITS_2   0x04

#define SERIAL_LINE_PARITY_NONE   0x00
#define SERIAL_LINE_PARITY_ODD    0x08
#define SERIAL_LINE_PARITY_EVEN   0x18

// FIFO Control Register Flags
#define SERIAL_FIFO_ENABLE              0x01
#define SERIAL_FIFO_CLEAR_RECEIVE       0x02
#define SERIAL_FIFO_CLEAR_TRANSMIT      0x04
#define SERIAL_FIFO_TRIGGER_LEVEL_14    0xC0

// Modem Control Register Flags
#define SERIAL_MODEM_DTR_ASSERT         0x01
#define SERIAL_MODEM_RTS_ASSERT         0x02
#define SERIAL_MODEM_IRQ_ENABLE         0x08

// Macros to encapsulate VFS function defs
#define SERIAL_VFS_ADAPTER(NAME, PORT)                      \
    int32_t NAME##_write(const char* buf, size_t count) {  \
        for (size_t i = 0; i < count; i++) {                \
            serial_write_char(PORT, buf[i]);                \
        }                                                   \
        return (int32_t)count;                             \
    }                                                       \
    int32_t NAME##_write_string(const char* str) {         \
        serial_write_string(PORT, str);                     \
        return (int32_t)strlen(str);                       \
    }

// Function prototypes
void serial_init(int16_t port);
void serial_write_char(int16_t port, char c);
void serial_writestring(int16_t port, const char* str);
int8_t serial_received(int16_t port);
int8_t serial_read_char(int16_t port);
int8_t serial_is_transmit_empty(int16_t port);

void serial_register();

#endif