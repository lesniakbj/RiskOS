#include <drivers/serio.h>
#include <drivers/fs/devfs.h>
#include <kernel/log.h>
#include <arch/x86-64/io.h>

int64_t serial_vfs_write(vfs_node_t *node, uint64_t offset, size_t size, const void *buffer) {
    LOG_DEBUG("Serial COM1 write called from user context!");
    LOG_DEBUG("Buffer is %s", buffer);
    (void)node;
    (void)offset;
    serial_writestring(SERIAL_COM1, buffer);
    return size;
}

int64_t serial2_vfs_write(vfs_node_t *node, uint64_t offset, size_t size, const void *buffer) {
    LOG_DEBUG("Serial COM2 write called from user context!");
    LOG_DEBUG("Buffer is %s", buffer);
    (void)node;
    (void)offset;
    serial_writestring(SERIAL_COM2, buffer);
    return size;
}

static file_ops_t serial_ops = {
    .write = serial_vfs_write
};

static file_ops_t serial2_ops = {
    .write = serial2_vfs_write
};

void serial_init(int16_t port) {
    // Disable interrupts
    outb(port + SERIAL_INTERRUPT_REG, DISABLE_INTERRUPTS);

    // Set divisor to 1 (115200 baud)
    outb(port + SERIAL_LINE_REG, ENABLE_BAUD_DIVISOR);
    outb(port + SERIAL_DATA_REG, 0x01);        // Low byte
    outb(port + SERIAL_INTERRUPT_REG, 0x00);   // High byte

    // 8 bits, no parity, one stop bit
    outb(port + SERIAL_LINE_REG, SERIAL_LINE_DATA_BITS_8 | SERIAL_LINE_PARITY_NONE | SERIAL_LINE_STOP_BIT_1);

    // Enable FIFO, clear them, with 14-byte threshold
    outb(port + SERIAL_FIFO_REG, SERIAL_FIFO_ENABLE | SERIAL_FIFO_CLEAR_RECEIVE | SERIAL_FIFO_CLEAR_TRANSMIT | SERIAL_FIFO_TRIGGER_LEVEL_14);

    // RTS/DSR set, enable IRQs
    outb(port + SERIAL_MODEM_REG, SERIAL_MODEM_DTR_ASSERT | SERIAL_MODEM_RTS_ASSERT | SERIAL_MODEM_IRQ_ENABLE);

    // Keep interrupts disabled until we have a proper interrupt handler
    outb(port + SERIAL_INTERRUPT_REG, ENABLE_INTERRUPTS);
}

int8_t serial_received(int16_t port) {
    return inb(port + SERIAL_LINE_STATUS_REG) & SERIAL_LINE_STATUS_DATA_READY;
}

int8_t serial_read_char(int16_t port) {
    while (serial_received(port) == 0);
    return inb(port);
}

int8_t serial_is_transmit_empty(int16_t port) {
    return inb(port + SERIAL_LINE_STATUS_REG) & SERIAL_LINE_STATUS_TRANSMIT_EMPTY;
}

void serial_write_char(int16_t port, char c) {
    while (serial_is_transmit_empty(port) == 0);
    outb(port, c);
}

void serial_writestring(int16_t port, const char* str) {
    while (*str) {
        serial_write_char(port, *str++);
    }
}

void serial_register() {
    devfs_register_device("serial01", &serial_ops);
    devfs_register_device("serial02", &serial2_ops);
}