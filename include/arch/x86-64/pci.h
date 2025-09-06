#ifndef PCI_H
#define PCI_H

#include <stdint.h>

// Represents a device that we found on the PCI Bus
typedef struct pci_device {
    uint16_t bus;
    uint8_t  device;
    uint8_t  function;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t  class_code;
    uint8_t  subclass;
    uint8_t  prog_if;
    uint8_t  revision;
    struct pci_device* next;
} pci_device_t;

void pci_init();
uint32_t pci_read_dword(uint16_t bus, uint8_t device, uint8_t function, uint8_t offset);

const char* pci_class_subclass_to_string(uint8_t class_code, uint8_t subclass);

#endif //PCI_H