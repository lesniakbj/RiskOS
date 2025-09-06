#include <arch/x86-64/pci.h>
#include <arch/x86-64/io.h>
#include <kernel/log.h>
#include <kernel/heap.h>

#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

static void pci_write_dword(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset, uint32_t value);
static uint16_t pci_get_vendor_id(uint8_t bus, uint8_t device, uint8_t function);
static uint16_t pci_get_device_id(uint8_t bus, uint8_t device, uint8_t function);
static uint8_t pci_get_class_code(uint8_t bus, uint8_t device, uint8_t function);
static uint8_t pci_get_subclass(uint8_t bus, uint8_t device, uint8_t function);

static void pci_check_device(uint16_t bus, uint8_t device);
static void pci_probe_function(uint16_t bus, uint8_t device, uint8_t function);
static void pci_device_found(pci_device_t* device);
static uint8_t pci_get_header_type(uint16_t bus, uint8_t device, uint8_t function);

static pci_device_t *devices = NULL;
static uint32_t num_devices = 0;

void pci_init() {
    LOG_INFO("PCI bus scan...");
    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint8_t device = 0; device < 32; device++) {
            pci_check_device(bus, device);
        }
    }


    LOG_INFO("PCI bus scan complete. Found %d devices.", num_devices);
    // TODO: Using ACPI, find RSDP->XSDT, interate XSDT to find MCFG table, == MMIO to devices
}

const char* pci_class_subclass_to_string(uint8_t class_code, uint8_t subclass) {
    switch (class_code) {
        case 0x00: return "Unclassified";
        case 0x01:
            switch (subclass) {
                case 0x00: return "SCSI Bus Controller";
                case 0x01: return "IDE Controller";
                case 0x02: return "Floppy Disk Controller";
                case 0x03: return "IPI Bus Controller";
                case 0x04: return "RAID Controller";
                case 0x05: return "ATA Controller";
                case 0x06: return "Serial ATA";
                case 0x07: return "Serial Attached SCSI";
                case 0x08: return "Non-Volatile Memory Controller";
                default: return "Mass Storage Controller";
            }
        case 0x02:
            switch (subclass) {
                case 0x00: return "Ethernet Controller";
                case 0x01: return "Token Ring Controller";
                case 0x02: return "FDDI Controller";
                case 0x03: return "ATM Controller";
                case 0x04: return "ISDN Controller";
                case 0x05: return "WorldFip Controller";
                case 0x06: return "PICMG 2.14 Multi-Computing";
                case 0x07: return "Infiniband Controller";
                case 0x08: return "Fabric Controller";
                default: return "Network Controller";
            }
        case 0x03:
            switch (subclass) {
                case 0x00: return "VGA Compatible Controller";
                case 0x01: return "XGA Controller";
                case 0x02: return "3D Controller (Not VGA-Compatible)";
                default: return "Display Controller";
            }
        case 0x04:
            switch (subclass) {
                case 0x00: return "Multimedia Video Controller";
                case 0x01: return "Multimedia Audio Controller";
                case 0x02: return "Computer Telephony Device";
                case 0x03: return "Audio Device";
                default: return "Multimedia Controller";
            }
        case 0x05:
            switch (subclass) {
                case 0x00: return "RAM Controller";
                case 0x01: return "Flash Controller";
                default: return "Memory Controller";
            }
        case 0x06:
            switch (subclass) {
                case 0x00: return "Host Bridge";
                case 0x01: return "ISA Bridge";
                case 0x02: return "EISA Bridge";
                case 0x03: return "MCA Bridge";
                case 0x04: return "PCI-to-PCI Bridge";
                case 0x05: return "PCMCIA Bridge";
                case 0x06: return "NuBus Bridge";
                case 0x07: return "CardBus Bridge";
                case 0x08: return "RACEway Bridge";
                case 0x09: return "PCI-to-PCI Bridge";
                case 0x0A: return "InfiniBand-to-PCI Host Bridge";
                default: return "Bridge Device";
            }
        case 0x07:
            switch (subclass) {
                case 0x00: return "Serial Controller";
                case 0x01: return "Parallel Controller";
                case 0x02: return "Multiport Serial Controller";
                case 0x03: return "Modem";
                case 0x04: return "GPIB (IEEE 488.1/2) Controller";
                case 0x05: return "Smart Card";
                default: return "Simple Communication Controller";
            }
        case 0x08:
            switch (subclass) {
                case 0x00: return "PIC";
                case 0x01: return "DMA Controller";
                case 0x02: return "Timer";
                case 0x03: return "RTC Controller";
                case 0x04: return "PCI Hot-Plug Controller";
                case 0x05: return "SD Host controller";
                case 0x06: return "IOMMU";
                default: return "Base System Peripheral";
            }
        case 0x09:
            switch (subclass) {
                case 0x00: return "Keyboard Controller";
                case 0x01: return "Digitizer Pen";
                case 0x02: return "Mouse Controller";
                case 0x03: return "Scanner Controller";
                case 0x04: return "Gameport Controller";
                default: return "Input Device Controller";
            }
        case 0x0A:
            switch (subclass) {
                case 0x00: return "Generic";
                default: return "Docking Station";
            }
        case 0x0B:
            switch (subclass) {
                case 0x00: return "386";
                case 0x01: return "486";
                case 0x02: return "Pentium";
                case 0x10: return "Alpha";
                case 0x20: return "PowerPC";
                case 0x30: return "MIPS";
                case 0x40: return "Co-Processor";
                default: return "Processor";
            }
        case 0x0C:
            switch (subclass) {
                case 0x00: return "FireWire (IEEE 1394) Controller";
                case 0x01: return "ACCESS Bus";
                case 0x02: return "SSA";
                case 0x03: return "USB Controller";
                case 0x04: return "Fibre Channel";
                case 0x05: return "SMBus";
                case 0x06: return "InfiniBand";
                case 0x07: return "IPMI Interface";
                case 0x08: return "SERCOS Interface (IEC 61491)";
                case 0x09: return "CANbus";
                default: return "Serial Bus Controller";
            }
        case 0x0D: return "Wireless Controller";
        case 0x0E: return "Intelligent Controller";
        case 0x0F: return "Satellite Communication Controller";
        case 0x10: return "Encryption Controller";
        case 0x11: return "Signal Processing Controller";
        case 0x12: return "Processing Accelerator";
        case 0x13: return "Non-Essential Instrumentation";
        case 0x40: return "Co-Processor";
        case 0xFF: return "Unassigned Class (Vendor specific)";
        default: return "Unknown";
    }
}

// Checks a specific bus/device slot for functions.
static void pci_check_device(uint16_t bus, uint8_t device) {
    // First check function 0
    uint32_t vendor_device = pci_read_dword(bus, device, 0, 0x00);
    if ((vendor_device & 0xFFFF) == 0xFFFF) {
        return;
    }

    // Probe the function since it exists...
    pci_probe_function(bus, device, 0);

    // Check if it's a multi-function device.
    // The header type is at offset 0x0E. Bit 7 is the multi-function flag.
    uint8_t header_type = pci_get_header_type(bus, device, 0);
    if ((header_type & 0x80) != 0) {
        // It is a multi-function device, so check functions 1 through 7.
        for (uint8_t function = 1; function < 8; function++) {
            vendor_device = pci_read_dword(bus, device, function, 0x00);
            if ((vendor_device & 0xFFFF) != 0xFFFF) {
                pci_probe_function(bus, device, function);
            }
        }
    }
}

static void pci_probe_function(uint16_t bus, uint8_t device, uint8_t function) {
    // If we don't have any devices yet, create the first one, otherwise allocate a new one and add it to our list.
    pci_device_t* new_device = (pci_device_t*)kmalloc(sizeof(pci_device_t));
    if (new_device == NULL) {
        LOG_ERR("PCI: Failed to allocate memory for device node!");
        return;
    }

    uint32_t vendor_device = pci_read_dword(bus, device, function, 0x00);
    uint32_t class_rev = pci_read_dword(bus, device, function, 0x08);

    new_device->bus         = bus;
    new_device->device      = device;
    new_device->function    = function;
    new_device->vendor_id   = vendor_device & 0xFFFF;
    new_device->device_id   = vendor_device >> 16;
    new_device->class_code  = (class_rev >> 24) & 0xFF;
    new_device->subclass    = (class_rev >> 16) & 0xFF;
    new_device->prog_if     = (class_rev >> 8) & 0xFF;
    new_device->revision    = class_rev & 0xFF;

    // Link to the head of the device list
    new_device->next = devices;
    devices = new_device;

    pci_device_found(new_device);
    num_devices++;
}

// Dispatches the device to the correct subsystem (SATA, IDE, etc)
static void pci_device_found(pci_device_t* pci_dev) {
    const char* class_str = pci_class_subclass_to_string(pci_dev->class_code, pci_dev->subclass);
    LOG_INFO("Found PCI device %d:%d:%d - V:0x%x, D:0x%x, %s",
        pci_dev->bus, pci_dev->device, pci_dev->function, pci_dev->vendor_id,
        pci_dev->device_id, class_str);

    switch (pci_dev->class_code) {
        case 0x01:  // Mass Storage Controller
            if(pci_dev->subclass == 0x01) { // IDE Controller
                LOG_INFO("-> Handing off to Disk Driver...");
                // TODO: Fix disk and ide initialization
                // ide_controller_initialize(pci_dev);
            }
            break;
    }
}

static uint8_t pci_get_header_type(uint16_t bus, uint8_t device, uint8_t function) {
    uint32_t reg = pci_read_dword(bus, device, function, 0x0C);
    return (reg >> 16) & 0xFF;
}

uint32_t pci_read_dword(uint16_t bus, uint8_t device, uint8_t function, uint8_t offset) {
    uint32_t address = (uint32_t)((bus << 16) | (device << 11) | (function << 8) | (offset & 0xFC) | 0x80000000);
    outl(PCI_CONFIG_ADDRESS, address);
    return inl(PCI_CONFIG_DATA);
}

static void pci_write_dword(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset, uint32_t value) {
    uint32_t address = (uint32_t)((bus << 16) | (device << 11) | (function << 8) | (offset & 0xFC) | 0x80000000);
    outl(PCI_CONFIG_ADDRESS, address);
    outl(PCI_CONFIG_DATA, value);
}

static uint16_t pci_get_vendor_id(uint8_t bus, uint8_t device, uint8_t function) {
    uint32_t reg = pci_read_dword(bus, device, function, 0x00);
    return reg & 0xFFFF;
}

static uint16_t pci_get_device_id(uint8_t bus, uint8_t device, uint8_t function) {
    uint32_t reg = pci_read_dword(bus, device, function, 0x00);
    return reg >> 16;
}

static uint8_t pci_get_class_code(uint8_t bus, uint8_t device, uint8_t function) {
    uint32_t reg = pci_read_dword(bus, device, function, 0x08);
    return (reg >> 24) & 0xFF;
}

static uint8_t pci_get_subclass(uint8_t bus, uint8_t device, uint8_t function) {
    uint32_t reg = pci_read_dword(bus, device, function, 0x08);
    return (reg >> 16) & 0xFF;
}