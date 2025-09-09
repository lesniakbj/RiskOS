#include <drivers/devdisc.h>
#include <drivers/device.h>
#include <drivers/ide.h>
#include <kernel/log.h>
#include <arch/x86-64/pci.h>
#include <libc/string.h>

static void discover_pci_devices();
// static char* devdisc_parse_pci_device_name(uint8_t class_code, uint8_t subclass);

void devdisc_discover_devices() {
    discover_pci_devices();
}

static void discover_pci_devices() {
    // Scan the PCI bus and gather those devices
    pci_bus_scan();
    pci_device_t* pci_devices = pci_get_devices();

    // For device naming
    static uint8_t scsi_count = 0;
    static uint8_t ide_count = 0;
    static uint8_t sata_count = 0;
    static uint8_t eth_count = 0;
    static uint8_t vga_count = 0;
    static uint8_t gpu_count = 0;
    static uint8_t usb_count = 0;

    while(pci_devices != NULL) {
        // Determine device type and name
        device_type_t dev_type = DEVICE_TYPE_UNKNOWN;
        device_class_t dev_class = DEVICE_CLASS_UNKNOWN;
        char device_name[32] = {0};

        switch(pci_devices->class_code) {
            case 0x01: // Mass Storage Controller
                switch (pci_devices->subclass) {
                    case 0x00: // SCSI Bus Controller
                        format_string_simple(device_name, sizeof(device_name), "scsi%d", scsi_count++);
                        dev_type = DEVICE_TYPE_BLOCK;
                        dev_class = DEVICE_CLASS_DISK;
                        break;
                    case 0x01: // IDE Controller
                        format_string_simple(device_name, sizeof(device_name), "ide%d", ide_count++);
                        dev_type = DEVICE_TYPE_PCI;
                        dev_class = DEVICE_CLASS_PCI_DEVICE;
                        break;
                    case 0x06: // Serial ATA
                        format_string_simple(device_name, sizeof(device_name), "sata%d", sata_count++);
                        dev_type = DEVICE_TYPE_BLOCK;
                        dev_class = DEVICE_CLASS_DISK;
                        break;
                    default:
                        // Skip other mass storage controllers for now
                        pci_devices = pci_devices->next;
                        continue;
                }
                break;

            case 0x02: // Network Controller
                switch(pci_devices->subclass) {
                    case 0x00: // Ethernet Controller
                        format_string_simple(device_name, sizeof(device_name), "eth%d", eth_count++);
                        dev_type = DEVICE_TYPE_NETWORK;
                        dev_class = DEVICE_CLASS_NETWORK;
                        break;
                    default:
                        // Skip other network controllers for now
                        pci_devices = pci_devices->next;
                        continue;
                }
                break;

            case 0x03: // Display Controller
                switch(pci_devices->subclass) {
                    case 0x00: // VGA Compatible Controller
                        format_string_simple(device_name, sizeof(device_name), "vga%d", vga_count++);
                        dev_type = DEVICE_TYPE_DISPLAY;
                        dev_class = DEVICE_CLASS_DISPLAY;
                        break;
                    case 0x02: // 3D Controller (Not VGA-Compatible)
                        format_string_simple(device_name, sizeof(device_name), "gpu%d", gpu_count++);
                        dev_type = DEVICE_TYPE_DISPLAY;
                        dev_class = DEVICE_CLASS_DISPLAY;
                        break;
                    default:
                        // Skip other display controllers for now
                        pci_devices = pci_devices->next;
                        continue;
                }
                break;

            case 0x0C: // Serial Bus Controller
                switch(pci_devices->subclass) {
                    case 0x03: // USB Controller
                        format_string_simple(device_name, sizeof(device_name), "usb%d", usb_count++);
                        dev_type = DEVICE_TYPE_PCI;
                        dev_class = DEVICE_CLASS_PCI_DEVICE;
                        break;
                    default:
                        // Skip other serial bus controllers for now
                        pci_devices = pci_devices->next;
                        continue;
                }
                break;

            default:
                // Skip all other device types
                pci_devices = pci_devices->next;
                continue;
        }

        // Skip bridge devices and other system infrastructure
        if (pci_devices->class_code == 0x06) { // Bridge Device
            pci_devices = pci_devices->next;
            continue;
        }

        // Skip if we didn't create a name
        if (device_name[0] == '\0') {
            pci_devices = pci_devices->next;
            continue;
        }

        // Create and register the device
        device_t* new_dev = device_create(device_name, dev_type, dev_class);
        if (new_dev != NULL) {
            new_dev->vendor_id = pci_devices->vendor_id;
            new_dev->device_id = pci_devices->device_id;
            new_dev->private_data = pci_devices;
            new_dev->private_data_size = sizeof(pci_device_t);

            // TODO: Find and attach the appropriate driver
            // device_driver_t* driver = driver_find(dev_type, dev_class);
            // if (driver && driver->attach) {
            //     driver->attach(new_dev);
            // }

            new_dev->ops = NULL; // TODO: Fill with appropriate device ops
            new_dev->fops = NULL;
            new_dev->parent = NULL;
            new_dev->child = NULL;
            new_dev->next = NULL;
            device_register(new_dev);
        }

        pci_devices = pci_devices->next;
    }
}
