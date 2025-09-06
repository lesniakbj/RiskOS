#include <drivers/ide.h>
#include <kernel/log.h>
#include <kernel/heap.h>
#include <arch/x86-64/io.h>

static void ide_probe_drive(uint16_t channel_base, uint8_t channel_num, uint8_t drive_type);

static ide_device_t* ide_devices;
static uint32_t ide_device_count = 0;

void ide_init() {
    // Step 1: Discover IDE Controllers vai PCI IDE Controller
}

void ide_controller_initialize(pci_device_t* pci_dev) {
    LOG_INFO("Initializing IDE controller for PCI device %d:%d:%d", pci_dev->bus, pci_dev->device, pci_dev->function);
    // An IDE controller has 4 channels (Primary/Secondary, Master/Slave).
    // For a legacy IDE controller, the I/O ports are usually fixed,
    // but the correct way is to read them from the PCI Base Address Registers (BARs).

    // Reading BARs is an advanced topic. For now, we can assume the standard legacy I/O ports.
    uint16_t primary_channel_base = 0x1F0;
    uint16_t secondary_channel_base = 0x170;

    // Check bit 3 of Prog IF. If set, BAR1 contains the secondary channel's base address.
    if (pci_dev->prog_if & 0b00001000) {
        uint32_t bar1 = pci_read_dword(pci_dev->bus, pci_dev->device, pci_dev->function, 0x14);
        secondary_channel_base = bar1 & 0xFFFC;
    }

    LOG_DEBUG("IDE: Primary channel base=0x%x, Secondary channel base=0x%x", primary_channel_base, secondary_channel_base);

    // Now that we have the correct port addresses, probe all four possible drive slots.
    ide_probe_drive(primary_channel_base, ATA_PRIMARY, ATA_MASTER);
    ide_probe_drive(primary_channel_base, ATA_PRIMARY, ATA_SLAVE);
    ide_probe_drive(secondary_channel_base, ATA_SECONDARY, ATA_MASTER);
    ide_probe_drive(secondary_channel_base, ATA_SECONDARY, ATA_SLAVE);
}

// This function sends the IDENTIFY command to a specific drive (e.g., Primary Master)
// to see if it exists and what it is.
static void ide_probe_drive(uint16_t channel_base, uint8_t channel_num, uint8_t drive_type) {
    // --- Step 1: Select the drive and add a delay ---
    outb(channel_base + ATA_REG_HDDEVSEL, 0xA0 | (drive_type << 4));

    // FIX: A 400ns delay is required after selecting a drive.
    // Reading the alternate status port 4 times is the standard way to do this.
    inb(channel_base + ATA_REG_ALTSTATUS);
    inb(channel_base + ATA_REG_ALTSTATUS);
    inb(channel_base + ATA_REG_ALTSTATUS);
    inb(channel_base + ATA_REG_ALTSTATUS);

    // --- Step 2: Send the IDENTIFY command ---
    outb(channel_base + ATA_REG_SECCOUNT0, 0);
    outb(channel_base + ATA_REG_LBA0, 0);
    outb(channel_base + ATA_REG_LBA1, 0);
    outb(channel_base + ATA_REG_LBA2, 0);
    outb(channel_base + ATA_REG_COMMAND, ATA_CMD_IDENTIFY);

    // --- Step 3: Check for the drive's presence ---
    if (inb(channel_base + ATA_REG_STATUS) == 0) {
        return; // No drive.
    }

    // --- Step 4: Poll for completion ---
    while (inb(channel_base + ATA_REG_STATUS) & ATA_SR_BSY);

    uint8_t lba_mid = inb(channel_base + ATA_REG_LBA1);
    uint8_t lba_hi = inb(channel_base + ATA_REG_LBA2);
    if (lba_mid != 0 || lba_hi != 0) {
        return; // This is an ATAPI device.
    }

    while (!(inb(channel_base + ATA_REG_STATUS) & ATA_SR_DRQ)) {
        if (inb(channel_base + ATA_REG_STATUS) & ATA_SR_ERR) {
            LOG_ERR("IDE: Error during IDENTIFY for drive %d:%d", channel_num, drive_type);
            return;
        }
    }

    // --- Step 5: Read the 512-byte identification data ---
    uint16_t identify_data[256];
    for (int i = 0; i < 256; i++) {
        identify_data[i] = inw(channel_base + ATA_REG_DATA);
    }

    // --- Step 6: A drive was found! Create and register it. ---
    LOG_INFO("Found IDE drive on channel %d, %s", channel_num, drive_type == ATA_MASTER ? "Master" : "Slave");

    ide_device_t* device = (ide_device_t*)kmalloc(sizeof(ide_device_t));
    device->present = 1;
    device->channel = channel_num;
    device->drive = drive_type;
    device->type = IDE_ATA;

    // FIX: The size is a 32-bit value at word offset 60.
    // We cast the array of words to a pointer to a 32-bit integer to read it correctly.
    device->size = *((uint32_t*)&identify_data[ATA_IDENT_MAX_LBA / 2]);

    // The model string is 40 bytes (20 words) starting at word 27.
    // The characters in each word are swapped.
    for(int k = 0; k < 20; k++) {
        device->model[k*2] = (char)(identify_data[ATA_IDENT_MODEL / 2 + k] >> 8);
        device->model[k*2+1] = (char)identify_data[ATA_IDENT_MODEL / 2 + k];
    }
    device->model[40] = '\0'; // Null terminate

    LOG_INFO("-> Model: %s, Size: %d MB", device->model, (uint32_t)(device->size * 512 / (1024 * 1024)));

    // Add the new device to our global list
    device->next = ide_devices;
    ide_devices = device;
    ide_device_count++;

    // Finally, announce to the system that we have a new disk
    disk_device_t* new_disk_device = (disk_device_t*)kmalloc(sizeof(disk_device_t));
    strcpy(new_disk_device->name, "hda");       // TODO: name based on slot (1st hda, hdb etc)
    new_disk_device->id                 = 0;    // TODO: call disk_get_next_id(); or generate a GUID
    new_disk_device->read               = ide_read_sectors;
    new_disk_device->write              = ide_write_sectors;
    new_disk_device->partition_count    = 0;
    new_disk_device->assoc_device       = device;
    new_disk_device->next               = NULL;
    disk_register(new_disk_device);
}

int64_t ide_read_sectors(disk_device_t* disk, uint64_t lba, uint32_t count, void* buffer) {
    LOG_DEBUG("ide_read_sectors: Reading %d sectors from LBA %d", count, lba);

    // 1. Get our internal IDE device info from the generic disk struct.
    ide_device_t* ide_dev = (ide_device_t*)disk->assoc_device;
    uint16_t channel_base = ide_dev->channel == ATA_PRIMARY ? 0x1F0 : 0x170;
    LOG_DEBUG("-> Using channel base 0x%x for drive %d:%d", channel_base, ide_dev->channel, ide_dev->drive);

    // 2. Wait until the controller is not busy.
    while (inb(channel_base + ATA_REG_STATUS) & ATA_SR_BSY);
    LOG_DEBUG("-> Drive is not busy.");

    // 3. Select the drive (Master/Slave) and set LBA mode.
    outb(channel_base + ATA_REG_HDDEVSEL, 0xE0 | (ide_dev->drive << 4) | ((lba >> 24) & 0x0F));
    
    // 400ns delay after drive select
    inb(channel_base + ATA_REG_ALTSTATUS);
    inb(channel_base + ATA_REG_ALTSTATUS);
    inb(channel_base + ATA_REG_ALTSTATUS);
    inb(channel_base + ATA_REG_ALTSTATUS);

    // 4. Send the sector count and LBA address.
    outb(channel_base + ATA_REG_SECCOUNT0, count);
    outb(channel_base + ATA_REG_LBA0, (uint8_t)lba);
    outb(channel_base + ATA_REG_LBA1, (uint8_t)(lba >> 8));
    outb(channel_base + ATA_REG_LBA2, (uint8_t)(lba >> 16));

    // 5. Send the READ SECTORS command.
    outb(channel_base + ATA_REG_COMMAND, ATA_CMD_READ_PIO);
    LOG_DEBUG("-> Sent READ_PIO command.");

    // 6. Loop `count` times to read each sector.
    for (uint32_t i = 0; i < count; i++) {
        // Wait for the drive to be ready to send data (BSY clear, DRQ set).
        while (!(inb(channel_base + ATA_REG_STATUS) & ATA_SR_DRQ));
        LOG_DEBUG("--> DRQ set for sector %d. Reading 512 bytes.", i);

        // Read 256 words (512 bytes) from the data port.
        uint16_t* word_buffer = (uint16_t*)((uintptr_t)buffer + (i * 512));
        for (int j = 0; j < 256; j++) {
            word_buffer[j] = inw(channel_base + ATA_REG_DATA);
        }
    }

    // This is the most important log. Let's see what we actually read.
    uint8_t* byte_buffer = (uint8_t*)buffer;
    LOG_INFO("ide_read_sectors: Read complete. MBR magic number should be 0x55AA, found: 0x%x%x", byte_buffer[510], byte_buffer[511]);

    return count; // Success
}

int64_t ide_write_sectors(disk_device_t* disk, uint64_t lba, uint32_t count, const void* buffer) {
    return -1;
}