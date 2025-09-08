#include <drivers/disk.h>
#include <drivers/fs/fat32.h>
#include <kernel/log.h>
#include <kernel/heap.h>

static disk_device_t* disk_devices;

void disk_system_init() {
    LOG_INFO("Initializing the disk system");
    disk_device_t* disk = disk_devices;

    while (disk != NULL) {
        LOG_INFO("Probing disk '%s' for partitions...", disk->name);

        // For each disk, read the first sector to find the MBR.
        uint8_t buffer[512];
        disk->read(disk, 0, 1, buffer);

        master_boot_record_t* mbr = (master_boot_record_t*)buffer;

        // --- DETAILED DEBUGGING ---
        uint16_t magic_from_buffer = *((uint16_t*)&buffer[510]);
        LOG_DEBUG("Value of mbr->magic from struct: 0x%x", mbr->magic);
        LOG_DEBUG("Value of magic from raw buffer:  0x%x", magic_from_buffer);

        // Check the MBR magic number
        if (mbr->magic == 0xAA55) {
            LOG_INFO("-> MBR Magic Found!");

            // It's a valid MBR, so loop through the partition entries.
            for (int i = 0; i < 4; i++) {
                partition_table_entry_t* part = &mbr->partitions[i];
                if (part->type != 0) {
                    partition_t* new_partition = (partition_t*)kmalloc(sizeof(partition_t));
                    if (new_partition == NULL) {
                        LOG_ERR("Failed to allocate memory for partition_t!");
                        continue; // Try next partition
                    }

                    // FIX: Zero-initialize the struct to prevent garbage values.
                    memset(new_partition, 0, sizeof(partition_t));

                    // Populate the new partition_t struct.
                    new_partition->disk = disk; // CRUCIAL: Link to the disk_device_t
                    // FIX: Use the correct field name 'start_sector'
                    new_partition->start_sector = part->start_logic_addr;
                    new_partition->size_in_sectors = part->size_in_sectors;
                    new_partition->type = part->type;

                    LOG_INFO("--> Found Partition %d: Type=0x%x, StartLBA=%d, Size=%d sectors",
                        i + 1, part->type, part->start_logic_addr, part->size_in_sectors);

                    // TODO: We can't just assume that we have a FAT32 here...
                    if(new_partition->type == 0x0C) {
                        fat32_mount_partition(new_partition, disk);
                    }
                }
            }
        } else {
            LOG_WARN("-> No valid MBR found on disk '%s'.", disk->name);
        }

        disk = disk->next;
    }
}

void disk_register(disk_device_t* disk) {
    LOG_INFO("Registering a disk with the disk subsystem...");
    if(disk == NULL) {
        return;
    }

    disk->next = disk_devices;
    disk_devices = disk;
}

int64_t partition_read_sectors(partition_t* part, uint64_t sector, uint32_t count, void* buffer) {
    LOG_DEBUG("partition_read_sectors: Reading from partition starting at sector %llu", part->start_sector);
    if (part == NULL) {
        LOG_ERR("--> ERROR: partition is NULL!");
        return -1;
    }
    if (part->disk == NULL) {
        LOG_ERR("--> ERROR: part->disk is NULL!");
        return -1;
    }
    if (part->disk->read == NULL) {
        LOG_ERR("--> ERROR: part->disk->read function pointer is NULL!");
        return -1;
    }

    uint64_t absolute_sector = part->start_sector + sector;
    LOG_DEBUG("--> Reading %d sectors from partition-relative sector %d (absolute sector %d)", count, sector, absolute_sector);

    LOG_DEBUG("--> Calling underlying disk read function...");
    int64_t result = part->disk->read(part->disk, absolute_sector, count, buffer);
    LOG_DEBUG("--> Underlying disk read function returned %d", result);

    return result;
}