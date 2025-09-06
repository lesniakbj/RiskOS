#ifndef DRIVERS_DISK_H
#define DRIVERS_DISK_H

#include <stdint.h>
#include <drivers/mbrdisk.h>
#include <drivers/gptdisk.h>

typedef struct partition partition_t;

int64_t partition_read_sectors(partition_t* part, uint64_t lba, uint32_t count, void* buffer);

typedef struct disk_device disk_device_t;

typedef int64_t (*read_sectors)(disk_device_t* disk, uint64_t start_sector, uint32_t count, void* buffer);
typedef int64_t (*write_sectors)(disk_device_t* disk, uint64_t start_sector, uint32_t count, const void* buffer);

// Abstraction of single partition on a disk
typedef struct partition {
    disk_device_t*  disk;
    uint64_t        start_sector;
    uint64_t        size_in_sectors;
    uint8_t         type;
} partition_t;

// Abstraction of a physical disk device (AHCI, NVMe, RAM, etc)
typedef struct disk_device {
    char            name[32];
    uint32_t        id;
    read_sectors    read;
    write_sectors   write;
    partition_t     partitions[16];
    int64_t         partition_count;
    void*           assoc_device;
    struct disk_device* next;
} disk_device_t;

void disk_system_init();
void disk_register(disk_device_t* disk);
int64_t partition_read_sectors(partition_t* part, uint64_t sector, uint32_t count, void* buffer);

#endif