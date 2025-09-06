#ifndef DRIVERS_MBR_DISK_H
#define DRIVERS_MBR_DISK_H

// Partition Table Entry
typedef struct partition_table_entry {
    uint8_t status;             // 0x80 for bootable, 0x00 otherwise
    uint8_t start_head;         // CHS address (obsolete)
    uint16_t start_sector;      // CHS address (obsolete)
    uint8_t type;               // The partition type (e.g., 0x0C for FAT32 w/ LBA)
    uint8_t end_head;           // CHS address (obsolete)
    uint16_t end_sector;        // CHS address (obsolete)
    uint32_t start_logic_addr;  // The Logical Block Address of the first sector in the partition
    uint32_t size_in_sectors;   // The total number of sectors in the partition
} __attribute__((packed)) partition_table_entry_t;

// Master Boot Record (occupies 1 sector, logical sector 0 of the partition OR beginning of the disk)
typedef struct master_boot_record {
    uint8_t bootstrap_code[446];
    partition_table_entry_t partitions[4];
    uint16_t magic;
} __attribute__((packed)) master_boot_record_t;

#endif