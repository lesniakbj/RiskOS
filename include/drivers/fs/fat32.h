#ifndef DRIVERS_FS_FAT32_H
#define DRIVERS_FS_FAT32_H

#include <stdint.h>
#include <drivers/disk.h>
#include <drivers/fs/vfs.h>

// FAT FS views storage media as a flat array of clusters
// NOTE: We are not supporting the extremely old HD and Floppies that
// do not address their data as a flat list of sectors

// A FAT32 Disk will look something like:
/*
* =======================================================================================
*                            Partitioned Disk Layout (MBR)
* =======================================================================================
*
* This is the typical layout for a hard drive or SSD. The disk starts with an MBR,
* which acts as a map to the partitions. The FAT32 filesystem then resides within
* one of those partitions.
*
* Physical Disk
* +-------------------------------------------------------------------------------------+
* | Sector 0: MBR (Master Boot Record)                                                  |
* | +-------------------------------------------------+-----------------------+-------+ |
* | | Bootstrap Code (446 bytes)                    | Partition Table (64 B)| 0xAA55| |
* | +-------------------------------------------------+-----------------------+-------+ |
* |-------------------------------------------------------------------------------------|
* |                                                                                     |
* | (Usually some empty space for alignment)                                            |
* |                                                                                     |
* |-------------------------------------------------------------------------------------|
* | Partition 1 (Starts at LBA address specified in MBR Partition Table)                |
* | +---------------------------------------------------------------------------------+ |
* | | Sector 0 of Partition: VBR (Volume Boot Record)                             | |
* | | +-------------------------------------------+-----------------------------+ | |
* | | | BPB (BIOS Parameter Block) & Ext. BPB   | More Bootstrap Code         | | |
* | | +-------------------------------------------+-----------------------------+ | |
* | |-----------------------------------------------------------------------------| |
* | | Reserved Sectors (The VBR is the first of these)                          | |
* | |-----------------------------------------------------------------------------| |
* | | FAT #1 (File Allocation Table)                                            | |
* | |-----------------------------------------------------------------------------| |
* | | FAT #2 (A backup copy of FAT #1)                                          | |
 * | |-----------------------------------------------------------------------------| |
* | | Data Area (Root Directory, files, sub-directories are all here)         | |
* | |                                                                         | |
* | | ...                                                                     | |
* | +---------------------------------------------------------------------------------+ |
* |-------------------------------------------------------------------------------------|
* | Partition 2 (Could be another filesystem like ext4, or unallocated space)         |
* | +---------------------------------------------------------------------------------+ |
* | | ...                                                                         | |
* | +---------------------------------------------------------------------------------+ |
* +-------------------------------------------------------------------------------------+
*
* =======================================================================================
*                          Unpartitioned Volume Layout
* =======================================================================================
*
* This is the layout for a device (like a floppy disk) that is not partitioned.
* There is no MBR. The entire disk is one filesystem, so the VBR/BPB starts
* at the very first sector.
*
* Physical Disk
* +-------------------------------------------------------------------------------------+
* | Sector 0: VBR (Volume Boot Record)                                                  |
* | +-------------------------------------------+-------------------------------------+ |
* | | BPB (BIOS Parameter Block) & Ext. BPB   | Bootstrap Code                      | |
* | +-------------------------------------------+-------------------------------------+ |
* |-------------------------------------------------------------------------------------|
* | Reserved Sectors (The VBR is the first of these)                                    |
* |-------------------------------------------------------------------------------------|
* | FAT #1 (File Allocation Table)                                                      |
* |-------------------------------------------------------------------------------------|
* | FAT #2 (A backup copy of FAT #1)                                                    |
* |-------------------------------------------------------------------------------------|
* | Data Area (Root Directory, files, sub-directories are all here)                   |
* |                                                                                   |
* | ...                                                                               |
* +-------------------------------------------------------------------------------------+
*/

// So we neeed...
// The BIOS Parameter Block and Extended BPB for FAT32.
// This entire structure is located at the beginning of a FAT32 partition's
// Volume Boot Record (VBR).
typedef struct bios_parameter_block {
    // --- Common DOS 2.0 BPB ---
    uint8_t  BS_jmpBoot[3];           // Jump instruction to boot code
    char     BS_OEMName[8];           // OEM Name in ASCII
    uint16_t BPB_BytsPerSec;          // Bytes per sector (should be 512, 1024, 2048, or 4096)
    uint8_t  BPB_SecPerClus;          // Sectors per cluster (must be a power of 2)
    uint16_t BPB_RsvdSecCnt;          // Number of reserved sectors at the beginning of the volume
    uint8_t  BPB_NumFATs;             // Number of File Allocation Tables (usually 2)
    uint16_t BPB_RootEntCnt;          // MUST BE 0 for FAT32.
    uint16_t BPB_TotSec16;            // MUST BE 0 for FAT32.
    uint8_t  BPB_Media;               // Media type (e.g., 0xF8 for hard disk)
    uint16_t BPB_FATSz16;             // MUST BE 0 for FAT32. Use BPB_FATSz32 instead.

    // --- Common DOS 3.31 BPB ---
    uint16_t BPB_SecPerTrk;           // Sectors per track (for geometry)
    uint16_t BPB_NumHeads;            // Number of heads (for geometry)
    uint32_t BPB_HiddSec;             // Count of hidden sectors preceding this partition
    uint32_t BPB_TotSec32;            // Total sectors in the volume (if BPB_TotSec16 is 0)

    // --- FAT32 Extended BPB (EBPB) ---
    uint32_t BPB_FATSz32;             // Sectors per FAT. The 32-bit version for FAT32.
    uint16_t BPB_ExtFlags;            // Extended flags (e.g., mirroring)
    uint16_t BPB_FSVer;               // Filesystem version (major/minor)
    uint32_t BPB_RootClus;            // Cluster number of the root directory (usually 2)
    uint16_t BPB_FSInfo;              // Sector number of the FSINFO structure (usually 1)
    uint16_t BPB_BkBootSec;           // Sector number of the backup boot sector (usually 6)
    uint8_t  BPB_Reserved[12];        // Reserved for future expansion
    uint8_t  BS_DrvNum;               // Drive number (for INT 13h)
    uint8_t  BS_Reserved1;            // Reserved (used by Windows NT)
    uint8_t  BS_BootSig;              // Extended boot signature (must be 0x29)
    uint32_t BS_VolID;                // Volume serial number
    char     BS_VolLab[11];           // Volume label (padded with spaces)
    char     BS_FilSysType[8];        // Filesystem type, e.g., "FAT32   "

} __attribute__((packed)) bios_parameter_block_t;

// A FAT32 Filesystem Info Block, used to track info about the filesystems
typedef struct fat32_fs_info {
    uint32_t magic;
    uint8_t  reserved[480];
    uint32_t magic2;
    uint32_t free_cluster_count;
    uint32_t free_cluster_offset;
    uint8_t  reserved2[12];
    uint32_t magic3;
} fat32_fs_info_t;

// Abstraction for a mounted FAT32 filesystem
typedef struct fat32_volume {
    partition_t* partition;
    bios_parameter_block_t bpb;
    // TODO: Fill with cached FAT, and other metadata that is useful
} fat32_volume_t;

void fat32_init();
vfs_node_t* fat32_mount_partition(partition_t* partition, const char* name);

// File Ops
int64_t fat32_read(struct vfs_node *node, uint64_t offset, size_t size, void *buffer);
int64_t fat32_write(struct vfs_node *node, uint64_t offset, size_t size, const void *buffer);
int64_t fat32_open(struct vfs_node *node);
int64_t fat32_close(struct vfs_node *node);
int64_t fat32_stat(struct vfs_node *node, file_stats_t *st);

// Filesystem Ops
vfs_node_t* fat32_mount_partition(partition_t* partition, const char* name);
vfs_node_t* fat32_lookup(vfs_node_t* parent, const char* name);
vfs_node_t* fat32_create(vfs_node_t* parent, const char* name, uint32_t mode);
int64_t fat32_mkdir(vfs_node_t* parent, const char* name, uint32_t mode);
int64_t fat32_rmdir(vfs_node_t* parent, const char* name);

#endif