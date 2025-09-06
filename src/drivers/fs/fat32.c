#include <drivers/fs/fat32.h>
#include <drivers/fs/vfs.h>
#include <kernel/log.h>
#include <kernel/heap.h>
#include <libc/string.h>

// This struct holds the functions for filesystem-level operations (mount, lookup, etc)
static file_system_ops_t fat32_fs_ops = {
    .mount = fat32_mount_partition,
    .lookup = fat32_lookup
};

// This struct holds the functions for file-level operations (read, write, etc)
static file_ops_t fat32_file_ops = {
    .read = fat32_read,
    // .write = fat32_write, // Not implemented yet
    // .open = fat32_open,   // Not implemented yet
    // .close = fat32_close, // Not implemented yet
    // .stat = fat32_stat,   // Not implemented yet
};

// This is the main entry point for the driver, called once at kernel startup.
void fat32_init() {
    vfs_register_filesystem("fat32", &fat32_fs_ops);
    LOG_INFO("FAT32 driver registered with VFS.");
}

// This is called by the VFS to mount a partition.
vfs_node_t* fat32_mount_partition(partition_t* partition, const char* name) {
    LOG_INFO("fat32_mount_partition: Attempting to mount partition type 0x%x as '%s'", partition->type, name);

    // 1. Read the BPB from the first sector of the partition.
    uint8_t buffer[512];
    LOG_DEBUG("--> Reading sector 0 from partition...");
    int64_t read_result = partition_read_sectors(partition, 0, 1, buffer);
    if (read_result < 0) {
        LOG_ERR("--> Failed to read BPB sector.");
        return NULL;
    }
    LOG_DEBUG("--> BPB sector read complete.");

    bios_parameter_block_t* bpb = (bios_parameter_block_t*)buffer;

    // 2. Validate the BPB to make sure it's actually FAT32.
    LOG_DEBUG("--> Validating BPB: OEM Name: '%.8s'", bpb->BS_OEMName);
    LOG_DEBUG("--> Boot Signature should be 0x29, found 0x%x", bpb->BS_BootSig);
    LOG_DEBUG("--> Filesystem Type should be 'FAT32   ', found '%.8s'", bpb->BS_FilSysType);

    if (bpb->BS_BootSig != 0x29 || memcmp(bpb->BS_FilSysType, "FAT32   ", 8) != 0) {
        LOG_ERR("--> BPB validation failed. Not a valid FAT32 partition.");
        return NULL;
    }
    LOG_INFO("--> BPB validation passed!");

    // 3. Create a 'volume' struct
    LOG_DEBUG("--> Allocating fat32_volume_t...");
    fat32_volume_t* volume = (fat32_volume_t*)kmalloc(sizeof(fat32_volume_t));
    volume->partition = partition;
    memcpy(&volume->bpb, bpb, sizeof(bios_parameter_block_t));
    LOG_DEBUG("--> Volume struct created.");

    // 4. Create the root VFS node
    LOG_DEBUG("--> Allocating root vfs_node_t...");
    vfs_node_t* root_node = (vfs_node_t*)kmalloc(sizeof(vfs_node_t));
    strcpy(root_node->name, name);
    root_node->flags = VFS_DIR;
    root_node->private_data = volume;
    root_node->inode = bpb->BPB_RootClus;
    root_node->fops = &fat32_file_ops;
    LOG_DEBUG("--> VFS root node created. Inode (root cluster) is %d.", root_node->inode);

    LOG_INFO("FAT32 volume mounted successfully on '%s'.", name);

    return root_node;
}

// --- Stub Functions --- 
// (These need to be implemented to make the filesystem functional)

vfs_node_t* fat32_lookup(struct vfs_node* parent, const char* name) {
    LOG_WARN("fat32_lookup not implemented");
    return NULL;
}

int64_t fat32_read(struct vfs_node *node, uint64_t offset, size_t size, void *buffer) {
    LOG_WARN("fat32_read not implemented");
    return -1;
}