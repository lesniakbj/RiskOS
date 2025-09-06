#ifndef DRIVERS_FS_TARFS_H
#define DRIVERS_FS_TARFS_H

#include <stdint.h>
#include <stdbool.h>
#include <kernel/limine.h>
#include <drivers/fs/vfs.h>

typedef struct tar_file_data {
    uint8_t* data;
    int64_t size;
    bool is_exec;
} tar_file_data_t;

void tarfs_init(struct limine_file* init_tar, const char* root_name);
vfs_node_t* tarfs_root();

#endif