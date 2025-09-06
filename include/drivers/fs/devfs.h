#ifndef DRIVERS_DEVFS_H
#define DRIVERS_DEVFS_H

#include <drivers/fs/vfs.h>

typedef struct devfs_device {
    char name[256];
    file_ops_t* fops;
    struct devfs_device* next;
} devfs_device_t;

void devfs_init();
void devfs_register_device(const char* name, file_ops_t* fops);

#endif