#ifndef DRIVER_VFS_H
#define DRIVER_VFS_H

#include <stdint.h>
#include <stddef.h>
#include <drivers/disk.h>
#include <libc/string.h>

#define VFS_FILE    (1 << 1)
#define VFS_DIR     (1 << 2)
#define VFS_DEV     (1 << 3)
#define VFS_READ    (1 << 4)
#define VFS_WRITE   (1 << 5)

struct vfs_node;
struct mount_point;

// File stats
typedef struct file_stats {
    uint64_t device_id;
    uint64_t inode;
    uint32_t mode;
    uint32_t num_links;
    uint64_t size_bytes;
    uint64_t num_blocks;
    uint64_t access_time;
    uint64_t modified_time;
    uint64_t create_time;
} file_stats_t;

typedef struct file_ops {
    int64_t (*write)(struct vfs_node *node, uint64_t offset, size_t size, const void *buffer);
    int64_t (*read)(struct vfs_node *node, uint64_t offset, size_t size, void *buffer);
    int64_t (*open)(struct vfs_node *node);
    int64_t (*close)(struct vfs_node *node);
    int64_t (*stat)(struct vfs_node *node, file_stats_t *stats);
} file_ops_t;

typedef struct file_system_ops {
    struct vfs_node* (*create)(struct vfs_node *parent, const char *name, uint32_t mode);
    struct vfs_node* (*lookup)(struct vfs_node *parent, const char *name);
    int64_t (*mkdir)(struct vfs_node *parent, const char *name, uint32_t mode);
    int64_t (*rmdir)(struct vfs_node *parent, const char *name);
    struct vfs_node* (*mount)(partition_t* partition, const char* name);
} file_system_ops_t;

typedef struct vfs_node {
    char name[256];
    uint32_t flags;
    uint32_t refcount;
    uint64_t inode;
    uint64_t length;
    file_ops_t *fops;
    void* private_data;
    struct vfs_node *parent;
    struct vfs_node *first_child;
    struct vfs_node *next_sibling;
    struct mount_point *mount_point;
} vfs_node_t;

typedef struct filesystem {
    char name[256];
    struct file_system_ops *fs_ops;
    struct filesystem *next;
} filesystem_t;

typedef struct mount_point {
    struct vfs_node *node;
    struct filesystem *fs;
    struct mount_point *next;
} mount_point_t;

void vfs_init();
void vfs_create_directory(const char* dir_name);

void vfs_register_filesystem(const char *name, file_system_ops_t *fs_ops);
int64_t vfs_mount(partition_t* partition, const char* path, const char* fs_type);

vfs_node_t* vfs_open(const char *path);
int64_t vfs_write(vfs_node_t *node, uint64_t offset, size_t size, const void *buffer);
int64_t vfs_read(vfs_node_t *node, uint64_t offset, size_t size, void *buffer);

#endif