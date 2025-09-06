#include <drivers/fs/devfs.h>
#include <drivers/fs/vfs.h>
#include <kernel/heap.h>
#include <kernel/log.h>
#include <libc/string.h>

static devfs_device_t* device_list_head = NULL;

static vfs_node_t* devfs_lookup(vfs_node_t* parent, const char* name);
static vfs_node_t* devfs_mount(partition_t* partition, const char* name);

static file_system_ops_t devfs_ops = {
    .lookup = devfs_lookup,
    .mount = devfs_mount
};

void devfs_init() {
    device_list_head = NULL;

    // TODO: Initialze the first device in the list (console) and add it to the list
    vfs_register_filesystem("devfs", &devfs_ops);
    LOG_INFO("DEVFS initialized and registered with VFS.");
}

void devfs_register_device(const char* name, file_ops_t* fops) {
    devfs_device_t* new_dev = (devfs_device_t*)kmalloc(sizeof(devfs_device_t));
    if(new_dev == NULL) {
        LOG_ERR("DEVFS: Failed to alloc for device '%s'", name);
        return;
    }

    // Populate device info
    strcpy(new_dev->name, name);
    new_dev->fops = fops;
    new_dev->next = NULL;

    // Append to the list
    if (device_list_head == NULL) {
        device_list_head = new_dev;
    } else {
        devfs_device_t* current = device_list_head;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = new_dev;
    }
    LOG_INFO("DEVFS: Registered device '%s'", name);
}

static vfs_node_t* devfs_lookup(vfs_node_t* parent, const char *name) {
    LOG_INFO("DEVFS: Looking for device %s", name);
    devfs_device_t* current = device_list_head;
    while (current != NULL) {
        if(strcmp(name, current->name) == 0) {
            vfs_node_t* node = (vfs_node_t*)kmalloc(sizeof(vfs_node_t));
            if(node == NULL) {
                LOG_ERR("DEVFS: Failed to alloc VFS node for lookup");
                return NULL;
            }

            strcpy(node->name, name);
            node->flags = VFS_DEV;
            node->parent = parent;
            node->fops = current->fops;
            node->first_child = NULL;
            node->next_sibling = NULL;
            return node;
        }
        current = current->next;
    }
    LOG_ERR("DEVFS: Failed to find device");
    return NULL;
}

// This is the new mount function for devfs.
static vfs_node_t* devfs_mount(partition_t* partition, const char* name) {
    // devfs is a virtual filesystem, so it doesn't use a partition.
    // We can ignore the 'partition' argument.
    (void)partition;

    // Create a root node for the devfs mount point.
    vfs_node_t* root_node = (vfs_node_t*)kmalloc(sizeof(vfs_node_t));
    if (root_node == NULL) {
        return NULL;
    }

    strcpy(root_node->name, name);
    root_node->flags = VFS_DIR;
    root_node->private_data = NULL; // devfs doesn't need volume-specific data
    root_node->fops = NULL; // Directories don't have file ops, they have fs_ops

    LOG_INFO("DEVFS: Mount function called, root node created.");
    return root_node;
}