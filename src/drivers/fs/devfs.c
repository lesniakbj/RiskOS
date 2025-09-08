#include <drivers/fs/devfs.h>
#include <drivers/fs/vfs.h>
#include <kernel/heap.h>
#include <kernel/log.h>
#include <libc/string.h>

static devfs_device_t* device_list_head = NULL;

static vfs_node_t* devfs_lookup(vfs_node_t* parent, const char* name);
static vfs_node_t* devfs_mount(partition_t* partition, const char* name);
static vfs_node_t* devfs_readdir(vfs_node_t* dir_node, uint32_t index);

static file_system_ops_t devfs_ops = {
    .lookup = devfs_lookup,
    .mount = devfs_mount,
    .readdir = devfs_readdir
};

void devfs_init() {
    device_list_head = NULL;
    vfs_register_filesystem("devfs", &devfs_ops);
    LOG_INFO("DEVFS initialized and registered with VFS.");
}

void devfs_register_device(const char* name, file_ops_t* fops) {
    devfs_device_t* new_dev = (devfs_device_t*)kmalloc(sizeof(devfs_device_t));
    if(new_dev == NULL) {
        LOG_ERR("DEVFS: Failed to alloc for device '%s'", name);
        return;
    }

    strcpy(new_dev->name, name);
    new_dev->fops = fops;
    new_dev->next = NULL;

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

static vfs_node_t* devfs_readdir(vfs_node_t* dir_node, uint32_t index) {
    (void)dir_node; // We know this is the /dev directory

    devfs_device_t* current = device_list_head;
    uint32_t i = 0;
    while (current != NULL && i < index) {
        current = current->next;
        i++;
    }

    if (current == NULL) {
        return NULL; // Index out of bounds
    }

    vfs_node_t* node = (vfs_node_t*)kmalloc(sizeof(vfs_node_t));
    if(node == NULL) {
        LOG_ERR("DEVFS: Failed to alloc VFS node for readdir");
        return NULL;
    }

    strcpy(node->name, current->name);
    node->flags = VFS_DEV;
    node->fops = current->fops;
    node->parent = dir_node; // Set parent to the /dev directory node
    node->first_child = NULL;
    node->next_sibling = NULL;
    node->private_data = NULL;

    return node;
}

static vfs_node_t* devfs_lookup(vfs_node_t* parent, const char *name) {
    LOG_INFO("DEVFS: Looking for device '%s'", name);
    devfs_device_t* current = device_list_head;
    while (current != NULL) {
        int cmp = strcmp(name, current->name);
        LOG_DEBUG("DEVFS: Comparing '%s' with '%s', strcmp result: %d", name, current->name, cmp);
        if(cmp == 0) {
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
            LOG_INFO("DEVFS: Found device '%s', fops at 0x%llx", name, (uint64_t)node->fops);
            return node;
        }
        current = current->next;
    }
    LOG_ERR("DEVFS: Failed to find device '%s'", name);
    return NULL;
}

static vfs_node_t* devfs_mount(partition_t* partition, const char* name) {
    (void)partition;

    vfs_node_t* root_node = (vfs_node_t*)kmalloc(sizeof(vfs_node_t));
    if (root_node == NULL) {
        return NULL;
    }

    strcpy(root_node->name, name);
    root_node->flags = VFS_DIR;
    root_node->private_data = NULL;
    root_node->fops = NULL;
    root_node->first_child = NULL; // devfs children are dynamic, not stored here
    root_node->next_sibling = NULL;
    root_node->parent = NULL;

    LOG_INFO("DEVFS: Mount function called, root node created.");
    return root_node;
}
