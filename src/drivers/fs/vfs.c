#include <drivers/fs/vfs.h>
#include <kernel/heap.h>
#include <libc/string.h>
#include <kernel/log.h>

// User visible directory structure
static vfs_node_t *root_node = NULL;

// List of registered filesystems
static filesystem_t *registered_fs = NULL;

// List of all active mnts
static mount_point_t *active_mnts = NULL;

// Forward declarations for internal helpers
static filesystem_t* find_mount_point(vfs_node_t* node);

void vfs_init() {
    registered_fs = NULL;
    active_mnts = NULL;

    root_node = (vfs_node_t*)kmalloc(sizeof(vfs_node_t));
    if (root_node == NULL) {
        LOG_ERR("VFS: Failed to allocate memory for root node!");
        return;
    }

    strcpy(root_node->name, "/");
    root_node->flags = VFS_DIR | VFS_READ | VFS_WRITE;
    root_node->fops = NULL;
    root_node->parent = NULL;
    root_node->first_child = NULL;
    root_node->next_sibling = NULL;

    LOG_INFO("VFS initialized. Root node at 0x%llx", (uint64_t)root_node);
}

void vfs_create_directory(const char* name) {
    if (root_node == NULL || name == NULL || name[0] == '\0') {
        return;
    }

    vfs_node_t* new_dir = (vfs_node_t*)kmalloc(sizeof(vfs_node_t));
    if (new_dir == NULL) {
        LOG_ERR("VFS: Failed to allocate memory for directory '%s'", name);
        return;
    }

    strcpy(new_dir->name, name);
    new_dir->flags = VFS_DIR | VFS_READ | VFS_WRITE;
    new_dir->fops = NULL;
    new_dir->parent = root_node;
    new_dir->first_child = NULL;
    new_dir->next_sibling = NULL;

    if (root_node->first_child == NULL) {
        root_node->first_child = new_dir;
    } else {
        vfs_node_t* sibling = root_node->first_child;
        while (sibling->next_sibling != NULL) {
            sibling = sibling->next_sibling;
        }
        sibling->next_sibling = new_dir;
    }

    LOG_INFO("VFS: Created directory '/%s'", name);
}

void vfs_register_filesystem(const char *name, file_system_ops_t *fs_ops) {
    filesystem_t* new_fs = (filesystem_t*)kmalloc(sizeof(filesystem_t));
    if (new_fs == NULL) {
        LOG_ERR("VFS: Failed to allocate memory for new filesystem");
        return;
    }

    strcpy(new_fs->name, name);
    new_fs->fs_ops = fs_ops;
    new_fs->next = NULL;

    if (registered_fs == NULL) {
        registered_fs = new_fs;
    }
    else {
        filesystem_t* current = registered_fs;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = new_fs;
    }
}

int64_t vfs_mount(partition_t* partition, const char* fs_name, const char* path) {
    filesystem_t* fs = registered_fs;
    while (fs != NULL) {
        if (strcmp(fs_name, fs->name) == 0) break;
        fs = fs->next;
    }

    if (fs == NULL) {
        LOG_ERR("VFS: Filesystem '%s' not registered.", fs_name);
        return;
    }

    vfs_node_t* mount_node = vfs_open(path);
    if (mount_node == NULL) {
        LOG_ERR("VFS: Mount point '%s' not found.", path);
        return;
    }

    mount_point_t* new_mp = (mount_point_t*)kmalloc(sizeof(mount_point_t));
    if (new_mp == NULL) {
        LOG_ERR("VFS: Failed to allocate memory for mount point");
        return;
    }

    new_mp->node = mount_node;
    new_mp->fs = fs;
    new_mp->next = NULL;

    if (active_mnts == NULL) {
        active_mnts = new_mp;
    } else {
        mount_point_t* current = active_mnts;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = new_mp;
    }

    LOG_INFO("VFS: Mounted '%s' at '%s'", fs_name, path);
}

vfs_node_t* vfs_open(const char *path) {
    LOG_DEBUG("VFS: Attempting to open path: '%s'", path);

    if (path == NULL || path[0] != '/') {
        LOG_ERR("VFS: Path must be absolute.");
        return NULL;
    }

    if (strcmp(path, "/") == 0) {
        LOG_DEBUG("VFS: Opening root node.");
        return root_node;
    }

    vfs_node_t* current_node = root_node;
    const char* path_ptr = path;

    while (*path_ptr != '\0') {
        // Skip leading slashes
        while (*path_ptr == '/') {
            path_ptr++;
        }

        if (*path_ptr == '\0') {
            break; // End of path
        }

        // Find the end of the current path component
        const char* component_end = path_ptr;
        while (*component_end != '/' && *component_end != '\0') {
            component_end++;
        }

        // Extract the component into a temporary buffer
        char component[256];
        size_t component_len = component_end - path_ptr;
        if (component_len >= 256) {
            LOG_ERR("VFS: Path component too long.");
            return NULL;
        }
        memcpy(component, path_ptr, component_len);
        component[component_len] = '\0';

        LOG_DEBUG("VFS: Processing component: '%s'", component);

        // --- Perform lookup --- 
        filesystem_t* mounted_fs = find_mount_point(current_node);
        vfs_node_t* found_node = NULL;

        if (mounted_fs && mounted_fs->fs_ops && mounted_fs->fs_ops->lookup) {
            LOG_DEBUG("VFS: Delegating lookup to mounted FS '%s'", mounted_fs->name);
            found_node = mounted_fs->fs_ops->lookup(current_node, component);
        } else {
            LOG_DEBUG("VFS: Traversing in-memory children.");
            vfs_node_t* child = current_node->first_child;
            while(child) {
                if (strcmp(component, child->name) == 0) {
                    found_node = child;
                    break;
                }
                child = child->next_sibling;
            }
        }

        if (found_node == NULL) {
            LOG_ERR("VFS: Path not found: component '%s' does not exist.", component);
            return NULL; // Path component not found
        }
        
        current_node = found_node;
        path_ptr = component_end;
        LOG_DEBUG("VFS: Found node for '%s' at 0x%llx", component, (uint64_t)current_node);
    }

    LOG_DEBUG("VFS: Successfully opened path.");
    return current_node;
}

int64_t vfs_write(vfs_node_t *node, uint64_t offset, size_t size, const void *buffer) {
    if (node == NULL || node->fops == NULL || node->fops->write == NULL) {
        return -1; // Or some other error code
    }
    LOG_DEBUG("VFS: Writing to %s, message: %s", node->name, buffer);
    return node->fops->write(node, offset, size, buffer);
}

int64_t vfs_read(vfs_node_t *node, uint64_t offset, size_t size, void *buffer) {
    if (node == NULL || node->fops == NULL || node->fops->read == NULL) {
        return -1; // Or some other error code
    }
    return node->fops->read(node, offset, size, buffer);
}

static filesystem_t* find_mount_point(vfs_node_t* node) {
    mount_point_t* current = active_mnts;
    while (current) {
        if (current->node == node) {
            return current->fs;
        }
        current = current->next;
    }
    return NULL;
}
