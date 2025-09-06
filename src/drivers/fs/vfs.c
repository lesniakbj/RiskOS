#include <drivers/fs/vfs.h>
#include <drivers/fs/tarfs.h>
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
static vfs_node_t* get_mounted_fs_root(vfs_node_t* mount_point_node);

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
        return -1;
    }

    vfs_node_t* mount_node = vfs_open(path);
    if (mount_node == NULL) {
        LOG_ERR("VFS: Mount point '%s' not found.", path);
        return -1;
    }

    vfs_node_t* fs_root = NULL;
    if (fs->fs_ops && fs->fs_ops->mount) {
        fs_root = fs->fs_ops->mount(partition, fs_name);
    }

    mount_point_t* new_mp = (mount_point_t*)kmalloc(sizeof(mount_point_t));
    if (new_mp == NULL) {
        LOG_ERR("VFS: Failed to allocate memory for mount point");
        return -1;
    }

    new_mp->node = mount_node;
    new_mp->fs_root = fs_root;
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
    return 0;
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
            vfs_node_t* fs_root = get_mounted_fs_root(current_node);
            if (fs_root) {
                found_node = mounted_fs->fs_ops->lookup(fs_root, component);
            }
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

vfs_node_t* vfs_root_node() {
    return root_node;
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

void print_vfs_tree(vfs_node_t* node, int depth) {
    if (!node) return;

    // Create indentation string
    char indent[256] = {0};
    for (int i = 0; i < depth && i < (int)(sizeof(indent)/2 - 1); i++) {
        indent[i*2] = ' ';
        indent[i*2 + 1] = ' ';
    }

    // Special case for root
    if (depth == 0 && strcmp(node->name, "/") == 0) {
        LOG_DEBUG("VFS: /");
    } else if (node->flags & VFS_DIR) {
        LOG_DEBUG("VFS: %s%s/", indent, node->name);
    } else {
        if (node->private_data) {
            // Check if it's an executable
            tar_file_data_t* data = (tar_file_data_t*)node->private_data;
            if (node->flags & VFS_EXEC) {
                LOG_DEBUG("VFS: %s%s (%lld bytes) [EXEC]", indent, node->name, data->size);
            } else {
                LOG_DEBUG("VFS: %s%s (%lld bytes)", indent, node->name, data->size);
            }
        } else {
            LOG_DEBUG("VFS: %s%s", indent, node->name);
        }
    }

    // Print all children - both in-memory and from mounted filesystems
    // First print in-memory children
    vfs_node_t* child = node->first_child;
    while (child) {
        print_vfs_tree(child, depth + 1);
        child = child->next_sibling;
    }

    // Then, if this is a mount point, print children from the mounted filesystem
    filesystem_t* mounted_fs = find_mount_point(node);
    if (mounted_fs && mounted_fs->fs_ops && mounted_fs->fs_ops->lookup) {
        vfs_node_t* fs_root = get_mounted_fs_root(node);
        if (fs_root) {
            // Print the mounted filesystem's children by actually traversing them
            vfs_node_t* fs_child = fs_root->first_child;
            while (fs_child) {
                print_vfs_tree(fs_child, depth + 1);
                fs_child = fs_child->next_sibling;
            }
        }
    }
}

void vfs_mount_dir(vfs_node_t *parent, vfs_node_t *mount_dir) {
    if(parent == NULL || mount_dir == NULL) {
        return;
    }

    mount_dir->parent = parent;

    if (parent->first_child == NULL) {
        parent->first_child = mount_dir;
    } else {
        vfs_node_t* sibling = parent->first_child;
        while (sibling->next_sibling != NULL) {
            sibling = sibling->next_sibling;
        }
        sibling->next_sibling = mount_dir;
    }
}

// Add this function to vfs.c:
static vfs_node_t* get_mounted_fs_root(vfs_node_t* mount_point_node) {
    mount_point_t* current = active_mnts;
    while (current) {
        if (current->node == mount_point_node) {
            return current->fs_root;
        }
        current = current->next;
    }
    return NULL;
}