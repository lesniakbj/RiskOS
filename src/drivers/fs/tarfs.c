#include <drivers/fs/tarfs.h>
#include <kernel/heap.h>
#include <kernel/log.h>
#include <lib/tar.h>
#include <lib/elf.h> // Used to determine if files are executables
#include <libc/string.h>

static int64_t tar_file_read(vfs_node_t *node, uint64_t offset, size_t size, void *buffer);
static int64_t tar_file_write(vfs_node_t *node, uint64_t offset, size_t size, const void *buffer);
static int64_t tar_file_open(vfs_node_t *node);
static int64_t tar_file_close(vfs_node_t *node);
static int64_t tar_file_stat(vfs_node_t *node, file_stats_t *stats);

static vfs_node_t* tar_system_lookup(vfs_node_t *parent, const char *name);
static vfs_node_t* tar_system_mount(partition_t* partition, const char* name);

static vfs_node_t* tarfs_create_node(vfs_node_t* parent, const char* name, uint8_t type, uint8_t* data, int64_t size);
static vfs_node_t* tarfs_create_path(vfs_node_t* root, const char* path, uint8_t type, uint8_t* data, int64_t size);
static bool tarfs_is_executable(uint8_t* data, int64_t size);
static void tarfs_print_tree(vfs_node_t* node, int depth);

static file_ops_t tar_file_ops = {
    .read = tar_file_read,
    .write = tar_file_write,
    .open = tar_file_open,
    .close = tar_file_close,
    .stat = tar_file_stat
};

static file_system_ops_t tar_system_ops = {
    .lookup = tar_system_lookup,
    .mount = tar_system_mount,
    // All others NULL as tarfs does not support them
};

static vfs_node_t* tar_root;

void tarfs_init(struct limine_file* init_tar, const char* root_name) {
    tar_header_list_t* headers = NULL;
    int64_t files = tar_list(init_tar->address, &headers);
    LOG_DEBUG("TARFS: Found %lld files in initramfs", files);

    // Create the root VFS node
    tar_root = tarfs_create_node(NULL, root_name, TAR_DIRECTORY, NULL, 0);
    LOG_DEBUG("TARFS: tar_root after creation: 0x%llx", (uint64_t)tar_root);
    if(!tar_root) {
        LOG_ERR("TARFS: Failed to create TAR root node");
        return;
    }

    // First pass: Create all directories
    tar_header_list_t* cur = headers;
    while(cur != NULL) {
        tar_header_t head = cur->header;
        if (head.type == TAR_DIRECTORY) {
            // Remove trailing slash from directory names
            char dir_name[256];
            memcpy(dir_name, head.filename, sizeof(dir_name) - 1);
            dir_name[sizeof(dir_name) - 1] = '\0';
            
            // Remove trailing slash if present
            size_t len = strlen(dir_name);
            if (len > 0 && dir_name[len - 1] == '/') {
                dir_name[len - 1] = '\0';
            }
            
            tarfs_create_path(tar_root, dir_name, TAR_DIRECTORY, NULL, 0);
        }
        cur = cur->next;
    }

    // Second pass: Create all files
    cur = headers;
    while(cur != NULL) {
        tar_header_t head = cur->header;
        if (head.type == TAR_NORMAL_FILE) {
            // Lookup the file in the TAR to get its information
            uint8_t* file_data = NULL;
            int64_t file_size = tar_lookup(init_tar->address, head.filename, &file_data);
            
            tarfs_create_path(tar_root, head.filename, TAR_NORMAL_FILE, file_data, file_size);
        }
        cur = cur->next;
    }

    vfs_register_filesystem("initramfs", &tar_system_ops);
    vfs_create_directory("init");
    vfs_mount(NULL, "initramfs", "/init");

    // Print the directory tree for debugging
    LOG_DEBUG("TARFS: Root: 0x%llx", (uint64_t)tar_root);
    LOG_DEBUG("TARFS Directory Structure:");
    tarfs_print_tree(tar_root, 0);
    LOG_DEBUG("TARFS: Root: 0x%llx", (uint64_t)tar_root);
}

static vfs_node_t* tarfs_create_path(vfs_node_t* root, const char* path, uint8_t type, uint8_t* data, int64_t size) {
    // Handle absolute paths by skipping leading slash
    const char* current_path = path;
    if (path[0] == '/') {
        current_path = path + 1;
    }
    
    if (!current_path[0]) {
        return root; // Empty path, return root
    }
    
    vfs_node_t* current_node = root;
    
    // Parse path components
    char component[256];
    const char* start = current_path;
    
    while (start && *start) {
        // Find the next slash or end of string
        const char* end = strchr(start, '/');
        bool is_last_component = (end == NULL);
        
        // Extract component
        size_t len;
        if (end) {
            len = end - start;
        } else {
            len = strlen(start);
        }
        
        if (len >= sizeof(component)) {
            len = sizeof(component) - 1;
        }
        
        if (len == 0) {
            // Empty component, move to next
            if (end) {
                start = end + 1;
            } else {
                break;
            }
            continue;
        }
        
        memcpy(component, start, len);
        component[len] = '\0';
        
        // For the last component, we need to create the actual file or directory
        // For intermediate components, we just need to find or create directories
        bool should_create = is_last_component || (end && *(end + 1) == '\0');
        
        // Look for existing child with this name
        vfs_node_t* child = current_node->first_child;
        while (child) {
            if (strcmp(child->name, component) == 0) {
                break;
            }
            child = child->next_sibling;
        }
        
        // Create if not found
        if (!child) {
            uint8_t node_type = is_last_component ? type : TAR_DIRECTORY;
            uint8_t* node_data = is_last_component ? data : NULL;
            int64_t node_size = is_last_component ? size : 0;
            
            child = tarfs_create_node(current_node, component, node_type, node_data, node_size);
            if (!child) {
                return NULL;
            }
        }
        
        current_node = child;
        
        // Move to next component
        if (end) {
            start = end + 1;
        } else {
            break;
        }
    }
    
    return current_node;
}

static void tarfs_print_tree(vfs_node_t* node, int depth) {
    if (!node) return;
    
    // Create indentation string
    char indent[256] = {0};
    for (int i = 0; i < depth && i < sizeof(indent)/2 - 1; i++) {
        indent[i*2] = ' ';
        indent[i*2 + 1] = ' ';
    }
    
    // Print node information
    if (node->flags & VFS_DIR) {
        LOG_DEBUG("TARFS: %s%s/", indent, node->name);
    } else {
        if (node->private_data) {
            tar_file_data_t* data = (tar_file_data_t*)node->private_data;
            if (data->is_exec) {
                LOG_DEBUG("TARFS: %s%s (%lld bytes) [EXEC]", indent, node->name, data->size);
            } else {
                LOG_DEBUG("TARFS: %s%s (%lld bytes)", indent, node->name, data->size);
            }
        } else {
            LOG_DEBUG("TARFS: %s%s", indent, node->name);
        }
    }
    
    // Print children
    vfs_node_t* child = node->first_child;
    while (child) {
        tarfs_print_tree(child, depth + 1);
        child = child->next_sibling;
    }
}

static bool tarfs_is_executable(uint8_t* data, int64_t size) {
    return (size >= 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F');
}

static int64_t tar_file_read(vfs_node_t *node, uint64_t offset, size_t size, void *buffer) {
    if (!node || !node->private_data || !buffer) {
        return -1;
    }

    tar_file_data_t* tar_data = (tar_file_data_t*)node->private_data;

    // Check bounds
    if (offset >= tar_data->size) {
        return 0; // EOF
    }

    // Calculate actual read size
    size_t actual_size = size;
    if (offset + size > tar_data->size) {
        actual_size = tar_data->size - offset;
    }

    // Copy data
    memcpy(buffer, tar_data->data + offset, actual_size);
    return actual_size;
}

static int64_t tar_file_write(vfs_node_t *node, uint64_t offset, size_t size, const void *buffer) {
    // Read only
    return -1;
}

static int64_t tar_file_open(vfs_node_t *node) {
    // Maybe do tracking later, otherwise they're already in memory... no need to open...
    return -1;
}

static int64_t tar_file_close(vfs_node_t *node) {
    // See open
    return -1;
}

static int64_t tar_file_stat(vfs_node_t *node, file_stats_t *stats) {
    if (!node || !stats) {
        return -1;
    }

    tar_file_data_t* tar_data = (tar_file_data_t*)node->private_data;

    memset(stats, 0, sizeof(file_stats_t));
    stats->size_bytes = tar_data->size;
    stats->mode = node->flags;

    return 0;
}

static vfs_node_t* tarfs_create_node(vfs_node_t* parent, const char* name, uint8_t type, uint8_t* data, int64_t size) {
    vfs_node_t* node = kmalloc(sizeof(vfs_node_t));
    if (!node) return NULL;

    memset(node, 0, sizeof(vfs_node_t));
    strcpy(node->name, name);
    node->name[sizeof(node->name) - 1] = '\0';

    if (type == TAR_DIRECTORY) {
        node->flags = VFS_DIR | VFS_READ;
    } else {
        node->flags = VFS_FILE | VFS_READ;
    }

    // Copy private data if this is a file
    if (type == TAR_NORMAL_FILE && data && size > 0) {
        tar_file_data_t* tar_data = kmalloc(sizeof(tar_file_data_t));
        if (tar_data) {
            tar_data->data = kmalloc(size);
            if (tar_data->data) {
                memcpy(tar_data->data, data, size);
                tar_data->size = size;
                tar_data->is_exec = tarfs_is_executable(data, size);
                if(tar_data->is_exec) {
                    node->flags = node->flags | VFS_EXEC;
                }

                node->private_data = tar_data;
                node->fops = &tar_file_ops;
                node->private_data_size = size;
            } else {
                kfree(tar_data);
                kfree(node);
                return NULL;
            }
        } else {
            kfree(node);
            return NULL;
        }
    }

    node->parent = parent;
    node->refcount = 1;

    if (parent) {
        node->next_sibling = parent->first_child;
        parent->first_child = node;
    }

    return node;
}

static vfs_node_t* tar_system_lookup(vfs_node_t *parent, const char *name) {
    LOG_DEBUG("TARFS: Delegated lookup from parent %s for node %s", parent->name, name);

    if (!parent || !name) {
        return NULL;
    }

    // Look for a child with the matching name
    vfs_node_t* child = parent->first_child;
    while (child) {
        if (strcmp(child->name, name) == 0) {
            return child;
        }
        child = child->next_sibling;
    }

    return NULL; // Not found
}

static vfs_node_t* tar_system_mount(partition_t* partition, const char* name) {
    return tar_root;
}

vfs_node_t* tarfs_root() {
    return tar_root;
}