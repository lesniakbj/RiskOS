#ifndef DRIVERS_DEVICE_H
#define DRIVERS_DEVICE_H

#include <stdint.h>
#include <drivers/fs/vfs.h>

typedef enum device_type {
    DEVICE_TYPE_UNKNOWN = 0,
    DEVICE_TYPE_BLOCK,
    DEVICE_TYPE_CHARACTER,
    DEVICE_TYPE_NETWORK,
    DEVICE_TYPE_PCI,
    DEVICE_TYPE_SERIAL,
    DEVICE_TYPE_DISPLAY,
    DEVICE_TYPE_STORAGE
} device_type_t;

typedef enum device_class {
    DEVICE_CLASS_UNKNOWN = 0,
    DEVICE_CLASS_DISK,
    DEVICE_CLASS_KEYBOARD,
    DEVICE_CLASS_MOUSE,
    DEVICE_CLASS_SERIAL_PORT,
    DEVICE_CLASS_DISPLAY,
    DEVICE_CLASS_NETWORK,
    DEVICE_CLASS_USB_DEVICE,
    DEVICE_CLASS_PCI_DEVICE
} device_class_t;

typedef enum device_state {
    DEVICE_STATE_UNKNOWN = 0,
    DEVICE_STATE_INIT,
    DEVICE_STATE_ACTIVE,
    DEVICE_STATE_ERROR,
    DEVICE_STATE_REMOVED
} device_state_t;

typedef enum device_event_type {
    DEVICE_EVENT_ADD = 0,
    DEVICE_EVENT_REMOVE,
    DEVICE_EVENT_CHANGE
} device_event_type_t;

// Forward Declarations
typedef struct device device_t;
typedef struct device_driver device_driver_t;

// Device ops
typedef struct device_ops {
    int64_t (*init)(device_t* device);
    int64_t (*deinit)(device_t* device);
    int64_t (*read)(device_t* device, uint64_t offset, size_t size, void* buffer);
    int64_t (*write)(device_t* device, uint64_t offset, size_t size, const void* buffer);
    int64_t (*ioctl)(device_t* device, uint32_t cmd, void* arg);
} device_ops_t;

struct device {
    char name[64];
    device_type_t type;
    device_class_t class;
    device_state_t state;
    uint32_t vendor_id;
    uint32_t device_id;
    uint64_t instance;
    void* private_data;
    size_t private_data_size;
    device_ops_t* ops;
    file_ops_t* fops;
    device_t* parent;
    device_t* child;
    device_t* next;
};

struct device_driver {
    char name[64];
    device_type_t type;
    device_class_t class;
    int64_t (*probe)(device_t* device);
    int64_t (*attach)(device_t* device);
    int64_t (*detach)(device_t* device);
    device_driver_t* next;
};

typedef struct device_event {
    device_event_type_t type;   // Event type
    device_t* device;           // Device associated with event
    uint64_t timestamp;         // Timestamp of event
} device_event_t;

// Maximum number of events in queue
#define DEVICE_EVENT_QUEUE_SIZE 64

// Device event queue
typedef struct device_event_queue {
    device_event_t events[DEVICE_EVENT_QUEUE_SIZE];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
} device_event_queue_t;

// Function prototypes
void device_manager_init();
device_t* device_create(const char* name, device_type_t type, device_class_t class);
int64_t device_register(device_t* device);
int64_t device_unregister(device_t* device);
device_t* device_find_by_name(const char* name);
device_t* device_find_by_id(uint64_t instance_id);
int64_t device_init(device_t* device);
int64_t device_deinit(device_t* device);

// Driver functions
int64_t driver_register(device_driver_t* driver);
device_driver_t* driver_find(device_type_t type, device_class_t class);

// Event functions
int64_t device_event_queue_push(device_event_type_t type, device_t* device);
int64_t device_event_queue_pop(device_event_t* event);
int64_t device_event_queue_count();

// VFS integration
int64_t device_vfs_populate();

#endif
