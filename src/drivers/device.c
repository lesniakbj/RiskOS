#include <drivers/device.h>
#include <kernel/heap.h>
#include <kernel/time.h>
#include <kernel/log.h>
#include <libc/string.h>

// Global device list, driver list and event queue
static device_t* device_list = NULL;
static device_driver_t* driver_list = NULL;
static device_event_queue_t event_queue = {0};

void device_manager_init() {
    device_list = NULL;
    driver_list = NULL;
    LOG_INFO("DEV: Device manager initialized");
}

device_t* device_create(const char* name, device_type_t type, device_class_t class) {
    device_t* device;
    SAFE_ALLOC(device, device_t*, "DEV: Failed to allocated memory for device: %s", name, return NULL);

    // Init the device
    memset(device, 0, sizeof(device_t));
    strcpy(device->name, name);
    device->name[sizeof(device->name) - 1] = '\0';
    device->type = type;
    device->class = class;
    device->state = DEVICE_STATE_UNKNOWN;

    // TODO: Replace with GUID generation via systime/rand/etc
    device->instance = 0;

    LOG_INFO("DEV: Created device '%s' (type: %d, class: %d)", name, type, class);
    return device;
}

int64_t device_register(device_t* device) {
    if(!device) {
        LOG_ERR("DEV: Cannot register a NULL device");
        return -1;
    }

    // Add to the device list
    device->next = device_list;
    device_list = device;

    // TODO: Ensure init happens before registration
    device->state = DEVICE_STATE_INIT;
    device_event_queue_push(DEVICE_EVENT_ADD, device);

    LOG_INFO("DEV: Registered device '%s'", device->name);
    return 0;
}

int64_t device_unregister(device_t* device) {
   if(!device) {
       LOG_ERR("DEV: Cannot unregister a NULL device");
       return -1;
   }

   // Remove from the device list
   if (device_list == device) {
    device_list = device->next;
    } else {
        device_t* current = device_list;
        while (current && current->next != device) {
            current = current->next;
        }
        if (current) {
            current->next = device->next;
        } else {
            LOG_ERR("DEV: Device not found in global list");
            return -1;
        }
    }

    device_event_queue_push(DEVICE_EVENT_REMOVE, device);
    device->state = DEVICE_STATE_REMOVED;

    LOG_INFO("DEV: Unregistered device '%s'", device->name);
    return 0;
}

device_t* device_find_by_name(const char* name) {
    device_t* current = device_list;
    while (current) {
        if (strcmp(current->name, name) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

device_t* device_find_by_id(uint64_t instance_id) {
    device_t* current = device_list;
    while (current) {
        if (current->instance == instance_id) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

int64_t device_init(device_t* device) {
   if(!device) {
       LOG_ERR("DEV: Cannot init a NULL device");
       return -1;
   }

    if (device->ops && device->ops->init) {
        int64_t result = device->ops->init(device);
        if (result == 0) {
            device->state = DEVICE_STATE_ACTIVE;
            LOG_INFO("DEV: Device '%s' initialized successfully", device->name);
        } else {
            device->state = DEVICE_STATE_ERROR;
            LOG_ERR("DEV: Failed to initialize device '%s'", device->name);
        }
        return result;
    }

    // No init function, just mark as active
    device->state = DEVICE_STATE_ACTIVE;
    LOG_INFO("DEV: Device '%s' marked as active (no init function)", device->name);
    return 0;
}

int64_t device_deinit(device_t* device) {
    if (!device) {
        LOG_ERR("DEV: Cannot deinitialize NULL device");
        return -1;
    }

    if (device->ops && device->ops->deinit) {
        int64_t result = device->ops->deinit(device);
        if (result == 0) {
            device->state = DEVICE_STATE_INIT;
            LOG_INFO("DEV: Device '%s' deinitialized successfully", device->name);
        } else {
            device->state = DEVICE_STATE_ERROR;
            LOG_ERR("DEV: Failed to deinitialize device '%s'", device->name);
        }
        return result;
    }

    // No deinit function, just mark as initialized
    device->state = DEVICE_STATE_INIT;
    LOG_INFO("DEV: Device '%s' marked as initialized (no deinit function)", device->name);
    return 0;
}

int64_t driver_register(device_driver_t* driver) {
    if (!driver) {
        LOG_ERR("DEV: Cannot register NULL driver");
        return -1;
    }

    // Add to global driver list
    driver->next = driver_list;
    driver_list = driver;

    LOG_INFO("DEV: Registered driver '%s'", driver->name);
    return 0;
}

device_driver_t* driver_find(device_type_t type, device_class_t class) {
    device_driver_t* current = driver_list;
    while (current) {
        if (current->type == type && current->class == class) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

int64_t device_event_queue_push(device_event_type_t type, device_t* device) {
    if (!device) {
        LOG_ERR("DEV: Cannot queue event for NULL device");
        return -1;
    }

    // Check if queue is full
    if (event_queue.count >= DEVICE_EVENT_QUEUE_SIZE) {
        LOG_WARN("DEV: Device event queue is full, dropping event");
        return -1;
    }

    // Add event to queue
    uint32_t index = event_queue.tail % DEVICE_EVENT_QUEUE_SIZE;
    event_queue.events[index].type = type;
    event_queue.events[index].device = device;
    event_queue.events[index].timestamp = system_get_ticks(); // Assuming this function exists

    event_queue.tail++;
    event_queue.count++;

    LOG_DEBUG("DEV: Queued event %d for device '%s'", type, device->name);
    return 0;
}

int64_t device_event_queue_pop(device_event_t* event) {
    if (!event) {
        LOG_ERR("DEV: Cannot pop event to NULL pointer");
        return -1;
    }

    // Check if queue is empty
    if (event_queue.count == 0) {
        return -1; // No events
    }

    // Get event from queue
    uint32_t index = event_queue.head % DEVICE_EVENT_QUEUE_SIZE;
    *event = event_queue.events[index];

    event_queue.head++;
    event_queue.count--;

    LOG_DEBUG("DEV: Popped event %d for device '%s'", event->type, event->device->name);
    return 0;
}

int64_t device_event_queue_count() {
    return event_queue.count;
}