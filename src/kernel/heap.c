#include <kernel/heap.h>
#include <kernel/log.h>
#include <arch/x86-64/pmm.h>
#include <arch/x86-64/vmm.h>
#include <libc/string.h>
#include <stdbool.h>

static heap_block_t *heap_start = NULL;
static size_t heap_size = 0;

// Forward declaration for internal function
static bool heap_expand(size_t size);

void heap_init(uint64_t addr_start, size_t size) {
    uint64_t aligned_addr = (addr_start + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    if (size < HEAP_MIN_SIZE) {
        size = HEAP_MIN_SIZE;
    }
    size_t aligned_size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    for (uint64_t offset = 0; offset < aligned_size; offset += PAGE_SIZE) {
        void* phys_block = pmm_alloc_block();
        if (!phys_block) {
            LOG_ERR("HEAP: Failed to allocate physical memory for heap");
            return;
        }
        vmm_map_page(aligned_addr + offset, (uint64_t)phys_block, (PAGE_PRESENT | PAGE_READ_WRITE));
    }

    heap_start = (heap_block_t*)aligned_addr;
    heap_start->size = aligned_size;
    heap_start->next = NULL;
    heap_start->prev = NULL;
    heap_start->free = true;
    heap_start->magic = HEAP_MAGIC;

    heap_size = aligned_size;
    LOG_INFO("Heap initialized at 0x%llx with size %s", aligned_addr, format_size(aligned_size));
}

void* kmalloc(size_t size) {
    if (heap_start == NULL || size == 0) {
        return NULL;
    }

    // Align size to 8 bytes and add header size
    size_t total_size = size + sizeof(heap_block_t);
    if ((total_size & 0x7) != 0) { // Align to 8-byte boundary
        total_size = (total_size + 7) & ~7;
    }

    // First-fit: Find a free block that is large enough
    heap_block_t* current = heap_start;
    while (current) {
        if (current->free && current->size >= total_size) {
            break; // Found a suitable block
        }
        current = current->next;
    }

    // If no block was found, try to expand the heap
    if (current == NULL) {
        if (heap_expand(total_size)) {
            // After expansion, the last block is the new free block, try again
            return kmalloc(size);
        }
        LOG_ERR("HEAP: No suitable block found and expansion failed.");
        return NULL;
    }

    // If the found block is much larger than needed, split it.
    // The remaining piece must be large enough to hold a header and a minimal allocation.
    if (current->size > total_size + sizeof(heap_block_t) + 8) {
        heap_block_t* new_block = (heap_block_t*)((uintptr_t)current + total_size);
        new_block->size = current->size - total_size;
        new_block->free = true;
        new_block->magic = HEAP_MAGIC;
        new_block->next = current->next;
        new_block->prev = current;

        if (current->next) {
            current->next->prev = new_block;
        }
        current->size = total_size;
        current->next = new_block;
    }

    current->free = false;

    // Return a pointer to the memory region after the header
    return (void*)((uintptr_t)current + sizeof(heap_block_t));
}

void kfree(void *ptr) {
    if (ptr == NULL) {
        return;
    }

    // Get the block header from the pointer
    heap_block_t* block = (heap_block_t*)((uintptr_t)ptr - sizeof(heap_block_t));

    // Validate magic number to prevent freeing invalid pointers
    if (block->magic != HEAP_MAGIC) {
        LOG_ERR("HEAP: kfree detected corrupted block or invalid pointer");
        return;
    }

    block->free = true;

    // Coalesce with the next block if it's also free
    if (block->next && block->next->free) {
        block->size += block->next->size;
        block->next = block->next->next;
        if (block->next) {
            block->next->prev = block;
        }
    }

    // Coalesce with the previous block if it's also free
    if (block->prev && block->prev->free) {
        block->prev->size += block->size;
        block->prev->next = block->next;
        if (block->next) {
            block->next->prev = block;
        }
    }
}

static bool heap_expand(size_t size) {
    size_t expansion_size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    uint64_t old_heap_end = (uint64_t)heap_start + heap_size;

    for (uint64_t offset = 0; offset < expansion_size; offset += PAGE_SIZE) {
        void* phys_block = pmm_alloc_block();
        if (!phys_block) {
            LOG_ERR("HEAP: Expansion failed to allocate physical memory");
            return false;
        }
        vmm_map_page(old_heap_end + offset, (uint64_t)phys_block, (PAGE_PRESENT | PAGE_READ_WRITE));
    }

    // Find the last block in the heap
    heap_block_t* last_block = heap_start;
    while (last_block->next) {
        last_block = last_block->next;
    }

    // If the last block was free, just extend its size
    if (last_block->free) {
        last_block->size += expansion_size;
    } else {
        // Otherwise, create a new free block for the expanded region
        heap_block_t* new_block = (heap_block_t*)old_heap_end;
        new_block->size = expansion_size;
        new_block->free = true;
        new_block->magic = HEAP_MAGIC;
        new_block->prev = last_block;
        new_block->next = NULL;
        last_block->next = new_block;
    }

    heap_size += expansion_size;
    LOG_INFO("Heap expanded by %s to %s", format_size(expansion_size), format_size(heap_size));
    return true;
}
