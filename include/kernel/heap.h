#ifndef KERNEL_HEAP_H
#define KERNEL_HEAP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define HEAP_MAGIC 0x12345678
#define HEAP_MIN_SIZE 0x10000    // 64KB minimum heap size
#define FIXED_MIN_BLOCK_SIZE

#ifndef FIXED_MIN_BLOCK_SIZE
#define MIN_BLOCK_SIZE 128
#endif

typedef struct heap_block {
    size_t size;                // Size of the block (including this header)
    struct heap_block* next;    // Pointer to the next block
    struct heap_block* prev;    // Pointer to the prev block
    bool free;                  // 1 if free, 0 if used
    uint64_t magic;             // Magic number for validation (HEAP_MAGIC)
} heap_block_t;

void heap_init(uint64_t addr_start, size_t size);
void* kmalloc(size_t size);
void kfree(void *ptr);
void* krealloc(void *ptr, size_t size);

size_t heap_get_total_size();
size_t heap_get_free_size();
size_t heap_get_used_size();

#endif