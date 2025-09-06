#ifndef KERNEL_LOG_H
#define KERNEL_LOG_H

#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <libc/string.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : \
        (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__))

typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERR,
    LOG_LEVEL_PANIC,
} log_level_t;


void log_init();
void log_screen_ready();

void log_print(log_level_t level, const char* file, void* caller_addr, int line, const char* format, ...);

char* format_size(uint64_t size);

#define LOG_DEBUG(format, ...) log_print(LOG_LEVEL_DEBUG, __FILENAME__,  __builtin_return_address(0), __LINE__, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...)  log_print(LOG_LEVEL_INFO, __FILENAME__,  __builtin_return_address(0), __LINE__, format, ##__VA_ARGS__)
#define LOG_WARN(format, ...)  log_print(LOG_LEVEL_WARN, __FILENAME__,  __builtin_return_address(0), __LINE__, format, ##__VA_ARGS__)
#define LOG_ERR(format, ...)   log_print(LOG_LEVEL_ERR, __FILENAME__,  __builtin_return_address(0), __LINE__, format, ##__VA_ARGS__)
#define LOG_PANIC(format, ...) log_print(LOG_LEVEL_PANIC, __FILENAME__,  __builtin_return_address(0), __LINE__, format, ##__VA_ARGS__)

#endif