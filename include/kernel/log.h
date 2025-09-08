#ifndef KERNEL_LOG_H
#define KERNEL_LOG_H

#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <libc/string.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : \
        (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__))

#define LOG_LEVEL DEBUG
#define LOG_ENABLED false
#define SERIAL_LOG 1
#define SCREEN_LOG 0
#define LOG_CALLER 1

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
void format_string_simple(char* buffer, size_t buff_size, const char* format, ...);

char* format_size(uint64_t size);

#define LOG_DEBUG(format, ...) if(LOG_ENABLED) log_print(LOG_LEVEL_DEBUG, __FILENAME__,  __builtin_return_address(0), __LINE__, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...)  if(LOG_ENABLED) log_print(LOG_LEVEL_INFO, __FILENAME__,  __builtin_return_address(0), __LINE__, format, ##__VA_ARGS__)
#define LOG_WARN(format, ...)  if(LOG_ENABLED) log_print(LOG_LEVEL_WARN, __FILENAME__,  __builtin_return_address(0), __LINE__, format, ##__VA_ARGS__)
#define LOG_ERR(format, ...)   if(LOG_ENABLED) log_print(LOG_LEVEL_ERR, __FILENAME__,  __builtin_return_address(0), __LINE__, format, ##__VA_ARGS__)
#define LOG_PANIC(format, ...) if(LOG_ENABLED) log_print(LOG_LEVEL_PANIC, __FILENAME__,  __builtin_return_address(0), __LINE__, format, ##__VA_ARGS__)

#endif