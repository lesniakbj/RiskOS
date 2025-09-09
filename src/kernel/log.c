#include <kernel/log.h>
#include <libc/stdlib.h>
#include <drivers/serio.h>
// TODO: Have the log "attach" to a console, that is either freestanding (GUI app) or "attached" to a screen
#include <drivers/fb_console.h>

static bool screen_available = false;

static const char* levelNames[] = {
    [LOG_LEVEL_DEBUG] = "DEBUG",
    [LOG_LEVEL_INFO] =  "INFO",
    [LOG_LEVEL_WARN] =  "WARN",
    [LOG_LEVEL_ERR] =   "ERROR",
    [LOG_LEVEL_PANIC] = "PANIC",
};

static void format_string(char* buffer, size_t buff_size, const char* format, va_list args);
void format_string_simple(char* buffer, size_t buff_size, const char* format, ...);
static void vformat_string(char* buffer, size_t buff_size, const char* format, va_list args);

void log_init() {
    LOG_INFO("Booting %s-kernel %s (Built %s %s)", "BlankOS", "0.0.1v", __DATE__, __TIME__);
    LOG_INFO("Copyright (C) 2025 Brendan Lesniak. MIT Licensed.");
}

void log_screen_ready() {
    screen_available = true;
}

void log_print(log_level_t level, const char* file, void* caller_addr, int line, const char* format, ...) {
    va_list args;
    va_start(args, format);

    (void)file;
    (void)caller_addr;
    (void)line;

#if LOG_CALLER
    // For each log line, we concatenate 3 pieces of information...
    // ... Call info (File, Line, Caller Address) ...
    char call_info[128];
    format_string_simple(call_info, 128, "%s.%d:0x%x :: ", file, line, caller_addr);
#if SERIAL_LOG
    serial_writestring(SERIAL_COM1, call_info);
#endif
#if SCREEN_LOG
    if(screen_available) {
        framebuffer_writestring(call_info);
    }
#endif

#endif // LOG_CALLER

    // ... Log Level Header ...
    char header[64];
    format_string_simple(header, 64, "%s", levelNames[level]);
#if SERIAL_LOG
    serial_writestring(SERIAL_COM1, "[");
    serial_writestring(SERIAL_COM1, header);
    serial_writestring(SERIAL_COM1, "]\t");
#endif
#if SCREEN_LOG
    if(screen_available) {
        framebuffer_writestring("[");
        framebuffer_writestring(header);
        framebuffer_writestring("]\t");
    }
#endif

    // ... The Log Message
    char buf[256];
    format_string(buf, 256, format, args);
    size_t len = strlen(buf);
    if(buf[len - 1] != '\n') {
        if (len < sizeof(buf) - 1) {  // Ensure space for newline
            buf[len] = '\n';
            buf[len + 1] = '\0';
        }
    }
#if SERIAL_LOG
    serial_writestring(SERIAL_COM1, buf);
#endif
#if SCREEN_LOG
    if(screen_available) {
        framebuffer_writestring(buf);
    }
#endif

    va_end(args);
}

char* format_size(uint64_t size) {
    static char buf[40];
    char* p = buf;
    const uint64_t GIB = 1024ULL * 1024 * 1024;
    const uint64_t MIB = 1024 * 1024;
    const uint64_t KIB = 1024;

    if (size >= GIB) {
        uint64_t val = size * 100 / GIB;
        utoa(val / 100, p, 10);
        p += strlen(p);
        if (val % 100 != 0) {
            *p++ = '.';
            if (val % 100 < 10) *p++ = '0';
            utoa(val % 100, p, 10);
            p += strlen(p);
        }
        strcpy(p, " GiB");
    } else if (size >= MIB) {
        uint64_t val = size * 100 / MIB;
        utoa(val / 100, p, 10);
        p += strlen(p);
        if (val % 100 != 0) {
            *p++ = '.';
            if (val % 100 < 10) *p++ = '0';
            utoa(val % 100, p, 10);
            p += strlen(p);
        }
        strcpy(p, " MiB");
    } else if (size >= KIB) {
        uint64_t val = size * 100 / KIB;
        utoa(val / 100, p, 10);
        p += strlen(p);
        if (val % 100 != 0) {
            *p++ = '.';
            if (val % 100 < 10) *p++ = '0';
            utoa(val % 100, p, 10);
            p += strlen(p);
        }
        strcpy(p, " KiB");
    } else {
        utoa(size, p, 10);
        p += strlen(p);
        strcpy(p, " B");
    }
    return buf;
}

static void vformat_string(char* buffer, size_t buff_size, const char* format, va_list args) {
    uint64_t i = 0;
    char num_buf[65]; // Sufficient for 64-bit binary + null
    char* s;

    while (*format != '\0' && i < buff_size - 1) {
        if (*format == '%') {
            format++;

            // Check for length modifiers
            char length_modifier = 0;
            if (*format == 'l') {
                length_modifier = 'l';
                format++;
                if (*format == 'l') {
                    length_modifier = 'L'; // long long
                    format++;
                }
            } else if (*format == 'z') {
                length_modifier = 'z'; // size_t, treat as long long
                format++;
            }

            // Handle format specifiers
            switch (*format) {
                case 's':
                    s = va_arg(args, char*);
                    while (*s != '\0' && i < buff_size - 1) {
                        buffer[i++] = *s++;
                    }
                    break;

                case 'd':
                    if (length_modifier == 'L' || length_modifier == 'l') {
                        itoa(va_arg(args, int64_t), num_buf, 10);
                    } else {
                        itoa(va_arg(args, int32_t), num_buf, 10);
                    }
                    s = num_buf;
                    while (*s != '\0' && i < buff_size - 1) {
                        buffer[i++] = *s++;
                    }
                    break;

                case 'u':
                    if (length_modifier == 'L' || length_modifier == 'l' || length_modifier == 'z') {
                        utoa(va_arg(args, uint64_t), num_buf, 10);
                    } else {
                        utoa(va_arg(args, uint32_t), num_buf, 10);
                    }
                    s = num_buf;
                    while (*s != '\0' && i < buff_size - 1) {
                        buffer[i++] = *s++;
                    }
                    break;

                case 'x':
                    if (length_modifier == 'L' || length_modifier == 'l' || length_modifier == 'z') {
                        utoa(va_arg(args, uint64_t), num_buf, 16);
                    } else {
                        utoa(va_arg(args, uint32_t), num_buf, 16);
                    }
                    s = num_buf;
                    while (*s != '\0' && i < buff_size - 1) {
                        buffer[i++] = *s++;
                    }
                    break;

                case '%':
                    buffer[i++] = '%';
                    break;
            }
        } else {
            buffer[i++] = *format;
        }
        format++;
    }
    buffer[i] = '\0';
}


void format_string_simple(char* buffer, size_t buff_size, const char* format, ...) {
    va_list args;
    va_start(args, format);
    vformat_string(buffer, buff_size, format, args);
    va_end(args);
}

static void format_string(char* buffer, size_t buff_size, const char* format, va_list args) {
     // Simply delegate to the core logic
     vformat_string(buffer, buff_size, format, args);
}