#ifndef DRIVERS_FB_CONSOLE_H// Partition Table Entry
#define DRIVERS_FB_CONSOLE_H

#include <kernel/limine.h>

#define TAB_WIDTH 4
#define FONT_WIDTH 8
#define FONT_HEIGHT 16
#define SCROLLBACK_BUFFER_SIZE 1000

typedef struct limine_framebuffer limine_framebuffer_t;

typedef struct {
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t a;
} color_t;

void framebuffer_console_init(limine_framebuffer_t *framebuffer);
void framebuffer_init(struct limine_framebuffer_response *framebuffer_resp);
void framebuffer_putchar(char c);
void framebuffer_writestring(const char* data);
void draw_char(char c, uint32_t x, uint32_t y, color_t color_val);
void framebuffer_console_register();
#endif