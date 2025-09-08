#include <stdbool.h>
#include <stdint.h>
#include <libc/string.h>
#include <kernel/limine.h>
#include <kernel/log.h>
#include <drivers/fb_console.h>
#include <drivers/fs/devfs.h>
#include <fonts/font.h>
#include <fonts/cascadiamono.h>

// Basic display metadata/buffer/etc
static limine_framebuffer_t local_framebuffer;
static limine_framebuffer_t *display_buffer;
static const Font *font;
static uint16_t cursor_x;
static uint16_t cursor_y;
static color_t current_color;
static bool is_new_line = true;

// Scrollback buffer
static char scrollback_buffer[SCROLLBACK_BUFFER_SIZE][256];
static int32_t scrollback_head = 0;
static int32_t scrollback_tail = 0;
static int32_t scroll_offset = 0;

static color_t uint_to_color(uint32_t color_val) {
    color_t color;
    color.a = (color_val >> 24) & 0xFF;
    color.r = (color_val >> 16) & 0xFF;
    color.g = (color_val >> 8) & 0xFF;
    color.b = color_val & 0xFF;
    return color;
}

static uint32_t color_to_uint(color_t color) {
    return (color.a << 24) | (color.r << 16) | (color.g << 8) | color.b;
}

int64_t fb_console_write(vfs_node_t *node, uint64_t offset, size_t size, const void *buffer) {
    LOG_INFO("Console write called from a file context!");
    LOG_INFO("Buffer is %s", buffer);
    (void)node; // We don't need the node for this simple driver
    framebuffer_writestring(buffer);
    return size;
}

// 2. Create a file_ops struct that points to your write function.
static file_ops_t fb_console_fops = {
    .write = fb_console_write,
    .read = NULL, // This device doesn't support reading
    .open = NULL,
    .close = NULL,
    .stat = NULL,
};

void framebuffer_console_init(limine_framebuffer_t *framebuffer) {
    (void)scroll_offset;

    // Create a copy of the buffer info so we can reclaim that memory later
    display_buffer = &local_framebuffer;
    memcpy(display_buffer, framebuffer, sizeof(limine_framebuffer_t));

    // Init the font for this console
    font = &g_cascadia_mono_font;
    current_color = (color_t){255, 0, 0, 0};

    // TODO: Init anything we need with the framebuffer here (draw initial boot glyphs, etc)
    log_screen_ready();
}

void framebuffer_console_register() {
    devfs_register_device("console", &fb_console_fops);
}

void framebuffer_init(struct limine_framebuffer_response *framebuffer_resp) {
    if (framebuffer_resp == NULL || framebuffer_resp->framebuffer_count < 1) {
        LOG_ERR("Framebuffer request not honored! Halting...");
        for (;;) {
            asm volatile ("hlt");
        }
    }

    // Initialize the console with the first framebuffer.
    framebuffer_console_init(framebuffer_resp->framebuffers[0]);
}

void framebuffer_writestring(const char* data) {
    int32_t i = 0;
    while (data[i] != 0) {
    	framebuffer_putchar(data[i++]);
    }
}

void framebuffer_putchar(char c) {
    // Ensure we have a valid framebuffer before we attempt to draw a character
    if (display_buffer->address) {
        // Advance to a new line if we have a newline character, keep circular scrollback buffer in bounds
        if (c == '\n') {
            cursor_x = 0;
            cursor_y += FONT_HEIGHT;
            is_new_line = true;
            scrollback_head = (scrollback_head + 1) % SCROLLBACK_BUFFER_SIZE;
            if (scrollback_head == scrollback_tail) {
                scrollback_tail = (scrollback_tail + 1) % SCROLLBACK_BUFFER_SIZE;
            }
            memset(scrollback_buffer[scrollback_head], 0, 256);
            return;
        }

        // Handle tab characters ensuring we are tabbing to tab stops
        if (c == '\t') {
            // Calculate how many pixels to advance, snap cursor_x to the next tab stop
            int32_t tab_stop_pixels = TAB_WIDTH * FONT_WIDTH;
            cursor_x = ((cursor_x / tab_stop_pixels) + 1) * tab_stop_pixels;

            // Handle line wrap if the tab pushes the cursor past the screen width
            if (cursor_x >= display_buffer->width) {
                cursor_x = 0;
                cursor_y += FONT_HEIGHT;
                is_new_line = true;
            }
            return;
        }

        // ... otherwise handle the drawing of this character
        draw_char(c, cursor_x, cursor_y, current_color);
        cursor_x += FONT_WIDTH;

        // Handle line wrap if the tab pushes the cursor past the screen width
        if (cursor_x >= display_buffer->width) {
            cursor_x = 0;
            cursor_y += FONT_HEIGHT;
            is_new_line = true;
        }
    }
}

void draw_char(char c, uint32_t x, uint32_t y, color_t color_val) {
    uint8_t char_height = font->asciiHeight;
    uint8_t char_width = font->asciiWidths[(int32_t)c];
    const uint8_t* glyph = font->asciiGlyphs[(int32_t)c];
    color_t text_color = color_val;

    // For X..Y in the framebuffer for the size of the character we have,
    // draw the pixels for the character based on the font
    for (uint8_t y_offset = 0; y_offset < char_height; y_offset++) {
        for (uint8_t x_offset = 0; x_offset < char_width; x_offset++) {

            // Gives the intensity of the pixel at this point for the font
            uint8_t intensity = glyph[y_offset * char_width + x_offset];

            // Only draw if the pixel is not fully transparent.
            if (intensity > 0) {
                uint32_t screen_x = x + x_offset;
                uint32_t screen_y = y + y_offset;

                // Bounds check to ensure we don't draw outside the framebuffer.
                if (screen_x < display_buffer->width && screen_y < display_buffer->height) {
                    uint32_t* pixel_addr = (uint32_t*)((uintptr_t)display_buffer->address + (screen_y * display_buffer->pitch) + (screen_x * (display_buffer->bpp / 8)));

                    // Alpha blending: FinalColor = TextColor * alpha + BgColor * (1 - alpha)
                    color_t bg_color = uint_to_color(*pixel_addr);
                    uint8_t r = (text_color.r * intensity + bg_color.r * (255 - intensity)) / 255;
                    uint8_t g = (text_color.g * intensity + bg_color.g * (255 - intensity)) / 255;
                    uint8_t b = (text_color.b * intensity + bg_color.b * (255 - intensity)) / 255;

                    *pixel_addr = color_to_uint((color_t){r, g, b, 255});
                }
            }
        }
    }
}