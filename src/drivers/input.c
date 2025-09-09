#include <drivers/input.h>
#include <kernel/log.h>

// Initialize the global handler to NULL
char_input_handler_t g_char_input_handler = NULL;

void input_register_char_handler(char_input_handler_t handler) {
    if (handler == NULL) {
        LOG_WARN("Input: Attempted to register a NULL character input handler.");
        return;
    }
    g_char_input_handler = handler;
    LOG_INFO("Input: Character input handler registered at 0x%llx.", (uint64_t)handler);
}