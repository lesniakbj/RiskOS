#ifndef DRIVERS_INPUT_H
#define DRIVERS_INPUT_H

#include <stdint.h>

// Define a function pointer type for a character input handler
typedef void (*char_input_handler_t)(char c);

// Global variable to hold the currently registered character input handler
extern char_input_handler_t g_char_input_handler;

// Function to register a character input handler
void input_register_char_handler(char_input_handler_t handler);

#endif // DRIVERS_INPUT_H