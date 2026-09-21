#pragma once
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Define the callback signature for Moksha and C++ interop
typedef void (*sigint_callback_t)(int);

// Expose the registration function
void register_sigint_handler(sigint_callback_t handler);

// Expose the polling function
bool shutdown_was_requested(void);

#ifdef __cplusplus
}
#endif
