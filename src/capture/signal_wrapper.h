#pragma once
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* @brief Callback signature for handling process interruption signals */
typedef void (*sigint_callback_t)(int);

/* @brief Registers an application callback to execute upon receiving SIGINT */
void register_sigint_handler(sigint_callback_t handler);

/* @brief Returns true if a shutdown interrupt has been requested */
bool shutdown_was_requested(void);

#ifdef __cplusplus
}
#endif
