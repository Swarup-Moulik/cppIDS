#include "signal_wrapper.h"
#include <atomic>
#include <csignal>

/* @brief Atomic flag indicating if a termination interrupt has been requested
 */
std::atomic<bool> g_shutdown_requested{false};

// Custom user callback invoked when an interrupt is caught
static sigint_callback_t g_custom_handler = nullptr;

/* @brief Internal signal handler setting the atomic shutdown flag and executing
 * the registered callback */
void internal_sigint_handler(int sig) {
  // Set atomic shutdown state so worker loops can terminate cleanly
  g_shutdown_requested.store(true, std::memory_order_relaxed);
  if (g_custom_handler) {
    g_custom_handler(sig);
  }
}

/* @brief Registers a signal handler callback and binds internal_sigint_handler
 * to SIGINT */
void register_sigint_handler(sigint_callback_t handler) {
  g_custom_handler = handler;
  std::signal(SIGINT, internal_sigint_handler);
}

/* @brief Returns true if an interrupt signal was caught by the handler */
bool shutdown_was_requested(void) {
  return g_shutdown_requested.load(std::memory_order_relaxed);
}
