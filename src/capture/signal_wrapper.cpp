#include "signal_wrapper.h"
#include <atomic>
#include <csignal>

std::atomic<bool> g_shutdown_requested{false};
static sigint_callback_t g_custom_handler = nullptr;

void internal_sigint_handler(int sig) {
  g_shutdown_requested.store(true, std::memory_order_relaxed);
  if (g_custom_handler) {
    g_custom_handler(sig);
  }
}

void register_sigint_handler(sigint_callback_t handler) {
  g_custom_handler = handler;
  std::signal(SIGINT, internal_sigint_handler);
}

bool shutdown_was_requested(void) {
  return g_shutdown_requested.load(std::memory_order_relaxed);
}
