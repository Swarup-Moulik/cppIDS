#pragma once

namespace engine_runner {
/* @brief Spawns the background NIDS daemon thread */
void StartLiveCapture();

/* @brief Signals the daemon thread to gracefully terminate */
void StopCapture();

/* @brief Forces a thread join on application exit */
void ShutdownEngine();
} // namespace engine_runner
