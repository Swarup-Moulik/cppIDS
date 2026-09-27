#pragma once
#include <cstdint>
#include <string>

/* @brief Holds tunable runtime parameters for the SNN engine and flow tracker */
struct IDSConfig {
  float fire_threshold = 5000.0f;       // Membrane potential threshold for hidden LIF neurons
  float tau = 0.5f;                     // Membrane potential decay time constant in seconds
  uint32_t alert_threshold = 15;        // Minimum anomaly magnitude required to trigger an alert
  uint32_t debug_mode = 0;              // Verbose debugging output flag
  float expiration_seconds = 60.0f;     // Inactivity timeout before a flow record is evicted
  uint32_t max_active_flows = 65536;    // Maximum concurrent flows allowed in memory
  uint64_t alert_cooldown_ms = 10000;   // Cooldown window between repeated alerts on the same flow
  float prediction_alpha = 0.125f;      // EWMA adaptation learning rate for predictive coding
  float drift_lock_threshold = 3.5f;    // Anomaly distance threshold triggering
                                        // adaptation rate reduction
  uint64_t episode_timeout_ms = 30000;  // Idle timeout before an active threat episode is resolved
};

/* @brief Initializes the configuration structure with default operational parameters */
void load_default_config(IDSConfig &cfg);

/* @brief Loads and parses operational parameters from an INI configuration file */
void load_config_file(const std::string &filepath, IDSConfig &cfg);
