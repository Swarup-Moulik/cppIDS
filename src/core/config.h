#pragma once
#include <cstdint>
#include <string>

struct IDSConfig {
  float fire_threshold = 5000.0f;
  float tau = 0.5f;
  uint32_t alert_threshold = 15;
  uint32_t debug_mode = 0;
  float expiration_seconds = 60.0f;
  uint32_t max_active_flows = 65536;
  uint64_t alert_cooldown_ms = 10000;
  float prediction_alpha = 0.125f;
  float drift_lock_threshold = 3.5f;
  uint64_t episode_timeout_ms = 30000;
};

void load_default_config(IDSConfig &cfg);
void load_config_file(const std::string &filepath, IDSConfig &cfg);
