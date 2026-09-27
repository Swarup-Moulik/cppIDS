#include "config.h"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>

/* @brief Resets the configuration structure back to default parameters */
void load_default_config(IDSConfig &cfg) { cfg = IDSConfig(); }

/* @brief Parses an unsigned 32-bit integer and ensures it is positive and
 * nonzero */
static bool parse_positive_uint32(const std::string &s, uint32_t &out) {
  if (s.empty() || s[0] == '-')
    return false;
  size_t idx = 0;
  unsigned long long v = std::stoull(s, &idx);
  if (idx != s.size() || v == 0 || v > 0xFFFFFFFFULL)
    return false;
  out = static_cast<uint32_t>(v);
  return true;
}

/* @brief Parses an unsigned 64-bit integer and ensures it is positive and
 * nonzero */
static bool parse_positive_uint64(const std::string &s, uint64_t &out) {
  if (s.empty() || s[0] == '-')
    return false;
  size_t idx = 0;
  unsigned long long v = std::stoull(s, &idx);
  if (idx != s.size() || v == 0)
    return false;
  out = static_cast<uint64_t>(v);
  return true;
}

/* @brief Parses a floating point number and verifies it is finite and not NaN
 */
static bool parse_finite_float(const std::string &s, float &out) {
  if (s.empty())
    return false;
  size_t idx = 0;
  float v = std::stof(s, &idx);
  if (idx != s.size() || std::isnan(v) || std::isinf(v))
    return false;
  out = v;
  return true;
}

/* @brief Parses an INI configuration file and updates engine parameters */
void load_config_file(const std::string &filepath, IDSConfig &cfg) {
  std::ifstream file(filepath);
  if (!file.is_open()) {
    std::cerr << "[CONFIG] Notice: Could not open " << filepath
              << ", keeping default configuration.\n";
    return;
  }

  std::string line;
  while (std::getline(file, line)) {
    size_t eq_pos = line.find('=');
    if (eq_pos == std::string::npos)
      continue;

    std::string key = line.substr(0, eq_pos);
    std::string val = line.substr(eq_pos + 1);

    // Trim whitespace from both ends of key and value
    key.erase(0, key.find_first_not_of(" \t"));
    key.erase(key.find_last_not_of(" \t") + 1);
    val.erase(0, val.find_first_not_of(" \t"));
    val.erase(val.find_last_not_of(" \t") + 1);

    // Skip empty lines and comments
    if (key.empty() || key[0] == '#')
      continue;

    try {
      if (key == "FIRE_THRESHOLD") {
        float f;
        if (parse_finite_float(val, f))
          cfg.fire_threshold = f;
      } else if (key == "TAU") {
        float f;
        if (parse_finite_float(val, f))
          cfg.tau = f;
      } else if (key == "ALERT_THRESHOLD") {
        uint32_t u;
        if (parse_positive_uint32(val, u))
          cfg.alert_threshold = u;
      } else if (key == "MAX_ACTIVE_FLOWS") {
        uint32_t u;
        if (parse_positive_uint32(val, u))
          cfg.max_active_flows = u;
      } else if (key == "ALERT_COOLDOWN_MS") {
        uint64_t u;
        if (parse_positive_uint64(val, u))
          cfg.alert_cooldown_ms = u;
      } else if (key == "PREDICTION_ALPHA") {
        float f;
        if (parse_finite_float(val, f))
          cfg.prediction_alpha = f;
      } else if (key == "DRIFT_LOCK_THRESHOLD") {
        float f;
        if (parse_finite_float(val, f))
          cfg.drift_lock_threshold = f;
      } else if (key == "EPISODE_TIMEOUT_MS") {
        uint64_t u;
        if (parse_positive_uint64(val, u))
          cfg.episode_timeout_ms = u;
      } else if (key == "EXPIRATION_SECONDS") {
        float f;
        if (parse_finite_float(val, f))
          cfg.expiration_seconds = f;
      } else {
        std::cerr << "[CONFIG] Unknown parameter ignored: " << key << "\n";
      }
    } catch (const std::exception &e) {
      std::cerr << "[CONFIG] Exception parsing key '" << key << "' with value '"
                << val << "': " << e.what() << "\n";
    }
  }

  // Enforce boundary safety limits on configured parameters
  cfg.tau = std::max(0.001f, cfg.tau);
  cfg.prediction_alpha = std::clamp(cfg.prediction_alpha, 0.001f, 1.0f);
  cfg.fire_threshold = std::max(10.0f, cfg.fire_threshold);
  cfg.max_active_flows = std::max(1000u, cfg.max_active_flows);
  cfg.expiration_seconds = std::max(1.0f, cfg.expiration_seconds);
  cfg.drift_lock_threshold = std::max(0.1f, cfg.drift_lock_threshold);
  cfg.alert_cooldown_ms = std::max(1000ULL, cfg.alert_cooldown_ms);
  cfg.episode_timeout_ms = std::max(1000ULL, cfg.episode_timeout_ms);
}
