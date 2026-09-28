#pragma once
#include "../features/flow_tracker.h"
#include <algorithm>
#include <array>
#include <cstdint>

/* @brief Total number of features generated for the readout layer */
constexpr size_t READOUT_DIM = 11;

/* @brief Extracts normalized continuous and categorical features from an active
 * FlowRecord */
inline std::array<float, READOUT_DIM>
compute_readout_features(const FlowRecord &flow) {
  std::array<float, READOUT_DIM> f{};

  // Dimensions 0-5: Peak anomaly magnitude across the 6 predictive coding
  // channels
  for (int c = 0; c < 6; ++c) {
    f[c] = static_cast<float>(flow.last_alert_magnitudes[c]);
  }

  // Dimension 6: Total spike count accumulated within the active episode
  f[6] = static_cast<float>(flow.episode_spike_count);

  // Dimension 7: Bidirectional IP pair flow concurrency density
  uint64_t fwd = (static_cast<uint64_t>(flow.src_ip) << 32) | flow.dest_ip;
  uint64_t rev = (static_cast<uint64_t>(flow.dest_ip) << 32) | flow.src_ip;
  f[7] = static_cast<float>(
      std::max(get_active_ip_pair_count(fwd), get_active_ip_pair_count(rev)));

  uint16_t p1 = flow.dest_port, p2 = flow.src_port;
  bool eph = (p1 >= 1024 || p2 >= 1024 || p1 == p2);

  // Protocol identification predicates for common network services
  auto is_web = [](uint16_t p) {
    return p == 80 || p == 443 || p == 3128 || p == 4443 || p == 8000 ||
           p == 8008 || p == 8080 || p == 8443 || p == 8888;
  };
  auto is_dns = [](uint16_t p) { return p == 53 || p == 853; };
  auto is_ent = [](uint16_t p) {
    return p == 88 || p == 135 || p == 137 || p == 138 || p == 139 ||
           p == 389 || p == 445 || p == 636 || p == 1433 || p == 3268 ||
           p == 3306 || p == 3389 || p == 5432 || p == 5985 || p == 5986;
  };

  // Dimensions 8-10: Binary one-hot flags for service traffic classes
  f[8] = (eph && (is_web(p1) || is_web(p2))) ? 1.0f : 0.0f;
  f[9] = (eph && (is_dns(p1) || is_dns(p2))) ? 1.0f : 0.0f;
  f[10] = (eph && (is_ent(p1) || is_ent(p2))) ? 1.0f : 0.0f;

  return f;
}
