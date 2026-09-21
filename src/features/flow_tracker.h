#pragma once
#include "robin_hood.h"
#include <cstdint>

extern uint64_t gt_true_positives;
extern uint64_t gt_true_negatives;
extern uint64_t gt_false_positives;
extern uint64_t gt_false_negatives;

// Diagnostics counters for the evaluation harness
extern uint64_t g_dropped_new_flows;
extern uint64_t fp_by_reason[5];
extern uint64_t tp_by_reason[5];

enum ConfirmReason : uint8_t {
  CONFIRM_NONE = 0,
  CONFIRM_PAIR_FLOOD = 1,
  CONFIRM_SRC_CONCURRENCY = 2,
  CONFIRM_SLOW_DOS = 3,
  CONFIRM_SPIKE_COUNT = 4
};

struct FlowRecord {
  uint64_t last_packet_time = 0;
  uint64_t episode_start_time = 0;
  uint64_t episode_last_update = 0;
  uint64_t last_alert_times[6] = {0};

  uint32_t flow_hash = 0;
  uint32_t src_ip = 0;
  uint32_t dest_ip = 0;
  uint32_t packet_count = 0;
  uint32_t total_bytes = 0;
  uint32_t bytes_forward = 0;
  uint32_t bytes_reverse = 0;
  uint32_t packets_forward = 0;
  uint32_t packets_reverse = 0;
  uint32_t episode_peak_magnitude = 0;
  uint32_t episode_peak_magnitude_ever = 0;
  uint32_t episode_dominant_channel = 0;
  uint32_t episode_spike_count = 0;
  uint32_t last_alert_magnitudes[6] = {0};
  uint32_t confirmed_channel = 0; // Added for diagnostics

  float expected_size = 0.0f;
  float expected_iat = 0.0f;
  float expected_rate = 0.0f;
  float expected_byte_ratio = 0.0f;
  float expected_packet_ratio = 0.0f;
  float expected_variance = 0.0f;

  uint16_t src_port = 0;
  uint16_t dest_port = 0;
  uint8_t protocol = 0;
  uint8_t episode_active = 0;
  uint8_t threat_confirmed = 0;
  ConfirmReason confirm_reason = CONFIRM_NONE; // Added for diagnostics
};

struct IPRecord {
  uint32_t src_ip = 0;
  uint32_t concurrent_flows = 0;
};

inline robin_hood::unordered_flat_map<uint32_t, FlowRecord> active_flows;
inline robin_hood::unordered_flat_map<uint32_t, IPRecord> active_ips;
inline robin_hood::unordered_flat_map<uint64_t, uint32_t> active_ip_pairs;

void commit_flow_ground_truth(const FlowRecord &flow);
void configure_tracker(float exp_sec, float alpha, float drift_thresh,
                       uint64_t ep_timeout, uint32_t max_flows);
void track_flow(uint32_t src_ip, uint32_t dest_ip, uint32_t src_port,
                uint32_t dest_port, uint8_t proto, uint16_t flags,
                uint32_t packet_len, uint64_t pkt_time_us);
uint32_t get_active_ip_pair_count(uint64_t pair_key);
uint32_t get_active_ip_flow_count(uint32_t ip);
