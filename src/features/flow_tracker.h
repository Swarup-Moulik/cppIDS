#pragma once
#include "robin_hood.h"
#include <cstdint>

// Ground truth classification counters
extern uint64_t gt_true_positives;
extern uint64_t gt_true_negatives;
extern uint64_t gt_false_positives;
extern uint64_t gt_false_negatives;

// Diagnostics counters tracking eviction and detection rationales
extern uint64_t g_dropped_new_flows;
extern uint64_t fp_by_reason[5];
extern uint64_t tp_by_reason[5];

/* @brief Categorical rationales for confirming an anomaly as a security
 * incident */
enum ConfirmReason : uint8_t {
  CONFIRM_NONE = 0,            // Threat unconfirmed
  CONFIRM_PAIR_FLOOD = 1,      // High concurrency pair volumetric flood
  CONFIRM_SRC_CONCURRENCY = 2, // High single-host concurrent flow fan-out
  CONFIRM_SLOW_DOS = 3,        // Low-rate inter-arrival jitter attack
  CONFIRM_SPIKE_COUNT = 4      // Repeated threshold-breaching spike persistence
};

/* @brief Stateful network flow context maintaining statistical predictive
 * baselines */
struct FlowRecord {
  uint64_t last_packet_time =
      0; // Timestamp of the most recently observed packet in milliseconds
  uint64_t episode_start_time =
      0; // Start timestamp of the current threat episode
  uint64_t episode_last_update =
      0; // Timestamp of the most recent anomaly escalation
  uint64_t last_alert_times[6] = {
      0}; // Microsecond alert timestamps across the 6 channels

  uint64_t flow_hash = 0;       // Symmetrical canonical 5-tuple hash key
  uint32_t src_ip = 0;          // Originating host IPv4 address
  uint32_t dest_ip = 0;         // Destination host IPv4 address
  uint32_t packet_count = 0;    // Total packet volume in this flow
  uint32_t total_bytes = 0;     // Total byte volume in this flow
  uint32_t bytes_forward = 0;   // Outbound byte transfer count
  uint32_t bytes_reverse = 0;   // Inbound byte transfer count
  uint32_t packets_forward = 0; // Outbound packet count
  uint32_t packets_reverse = 0; // Inbound packet count
  uint32_t episode_peak_magnitude =
      0; // Peak magnitude score of the active episode
  uint32_t episode_peak_magnitude_ever =
      0; // Highest peak magnitude seen throughout flow lifetime
  uint32_t episode_dominant_channel =
      0; // Channel ID causing initial episode activation
  uint32_t episode_spike_count =
      0; // Cumulative hidden reservoir spikes in this episode
  uint32_t last_alert_magnitudes[6] = {
      0}; // Peak anomaly magnitude scores per channel
  uint32_t confirmed_channel =
      0; // Offending channel ID responsible for threat confirmation

  float expected_size = 0.0f; // EWMA predicted packet payload size
  float expected_iat = 0.0f;  // EWMA predicted packet inter-arrival time
  float expected_rate = 0.0f; // EWMA predicted flow packet rate
  float expected_byte_ratio =
      0.0f; // EWMA predicted bidirectional byte asymmetry
  float expected_packet_ratio =
      0.0f; // EWMA predicted bidirectional packet asymmetry
  float expected_variance = 0.0f; // EWMA predicted packet size variance

  uint16_t src_port = 0;  // Originating transport port
  uint16_t dest_port = 0; // Destination transport port
  uint8_t protocol = 0;   // Transport protocol identifier
  uint8_t episode_active =
      0; // Active threat episode flag (1 = active, 0 = idle)
  uint8_t threat_confirmed = 0; // Confirmed malicious state flag
  ConfirmReason confirm_reason =
      CONFIRM_NONE; // Rule category that confirmed this attack
};

/* @brief Aggregates host-level flow concurrency */
struct IPRecord {
  uint32_t src_ip = 0; // Host IPv4 address
  uint32_t concurrent_flows =
      0; // Total open sessions currently established by this host
};

// Hash maps for active flow tracking and host concurrency monitoring
inline robin_hood::unordered_flat_map<uint64_t, FlowRecord> active_flows;
inline robin_hood::unordered_flat_map<uint32_t, IPRecord> active_ips;
inline robin_hood::unordered_flat_map<uint64_t, uint32_t> active_ip_pairs;

/* @brief Validates flow status against ground truth annotations and tallies
 * classification metrics */
void commit_flow_ground_truth(const FlowRecord &flow);

/* @brief Configures flow tracking timeouts, EWMA learning rate, and drift
 * parameters */
void configure_tracker(float exp_sec, float alpha, float drift_thresh,
                       uint64_t ep_timeout, uint32_t max_flows);

/* @brief Updates statistical predictive coding state and emits spikes on large
 * estimation errors */
void track_flow(uint32_t src_ip, uint32_t dest_ip, uint32_t src_port,
                uint32_t dest_port, uint8_t proto, uint16_t flags,
                uint32_t packet_len, uint64_t pkt_time_us);

/* @brief Returns the total concurrent active flow count for a bidirectional
 * host pair */
uint32_t get_active_ip_pair_count(uint64_t pair_key);

/* @brief Returns the total concurrent active flow count originated by a single
 * host IP */
uint32_t get_active_ip_flow_count(uint32_t ip);
