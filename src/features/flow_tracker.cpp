#include "flow_tracker.h"
#include "../alerting/logger.h"
#include "../core/telemetry.h"
#include "../detection/logistic_model.h"
#include "../detection/readout_features.h"
#include "../neuromorphic/snn_core.h"
#include "../neuromorphic/snn_readout.h"
#include "spike_encoder.h"
#include <algorithm>
#include <cmath>
#include <fstream>

// Global feature export CSV stream
std::ofstream feature_export_csv;

// Ground truth classification tracking metrics
uint64_t gt_true_positives = 0;
uint64_t gt_true_negatives = 0;
uint64_t gt_false_positives = 0;
uint64_t gt_false_negatives = 0;
uint64_t g_dropped_new_flows = 0;

// Evaluation diagnostic distributions
uint64_t fp_by_reason[5] = {0};
uint64_t tp_by_reason[5] = {0};

std::unordered_map<uint64_t, uint64_t> fp_by_pair;
std::unordered_map<uint16_t, uint64_t> fp_by_svc_port;
std::unordered_map<uint64_t, uint64_t> fn_by_pair;
std::unordered_map<uint16_t, uint64_t> fn_by_svc_port;

// Tunable tracking parameters
static uint32_t global_packet_counter = 0;
static float g_expiration_threshold = 60.0f;
static float g_alpha = 0.125f;
static float g_drift_lock_threshold = 3.5f;
static uint64_t g_episode_timeout_ms = 30000;
static uint32_t g_max_active_flows = 500000;

/* @brief Retrieves concurrent active flow count for a directional or reversed
 * IP pair key */
uint32_t get_active_ip_pair_count(uint64_t pair_key) {
  auto it = active_ip_pairs.find(pair_key);
  return (it != active_ip_pairs.end()) ? it->second : 0;
}

/* @brief Retrieves total active concurrent flows originating from an IP */
uint32_t get_active_ip_flow_count(uint32_t ip) {
  auto it = active_ips.find(ip);
  return (it != active_ips.end()) ? it->second.concurrent_flows : 0;
}

/* @brief Decrements and releases concurrency tracking counters upon flow
 * expiration */
static void release_flow_metrics(const FlowRecord &f_rec) {
  // Decrement source host concurrency counter
  auto ip_it = active_ips.find(f_rec.src_ip);
  if (ip_it != active_ips.end()) {
    if (ip_it->second.concurrent_flows <= 1)
      active_ips.erase(ip_it);
    else
      ip_it->second.concurrent_flows--;
  }

  // Decrement endpoint pair concurrency counter
  uint64_t pair_key =
      (static_cast<uint64_t>(f_rec.src_ip) << 32) | f_rec.dest_ip;
  auto pair_it = active_ip_pairs.find(pair_key);
  if (pair_it != active_ip_pairs.end()) {
    if (pair_it->second <= 1)
      active_ip_pairs.erase(pair_it);
    else
      pair_it->second--;
  }
}

/* @brief Assesses flow against evaluation ground truth and updates
 * classification matrix */
void commit_flow_ground_truth(const FlowRecord &flow) {
  if (flow.packet_count == 0)
    return;

  // Determine ground truth status using configured attacker, victim, and port
  // filters
  bool has_attacker =
      is_known_attacker(flow.src_ip) || is_known_attacker(flow.dest_ip);
  bool has_victim =
      is_known_victim(flow.src_ip) || is_known_victim(flow.dest_ip);
  bool has_target_port =
      is_target_port(flow.src_port) || is_target_port(flow.dest_port);

  bool matches_victim = are_victims_empty() ? true : has_victim;
  bool matches_port = are_ports_empty() ? true : has_target_port;
  bool is_actually_malicious = (has_attacker && matches_victim && matches_port);

  // Identify common background contexts
  uint16_t p1 = flow.src_port, p2 = flow.dest_port;
  bool is_ephemeral = (p1 >= 1024 || p2 >= 1024 || p1 == p2);
  bool is_dns =
      is_ephemeral && (p1 == 53 || p2 == 53 || p1 == 853 || p2 == 853);
  bool is_web =
      is_ephemeral && (p1 == 80 || p2 == 80 || p1 == 443 || p2 == 443);

  uint64_t pair_key = (static_cast<uint64_t>(flow.src_ip) << 32) | flow.dest_ip;
  bool is_dos_flood = (get_active_ip_pair_count(pair_key) > 60);
  bool is_suppressed_context = (is_dns) || (is_web && !is_dos_flood);

  // Apply supervisory reward-modulated STDP to the neuromorphic readout layer
  snn_readout_apply_r_stdp(flow.flow_hash, is_actually_malicious,
                           is_suppressed_context);

  // If training mode is active, buffer the normalized feature vector
  if (lr_readout_is_collecting()) {
    lr_get_training_buffer().push_back(
        {compute_readout_features(flow), is_actually_malicious});
  }

  // Export the flow's readout features to the CSV if the stream is open
  if (feature_export_csv.is_open()) {
    auto feat = compute_readout_features(flow);
    feature_export_csv << flow.src_ip << "," << flow.dest_ip << ","
                       << flow.src_port << "," << flow.dest_port << ","
                       << static_cast<int>(flow.protocol) << ",";

    // Write all 11 dimensions defined in readout_features.h
    for (int i = 0; i < 11; ++i) {
      feature_export_csv << feat[i] << ",";
    }
    feature_export_csv << (is_actually_malicious ? 1 : 0) << "\n";
  }

  bool ids_detected_threat = (flow.threat_confirmed == 1);

  // Track episode telemetry anomalies and contextual resolutions
  if (flow.episode_peak_magnitude_ever > 0) {
    g_context_stats.anomalies_detected++;
    if (ids_detected_threat) {
      g_context_stats.threats_confirmed++;
      g_context_stats.context_mismatches++;
    } else {
      g_context_stats.anomalies_dismissed++;
      g_context_stats.context_matches++;
    }
  }

  uint8_t r_idx = static_cast<uint8_t>(flow.confirm_reason);
  if (r_idx > 4)
    r_idx = 0;

  // Update classification confusion matrix and stratified tracking
  if (is_actually_malicious && ids_detected_threat) {
    gt_true_positives++;
    tp_by_reason[r_idx]++;
    snn_accumulate_truth(flow.flow_hash, r_idx);
  } else if (!is_actually_malicious && !ids_detected_threat) {
    gt_true_negatives++;
  } else if (!is_actually_malicious && ids_detected_threat) {
    gt_false_positives++;
    fp_by_reason[r_idx]++;
    fp_by_pair[(static_cast<uint64_t>(flow.src_ip) << 32) | flow.dest_ip]++;
    fp_by_svc_port[std::min(flow.src_port, flow.dest_port)]++;
  } else if (is_actually_malicious && !ids_detected_threat) {
    gt_false_negatives++;
    fn_by_pair[(static_cast<uint64_t>(flow.src_ip) << 32) | flow.dest_ip]++;
    fn_by_svc_port[std::min(flow.src_port, flow.dest_port)]++;
  }
}

/* @brief Configures flow expiration windows, learning rates, and concurrency
 * caps */
void configure_tracker(float exp_sec, float alpha, float drift_thresh,
                       uint64_t ep_timeout, uint32_t max_flows) {
  g_expiration_threshold = std::max(1.0f, exp_sec);
  g_alpha = alpha;
  g_drift_lock_threshold = drift_thresh;
  g_episode_timeout_ms = ep_timeout;
  if (max_flows > 0)
    g_max_active_flows = max_flows;
}

/* @brief Computes a canonical, symmetrical 64-bit 5-tuple hash key */
static uint64_t hash_5tuple(uint32_t src_ip, uint32_t dest_ip,
                            uint16_t src_port, uint16_t dest_port,
                            uint8_t proto) {
  uint32_t ip_min = src_ip, ip_max = dest_ip;
  uint16_t port_min = src_port, port_max = dest_port;
  if (src_ip > dest_ip || (src_ip == dest_ip && src_port > dest_port)) {
    ip_min = dest_ip;
    ip_max = src_ip;
    port_min = dest_port;
    port_max = src_port;
  }

  uint64_t k1 = (static_cast<uint64_t>(ip_min) << 32) | ip_max;
  uint64_t k2 = (static_cast<uint64_t>(port_min) << 24) |
                (static_cast<uint64_t>(port_max) << 8) | proto;

  // MurmurHash3 finalizer mixing
  k1 ^= k2 + 0x9e3779b97f4a7c15ULL + (k1 << 6) + (k1 >> 2);
  k1 ^= k1 >> 33;
  k1 *= 0xff51afd7ed558ccdULL;
  k1 ^= k1 >> 33;
  k1 *= 0xc4ceb9fe1a85ec53ULL;
  k1 ^= k1 >> 33;
  return k1;
}

/* @brief Evicts the oldest active flow from memory when table capacity is
 * exceeded */
static void evict_oldest_flow() {
  if (active_flows.empty())
    return;
  auto oldest_it = active_flows.begin();
  uint64_t min_time = UINT64_MAX;
  size_t samples = 0;

  // Sample oldest flow within a bounded linear search window
  for (auto it = active_flows.begin(); it != active_flows.end() && samples < 32;
       ++it, ++samples) {
    if (it->second.last_packet_time < min_time) {
      min_time = it->second.last_packet_time;
      oldest_it = it;
    }
  }

  // Finalize metrics and release resources for the evicted flow
  commit_flow_ground_truth(oldest_it->second);
  release_flow_metrics(oldest_it->second);
  cleanup_flow_encoders(oldest_it->first);
  snn_delete_state(oldest_it->first);

  active_flows.erase(oldest_it);
  g_dropped_new_flows++;
}

/* @brief Updates predictive coding statistics and triggers spike encoding on
 * anomalies */
void track_flow(uint32_t src_ip, uint32_t dest_ip, uint32_t src_port,
                uint32_t dest_port, uint8_t proto, uint16_t flags,
                uint32_t packet_len, uint64_t pkt_time_us) {
  uint64_t current_time_gc = pkt_time_us / 1000;

  // Periodic garbage collection sweep across active flows
  if (++global_packet_counter > 1000) {
    uint64_t expire_ms =
        static_cast<uint64_t>(g_expiration_threshold * 1000.0f);
    for (auto it = active_flows.begin(); it != active_flows.end();) {
      FlowRecord &f_rec = it->second;
      bool is_expired =
          (current_time_gc >= f_rec.last_packet_time) &&
          ((current_time_gc - f_rec.last_packet_time) >= expire_ms);
      if (is_expired) {
        commit_flow_ground_truth(f_rec);
        release_flow_metrics(f_rec);
        cleanup_flow_encoders(it->first);
        snn_delete_state(it->first);
        it = active_flows.erase(it);
      } else {
        // Resolve idle episodes if no anomalies were observed within timeout
        if (f_rec.episode_active == 1 &&
            current_time_gc >= f_rec.episode_last_update &&
            (current_time_gc - f_rec.episode_last_update) >
                g_episode_timeout_ms) {
          f_rec.episode_active = 0;
          f_rec.episode_peak_magnitude = 0;
          f_rec.episode_spike_count = 0;
          g_context_stats.episodes_resolved++;
        }
        ++it;
      }
    }
    global_packet_counter = 0;
  }

  // Derive canonical 5-tuple flow key
  uint64_t flow_hash = hash_5tuple(src_ip, dest_ip, src_port, dest_port, proto);
  auto it = active_flows.find(flow_hash);
  bool is_new_flow = (it == active_flows.end());

  // Enforce table capacity limit through deterministic eviction
  if (is_new_flow && active_flows.size() >= g_max_active_flows) {
    evict_oldest_flow();
  }

  FlowRecord &record = active_flows[flow_hash];

  // Initialize tracking state on first packet
  if (is_new_flow) {
    record.flow_hash = flow_hash;
    record.src_ip = src_ip;
    record.dest_ip = dest_ip;
    record.src_port = src_port;
    record.dest_port = dest_port;
    record.protocol = proto;
    active_ips[src_ip].src_ip = src_ip;
    active_ips[src_ip].concurrent_flows++;
    uint64_t pair_key = (static_cast<uint64_t>(src_ip) << 32) | dest_ip;
    active_ip_pairs[pair_key]++;
  }

  uint64_t current_time = pkt_time_us / 1000;
  uint64_t iat = 0;
  if (record.packet_count > 0) {
    iat = (current_time >= record.last_packet_time)
              ? (current_time - record.last_packet_time)
              : 0;
  }

  record.packet_count++;
  record.total_bytes += packet_len;
  record.last_packet_time = std::max(record.last_packet_time, current_time);

  // Track directional metrics
  if (src_ip == record.src_ip && src_port == record.src_port) {
    record.bytes_forward += packet_len;
    record.packets_forward++;
  } else {
    record.bytes_reverse += packet_len;
    record.packets_reverse++;
  }

  float actual_size = packet_len;
  float actual_iat = static_cast<float>(iat);
  float actual_rate = (actual_iat > 0.0f) ? (1000.0f / actual_iat) : 0.0f;
  float actual_byte_ratio =
      record.bytes_forward / (record.bytes_reverse + 1.0f);
  float actual_packet_ratio =
      record.packets_forward / (record.packets_reverse + 1.0f);
  float size_error = 0.0f, iat_error = 0.0f, rate_error = 0.0f,
        variance_error = 0.0f, ratio_error = 0.0f;

  // Initialize predictive coding expectations from the opening packet
  if (record.packet_count == 1) {
    record.expected_size = actual_size;
    record.expected_iat = 100.0f;
    record.expected_rate = actual_rate;
    record.expected_byte_ratio = actual_byte_ratio;
    record.expected_packet_ratio = actual_packet_ratio;
    record.expected_variance = 0.0f;
  } else {
    // Compute prediction errors against current statistical expectations
    size_error = std::abs(actual_size - record.expected_size);
    iat_error = std::abs(actual_iat - record.expected_iat);
    rate_error = std::abs(actual_rate - record.expected_rate);
    float actual_variance = size_error * size_error;
    variance_error = std::abs(actual_variance - record.expected_variance);
    ratio_error = std::abs(actual_byte_ratio - record.expected_byte_ratio);

    // Normalize error distances
    float norm_size_err = size_error / (record.expected_size + 1.0f);
    float norm_iat_err = iat_error / (record.expected_iat + 1.0f);
    float norm_ratio_err = ratio_error / (record.expected_byte_ratio + 1.0f);
    float total_anomaly_distance =
        norm_size_err + norm_iat_err + norm_ratio_err;

    // Apply drift locking: slow adaptation rate if observing large anomalous
    // deviations
    float effective_alpha = (total_anomaly_distance > g_drift_lock_threshold)
                                ? g_alpha * 0.05f
                                : g_alpha;

    // Update internal statistical expectations via EWMA
    record.expected_size +=
        (actual_size - record.expected_size) * effective_alpha;
    record.expected_iat += (actual_iat - record.expected_iat) * effective_alpha;
    record.expected_rate +=
        (actual_rate - record.expected_rate) * effective_alpha;
    record.expected_variance +=
        (actual_variance - record.expected_variance) * effective_alpha;
    record.expected_byte_ratio +=
        (actual_byte_ratio - record.expected_byte_ratio) * effective_alpha;
    record.expected_packet_ratio +=
        (actual_packet_ratio - record.expected_packet_ratio) * effective_alpha;
  }

  // Only emit spikes once the flow profile has converged past the warm-up
  // period (15 packets)
  if (record.packet_count > 15) {
    uint32_t scaled_size = std::min(
        10000u, static_cast<uint32_t>(
                    (size_error / (record.expected_size + 1.0f)) * 100.0f));
    uint32_t scaled_iat = std::min(
        10000u, static_cast<uint32_t>(
                    (iat_error / (record.expected_iat + 1.0f)) * 100.0f));
    uint32_t scaled_variance = std::min(
        10000u,
        static_cast<uint32_t>(
            (variance_error / (record.expected_variance + 1.0f)) * 100.0f));
    uint32_t scaled_rate = std::min(
        10000u, static_cast<uint32_t>(
                    (rate_error / (record.expected_rate + 1.0f)) * 100.0f));
    uint32_t scaled_ratio =
        std::min(10000u, static_cast<uint32_t>(ratio_error * 100.0f));

    // Channel 0: Packet length prediction error
    if (size_error > 1200.0f)
      encode_and_spike(flow_hash, 0, scaled_size, pkt_time_us);

    // Channel 1: Temporal rhythm divergence
    if (iat_error > 250.0f)
      encode_and_spike(flow_hash, 1, scaled_iat, pkt_time_us);

    // Channel 2: Protocol state violation (TCP SYN)
    if (proto == 6 && flags == 2)
      encode_and_spike(flow_hash, 2, 1500, pkt_time_us);

    // Channel 3: Volumetric rate surge
    if (rate_error > 250.0f)
      encode_and_spike(flow_hash, 3, scaled_rate, pkt_time_us);

    // Channel 4: Structural variance surge
    if (variance_error > 20000.0f)
      encode_and_spike(flow_hash, 4, scaled_variance, pkt_time_us);

    // Channel 5: Directional asymmetry surge
    if (ratio_error > 5.0f)
      encode_and_spike(flow_hash, 5, scaled_ratio, pkt_time_us);
  }

  // Check endpoint pair and host concurrency thresholds
  uint64_t forward_pair =
      (static_cast<uint64_t>(record.src_ip) << 32) | record.dest_ip;
  uint64_t reverse_pair =
      (static_cast<uint64_t>(record.dest_ip) << 32) | record.src_ip;
  uint32_t fwd_cnt = get_active_ip_pair_count(forward_pair);
  uint32_t rev_cnt = get_active_ip_pair_count(reverse_pair);
  uint32_t max_pair = std::max(fwd_cnt, rev_cnt);

  // Inject synthetic Channel 3 volumetric spikes if host pair concurrency
  // exceeds 52 sessions
  if (max_pair > 52) {
    uint32_t excess_pair = max_pair - 52;
    uint32_t pair_penalty = std::min(25000u, excess_pair * 200);
    encode_and_spike(flow_hash, 3, pair_penalty, pkt_time_us);
  } else {
    // Inject synthetic Channel 3 volumetric spikes if single-host concurrency
    // exceeds 350 sessions
    uint32_t src_concur = get_active_ip_flow_count(record.src_ip);
    if (src_concur > 350) {
      uint32_t excess_flows = src_concur - 350;
      uint32_t concurrent_penalty = std::min(25000u, excess_flows * 100);
      encode_and_spike(flow_hash, 3, concurrent_penalty, pkt_time_us);
    }
  }
}
