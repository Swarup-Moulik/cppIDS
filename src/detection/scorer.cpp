#include "scorer.h"
#include "../alerting/logger.h"
#include "../core/telemetry.h"
#include "../features/flow_tracker.h"
#include "../neuromorphic/snn_core.h"
#include "../neuromorphic/snn_readout.h"
#include "logistic_model.h"
#include "readout_features.h"

// Operational parameters controlling threshold scoring and homeostasis
static uint32_t g_alert_threshold = 45;
static float g_fire_threshold = 5000.0f;
static uint64_t g_cooldown_ms = 10000;
static float g_homeostatic_step = 1500.0f;
static float g_homeostatic_max_penalty = 25000.0f;

/* @brief Sets scoring thresholds, SNN firing limits, and alert suppression
 * cooldowns */
void set_scorer_config(uint32_t alert_thresh, float fire_thresh,
                       uint64_t cooldown) {
  g_alert_threshold = alert_thresh;
  g_fire_threshold = fire_thresh;
  g_cooldown_ms = cooldown;
}

/* @brief Validates if at least one port resides in the ephemeral or
 * non-privileged range */
static inline bool has_ephemeral(uint16_t p1, uint16_t p2) {
  return (p1 >= 1024 || p2 >= 1024 || p1 == p2);
}

/* @brief Checks if a flow endpoint matches a specified target service port */
static inline bool match_service_port(uint16_t p1, uint16_t p2,
                                      uint16_t target) {
  return has_ephemeral(p1, p2) && (p1 == target || p2 == target);
}

/* @brief Identifies common HTTP/HTTPS and web proxy service ports */
static inline bool match_web_ports(uint16_t p1, uint16_t p2) {
  if (!has_ephemeral(p1, p2))
    return false;
  auto is_web = [](uint16_t p) {
    return p == 80 || p == 443 || p == 3128 || p == 4443 || p == 8000 ||
           p == 8008 || p == 8080 || p == 8443 || p == 8888;
  };
  return is_web(p1) || is_web(p2);
}

/* @brief Identifies common email and file transfer service ports */
static inline bool match_email_ftp(uint16_t p1, uint16_t p2) {
  if (!has_ephemeral(p1, p2))
    return false;
  auto is_ef = [](uint16_t p) {
    return p == 20 || p == 21 || p == 25 || p == 110 || p == 143 || p == 587 ||
           p == 993 || p == 995;
  };
  return is_ef(p1) || is_ef(p2);
}

/* @brief Identifies enterprise administrative and directory service ports */
static inline bool match_enterprise(uint16_t p1, uint16_t p2) {
  if (!has_ephemeral(p1, p2))
    return false;
  auto is_ent = [](uint16_t p) {
    return p == 88 || p == 135 || p == 137 || p == 138 || p == 139 ||
           p == 389 || p == 445 || p == 636 || p == 1433 || p == 3268 ||
           p == 3306 || p == 3389 || p == 5432 || p == 5985 || p == 5986;
  };
  return is_ent(p1) || is_ent(p2);
}

/* @brief Evaluates an SNN neuron spike to update flow episodes and classify
 * security threats */
void on_anomaly_detected(uint64_t flow_hash, uint32_t channel_id,
                         uint32_t raw_potential, uint64_t current_time_us) {

  // Scale potential overflow into a normalized magnitude score
  float overflow = static_cast<float>(raw_potential) - g_fire_threshold;
  float anomaly_magnitude =
      (overflow > 0.0f) ? (overflow / (g_fire_threshold * 0.5f)) : 0.0f;

  uint32_t score = static_cast<uint32_t>(anomaly_magnitude * 100.0f);

  if (score > g_alert_threshold && channel_id < 6) {
    auto it = active_flows.find(flow_hash);
    if (it == active_flows.end())
      return;

    FlowRecord &flow = it->second;
    uint64_t current_ms = current_time_us / 1000;
    uint64_t last_channel_time = flow.last_alert_times[channel_id];
    uint32_t last_channel_mag = flow.last_alert_magnitudes[channel_id];

    uint64_t time_since_channel =
        (current_ms >= last_channel_time) ? current_ms - last_channel_time : 0;
    bool emit_alert = false;
    std::string event_stage = "";

    // Manage threat episode lifecycle: initialize new episodes or escalate
    // existing ones
    if (flow.episode_active == 0) {
      flow.episode_active = 1;
      flow.episode_start_time = current_ms;
      flow.episode_last_update = current_ms;
      flow.episode_peak_magnitude = score;
      flow.episode_dominant_channel = channel_id;
      event_stage = "EPISODE_START";
      emit_alert = true;
      g_context_stats.episodes_started++;
    } else {
      flow.episode_last_update = current_ms;
      if (time_since_channel > g_cooldown_ms) {
        flow.episode_peak_magnitude = score;
        event_stage = "EPISODE_RENEWED";
        emit_alert = true;
      } else if (score > (last_channel_mag + 15)) {
        flow.episode_peak_magnitude = score;
        event_stage = "EPISODE_ESCALATED";
        emit_alert = true;
      }
    }

    if (emit_alert) {
      flow.last_alert_times[channel_id] = current_ms;
      flow.last_alert_magnitudes[channel_id] = score;

      if (score > flow.episode_peak_magnitude_ever) {
        flow.episode_peak_magnitude_ever = score;
      }

      // Map channel IDs to descriptive anomaly labels
      std::string threat_type = "Payload Prediction Error";
      if (channel_id == 1)
        threat_type = "Temporal Rhythm Divergence";
      else if (channel_id == 2)
        threat_type = "Protocol State Violation";
      else if (channel_id == 3)
        threat_type = "Volumetric Rate Surge";
      else if (channel_id == 4)
        threat_type = "Structural Variance Anomaly";
      else if (channel_id == 5)
        threat_type = "Directional Asymmetry";

      std::string proto_str = (flow.protocol == 6)    ? "TCP"
                              : (flow.protocol == 17) ? "UDP"
                                                      : "OTHER";

      uint32_t dest_octet1 = (flow.dest_ip >> 24) & 255;
      bool is_multicast = (dest_octet1 >= 224 && dest_octet1 <= 239);

      // Check for bidirectional IP volumetric pair surges
      uint64_t pair_fwd =
          (static_cast<uint64_t>(flow.src_ip) << 32) | flow.dest_ip;
      uint64_t pair_rev =
          (static_cast<uint64_t>(flow.dest_ip) << 32) | flow.src_ip;
      bool is_dos_flood = (get_active_ip_pair_count(pair_fwd) > 60 ||
                           get_active_ip_pair_count(pair_rev) > 60);

      uint16_t p1 = flow.dest_port, p2 = flow.src_port;

      // Extract service classifications
      bool is_discovery =
          (flow.protocol == 17 && (match_service_port(p1, p2, 5353) ||
                                   match_service_port(p1, p2, 1900) ||
                                   match_service_port(p1, p2, 5355) ||
                                   match_service_port(p1, p2, 3702)));

      bool is_dns =
          ((flow.protocol == 17 || flow.protocol == 6) &&
           (match_service_port(p1, p2, 53) || match_service_port(p1, p2, 853)));

      bool is_ntp = (flow.protocol == 17 && match_service_port(p1, p2, 123));
      bool is_dhcp = (flow.protocol == 17 &&
                      ((p1 == 67 && p2 == 68) || (p1 == 68 && p2 == 67)));

      bool is_web = ((flow.protocol == 6 || flow.protocol == 17) &&
                     match_web_ports(p1, p2));
      bool is_email_ftp = (flow.protocol == 6 && match_email_ftp(p1, p2));
      bool is_enterprise = match_enterprise(p1, p2);
      bool is_ssh = (flow.protocol == 6 && match_service_port(p1, p2, 22));
      bool is_game =
          (flow.protocol == 17 && (match_service_port(p1, p2, 27015) ||
                                   match_service_port(p1, p2, 7777)));

      // =========================================================
      // PHASE 2A: NEUROMORPHIC SPIKING READOUT WITH FFI
      // =========================================================
      if (snn_readout_is_enabled()) {
        // Apply feed-forward inhibition on known benign context
        if (is_dns || is_ntp || is_dhcp || is_enterprise || is_ssh || is_game) {
          snn_readout_inject_inhibition(flow_hash, 500.0f, current_time_us);
          return;
        }

        if ((is_web || is_email_ftp) && !is_dos_flood) {
          snn_readout_inject_inhibition(flow_hash, 500.0f, current_time_us);
          return;
        }

        // Confirm threat if the downstream LIF neuron fired
        if (snn_readout_has_fired(flow_hash)) {
          if (flow.threat_confirmed == 0) {
            flow.threat_confirmed = 1;
            flow.confirm_reason = CONFIRM_SPIKE_COUNT;
            flow.confirmed_channel = channel_id;
            log_event(event_stage, "Neuromorphic Spiking Readout", threat_type,
                      flow_hash, flow.src_ip, flow.dest_ip, flow.src_port,
                      flow.dest_port, proto_str, 999, current_time_us);
          }
        }
        return;
      }

      // =========================================================
      // PHASE 2B: BATCH LOGISTIC REGRESSION READOUT INFERENCE
      // =========================================================
      if (lr_readout_is_enabled() && !lr_readout_is_collecting()) {
        auto feat = compute_readout_features(flow);
        float prob = lr_get_model().predict_proba(feat);

        if (prob > 0.50f) {
          if (flow.threat_confirmed == 0) {
            flow.threat_confirmed = 1;
            flow.confirm_reason = CONFIRM_SPIKE_COUNT;
            flow.confirmed_channel = channel_id;
            log_event(event_stage, "Logistic Readout Threat", threat_type,
                      flow_hash, flow.src_ip, flow.dest_ip, flow.src_port,
                      flow.dest_port, proto_str,
                      static_cast<uint32_t>(prob * 100.0f), current_time_us);
          }
        } else {
          flow.episode_peak_magnitude = 0;
          snn_apply_homeostasis(flow_hash, g_homeostatic_step,
                                g_homeostatic_max_penalty);
        }
        return;
      }

      // =========================================================
      // PHASE 1: DETERMINISTIC CONTEXT HEURISTICS
      // =========================================================
      if (is_multicast && is_discovery) {
        flow.episode_peak_magnitude = 0;
        snn_apply_homeostasis(flow_hash, g_homeostatic_step,
                              g_homeostatic_max_penalty);
        return;
      }

      // Volumetric flood confirmation for persistent stream protocols
      bool has_flood_escape = is_web || is_email_ftp;

      if (has_flood_escape && channel_id == 3 && is_dos_flood && score > 500) {
        if (flow.threat_confirmed == 0) {
          flow.threat_confirmed = 1;
          flow.confirm_reason = CONFIRM_PAIR_FLOOD;
          flow.confirmed_channel = channel_id;
          log_event(event_stage, "Malicious Deviation", threat_type, flow_hash,
                    flow.src_ip, flow.dest_ip, flow.src_port, flow.dest_port,
                    proto_str, score, current_time_us);
        }
        return;
      }

      // Suppress benign matches across common infrastructure services
      if (is_web || is_email_ftp || is_dns || is_ntp || is_dhcp ||
          is_enterprise || is_ssh || is_game) {
        flow.episode_peak_magnitude = 0;
        snn_apply_homeostasis(flow_hash, g_homeostatic_step,
                              g_homeostatic_max_penalty);
        return;
      }

      flow.episode_spike_count++;
      uint32_t required_spikes = (flow.protocol == 17) ? 20 : 10;
      bool is_slow_dos = ((channel_id == 1 || channel_id == 4) && score > 850 &&
                          flow.episode_spike_count >= 2);

      // Evaluate confirmation criteria
      ConfirmReason reason = CONFIRM_NONE;
      if (channel_id == 3 && is_dos_flood && score > 500) {
        reason = CONFIRM_PAIR_FLOOD;
      } else if (is_slow_dos) {
        reason = CONFIRM_SLOW_DOS;
      } else if (flow.episode_spike_count >= required_spikes && score > 600) {
        reason = CONFIRM_SPIKE_COUNT;
      }

      // Commit alert or apply homeostatic suppression
      if (reason != CONFIRM_NONE) {
        if (flow.threat_confirmed == 0) {
          flow.threat_confirmed = 1;
          flow.confirm_reason = reason;
          flow.confirmed_channel = channel_id;
          log_event(event_stage, "Malicious Deviation", threat_type, flow_hash,
                    flow.src_ip, flow.dest_ip, flow.src_port, flow.dest_port,
                    proto_str, score, current_time_us);
        }
      } else {
        flow.episode_peak_magnitude = 0;
        snn_apply_homeostasis(flow_hash, g_homeostatic_step,
                              g_homeostatic_max_penalty);
      }
    }
  }
}

/* @brief Binds on_anomaly_detected as the target SNN core spike callback */
void init_scorer() { snn_register_callback(on_anomaly_detected); }
