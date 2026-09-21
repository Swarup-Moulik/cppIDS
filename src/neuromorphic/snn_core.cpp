#include "snn_core.h"
#include "../core/telemetry.h"
#include "robin_hood.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <random>

constexpr int NUM_HIDDEN_NEURONS = 8;
constexpr int NUM_CHANNELS = 6;
constexpr float W_MIN = 0.1f;
constexpr float W_MAX = 5.0f;
constexpr float POTENTIATION_FACTOR = 1.05f;
constexpr float DEPRESSION_FACTOR = 0.95f;

static float g_tau = 0.5f;
static float g_fire_threshold = 5000.0f;
static int g_debug_mode = 0;

static uint64_t g_total_spikes = 0;
static uint64_t g_total_synops = 0;
static uint64_t g_total_weights = 0;
static uint64_t g_total_firing_neurons = 0;
static float g_max_potential = 0.0f;
static uint32_t g_firing_neurons_window = 0;

static std::mt19937 g_weight_rng{2463534242u};
static std::uniform_real_distribution<float> g_weight_dist(0.5f, 2.5f);

struct SNNState {
  uint64_t last_spike_time_us = 0;
  uint64_t last_update_time_us = 0;
  float homeostatic_penalty = 0.0f;
  std::array<float, NUM_HIDDEN_NEURONS> membrane_potentials;
  std::array<float, NUM_CHANNELS * NUM_HIDDEN_NEURONS> synaptic_weights;
};

static robin_hood::unordered_flat_map<uint32_t, SNNState> active_snn_states;
static anomaly_callback_t g_anomaly_cb = nullptr;

void snn_seed_rng(uint32_t seed) {
  g_weight_rng.seed(seed == 0 ? 2463534242u : seed);
}

void snn_register_callback(anomaly_callback_t cb) { g_anomaly_cb = cb; }

void snn_configure(float tau, float threshold, int debug_mode) {
  g_tau = (tau <= 0.0001f) ? 0.001f : tau;
  g_fire_threshold = threshold;
  g_debug_mode = debug_mode;
  if (active_snn_states.empty()) {
    active_snn_states.reserve(262144);
  }
}

void snn_sweep_stale(float max_idle_seconds, uint64_t pkt_time_us) {
  uint64_t max_idle_us = static_cast<uint64_t>(max_idle_seconds * 1000000.0f);
  uint32_t expired_count = 0;

  for (auto it = active_snn_states.begin(); it != active_snn_states.end();) {
    if (it->second.last_spike_time_us > 0 &&
        pkt_time_us >= it->second.last_spike_time_us &&
        (pkt_time_us - it->second.last_spike_time_us) > max_idle_us) {
      it = active_snn_states.erase(it);
      expired_count++;
    } else {
      ++it;
    }
  }

  if (expired_count > 0 && g_debug_mode > 0) {
    printf("[SNN GC] Swept %u stale flows.\n", expired_count);
  }
}

void snn_reset_state() {
  active_snn_states.clear();
  g_total_spikes = g_total_synops = g_total_weights = 0;
  g_max_potential = 0.0f;
  g_firing_neurons_window = 0;
}

void snn_receive_spike(uint32_t flow_hash, uint32_t channel_id,
                       uint32_t potential, uint64_t pkt_time_us) {
  g_total_spikes++;
  g_total_synops += NUM_HIDDEN_NEURONS;

  SNNState &state = active_snn_states[flow_hash];

  if (state.last_spike_time_us == 0) {
    state.last_spike_time_us = pkt_time_us;
    state.last_update_time_us = pkt_time_us;
    state.homeostatic_penalty = 0.0f;
    state.membrane_potentials.fill(0.0f);
    for (int i = 0; i < NUM_CHANNELS * NUM_HIDDEN_NEURONS; ++i) {
      state.synaptic_weights[i] = g_weight_dist(g_weight_rng);
    }
  }

  float dt_spike = (pkt_time_us >= state.last_spike_time_us)
                       ? (pkt_time_us - state.last_spike_time_us) / 1000000.0f
                       : 0.0f;
  state.last_spike_time_us = pkt_time_us;
  float decay_multiplier = std::exp(-dt_spike / g_tau);

  for (int i = 0; i < NUM_HIDDEN_NEURONS; ++i) {
    state.membrane_potentials[i] *= decay_multiplier;
  }

  float dt_update = (pkt_time_us >= state.last_update_time_us)
                        ? (pkt_time_us - state.last_update_time_us) / 1000000.0f
                        : 0.0f;
  state.last_update_time_us = pkt_time_us;

  if (state.homeostatic_penalty > 0.0f) {
    state.homeostatic_penalty *= std::exp(-dt_update / 60.0f);
  }

  int weight_offset = channel_id * NUM_HIDDEN_NEURONS;
  for (int i = 0; i < NUM_HIDDEN_NEURONS; ++i) {
    state.membrane_potentials[i] += (static_cast<float>(potential) *
                                     state.synaptic_weights[weight_offset + i]);
    if (state.membrane_potentials[i] > g_max_potential) {
      g_max_potential = state.membrane_potentials[i];
    }
  }

  const float penalty_snapshot = state.homeostatic_penalty;
  const float dynamic_threshold = g_fire_threshold + penalty_snapshot;

  for (int i = 0; i < NUM_HIDDEN_NEURONS; ++i) {
    if (state.membrane_potentials[i] >= dynamic_threshold) {
      g_firing_neurons_window++;
      g_total_firing_neurons++;
      g_total_weights += NUM_CHANNELS;

      state.synaptic_weights[weight_offset + i] = std::min(
          state.synaptic_weights[weight_offset + i] * POTENTIATION_FACTOR,
          W_MAX);

      for (int c = 0; c < NUM_CHANNELS; ++c) {
        if (c != static_cast<int>(channel_id)) {
          int syn_idx = c * NUM_HIDDEN_NEURONS + i;
          state.synaptic_weights[syn_idx] = std::max(
              state.synaptic_weights[syn_idx] * DEPRESSION_FACTOR, W_MIN);
        }
      }

      if (g_anomaly_cb) {
        uint32_t effective_potential = static_cast<uint32_t>(
            std::max(0.0f, state.membrane_potentials[i] - penalty_snapshot));
        g_anomaly_cb(flow_hash, channel_id, effective_potential, pkt_time_us);
      }

      state.membrane_potentials[i] = 0.0f;
      // Cap cumulative penalty at 25000.0f
      state.homeostatic_penalty =
          std::min(state.homeostatic_penalty + 500.0f, 25000.0f);
    }
  }
}

void snn_apply_homeostasis(uint32_t flow_hash, float increment,
                           float max_penalty) {
  auto it = active_snn_states.find(flow_hash);
  if (it != active_snn_states.end() && it->second.last_spike_time_us > 0) {
    it->second.homeostatic_penalty =
        std::min(it->second.homeostatic_penalty + increment, max_penalty);
  }
}

void snn_get_telemetry_flat(uint64_t *out_spikes, uint64_t *out_synops,
                            uint64_t *out_weights, uint32_t *out_neurons) {
  *out_spikes = g_total_spikes;
  *out_synops = g_total_synops;
  *out_weights = g_total_weights;
  *out_neurons = g_total_firing_neurons;
  g_firing_neurons_window = 0;
}

float snn_get_max_potential() { return g_max_potential; }

void snn_delete_state(uint32_t flow_hash) {
  active_snn_states.erase(flow_hash);
}
