#include "snn_core.h"
#include "../core/telemetry.h"
#include "robin_hood.h"
#include "snn_readout.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <random>

// Network topological dimensions and plasticity boundaries
constexpr int NUM_HIDDEN_NEURONS = 8; // Hidden LIF neurons per flow
constexpr int NUM_CHANNELS = 6;       // Input feature channels
constexpr float W_MIN = 0.1f;         // Minimum synaptic weight clamp limit
constexpr float W_MAX = 5.0f;         // Maximum synaptic weight clamp limit
constexpr float POTENTIATION_FACTOR =
    1.05f; // STDP Long-Term Potentiation (LTP) rate
constexpr float DEPRESSION_FACTOR =
    0.95f; // STDP Long-Term Depression (LTD) rate

// Reservoir dynamic thresholds and decay constants
static float g_tau = 0.5f; // Membrane potential decay time constant
static float g_fire_threshold =
    5000.0f;                 // Base potential required for hidden neuron firing
static int g_debug_mode = 0; // Logging verbosity flag

// Global telemetry accumulators
static uint64_t g_total_spikes = 0; // Cumulative incoming spikes received
static uint64_t g_total_synops =
    0; // Cumulative synaptic integration operations
static uint64_t g_total_weights = 0; // Cumulative STDP weight update passes
static uint64_t g_total_firing_neurons =
    0;                               // Cumulative hidden neuron spikes fired
static float g_max_potential = 0.0f; // Peak membrane potential encountered
static uint32_t g_firing_neurons_window =
    0; // Spike count within current telemetry interval

// Weight initialization RNG
static std::mt19937 g_weight_rng{2463534242u};
static std::uniform_real_distribution<float> g_weight_dist(0.5f, 2.5f);

// Model adaptation and transfer baseline states
static bool g_enable_stdp = true; // Flag controlling online STDP learning
static bool g_use_baseline =
    false; // Flag determining whether baseline weights are used
static std::array<float, NUM_CHANNELS *NUM_HIDDEN_NEURONS>
    global_baseline_weights = {0.0f}; // Hydrated baseline weight tensor

// Stratified synaptic weight arrays tracking verified true positives across
// confirm reasons
static std::array<double, NUM_CHANNELS * NUM_HIDDEN_NEURONS>
    g_accumulated_weights[5];
static uint64_t g_accumulated_count[5] = {0};

/* @brief State context of an 8-neuron LIF reservoir allocated per tracked flow
 */
struct SNNState {
  uint64_t last_spike_time_us =
      0; // Timestamp of the most recent spike reception
  uint64_t last_update_time_us =
      0; // Timestamp of the most recent decay calculation
  float homeostatic_penalty = 0.0f; // Dynamic refractory threshold increment
  std::array<float, NUM_HIDDEN_NEURONS>
      membrane_potentials; // Neuron membrane voltages
  std::array<float, NUM_CHANNELS * NUM_HIDDEN_NEURONS>
      synaptic_weights; // Synapse matrix
};

// Flat map of all active neural reservoir instances indexed by flow hash
static robin_hood::unordered_flat_map<uint64_t, SNNState> active_snn_states;
static anomaly_callback_t g_anomaly_cb = nullptr;

/* @brief Sets the pseudo-random generator seed for synaptic weight
 * initialization */
void snn_seed_rng(uint32_t seed) {
  g_weight_rng.seed(seed == 0 ? 2463534242u : seed);
}

/* @brief Registers consumer callback function triggered upon neuron firing */
void snn_register_callback(anomaly_callback_t cb) { g_anomaly_cb = cb; }

/* @brief Sets learning plasticity mode and pre-trained baseline initialization
 */
void snn_set_mode(bool stdp_on, bool baseline_on) {
  g_enable_stdp = stdp_on;
  g_use_baseline = baseline_on;
}

/* @brief Records true-positive synaptic weights into categorized reason buckets
 */
void snn_accumulate_truth(uint64_t flow_hash, uint8_t reason) {
  if (reason > 4)
    reason = 0;
  auto it = active_snn_states.find(flow_hash);
  if (it != active_snn_states.end()) {
    for (size_t i = 0; i < NUM_CHANNELS * NUM_HIDDEN_NEURONS; ++i) {
      g_accumulated_weights[reason][i] += it->second.synaptic_weights[i];
    }
    g_accumulated_count[reason]++;
  }
}

/* @brief Averages accumulated true-positive synaptic matrices and exports to
 * binary */
bool snn_export_model(const std::string &filepath) {
  std::array<float, NUM_CHANNELS *NUM_HIDDEN_NEURONS> final_weights = {0.0f};
  int valid_strata = 0;

  std::cout << "\n[SNN EXPORT] Inspecting Stratified Weights:\n";

  // Average weights across all active confirmed strata
  for (int r = 0; r < 5; ++r) {
    if (g_accumulated_count[r] > 0) {
      valid_strata++;
      for (size_t i = 0; i < final_weights.size(); ++i) {
        final_weights[i] += static_cast<float>(g_accumulated_weights[r][i] /
                                               g_accumulated_count[r]);
      }
    }
  }

  if (valid_strata == 0) {
    std::cerr << "[SNN EXPORT] Error: No valid True Positive states found.\n";
    return false;
  }

  // Print exported synaptic averages per channel
  std::cout << "[SNN EXPORT] Averaged synaptic weights per channel:\n";
  for (int c = 0; c < NUM_CHANNELS; ++c) {
    float sum = 0.0f;
    for (int i = 0; i < NUM_HIDDEN_NEURONS; ++i) {
      final_weights[c * NUM_HIDDEN_NEURONS + i] /= valid_strata;
      sum += final_weights[c * NUM_HIDDEN_NEURONS + i];
    }
    std::cout << "  Channel " << c << " Avg: " << (sum / NUM_HIDDEN_NEURONS)
              << "\n";
  }

  // Write float array to disk
  std::ofstream out(filepath, std::ios::binary);
  if (!out)
    return false;
  out.write(reinterpret_cast<char *>(final_weights.data()),
            final_weights.size() * sizeof(float));
  return out.good();
}

/* @brief Loads pre-trained baseline synaptic weights from binary storage */
bool snn_load_model(const std::string &filepath) {
  std::ifstream in(filepath, std::ios::binary);
  if (!in) {
    std::cerr << "[SNN LOAD] Error: Could not open model file " << filepath
              << "\n";
    return false;
  }
  in.read(reinterpret_cast<char *>(global_baseline_weights.data()),
          global_baseline_weights.size() * sizeof(float));
  return in.good();
}

/* @brief Initializes leaky integrate-and-fire time constants and dynamic
 * thresholds */
void snn_configure(float tau, float threshold, int debug_mode) {
  g_tau = (tau <= 0.0001f) ? 0.001f : tau;
  g_fire_threshold = threshold;
  g_debug_mode = debug_mode;
  if (active_snn_states.empty()) {
    active_snn_states.reserve(262144);
  }
}

/* @brief Deallocates inactive flow states exceeding the idle lifetime limit */
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

/* @brief Clears all neural states and resets telemetry variables */
void snn_reset_state() {
  active_snn_states.clear();
  g_total_spikes = g_total_synops = g_total_weights = 0;
  g_max_potential = 0.0f;
  g_firing_neurons_window = 0;
  for (int i = 0; i < 5; ++i) {
    g_accumulated_weights[i].fill(0.0);
    g_accumulated_count[i] = 0;
  }
}

/* @brief Decays membrane potential, integrates incoming charge, applies STDP,
 * and triggers firing */
void snn_receive_spike(uint64_t flow_hash, uint32_t channel_id,
                       uint32_t potential, uint64_t pkt_time_us) {
  g_total_spikes++;
  g_total_synops += NUM_HIDDEN_NEURONS;

  SNNState &state = active_snn_states[flow_hash];

  // Initialize new reservoir if first time observing this flow
  if (state.last_spike_time_us == 0) {
    state.last_spike_time_us = pkt_time_us;
    state.last_update_time_us = pkt_time_us;
    state.homeostatic_penalty = 0.0f;
    state.membrane_potentials.fill(0.0f);
    for (int i = 0; i < NUM_CHANNELS * NUM_HIDDEN_NEURONS; ++i) {
      if (g_use_baseline) {
        state.synaptic_weights[i] = global_baseline_weights[i];
      } else {
        state.synaptic_weights[i] = g_weight_dist(g_weight_rng);
      }
    }
  }

  // Calculate exponential membrane potential decay based on elapsed time
  float dt_spike = (pkt_time_us >= state.last_spike_time_us)
                       ? (pkt_time_us - state.last_spike_time_us) / 1000000.0f
                       : 0.0f;
  state.last_spike_time_us = pkt_time_us;
  float decay_multiplier = std::exp(-dt_spike / g_tau);

  for (int i = 0; i < NUM_HIDDEN_NEURONS; ++i) {
    state.membrane_potentials[i] *= decay_multiplier;
  }

  // Decay homeostatic refractory threshold penalty over a 60-second time
  // constant
  float dt_update = (pkt_time_us >= state.last_update_time_us)
                        ? (pkt_time_us - state.last_update_time_us) / 1000000.0f
                        : 0.0f;
  state.last_update_time_us = pkt_time_us;

  if (state.homeostatic_penalty > 0.0f) {
    state.homeostatic_penalty *= std::exp(-dt_update / 60.0f);
  }

  // Integrate incoming synaptic charge into hidden neurons
  int weight_offset = channel_id * NUM_HIDDEN_NEURONS;
  for (int i = 0; i < NUM_HIDDEN_NEURONS; ++i) {
    state.membrane_potentials[i] += (static_cast<float>(potential) *
                                     state.synaptic_weights[weight_offset + i]);
    if (state.membrane_potentials[i] > g_max_potential) {
      g_max_potential = state.membrane_potentials[i];
    }
  }

  // Evaluate dynamic threshold including homeostatic resistance penalty
  const float penalty_snapshot = state.homeostatic_penalty;
  const float dynamic_threshold = g_fire_threshold + penalty_snapshot;

  for (int i = 0; i < NUM_HIDDEN_NEURONS; ++i) {
    if (state.membrane_potentials[i] >= dynamic_threshold) {
      g_firing_neurons_window++;
      g_total_firing_neurons++;
      snn_readout_integrate_spike(flow_hash, i, pkt_time_us);

      // Apply biological STDP rules: potentiate causative synapses, depress
      // inactive ones
      if (g_enable_stdp) {
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
      }

      // Notify scoring listener of anomaly firing
      if (g_anomaly_cb) {
        uint32_t effective_potential = static_cast<uint32_t>(
            std::max(0.0f, state.membrane_potentials[i] - penalty_snapshot));
        g_anomaly_cb(flow_hash, channel_id, effective_potential, pkt_time_us);
      }

      // Reset potential and increment refractory resistance
      state.membrane_potentials[i] = 0.0f;
      state.homeostatic_penalty =
          std::min(state.homeostatic_penalty + 500.0f, 25000.0f);
    }
  }
}

/* @brief Increases dynamic firing threshold penalty to suppress repeated benign
 * firings */
void snn_apply_homeostasis(uint64_t flow_hash, float increment,
                           float max_penalty) {
  auto it = active_snn_states.find(flow_hash);
  if (it != active_snn_states.end() && it->second.last_spike_time_us > 0) {
    it->second.homeostatic_penalty =
        std::min(it->second.homeostatic_penalty + increment, max_penalty);
  }
}

/* @brief Exports flat telemetry counters and resets the periodic window
 * accumulator */
void snn_get_telemetry_flat(uint64_t *out_spikes, uint64_t *out_synops,
                            uint64_t *out_weights, uint32_t *out_neurons) {
  *out_spikes = g_total_spikes;
  *out_synops = g_total_synops;
  *out_weights = g_total_weights;
  *out_neurons = g_total_firing_neurons;
  g_firing_neurons_window = 0;
}

/* @brief Returns the maximum membrane potential value measured by the core */
float snn_get_max_potential() { return g_max_potential; }

/* @brief Erases reservoir states and associated readout contexts from memory */
void snn_delete_state(uint64_t flow_hash) {
  active_snn_states.erase(flow_hash);
  snn_readout_delete_state(flow_hash);
}
