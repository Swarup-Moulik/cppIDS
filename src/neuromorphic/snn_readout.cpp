#include "snn_readout.h"
#include "robin_hood.h"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>

// Operational mode flags for the spiking readout head
static bool g_readout_enabled = false;
static bool g_readout_training = false;

// Synaptic weight array connecting 8 hidden reservoir neurons to the single
// Threat LIF neuron
static std::array<float, READOUT_INPUTS> g_readout_weights;

// Readout neuron dynamics and learning parameters
static constexpr float READOUT_THRESHOLD =
    80.0f; // Firing threshold of the Threat LIF neuron
static constexpr float READOUT_TAU = 5.0f; // Decay time constant in seconds
static constexpr float W_MIN = 5.0f; // Lower bound on readout synaptic weights
static constexpr float W_MAX =
    200.0f; // Upper bound on readout synaptic weights

static constexpr float LR_POS =
    0.02f; // Potentiation learning rate on false negatives
static constexpr float LR_NEG =
    0.0005f; // Depression learning rate on false positives

// Readout neuron states indexed by canonical flow hash
static robin_hood::unordered_flat_map<uint64_t, SpikingReadoutState>
    readout_states;

/* @brief Resets readout states and initializes default synaptic weights */
void snn_readout_init() {
  readout_states.clear();
  g_readout_weights.fill(40.0f); // Set uniform initial synaptic weights
}

/* @brief Updates operational execution and R-STDP training state flags */
void snn_readout_set_mode(bool enabled, bool is_training) {
  g_readout_enabled = enabled;
  g_readout_training = is_training;
}

/* @brief Returns true if the neuromorphic readout layer is active */
bool snn_readout_is_enabled() { return g_readout_enabled; }

/* @brief Decays membrane potential of the Threat LIF neuron based on elapsed
 * time */
static inline void decay_readout_state(SpikingReadoutState &state,
                                       uint64_t pkt_time_us) {
  if (state.last_update_us == 0) {
    state.last_update_us = pkt_time_us;
    return;
  }
  float dt = (pkt_time_us >= state.last_update_us)
                 ? (pkt_time_us - state.last_update_us) / 1000000.0f
                 : 0.0f;
  state.last_update_us = pkt_time_us;

  // Apply exponential voltage decay; eligibility traces persist over the flow
  // lifetime
  state.membrane_potential *= std::exp(-dt / READOUT_TAU);
}

/* @brief Integrates incoming reservoir spike, increments eligibility trace, and
 * checks firing */
void snn_readout_integrate_spike(uint64_t flow_hash, uint32_t hidden_neuron_id,
                                 uint64_t pkt_time_us) {
  if (!g_readout_enabled || hidden_neuron_id >= READOUT_INPUTS)
    return;

  SpikingReadoutState &state = readout_states[flow_hash];
  decay_readout_state(state, pkt_time_us);

  // Deposit synaptic charge from the firing hidden reservoir neuron
  state.membrane_potential += g_readout_weights[hidden_neuron_id];

  // Tag causative synapse via bounded eligibility trace increment
  state.eligibility_traces[hidden_neuron_id] =
      std::min(state.eligibility_traces[hidden_neuron_id] + 1.0f, 10.0f);

  // Emit threat spike if membrane potential reaches the firing threshold
  if (state.membrane_potential >= READOUT_THRESHOLD) {
    state.has_fired = true;
    state.membrane_potential = 0.0f;
  }
}

/* @brief Injects hyperpolarizing inhibitory current to suppress firing on
 * benign contexts */
void snn_readout_inject_inhibition(uint64_t flow_hash, float ipsp_magnitude,
                                   uint64_t pkt_time_us) {
  if (!g_readout_enabled)
    return;

  auto it = readout_states.find(flow_hash);
  if (it == readout_states.end())
    return;

  decay_readout_state(it->second, pkt_time_us);
  it->second.membrane_potential =
      std::max(0.0f, it->second.membrane_potential - ipsp_magnitude);
  it->second.has_fired = false; // Suppress false firing on benign matches
}

/* @brief Queries whether the Threat LIF neuron emitted a spike for this flow */
bool snn_readout_has_fired(uint64_t flow_hash) {
  auto it = readout_states.find(flow_hash);
  return (it != readout_states.end()) && it->second.has_fired;
}

/* @brief Deallocates the spiking readout context of an expired flow */
void snn_readout_delete_state(uint64_t flow_hash) {
  readout_states.erase(flow_hash);
}

/* @brief Modulates synaptic weights via reward-modulated STDP using stored
 * eligibility traces */
void snn_readout_apply_r_stdp(uint64_t flow_hash, bool is_actually_malicious,
                              bool is_suppressed_context) {
  if (!g_readout_training)
    return;

  auto it = readout_states.find(flow_hash);
  if (it == readout_states.end())
    return;

  SpikingReadoutState &state = it->second;

  float step = 0.0f;
  if (is_actually_malicious && !state.has_fired) {
    // False Negative: Output failed to fire. Potentiate active contributing
    // synapses.
    step = +LR_POS;
  } else if (!is_actually_malicious && state.has_fired) {
    // False Positive: Output fired on benign flow. Depress active contributing
    // synapses.
    if (!is_suppressed_context) {
      step = -LR_NEG;
    }
  }

  // Update synapses tagged by eligibility traces
  if (std::abs(step) > 0.00001f) {
    for (size_t i = 0; i < READOUT_INPUTS; ++i) {
      if (state.eligibility_traces[i] >= 1.0f) {
        g_readout_weights[i] += step * state.eligibility_traces[i];
        g_readout_weights[i] = std::clamp(g_readout_weights[i], W_MIN, W_MAX);
      }
    }
  }
}

/* @brief Exports trained readout synaptic weights to a binary file */
bool snn_readout_export_model(const std::string &filepath) {
  std::ofstream out(filepath, std::ios::binary);
  if (!out)
    return false;

  out.write(reinterpret_cast<const char *>(g_readout_weights.data()),
            sizeof(float) * READOUT_INPUTS);

  std::cout << "\n[SNN READOUT EXPORT] Learned Synaptic Weights (Hidden -> "
               "Threat LIF):\n";
  for (size_t i = 0; i < READOUT_INPUTS; ++i) {
    std::cout << "  Synapse [Hidden " << i
              << " -> Threat]: " << g_readout_weights[i] << "\n";
  }
  return out.good();
}

/* @brief Loads pre-trained readout synaptic weights from a binary file */
bool snn_readout_load_model(const std::string &filepath) {
  std::ifstream in(filepath, std::ios::binary);
  if (!in)
    return false;

  in.read(reinterpret_cast<char *>(g_readout_weights.data()),
          sizeof(float) * READOUT_INPUTS);

  std::cout << "\n[SNN READOUT LOAD] Loaded Synaptic Weights (Hidden -> Threat "
               "LIF):\n";
  for (size_t i = 0; i < READOUT_INPUTS; ++i) {
    std::cout << "  Synapse [Hidden " << i
              << " -> Threat]: " << g_readout_weights[i] << "\n";
  }
  return in.good();
}
