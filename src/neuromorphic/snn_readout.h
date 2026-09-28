#pragma once
#include <array>
#include <cstdint>
#include <string>

/* @brief Input dimensionality matching the 8 hidden reservoir neurons */
constexpr size_t READOUT_INPUTS = 8;

/* @brief State tracking context for the downstream supervised Threat LIF neuron
 */
struct SpikingReadoutState {
  float membrane_potential = 0.0f; // Threat LIF membrane potential
  uint64_t last_update_us = 0;     // Monotonic timestamp of last integration
  bool has_fired = false; // Fired flag indicating confirmed threat state
  std::array<float, READOUT_INPUTS> eligibility_traces = {
      0.0f}; // Synaptic eligibility traces for R-STDP
};

/* @brief Initializes readout states and baseline synaptic weight connections */
void snn_readout_init();

/* @brief Toggles readout inference activity and R-STDP training updates */
void snn_readout_set_mode(bool enabled, bool is_training);

/* @brief Returns true if the neuromorphic readout layer is currently active */
bool snn_readout_is_enabled();

/* @brief Called on hidden reservoir spike to integrate charge into the Threat
 * LIF neuron */
void snn_readout_integrate_spike(uint64_t flow_hash, uint32_t hidden_neuron_id,
                                 uint64_t pkt_time_us);

/* @brief Injects an inhibitory hyperpolarizing potential to suppress benign
 * context */
void snn_readout_inject_inhibition(uint64_t flow_hash, float ipsp_magnitude,
                                   uint64_t pkt_time_us);

/* @brief Queries whether the Threat LIF neuron fired during this flow's
 * lifetime */
bool snn_readout_has_fired(uint64_t flow_hash);

/* @brief Deallocates the readout state associated with an evicted flow */
void snn_readout_delete_state(uint64_t flow_hash);

/* @brief Applies reward-modulated STDP using eligibility traces upon flow
 * ground truth resolution */
void snn_readout_apply_r_stdp(uint64_t flow_hash, bool is_actually_malicious,
                              bool is_suppressed_context);

/* @brief Exports learned readout synaptic weights to a binary file */
bool snn_readout_export_model(const std::string &filepath);

/* @brief Loads pre-trained readout synaptic weights from a binary file */
bool snn_readout_load_model(const std::string &filepath);
