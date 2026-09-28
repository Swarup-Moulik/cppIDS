#pragma once
#include <cstdint>
#include <string>
#include <vector>

/* @brief Callback signature invoked when an SNN hidden neuron fires an anomaly
 * spike */
typedef void (*anomaly_callback_t)(uint64_t flow_hash, uint32_t channel_id,
                                   uint32_t potential,
                                   uint64_t current_time_us);

/* @brief Initializes the pseudo-random generator for synaptic weight
 * initialization */
void snn_seed_rng(uint32_t seed);

/* @brief Registers a consumer callback to receive threshold-breaching anomaly
 * events */
void snn_register_callback(anomaly_callback_t cb);

/* @brief Configures leaky integrate-and-fire time constants, thresholds, and
 * debug flags */
void snn_configure(float tau, float threshold, int debug_mode);

/* @brief Sweeps and deallocates idle flow SNN states exceeding the inactivity
 * window */
void snn_sweep_stale(float max_idle_seconds, uint64_t pkt_time_us);

/* @brief Clears all active flow neural states and resets telemetry counters to
 * zero */
void snn_reset_state();

/* @brief Integrates incoming channel spike charge into flow neurons and checks
 * thresholds */
void snn_receive_spike(uint64_t flow_hash, uint32_t channel_id,
                       uint32_t potential, uint64_t pkt_time_us);

/* @brief Increases dynamic firing threshold penalties to suppress repeated
 * benign anomalies */
void snn_apply_homeostasis(uint64_t flow_hash, float increment,
                           float max_penalty);

/* @brief Flushes and returns cumulative neuromorphic operations, spikes, and
 * active neurons */
void snn_get_telemetry_flat(uint64_t *out_spikes, uint64_t *out_synops,
                            uint64_t *out_weights, uint32_t *out_neurons);

/* @brief Retrieves highest recorded membrane potential observed across all
 * flows */
float snn_get_max_potential();

/* @brief Deallocates neural and readout states associated with an evicted flow
 */
void snn_delete_state(uint64_t flow_hash);

/* @brief Toggles online STDP synaptic plasticity and pre-trained baseline
 * hydration */
void snn_set_mode(bool stdp_on, bool baseline_on);

/* @brief Accumulates verified true-positive synaptic weights into stratified
 * reason bins */
void snn_accumulate_truth(uint64_t flow_hash, uint8_t reason);

/* @brief Exports normalized synaptic weights across stratified reason bins to a
 * binary file */
bool snn_export_model(const std::string &filepath);

/* @brief Loads pre-trained baseline synaptic weights from a binary file */
bool snn_load_model(const std::string &filepath);
