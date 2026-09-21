#pragma once
#include <cstdint>

typedef void (*anomaly_callback_t)(uint32_t, uint32_t, uint32_t, uint64_t);

void snn_seed_rng(uint32_t seed);
void snn_register_callback(anomaly_callback_t cb);
void snn_configure(float tau, float threshold, int debug_mode);
void snn_sweep_stale(float max_idle_seconds, uint64_t pkt_time_us);
void snn_reset_state();
void snn_receive_spike(uint32_t flow_hash, uint32_t channel_id,
                       uint32_t potential, uint64_t pkt_time_us);
void snn_apply_homeostasis(uint32_t flow_hash, float increment,
                           float max_penalty);
void snn_get_telemetry_flat(uint64_t *out_spikes, uint64_t *out_synops,
                            uint64_t *out_weights, uint32_t *out_neurons);
float snn_get_max_potential();
void snn_delete_state(uint32_t flow_hash);
