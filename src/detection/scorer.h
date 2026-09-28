#pragma once
#include <cstdint>

/* @brief Configures threat evaluation thresholds and cooldown parameters */
void set_scorer_config(uint32_t alert_thresh, float fire_thresh,
                       uint64_t cooldown);

/* @brief SNN anomaly callback that evaluates potential spikes, manages
 * episodes, and confirms threats */
void on_anomaly_detected(uint64_t flow_hash, uint32_t channel_id,
                         uint32_t raw_potential, uint64_t current_time_us);

/* @brief Registers the scoring callback with the SNN core engine */
void init_scorer();
