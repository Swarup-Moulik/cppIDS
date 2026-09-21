#pragma once
#include <cstdint>

void set_scorer_config(uint32_t alert_thresh, float fire_thresh,
                       uint64_t cooldown);
void on_anomaly_detected(uint32_t flow_hash, uint32_t channel_id,
                         uint32_t raw_potential, uint64_t current_time_us);
void init_scorer();
