#pragma once
#include "robin_hood.h"
#include <array>
#include <cstdint>


struct PreSynapticNode {
  float leaky_accumulator = 0.0f;
  float threshold = 1500.0f;
};

inline robin_hood::unordered_flat_map<uint32_t, std::array<PreSynapticNode, 6>>
    encoder_nodes;

void encode_and_spike(uint32_t flow_hash, uint32_t channel_id,
                      uint32_t error_magnitude, uint64_t pkt_time_us);
void cleanup_flow_encoders(uint32_t flow_hash);
