#pragma once
#include "robin_hood.h"
#include <array>
#include <cstdint>

/* @brief Presynaptic leaky charge accumulator node for an input feature channel
 */
struct PreSynapticNode {
  float leaky_accumulator = 0.0f; // Integrated electrical charge
  float threshold =
      1500.0f; // Potential threshold required to emit a spike payload
};

// Flow channel encoder mapping: 6 discrete presynaptic channels per active flow
inline robin_hood::unordered_flat_map<uint64_t, std::array<PreSynapticNode, 6>>
    encoder_nodes;

/* @brief Integrates incoming feature error magnitude and emits a spike into the
 * SNN upon threshold breach */
void encode_and_spike(uint64_t flow_hash, uint32_t channel_id,
                      uint32_t error_magnitude, uint64_t pkt_time_us);

/* @brief Deallocates presynaptic encoder channel nodes associated with an
 * expired flow */
void cleanup_flow_encoders(uint64_t flow_hash);
