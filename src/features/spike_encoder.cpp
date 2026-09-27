#include "spike_encoder.h"
#include "../neuromorphic/snn_core.h"
#include <algorithm>

/* @brief Integrates channel error magnitude and discharges a spike payload to
 * the SNN reservoir */
void encode_and_spike(uint64_t flow_hash, uint32_t channel_id,
                      uint32_t error_magnitude, uint64_t pkt_time_us) {

  PreSynapticNode &node = encoder_nodes[flow_hash][channel_id];

  // Channel 3 (DoS density) allows up to 25000; other behavioral channels are
  // capped at 10000
  float max_in = (channel_id == 3) ? 25000.0f : 10000.0f;
  float safe_magnitude = std::min(static_cast<float>(error_magnitude), max_in);

  // Apply discrete leaky accumulation (decay factor 0.75)
  node.leaky_accumulator = (node.leaky_accumulator * 0.75f) + safe_magnitude;

  // Emit a spike if accumulated charge breaches the presynaptic threshold
  if (node.leaky_accumulator >= node.threshold) {
    uint32_t max_out = (channel_id == 3) ? 25000u : 10000u;
    uint32_t fire_payload =
        std::min(static_cast<uint32_t>(node.leaky_accumulator), max_out);

    // Forward the spike payload to the SNN hidden reservoir
    snn_receive_spike(flow_hash, channel_id, fire_payload, pkt_time_us);

    // Discharge the accumulator back to baseline
    node.leaky_accumulator = 0.0f;
  }
}

/* @brief Removes the presynaptic encoder states of an evicted flow from memory
 */
void cleanup_flow_encoders(uint64_t flow_hash) {
  encoder_nodes.erase(flow_hash);
}
