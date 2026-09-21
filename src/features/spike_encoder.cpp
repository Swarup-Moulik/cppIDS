#include "spike_encoder.h"
#include "../neuromorphic/snn_core.h"
#include <algorithm>

void encode_and_spike(uint32_t flow_hash, uint32_t channel_id,
                      uint32_t error_magnitude, uint64_t pkt_time_us) {

  PreSynapticNode &node = encoder_nodes[flow_hash][channel_id];

  // Channel 3 (DoS IP Density) is allowed to hit 25000.
  // Standard behavioral channels are capped at 10000 to prevent benign STDP
  // explosions.
  float max_in = (channel_id == 3) ? 25000.0f : 10000.0f;
  float safe_magnitude = std::min(static_cast<float>(error_magnitude), max_in);

  node.leaky_accumulator = (node.leaky_accumulator * 0.75f) + safe_magnitude;

  if (node.leaky_accumulator >= node.threshold) {
    uint32_t max_out = (channel_id == 3) ? 25000u : 10000u;
    uint32_t fire_payload =
        std::min(static_cast<uint32_t>(node.leaky_accumulator), max_out);

    snn_receive_spike(flow_hash, channel_id, fire_payload, pkt_time_us);
    node.leaky_accumulator = 0.0f;
  }
}

void cleanup_flow_encoders(uint32_t flow_hash) {
  encoder_nodes.erase(flow_hash);
}
