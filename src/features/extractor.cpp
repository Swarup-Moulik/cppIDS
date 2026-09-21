#include "extractor.h"
#include "../core/telemetry.h"
#include "flow_tracker.h"


void process_packet(const uint8_t *bytes, uint32_t len, uint64_t pkt_time_us) {
  if (len < 14) {
    g_runtime_stats.malformed_packets++;
    return;
  }

  uint16_t eth_type = (static_cast<uint16_t>(bytes[12]) << 8) | bytes[13];

  if (eth_type != 0x0800) {
    g_runtime_stats.skipped_packets++;
    return;
  }

  if (len < 34) {
    g_runtime_stats.malformed_packets++;
    return;
  }

  uint8_t ihl = bytes[14] & 0x0F;
  uint32_t ip_header_len = ihl * 4;

  if (ip_header_len < 20 || len < (14 + ip_header_len)) {
    g_runtime_stats.malformed_packets++;
    return;
  }

  uint16_t frag_field = (static_cast<uint16_t>(bytes[20]) << 8) | bytes[21];
  if ((frag_field & 0x1FFF) != 0) {
    g_runtime_stats.skipped_packets++;
    return;
  }

  uint8_t protocol = bytes[23];
  uint32_t src_ip = (static_cast<uint32_t>(bytes[26]) << 24) |
                    (static_cast<uint32_t>(bytes[27]) << 16) |
                    (static_cast<uint32_t>(bytes[28]) << 8) |
                    static_cast<uint32_t>(bytes[29]);
  uint32_t dest_ip = (static_cast<uint32_t>(bytes[30]) << 24) |
                     (static_cast<uint32_t>(bytes[31]) << 16) |
                     (static_cast<uint32_t>(bytes[32]) << 8) |
                     static_cast<uint32_t>(bytes[33]);
  uint32_t transport_offset = 14 + ip_header_len;

  if (protocol == 6) { // TCP
    if (len < (transport_offset + 20)) {
      g_runtime_stats.malformed_packets++;
      return;
    }
    uint16_t src_port = (static_cast<uint16_t>(bytes[transport_offset]) << 8) |
                        bytes[transport_offset + 1];
    uint16_t dest_port =
        (static_cast<uint16_t>(bytes[transport_offset + 2]) << 8) |
        bytes[transport_offset + 3];
    uint16_t flags = bytes[transport_offset + 13];
    track_flow(src_ip, dest_ip, src_port, dest_port, protocol, flags, len,
               pkt_time_us);
  } else if (protocol == 17) { // UDP
    if (len < (transport_offset + 8)) {
      g_runtime_stats.malformed_packets++;
      return;
    }
    uint16_t src_port = (static_cast<uint16_t>(bytes[transport_offset]) << 8) |
                        bytes[transport_offset + 1];
    uint16_t dest_port =
        (static_cast<uint16_t>(bytes[transport_offset + 2]) << 8) |
        bytes[transport_offset + 3];
    track_flow(src_ip, dest_ip, src_port, dest_port, protocol, 0, len,
               pkt_time_us);
  } else {
    g_runtime_stats.skipped_packets++;
  }
}
