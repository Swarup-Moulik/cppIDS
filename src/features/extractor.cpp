#include "extractor.h"
#include "../core/telemetry.h"
#include "flow_tracker.h"

/* @brief Decodes Ethernet, IPv4, and TCP/UDP transport headers from raw packet
 * bytes */
void process_packet(const uint8_t *bytes, uint32_t len, uint64_t pkt_time_us) {
  // Validate minimum Ethernet header size (14 bytes: 6 dest MAC, 6 src MAC, 2
  // EtherType)
  if (len < 14) {
    g_runtime_stats.malformed_packets++;
    return;
  }

  // Extract the 16-bit EtherType field
  uint16_t eth_type = (static_cast<uint16_t>(bytes[12]) << 8) | bytes[13];

  // Filter out non-IPv4 payloads (0x0800 = IPv4)
  if (eth_type != 0x0800) {
    g_runtime_stats.skipped_packets++;
    return;
  }

  // Ensure packet satisfies the minimum IPv4 frame length (14 Ethernet + 20
  // Base IPv4)
  if (len < 34) {
    g_runtime_stats.malformed_packets++;
    return;
  }

  // Parse Internet Header Length (lower 4 bits of byte 14) to determine IP
  // header size in bytes
  uint8_t ihl = bytes[14] & 0x0F;
  uint32_t ip_header_len = ihl * 4;

  // Confirm IPv4 header is at least 20 bytes and entirely contained within the
  // buffer
  if (ip_header_len < 20 || len < (14 + ip_header_len)) {
    g_runtime_stats.malformed_packets++;
    return;
  }

  // Check fragmentation offset and flags to skip fragmented frames
  uint16_t frag_field = (static_cast<uint16_t>(bytes[20]) << 8) | bytes[21];
  if ((frag_field & 0x1FFF) != 0) {
    g_runtime_stats.skipped_packets++;
    return;
  }

  // Extract IPv4 protocol and 32-bit endpoint addresses
  uint8_t protocol = bytes[23];
  uint32_t src_ip = (static_cast<uint32_t>(bytes[26]) << 24) |
                    (static_cast<uint32_t>(bytes[27]) << 16) |
                    (static_cast<uint32_t>(bytes[28]) << 8) |
                    static_cast<uint32_t>(bytes[29]);
  uint32_t dest_ip = (static_cast<uint32_t>(bytes[30]) << 24) |
                     (static_cast<uint32_t>(bytes[31]) << 16) |
                     (static_cast<uint32_t>(bytes[32]) << 8) |
                     static_cast<uint32_t>(bytes[33]);

  // Compute offset where L4 transport header starts
  uint32_t transport_offset = 14 + ip_header_len;

  // Protocol 6: TCP
  if (protocol == 6) {
    // Validate minimum TCP header length (20 bytes)
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

    // Protocol 17: UDP
  } else if (protocol == 17) {
    // Validate minimum UDP header length (8 bytes)
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

    // Ignore unsupported transport layer protocols
  } else {
    g_runtime_stats.skipped_packets++;
  }
}
