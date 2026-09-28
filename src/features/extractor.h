#pragma once
#include <cstdint>

/* @brief Represents the Ethernet L2 frame header */
struct EthernetHeader {
  uint8_t dest_mac[6]; // Destination Hardware MAC address
  uint8_t src_mac[6];  // Source Hardware MAC address
  uint16_t ethertype;  // Encapsulated protocol EtherType
};

/* @brief Tracks the total number of malformed or truncated packets encountered
 */
inline uint32_t g_malformed_packets = 0;

/* @brief Returns the total count of malformed frames received by the capture
 * pipeline */
inline uint32_t get_malformed_count() { return g_malformed_packets; }

/* @brief Ingests raw link-layer frame bytes, decodes IP and transport headers,
 * and forwards to flow tracking */
void process_packet(const uint8_t *bytes, uint32_t len, uint64_t pkt_time_us);
