#pragma once
#include <cstdint>

struct EthernetHeader {
  uint8_t dest_mac[6];
  uint8_t src_mac[6];
  uint16_t ethertype;
};

inline uint32_t g_malformed_packets = 0;
inline uint32_t get_malformed_count() { return g_malformed_packets; }
void process_packet(const uint8_t *bytes, uint32_t len, uint64_t pkt_time_us);
