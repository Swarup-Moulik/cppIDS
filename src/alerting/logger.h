#pragma once
#include <cstdint>
#include <string>

/* @brief Converts a 32-bit IPv4 address into dotted-decimal notation */
std::string format_ipv4(uint32_t ip);

/* @brief Appends a security threat event or episode state transition to the
 * JSON alert buffer */
void log_event(const std::string &stage, const std::string &classification,
               const std::string &desc, uint64_t hash, uint32_t src_ip,
               uint32_t dest_ip, uint16_t src_port, uint16_t dest_port,
               const std::string &proto, uint32_t magnitude,
               uint64_t timestamp_us);

/* @brief Appends an operational and neuromorphic runtime snapshot to the JSONL
 * telemetry file */
void log_telemetry_snapshot(uint64_t uptime, uint64_t processed,
                            uint64_t dropped, uint64_t p50, uint64_t p99,
                            uint64_t ram_mb, uint64_t spikes,
                            uint64_t anomalies, uint64_t threats);

/* @brief Writes benchmark evaluation statistics and ground truth matrix metrics
 * to CSV */
void log_evaluation_csv(uint64_t ts, uint64_t pkt_cnt, uint32_t flow_cnt,
                        uint64_t spikes, uint64_t synops, uint64_t weights,
                        uint64_t mem, uint64_t lat, uint64_t tput,
                        uint64_t alerts, uint64_t tp, uint64_t fp, uint64_t tn,
                        uint64_t fn);
