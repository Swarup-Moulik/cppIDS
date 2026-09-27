#pragma once
#include <cstdint>
#include <string>
#include <unordered_set>

/* @brief Binned latency histogram measuring packet processing overhead */
struct LatencyHistogram {
  uint64_t sub_100us_bins[100] = {
      0}; // 1 microsecond bins for 0 to 99 us
  uint64_t mid_range_bins[90] = {
      0}; // 10 microsecond bins for 100 to 999 us
  uint64_t overflow_bins =
      0; // Count of packets with latency >= 1000 us
};

/* @brief Aggregates runtime packet ingestion and timing statistics */
struct RuntimeMetrics {
  uint64_t packets_received = 0; // Total raw frames captured
  uint64_t packets_processed =
      0; // Total valid frames routed to flow tracking
  uint64_t packets_dropped =
      0; // Frames dropped by operating system socket buffers
  uint64_t malformed_packets = 0; // Truncated or malformed headers
  uint64_t skipped_packets = 0;   // Non-IPv4 or non-TCP/UDP traffic
  uint64_t total_latency_us =
      0; // Cumulative latency across all packets
  uint64_t min_latency_us = UINT64_MAX; // Minimum measured latency
  uint64_t max_latency_us = 0;          // Maximum measured latency
  LatencyHistogram hist; // Detailed histogram bin distribution
};

/* @brief Tracks contextual suppression outcomes and ground truth validation
 * metrics */
struct ContextTelemetry {
  uint64_t anomalies_detected =
      0; // Total LIF potential threshold breaches
  uint64_t anomalies_dismissed =
      0; // Benign alerts suppressed by context rules
  uint64_t threats_confirmed =
      0; // Alerts verified as malicious security incidents
  uint64_t context_matches = 0;    // Whitelist or benign match count
  uint64_t context_mismatches = 0; // Malicious anomaly match count
  uint64_t episodes_started =
      0; // Total threat tracking episodes created
  uint64_t episodes_resolved = 0; // Episodes timed out after recovery
  uint64_t true_positives =
      0; // Ground-truth verified malicious detections
  uint64_t false_positives =
      0; // Benign traffic incorrectly confirmed as threat
  uint64_t true_negatives = 0; // Benign traffic correctly suppressed
  uint64_t false_negatives =
      0; // Malicious traffic missed by the engine
};

// Global telemetry and ground truth registries
extern RuntimeMetrics g_runtime_stats;
extern ContextTelemetry g_context_stats;
extern std::unordered_set<uint32_t> g_ground_truth_attackers;
extern std::unordered_set<uint32_t> g_ground_truth_victims;
extern std::unordered_set<uint16_t> g_target_ports;

/* @brief Registers an individual IPv4 address as a ground truth attacker */
void register_ground_truth_attacker(uint32_t ip);

/* @brief Parses and registers a comma-separated list of attacker IPv4 addresses
 */
void parse_and_register_attackers(const std::string &ips_str);

/* @brief Parses and registers a comma-separated list of victim IPv4 addresses
 */
void parse_and_register_victims(const std::string &ips_str);

/* @brief Parses and registers a comma-separated list of targeted destination
 * ports */
void parse_and_register_ports(const std::string &ports_str);

/* @brief Checks if an IPv4 address is in the registered attacker list */
bool is_known_attacker(uint32_t ip);

/* @brief Checks if an IPv4 address is in the registered victim list */
bool is_known_victim(uint32_t ip);

/* @brief Checks if a transport port is in the targeted port list */
bool is_target_port(uint16_t port);

/* @brief Returns true if no ground truth victim filter is defined */
bool are_victims_empty();

/* @brief Returns true if no ground truth port filter is defined */
bool are_ports_empty();

/* @brief Resets runtime telemetry and latency bin statistics */
void init_telemetry();

/* @brief Returns current monotonic timestamp in microseconds */
uint64_t get_time_us();

/* @brief Records a packet processing latency sample into histogram bins */
void record_latency_bin(uint64_t lat_us);

/* @brief Computes processing latency percentiles from histogram bins */
uint64_t compute_percentile(double percentile);

/* @brief Retrieves current process working set RAM usage in bytes */
uint64_t sys_get_ram_usage_bytes();
