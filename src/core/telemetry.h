#pragma once
#include <cstdint>

struct LatencyHistogram {
  uint64_t sub_100us_bins[100] = {0};
  uint64_t mid_range_bins[90] = {0};
  uint64_t overflow_bins = 0;
};

struct RuntimeMetrics {
  uint64_t packets_received = 0;
  uint64_t packets_processed = 0;
  uint64_t packets_dropped = 0;
  uint64_t malformed_packets = 0;
  uint64_t skipped_packets = 0;
  uint64_t total_latency_us = 0;
  uint64_t min_latency_us = UINT64_MAX;
  uint64_t max_latency_us = 0;
  LatencyHistogram hist;
};

struct ContextTelemetry {
  uint64_t anomalies_detected = 0;
  uint64_t anomalies_dismissed = 0;
  uint64_t threats_confirmed = 0;
  uint64_t context_matches = 0;
  uint64_t context_mismatches = 0;
  uint64_t episodes_started = 0;
  uint64_t episodes_resolved = 0;
  uint64_t true_positives = 0;
  uint64_t false_positives = 0;
  uint64_t true_negatives = 0;
  uint64_t false_negatives = 0;
};

extern RuntimeMetrics g_runtime_stats;
extern ContextTelemetry g_context_stats;

bool is_known_attacker(uint32_t ip);
void init_telemetry();
uint64_t get_time_us();
void record_latency_bin(uint64_t lat_us);
uint64_t compute_percentile(double percentile);
uint64_t sys_get_ram_usage_bytes();
