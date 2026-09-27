#include "telemetry.h"
#include <chrono>
#include <cstdio>
#include <sstream>
#include <stdexcept>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>

#elif defined(__linux__)
#include <unistd.h>
#endif

// Global telemetry instances and ground truth evaluation registries
RuntimeMetrics g_runtime_stats;
ContextTelemetry g_context_stats;
std::unordered_set<uint32_t> g_ground_truth_attackers;
std::unordered_set<uint32_t> g_ground_truth_victims;
std::unordered_set<uint16_t> g_target_ports;

/* @brief Inserts an IPv4 address into the ground truth attacker registry */
void register_ground_truth_attacker(uint32_t ip) {
  g_ground_truth_attackers.insert(ip);
}

/* @brief Parses and registers a comma-delimited string of attacker IPv4
 * addresses */
void parse_and_register_attackers(const std::string &ips_str) {
  std::stringstream ss(ips_str);
  std::string ip_str;
  while (std::getline(ss, ip_str, ',')) {
    uint32_t a, b, c, d;
    if (sscanf(ip_str.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
      uint32_t ip = (a << 24) | (b << 16) | (c << 8) | d;
      g_ground_truth_attackers.insert(ip);
    }
  }
}

/* @brief Parses and registers a comma-delimited string of victim IPv4 addresses
 */
void parse_and_register_victims(const std::string &ips_str) {
  if (ips_str.empty())
    return;
  std::stringstream ss(ips_str);
  std::string ip_str;
  while (std::getline(ss, ip_str, ',')) {
    uint32_t a, b, c, d;
    if (sscanf(ip_str.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
      uint32_t ip = (a << 24) | (b << 16) | (c << 8) | d;
      g_ground_truth_victims.insert(ip);
    }
  }
}

/* @brief Parses and registers a comma-delimited string of evaluation target
 * ports */
void parse_and_register_ports(const std::string &ports_str) {
  if (ports_str.empty())
    return;

  std::stringstream ss(ports_str);
  std::string port_str;

  while (std::getline(ss, port_str, ',')) {
    try {
      int port = std::stoi(port_str);
      if (port > 0 && port <= 65535) {
        g_target_ports.insert(static_cast<uint16_t>(port));
      } else {
        std::cerr << "[TELEMETRY] Warning: Port out of valid range (1-65535) "
                     "ignored: "
                  << port << "\n";
      }
    } catch (const std::invalid_argument &) {
      std::cerr
          << "[TELEMETRY] Warning: Invalid non-numeric port string ignored: '"
          << port_str << "'\n";
    } catch (const std::out_of_range &) {
      std::cerr
          << "[TELEMETRY] Warning: Port number out of integer range ignored: '"
          << port_str << "'\n";
    }
  }
}

/* @brief Checks if a given IPv4 address matches the ground truth attacker list
 */
bool is_known_attacker(uint32_t ip) {
  return g_ground_truth_attackers.find(ip) != g_ground_truth_attackers.end();
}

/* @brief Checks if a given IPv4 address matches the ground truth victim list */
bool is_known_victim(uint32_t ip) {
  return g_ground_truth_victims.find(ip) != g_ground_truth_victims.end();
}

/* @brief Checks if a port matches the ground truth target port list */
bool is_target_port(uint16_t port) {
  return g_target_ports.find(port) != g_target_ports.end();
}

/* @brief Returns true if no ground truth victim filter is defined */
bool are_victims_empty() { return g_ground_truth_victims.empty(); }

/* @brief Returns true if no ground truth target port filter is defined */
bool are_ports_empty() { return g_target_ports.empty(); }

/* @brief Initializes runtime metric trackers and resets latency bounds */
void init_telemetry() {
  g_runtime_stats = RuntimeMetrics();
  g_runtime_stats.min_latency_us = UINT64_MAX;
  g_context_stats = ContextTelemetry();
  // Retain ground truth IP sets because they are loaded before capture begins
}

/* @brief Returns current monotonic clock timestamp in microseconds */
uint64_t get_time_us() {
  return std::chrono::duration_cast<std::chrono::microseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

/* @brief Updates latency statistics and populates the microsecond histogram
 * bins */
void record_latency_bin(uint64_t lat_us) {
  g_runtime_stats.total_latency_us += lat_us;
  if (lat_us > g_runtime_stats.max_latency_us)
    g_runtime_stats.max_latency_us = lat_us;
  if (lat_us < g_runtime_stats.min_latency_us)
    g_runtime_stats.min_latency_us = lat_us;

  if (lat_us < 100) {
    g_runtime_stats.hist.sub_100us_bins[lat_us]++;
  } else if (lat_us < 1000) {
    g_runtime_stats.hist.mid_range_bins[(lat_us - 100) / 10]++;
  } else {
    g_runtime_stats.hist.overflow_bins++;
  }
}

/* @brief Computes latency percentiles from binned microsecond histograms */
uint64_t compute_percentile(double percentile) {
  if (g_runtime_stats.packets_processed == 0)
    return 0;

  uint64_t target = static_cast<uint64_t>(
      static_cast<double>(g_runtime_stats.packets_processed) * percentile);
  uint64_t accum = 0;

  for (size_t i = 0; i < 100; ++i) {
    accum += g_runtime_stats.hist.sub_100us_bins[i];
    if (accum >= target)
      return i;
  }
  for (size_t i = 0; i < 90; ++i) {
    accum += g_runtime_stats.hist.mid_range_bins[i];
    if (accum >= target)
      return 100 + (i * 10);
  }
  return 1000;
}

/* @brief Queries host operating system to retrieve current RAM resident memory
 * usage */
uint64_t sys_get_ram_usage_bytes() {
#ifdef _WIN32
  PROCESS_MEMORY_COUNTERS pmc;
  if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
    return static_cast<uint64_t>(pmc.WorkingSetSize);
  }
  return 0;
#elif defined(__linux__)
  uint64_t rss = 0;
  FILE *fp = fopen("/proc/self/statm", "r");
  if (fp != NULL) {
    long t_size = 0, t_rss = 0;
    if (fscanf(fp, "%ld %ld", &t_size, &t_rss) == 2) {
      rss = static_cast<uint64_t>(t_rss) *
            static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
    }
    fclose(fp);
  }
  return rss;
#else
  return 0;
#endif
}
