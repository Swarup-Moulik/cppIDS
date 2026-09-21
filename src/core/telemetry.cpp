#include "telemetry.h"
#include <chrono>

#ifdef _WIN32
#include <windows.h> // This MUST be included first to define WINBOOL/DWORD
#include <psapi.h>
#elif defined(__linux__)
#include <cstdio>
#include <unistd.h>
#endif

RuntimeMetrics g_runtime_stats;
ContextTelemetry g_context_stats;

bool is_known_attacker(uint32_t ip) { return ip == 2886729729U; }

void init_telemetry() {
  g_runtime_stats = RuntimeMetrics();
  g_runtime_stats.min_latency_us = UINT64_MAX;
  g_context_stats = ContextTelemetry();
}

uint64_t get_time_us() {
  return std::chrono::duration_cast<std::chrono::microseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

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
