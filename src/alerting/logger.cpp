#include "logger.h"
#include <fstream>
#include <iostream>
#include <sstream>


uint64_t g_log_size = 0;
int g_log_index = 0;
std::string g_alert_buffer = "";
int g_alert_flush_counter = 0;
std::string g_csv_buffer = "";
int g_csv_flush_counter = 0;

std::string format_ipv4(uint32_t ip) {
  return std::to_string((ip >> 24) & 0xFF) + "." +
         std::to_string((ip >> 16) & 0xFF) + "." +
         std::to_string((ip >> 8) & 0xFF) + "." + std::to_string(ip & 0xFF);
}

void log_event(const std::string &stage, const std::string &classification,
               const std::string &desc, uint32_t hash, uint32_t src_ip,
               uint32_t dest_ip, uint16_t src_port, uint16_t dest_port,
               const std::string &proto, uint32_t magnitude,
               uint64_t timestamp_us) {

  std::string src_ip_str = format_ipv4(src_ip);
  std::string dest_ip_str = format_ipv4(dest_ip);

  std::ostringstream ss;
  ss << "{ \"timestamp_us\": " << timestamp_us << ", \"stage\": \"" << stage
     << "\", \"classification\": \"" << classification
     << "\", \"description\": \"" << desc << "\", \"source\": \"" << src_ip_str
     << ":" << src_port << "\", \"dest\": \"" << dest_ip_str << ":" << dest_port
     << "\", \"proto\": \"" << proto << "\", \"flow_hash\": " << hash
     << ", \"magnitude\": " << magnitude << " }\n";

  g_alert_buffer += ss.str();
  g_alert_flush_counter++;
  g_log_size += ss.str().length();

  if (g_log_size > 10485760) {
    g_log_index++;
    g_log_size = 0;
  }

  if (g_alert_flush_counter >= 100) {
    std::ofstream out("mokshaids_alerts_" + std::to_string(g_log_index) +
                          ".json",
                      std::ios::app);
    out << g_alert_buffer;
    g_alert_buffer.clear();
    g_alert_flush_counter = 0;
  }
}

void log_telemetry_snapshot(uint64_t uptime, uint64_t processed,
                            uint64_t dropped, uint64_t p50, uint64_t p99,
                            uint64_t ram_mb, uint64_t spikes,
                            uint64_t anomalies, uint64_t threats) {
  std::ofstream out("mokshaids_telemetry.jsonl", std::ios::app);
  out << "{ \"stage\": \"TELEMETRY_SNAPSHOT\", \"uptime_ms\": " << uptime
      << ", \"packets_processed\": " << processed
      << ", \"packets_dropped\": " << dropped << ", \"latency_p50_us\": " << p50
      << ", \"latency_p99_us\": " << p99 << ", \"ram_mb\": " << ram_mb
      << ", \"snn_spikes\": " << spikes
      << ", \"anomalies_detected\": " << anomalies
      << ", \"threats_confirmed\": " << threats << " }\n";
  std::cout
      << "[SYSTEM] Telemetry snapshot appended to mokshaids_telemetry.jsonl\n";
}

void log_evaluation_csv(uint64_t ts, uint64_t pkt_cnt, uint32_t flow_cnt,
                        uint64_t spikes, uint64_t synops, uint64_t weights,
                        uint64_t mem, uint64_t lat, uint64_t tput,
                        uint64_t alerts, uint64_t tp, uint64_t fp, uint64_t tn,
                        uint64_t fn) {
  const std::string filename = "evaluation_metrics.csv";
  std::ifstream check(filename);
  bool exists = check.good();
  check.close();

  if (!exists) {
    std::ofstream out(filename, std::ios::app);
    out << "timestamp_ms,packet_count,flow_count,spikes,synops,weights_updated,"
           "memory_mb,latency_us,throughput_pps,alerts,TP,FP,TN,FN\n";
  }

  std::ostringstream ss;
  ss << ts << "," << pkt_cnt << "," << flow_cnt << "," << spikes << ","
     << synops << "," << weights << "," << mem << "," << lat << "," << tput
     << "," << alerts << "," << tp << "," << fp << "," << tn << "," << fn
     << "\n";

  g_csv_buffer += ss.str();
  g_csv_flush_counter++;

  if (g_csv_flush_counter >= 5) {
    std::ofstream out(filename, std::ios::app);
    out << g_csv_buffer;
    g_csv_buffer.clear();
    g_csv_flush_counter = 0;
  }
}
