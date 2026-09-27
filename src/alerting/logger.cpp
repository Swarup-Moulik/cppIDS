#include "logger.h"
#include <fstream>
#include <iostream>
#include <sstream>

/* @brief Tracks the cumulative byte size of the current alert JSON file */
uint64_t g_log_size = 0;

/* @brief Tracks the rotation file index for alert outputs */
int g_log_index = 0;

/* @brief Memory buffer aggregating JSON alerts prior to disk flush */
std::string g_alert_buffer = "";

/* @brief Counter tracking pending alerts waiting to be flushed */
int g_alert_flush_counter = 0;

/* @brief Memory buffer aggregating CSV metrics prior to disk flush */
std::string g_csv_buffer = "";

/* @brief Counter tracking pending CSV lines waiting to be flushed */
int g_csv_flush_counter = 0;

/* @brief Converts a 32-bit IPv4 address into dotted-decimal notation */
std::string format_ipv4(uint32_t ip) {
  // Extract individual octets in network byte order via bit-shifting and
  // masking
  return std::to_string((ip >> 24) & 0xFF) + "." +
         std::to_string((ip >> 16) & 0xFF) + "." +
         std::to_string((ip >> 8) & 0xFF) + "." + std::to_string(ip & 0xFF);
}

/* @brief Buffers and serializes threat alerts into rotating JSON files */
void log_event(const std::string &stage, const std::string &classification,
               const std::string &desc, uint64_t hash, uint32_t src_ip,
               uint32_t dest_ip, uint16_t src_port, uint16_t dest_port,
               const std::string &proto, uint32_t magnitude,
               uint64_t timestamp_us) {

  // Convert raw 32-bit IP values to readable dotted-decimal strings
  std::string src_ip_str = format_ipv4(src_ip);
  std::string dest_ip_str = format_ipv4(dest_ip);

  // Construct a single line JSON alert record
  std::ostringstream ss;
  ss << "{ \"timestamp_us\": " << timestamp_us << ", \"stage\": \"" << stage
     << "\", \"classification\": \"" << classification
     << "\", \"description\": \"" << desc << "\", \"source\": \"" << src_ip_str
     << ":" << src_port << "\", \"dest\": \"" << dest_ip_str << ":" << dest_port
     << "\", \"proto\": \"" << proto << "\", \"flow_hash\": " << hash
     << ", \"magnitude\": " << magnitude << " }\n";

  // Append formatted event record to the alert buffer
  g_alert_buffer += ss.str();
  g_alert_flush_counter++;
  g_log_size += ss.str().length();

  // Rotate log file index when cumulative size reaches 10 MB (10485760
  // bytes)
  if (g_log_size > 10485760) {
    g_log_index++;
    g_log_size = 0;
  }

  // Batch commit to disk when 100 alerts accumulate to minimize I/O overhead
  if (g_alert_flush_counter >= 100) {
    std::ofstream out("mokshaids_alerts_" + std::to_string(g_log_index) +
                          ".json",
                      std::ios::app);
    out << g_alert_buffer;
    g_alert_buffer.clear();
    g_alert_flush_counter = 0;
  }
}

/* @brief Appends periodic telemetry snapshots to a JSONL log file */
void log_telemetry_snapshot(uint64_t uptime, uint64_t processed,
                            uint64_t dropped, uint64_t p50, uint64_t p99,
                            uint64_t ram_mb, uint64_t spikes,
                            uint64_t anomalies, uint64_t threats) {
  // Open line-delimited telemetry JSON output in append mode
  std::ofstream out("mokshaids_telemetry.jsonl", std::ios::app);

  // Serialize system performance and neuromorphic dynamics to a single JSON
  // record
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

/* @brief Formats and writes benchmark evaluation statistics to a CSV file */
void log_evaluation_csv(uint64_t ts, uint64_t pkt_cnt, uint32_t flow_cnt,
                        uint64_t spikes, uint64_t synops, uint64_t weights,
                        uint64_t mem, uint64_t lat, uint64_t tput,
                        uint64_t alerts, uint64_t tp, uint64_t fp, uint64_t tn,
                        uint64_t fn) {
  const std::string filename = "evaluation_metrics.csv";

  // Verify whether the evaluation metrics CSV file already exists on disk
  std::ifstream check(filename);
  bool exists = check.good();
  check.close();

  // Write header row if creating a new CSV file
  if (!exists) {
    std::ofstream out(filename, std::ios::app);
    out << "timestamp_ms,packet_count,flow_count,spikes,synops,weights_updated,"
           "memory_mb,latency_us,throughput_pps,alerts,TP,FP,TN,FN\n";
  }

  // Format benchmark record line
  std::ostringstream ss;
  ss << ts << "," << pkt_cnt << "," << flow_cnt << "," << spikes << ","
     << synops << "," << weights << "," << mem << "," << lat << "," << tput
     << "," << alerts << "," << tp << "," << fp << "," << tn << "," << fn
     << "\n";

  // Buffer formatted line into memory
  g_csv_buffer += ss.str();
  g_csv_flush_counter++;

  // Batch commit to file every 5 entries
  if (g_csv_flush_counter >= 5) {
    std::ofstream out(filename, std::ios::app);
    out << g_csv_buffer;
    g_csv_buffer.clear();
    g_csv_flush_counter = 0;
  }
}
