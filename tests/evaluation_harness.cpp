#include "alerting/logger.h"
#include "capture/pcap_wrapper.h"
#include "core/config.h"
#include "core/telemetry.h"
#include "detection/scorer.h"
#include "features/extractor.h"
#include "features/flow_tracker.h"
#include "neuromorphic/snn_core.h"
#include <iomanip>
#include <iostream>
#include <pcap.h>
#include <string>
#include <unordered_map>
#include <vector>


static const uint64_t TOTAL_EXPECTED_PACKETS = 13788878;
static uint32_t last_printed_pct = 0;

extern std::unordered_map<uint64_t, uint64_t> fp_by_pair;
extern std::unordered_map<uint16_t, uint64_t> fp_by_svc_port;
extern std::unordered_map<uint64_t, uint64_t> fn_by_pair;
extern std::unordered_map<uint16_t, uint64_t> fn_by_svc_port;

void init_matrix() {
  gt_true_positives = 0;
  gt_true_negatives = 0;
  gt_false_positives = 0;
  gt_false_negatives = 0;
  last_printed_pct = 0;
}

void on_benchmark_packet(u_char *user, const struct pcap_pkthdr *h,
                         const u_char *bytes) {
  (void)user;
  uint64_t start_us = get_time_us();

  uint32_t len = h->caplen;
  uint64_t pkt_time_us =
      (static_cast<uint64_t>(h->ts.tv_sec) * 1000000) + h->ts.tv_usec;

  process_packet(bytes, len, pkt_time_us);

  uint64_t latency = get_time_us() - start_us;
  record_latency_bin(latency);
  g_runtime_stats.packets_processed++;

  if ((g_runtime_stats.packets_processed % 100000) == 0) {
    uint32_t current_pct = static_cast<uint32_t>(
        (static_cast<float>(g_runtime_stats.packets_processed) /
         static_cast<float>(TOTAL_EXPECTED_PACKETS)) *
        100.0f);

    if (current_pct > 100)
      current_pct = 100;

    if (current_pct > last_printed_pct) {
      last_printed_pct = current_pct;
      std::cout << "[BENCHMARK] Progress: " << current_pct << "% done ("
                << g_runtime_stats.packets_processed
                << " packets processed)...\n";
    }
  }
}

void evaluate_flows() {
  for (auto &[hash, flow] : active_flows) {
    commit_flow_ground_truth(flow);
  }
}

static std::string format_ip(uint32_t ip) {
  return std::to_string((ip >> 24) & 0xFF) + "." +
         std::to_string((ip >> 16) & 0xFF) + "." +
         std::to_string((ip >> 8) & 0xFF) + "." + std::to_string(ip & 0xFF);
}

template <typename K, typename V>
void print_top_n_ports(const std::unordered_map<K, V> &map, int n,
                       const std::string &label) {
  std::vector<std::pair<K, V>> vec(map.begin(), map.end());
  std::sort(vec.begin(), vec.end(),
            [](const auto &a, const auto &b) { return a.second > b.second; });
  std::cout << "\n[" << label << "]\n";
  for (int i = 0; i < n && i < static_cast<int>(vec.size()); ++i) {
    std::cout << "  Port " << vec[i].first << " -> " << vec[i].second
              << " flows\n";
  }
}

template <typename K, typename V>
void print_top_n_pairs(const std::unordered_map<K, V> &map, int n,
                       const std::string &label) {
  std::vector<std::pair<K, V>> vec(map.begin(), map.end());
  std::sort(vec.begin(), vec.end(),
            [](const auto &a, const auto &b) { return a.second > b.second; });
  std::cout << "\n[" << label << "]\n";
  for (int i = 0; i < n && i < static_cast<int>(vec.size()); ++i) {
    uint32_t src = vec[i].first >> 32;
    uint32_t dst = vec[i].first & 0xFFFFFFFF;
    std::cout << "  " << format_ip(src) << " <-> " << format_ip(dst) << " ("
              << vec[i].second << " flows)\n";
  }
}

void print_full_metric_report(uint64_t total_time_ms) {
  double tp = static_cast<double>(gt_true_positives);
  double tn = static_cast<double>(gt_true_negatives);
  double fp = static_cast<double>(gt_false_positives);
  double fn = static_cast<double>(gt_false_negatives);

  double precision = ((tp + fp) > 0.0) ? (tp / (tp + fp)) * 100.0 : 0.0;
  double recall = ((tp + fn) > 0.0) ? (tp / (tp + fn)) * 100.0 : 0.0;
  double f1 = ((precision + recall) > 0.0)
                  ? (2.0 * precision * recall) / (precision + recall)
                  : 0.0;
  double accuracy = ((tp + tn + fp + fn) > 0.0)
                        ? ((tp + tn) / (tp + tn + fp + fn)) * 100.0
                        : 0.0;
  double fpr = ((fp + tn) > 0.0) ? (fp / (fp + tn)) * 100.0 : 0.0;
  double fnr = ((fn + tp) > 0.0) ? (fn / (fn + tp)) * 100.0 : 0.0;

  uint64_t p50 = compute_percentile(0.50);
  uint64_t p95 = compute_percentile(0.95);
  uint64_t p99 = compute_percentile(0.99);

  uint64_t final_ram_mb = sys_get_ram_usage_bytes() / (1024 * 1024);
  uint64_t min_lat = (g_runtime_stats.min_latency_us == UINT64_MAX)
                         ? 0
                         : g_runtime_stats.min_latency_us;

  std::cout << "\n=======================================================\n"
            << "          cppIDS Benchmark Evaluation Report           \n"
            << "=======================================================\n";

  std::cout << std::fixed << std::setprecision(2);

  std::cout << "\n[1. CORE IDS CLASSIFICATION METRICS]\n"
            << "True Positives (TP):       " << gt_true_positives << "\n"
            << "True Negatives (TN):       " << gt_true_negatives << "\n"
            << "False Positives (FP):      " << gt_false_positives << "\n"
            << "False Negatives (FN):      " << gt_false_negatives << "\n"
            << "Precision:                 " << precision << "%\n"
            << "Recall / Detection Rate:   " << recall << "%\n"
            << "F1-Score:                  " << f1 << "%\n"
            << "Classification Accuracy:   " << accuracy << "%\n"
            << "False Positive Rate:       " << fpr << "%\n"
            << "False Negative Rate:       " << fnr << "%\n";

  std::cout << "\n[2. RUNTIME & LATENCY BENCHMARKS]\n"
            << "Packets Processed:         "
            << g_runtime_stats.packets_processed << "\n"
            << "Packets Skipped:           " << g_runtime_stats.skipped_packets
            << "\n"
            << "Malformed/Invalid Pkts:    "
            << g_runtime_stats.malformed_packets << "\n"
            << "Dropped/Evicted Flows:     " << g_dropped_new_flows << "\n"
            << "Min Latency:               " << min_lat << " us\n";

  if (g_runtime_stats.packets_processed > 0) {
    double avg_lat = static_cast<double>(g_runtime_stats.total_latency_us) /
                     static_cast<double>(g_runtime_stats.packets_processed);
    std::cout << "Avg Latency:               " << avg_lat << " us\n";
  }
  std::cout << "Histogram Overflow (>1ms): "
            << g_runtime_stats.hist.overflow_bins << " packets\n"
            << "Median Latency (P50):      " << p50 << " us\n"
            << "P95 Latency:               " << p95 << " us\n"
            << "P99 Latency:               " << p99 << " us\n"
            << "Max Latency:               " << g_runtime_stats.max_latency_us
            << " us\n"
            << "Final Working Set RAM:     " << final_ram_mb << " MB\n";

  if (total_time_ms > 0) {
    uint64_t throughput =
        (g_runtime_stats.packets_processed * 1000) / total_time_ms;
    std::cout << "Throughput:                " << throughput << " PPS\n";
  }

  std::cout << "\n[3. CONTEXTUAL FALSE-POSITIVE SUPPRESSION]\n"
            << "Anomalies Detected (SNN):  "
            << g_context_stats.anomalies_detected << "\n"
            << "Anomalies Dismissed (Ctx): "
            << g_context_stats.anomalies_dismissed << "\n"
            << "Threats Confirmed:         "
            << g_context_stats.threats_confirmed << "\n"
            << "Context Matches:           " << g_context_stats.context_matches
            << "\n"
            << "Context Mismatches:        "
            << g_context_stats.context_mismatches << "\n";

  double context_fp_reduction = 0.0;
  if (g_context_stats.anomalies_detected > 0) {
    context_fp_reduction =
        (static_cast<double>(g_context_stats.anomalies_dismissed) /
         static_cast<double>(g_context_stats.anomalies_detected)) *
        100.0;
  }
  std::cout << "Context Anomaly Dismissal: " << context_fp_reduction << "%\n";

  std::cout << "\n[4. THREAT CONFIRMATION REASON BREAKDOWN]\n"
            << "Pair Volumetric Flood:     TP = "
            << tp_by_reason[CONFIRM_PAIR_FLOOD]
            << ", FP = " << fp_by_reason[CONFIRM_PAIR_FLOOD] << "\n"
            << "Slow DoS Heuristic:        TP = "
            << tp_by_reason[CONFIRM_SLOW_DOS]
            << ", FP = " << fp_by_reason[CONFIRM_SLOW_DOS] << "\n"
            << "Spike Count Persistence:   TP = "
            << tp_by_reason[CONFIRM_SPIKE_COUNT]
            << ", FP = " << fp_by_reason[CONFIRM_SPIKE_COUNT] << "\n";

  std::cout << "\n=======================================================\n"
            << "             FALSE POSITIVE DIAGNOSTICS                \n"
            << "=======================================================\n";
  print_top_n_ports(fp_by_svc_port, 10, "Top 10 FP Service Ports");
  print_top_n_pairs(fp_by_pair, 10, "Top 10 FP IP Pairs");

  std::cout << "\n=======================================================\n"
            << "             FALSE NEGATIVE DIAGNOSTICS                \n"
            << "=======================================================\n";
  print_top_n_ports(fn_by_svc_port, 10, "Top 10 FN Service Ports");
  print_top_n_pairs(fn_by_pair, 10, "Top 10 FN IP Pairs");
}

int main(int argc, char **argv) {
  std::cout << "=== Running cppIDS Benchmark Evaluation Harness ===\n";
  std::string pcap_file = "synthetic_dataset.pcap";
  if (argc > 1)
    pcap_file = argv[1];

  if (!load_npcap_dll())
    return 1;

  init_matrix();
  init_telemetry();

  snn_seed_rng(13371337u);
  snn_configure(1.5f, 5000.0f, 0);
  init_scorer();
  set_scorer_config(85, 5000.0f, 10000);
  configure_tracker(60.0f, 0.125f, 3.5f, 30000, 500000);

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap_h = pcap_open_offline(pcap_file.c_str(), errbuf);
  if (!pcap_h) {
    std::cout << "[ERROR] Could not open dataset file: " << pcap_file << "\n";
    return 1;
  }

  std::cout << "[BENCHMARK] Replaying packets from " << pcap_file << "\n";
  uint64_t start_time = get_time_us() / 1000;

  pcap_loop(pcap_h, -1, on_benchmark_packet, nullptr);
  pcap_close(pcap_h);

  uint64_t total_time = (get_time_us() / 1000) - start_time;

  evaluate_flows();
  print_full_metric_report(total_time);

  snn_reset_state();
  return 0;
}
