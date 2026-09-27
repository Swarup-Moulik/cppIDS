#include "CLI11.hpp"
#include "alerting/logger.h"
#include "capture/pcap_wrapper.h"
#include "core/config.h"
#include "core/telemetry.h"
#include "detection/logistic_model.h"
#include "detection/readout_features.h"
#include "detection/scorer.h"
#include "features/extractor.h"
#include "features/flow_tracker.h"
#include "neuromorphic/snn_core.h"
#include "neuromorphic/snn_readout.h"
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <pcap.h>
#include <string>
#include <unordered_map>
#include <vector>

// For exporting features for LSTM and CNN-SNN Hybrid comparisons
extern std::ofstream feature_export_csv;

// Diagnostic breakdown registries for classification anomalies
extern std::unordered_map<uint64_t, uint64_t> fp_by_pair;
extern std::unordered_map<uint16_t, uint64_t> fp_by_svc_port;
extern std::unordered_map<uint64_t, uint64_t> fn_by_pair;
extern std::unordered_map<uint16_t, uint64_t> fn_by_svc_port;

/* @brief Resets evaluation confusion matrix counters back to zero */
void init_matrix() {
  gt_true_positives = 0;
  gt_true_negatives = 0;
  gt_false_positives = 0;
  gt_false_negatives = 0;
}

// Track processed frame count for the current active PCAP replay
static uint64_t s_file_packets_processed = 0;

/* @brief Benchmark callback invoked per replayed packet to measure latency and
 * track progress */
void on_benchmark_packet(u_char *user, const struct pcap_pkthdr *h,
                         const u_char *bytes) {
  (void)user;
  uint64_t start_us = get_time_us();

  uint32_t len = h->caplen;
  uint64_t pkt_time_us =
      (static_cast<uint64_t>(h->ts.tv_sec) * 1000000) + h->ts.tv_usec;

  // Ingest frame into decoding and predictive coding pipeline
  process_packet(bytes, len, pkt_time_us);

  // Measure per-packet latency and record into microsecond histogram bins
  uint64_t latency = get_time_us() - start_us;
  record_latency_bin(latency);
  g_runtime_stats.packets_processed++;
  s_file_packets_processed++;

  // Periodically refresh terminal progress indicator
  if ((s_file_packets_processed % 100000) == 0) {
    std::cout << "\r[BENCHMARK] Packets processed: " << s_file_packets_processed
              << std::flush;
  }
}

/* @brief Commits ground truth evaluation for all remaining active flow sessions
 */
void evaluate_flows() {
  for (auto &[hash, flow] : active_flows) {
    commit_flow_ground_truth(flow);
  }
}

/* @brief Formats an unsigned 32-bit IPv4 address into dotted-decimal notation
 */
static std::string format_ip(uint32_t ip) {
  return std::to_string((ip >> 24) & 0xFF) + "." +
         std::to_string((ip >> 16) & 0xFF) + "." +
         std::to_string((ip >> 8) & 0xFF) + "." + std::to_string(ip & 0xFF);
}

/* @brief Sorts and prints the top N service ports by error flow count */
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

/* @brief Sorts and prints the top N IP endpoint pairs by error flow count */
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

/* @brief Generates comprehensive performance, latency, and classification
 * diagnostics */
void print_full_metric_report(uint64_t total_time_ms) {
  double tp = static_cast<double>(gt_true_positives);
  double tn = static_cast<double>(gt_true_negatives);
  double fp = static_cast<double>(gt_false_positives);
  double fn = static_cast<double>(gt_false_negatives);

  // Compute standard statistical classification performance indicators
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

  // Retrieve latency percentiles from microsecond histogram
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
            << "Slow DoS Heuristic:         TP = "
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

/* @brief Evaluation harness entry point: coordinates benchmark replaying and
 * diagnostic exports */
int main(int argc, char **argv) {
  CLI::App app{"cppIDS Benchmark Evaluation Harness"};

  std::vector<std::string> pcap_files;
  std::string attackers_csv = "172.16.0.1";
  std::string victims_csv = "";
  std::string ports_csv = "";
  std::string base_model_path = "";
  std::string export_csv_path = "";

  std::string mode = "stdp";
  std::string model_path = "model.bin";

  app.add_option("pcaps", pcap_files,
                 "Input PCAP files (leave empty for live network sniffing)");
  app.add_option("--attackers", attackers_csv, "CSV list of attacker IPs");
  app.add_option("--victims", victims_csv, "CSV list of victim IPs");
  app.add_option("--ports", ports_csv, "CSV list of target ports");
  app.add_option("--base-model", base_model_path,
                 "Path to pre-trained base model");
  app.add_option("--export-features", export_csv_path,
                 "Path to export DL features CSV");

  auto mode_group =
      app.add_option_group("Execution Modes", "Select exactly one mode")
          ->require_option(0, 1);

  auto opt_train =
      mode_group->add_option("--train", model_path, "Train SNN baseline");
  auto opt_test =
      mode_group->add_option("--test", model_path, "Test SNN baseline");
  auto opt_transfer = mode_group->add_option("--transfer", model_path,
                                             "Transfer learning mode");
  auto opt_stdp = mode_group->add_flag("--stdp", "Unsupervised STDP mode");
  auto opt_train_snn_ro = mode_group->add_option(
      "--train-snn-readout", model_path, "Train Spiking Readout");
  auto opt_test_snn_ro = mode_group->add_option(
      "--test-snn-readout", model_path, "Test Spiking Readout");
  auto opt_train_lr = mode_group->add_option("--train-lr", model_path,
                                             "Train Logistic Regression");
  auto opt_test_lr = mode_group->add_option("--test-lr", model_path,
                                            "Test Logistic Regression");

  CLI11_PARSE(app, argc, argv);

  if (*opt_train)
    mode = "train";
  else if (*opt_test)
    mode = "test";
  else if (*opt_transfer)
    mode = "transfer";
  else if (*opt_stdp)
    mode = "stdp";
  else if (*opt_train_snn_ro)
    mode = "train_snn_readout";
  else if (*opt_test_snn_ro)
    mode = "test_snn_readout";
  else if (*opt_train_lr)
    mode = "train_lr";
  else if (*opt_test_lr)
    mode = "test_lr";

  std::cout << "=== Running cppIDS Benchmark Evaluation Harness ===\n";

  // Load pre-trained baseline neural models
  if (!base_model_path.empty()) {
    if (!snn_load_model(base_model_path)) {
      return 1;
    }
    std::cout << "[SYSTEM] Pre-trained SNN BASELINE loaded from "
              << base_model_path << "\n";
  } else if (mode == "test" || mode == "transfer") {
    if (!snn_load_model(model_path)) {
      return 1;
    }
    std::cout << "[SYSTEM] Pre-trained weights loaded from " << model_path
              << "\n";
  }

  // Initialize both readout backends
  snn_readout_init();
  lr_readout_init();

  // Configure operational modes and plasticity states
  if (mode == "test") {
    snn_set_mode(false, true);
    std::cout << "[SYSTEM] Mode: TEST (STDP Disabled, Baseline Active)\n";
  } else if (mode == "transfer") {
    snn_set_mode(true, true);
    std::cout << "[SYSTEM] Mode: TRANSFER (STDP Enabled, Baseline Active)\n";
  } else if (mode == "train") {
    snn_set_mode(true, false);
    std::cout
        << "[SYSTEM] Mode: TRAIN (STDP Enabled, Baseline Export Pending)\n";
  } else if (mode == "train_snn_readout") {
    snn_set_mode(false,
                 true); // SNN Baseline must be frozen to provide stable inputs
    snn_readout_set_mode(true, true); // Enable R-STDP readout training
    std::cout << "[SYSTEM] Mode: TRAIN SNN READOUT (R-STDP Active)\n";
  } else if (mode == "test_snn_readout") {
    snn_set_mode(false, true);
    snn_readout_load_model(model_path);
    snn_readout_set_mode(true,
                         false); // Enable readout inference, freeze weights
    std::cout << "[SYSTEM] Mode: TEST SNN READOUT (Neuromorphic Inference)\n";
  } else if (mode == "train_lr") {
    snn_set_mode(false, true);       // Keep SNN baseline frozen
    lr_readout_set_mode(true, true); // Collect training examples into RAM
    std::cout << "[SYSTEM] Mode: TRAIN BATCH LOGISTIC REGRESSION (In-Memory "
                 "Collection)\n";
  } else if (mode == "test_lr") {
    snn_set_mode(false, true);
    if (!lr_get_model().load(model_path)) {
      std::cerr << "[ERROR] Could not load Logistic Model from " << model_path
                << "\n";
      return 1;
    }
    lr_readout_set_mode(true, false); // Enable inference mode
    std::cout
        << "[SYSTEM] Mode: TEST BATCH LOGISTIC REGRESSION (Inference Active)\n";
  } else {
    snn_set_mode(true, false);
    std::cout << "[SYSTEM] Mode: STDP (Unsupervised, No Baseline)\n";
  }

  // Ensure Npcap dynamic library is loaded
  if (!load_npcap_dll())
    return 1;

  // Initialize evaluation registers and filters
  init_matrix();
  init_telemetry();
  parse_and_register_attackers(attackers_csv);
  parse_and_register_victims(victims_csv);
  parse_and_register_ports(ports_csv);

  std::cout << "[SYSTEM] Ground Truth Attackers Registered: " << attackers_csv
            << "\n";

  // Configure neuromorphic reservoir, scoring engine, and predictive tracker
  snn_seed_rng(13371337u);
  snn_configure(1.5f, 5000.0f, 0);
  init_scorer();
  set_scorer_config(85, 5000.0f, 10000);
  configure_tracker(60.0f, 0.125f, 3.5f, 30000, 500000);

  // Open the feature export CSV if a path is provided
  if (!export_csv_path.empty()) {
    feature_export_csv.open(export_csv_path);
    if (feature_export_csv.is_open()) {
      feature_export_csv
          << "src_ip,dst_ip,src_port,dst_port,proto,"
          << "ch0_size,ch1_iat,ch2_proto,ch3_rate,ch4_var,ch5_asym,"
          << "spike_count,pair_density,is_web,is_dns,is_ent,label\n";
      std::cout << "[SYSTEM] Exporting DL features to: " << export_csv_path
                << "\n";
    }
  }

  uint64_t start_time = get_time_us() / 1000;

  // Execute packet capture loop: Offline PCAP replay vs Live interface sniffing
  if (pcap_files.empty()) {
    std::cout << "[SYSTEM] Live interface mode active.\n";
    // NOTE: In the evaluation harness, live sniffing is usually discouraged
    // because ground truth is unknown, but the path is open if needed.
    std::string active_interface = get_first_active_interface();
    if (active_interface.empty()) {
      std::cerr << "[FATAL] No valid network interfaces found.\n";
      return 1;
    }
#ifdef _WIN32
    else if (active_interface.find("\\Device\\NPF_") == std::string::npos) {
      active_interface = "\\Device\\NPF_" + active_interface;
    }
#endif

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_h =
        dyn_pcap_open_live(active_interface.c_str(), 65536, 0, 1000, errbuf);
    if (!pcap_h) {
      std::cerr << "[FATAL] Capture initialization failed.\n[PCAP ERROR] "
                << errbuf << "\n";
      return 1;
    }

    std::cout << "Monitoring live traffic. Active SNN logging enabled.\n";
    pcap_loop(pcap_h, -1, on_benchmark_packet, nullptr);
    dyn_pcap_close(pcap_h);

  } else {
    std::cout << "[SYSTEM] Offline mode active. Processing "
              << pcap_files.size() << " dataset(s)...\n";

    for (const auto &file : pcap_files) {
      char errbuf[PCAP_ERRBUF_SIZE];
      pcap_t *pcap_h = pcap_open_offline(file.c_str(), errbuf);
      if (!pcap_h) {
        std::cerr << "[ERROR] Could not open dataset file: " << file << " ("
                  << errbuf << ")\n";
        continue;
      }

      std::cout << "\n[BENCHMARK] Replaying packets from " << file << "\n";
      pcap_loop(pcap_h, -1, on_benchmark_packet, nullptr);
      pcap_close(pcap_h);
    }
  }

  std::cout << "\n";
  uint64_t total_time = (get_time_us() / 1000) - start_time;

  // Finalize ground truth verification across remaining active flows
  evaluate_flows();

  // Train and persist Logistic Regression model if training mode was active
  if (mode == "train_lr") {
    std::cout << "\n[TRAINING] Fitting Logistic Regression over collected flow "
                 "buffer...\n";
    lr_get_model().fit(lr_get_training_buffer(), /*epochs=*/100, /*lr=*/0.2f,
                       /*l2=*/0.001f);
    lr_get_model().print_weights();
    if (lr_get_model().save(model_path)) {
      std::cout << "[SYSTEM] Logistic Regression Model successfully saved to "
                << model_path << "\n";
    }
  }

  // Output detailed benchmark report
  print_full_metric_report(total_time);

  // Export trained SNN core baseline
  if (mode == "train") {
    if (snn_export_model(model_path)) {
      std::cout << "[SYSTEM] Successfully exported Threat Baseline to "
                << model_path << "\n";
    }
  }

  // Export trained spiking readout model
  if (mode == "train_snn_readout") {
    if (snn_readout_export_model(model_path)) {
      std::cout << "[SYSTEM] Successfully exported Spiking Readout to "
                << model_path << "\n";
    }
  }

  // Free SNN neural memory allocations
  snn_reset_state();
  return 0;
}
