#include "CLI11.hpp"
#include "alerting/logger.h"
#include "capture/pcap_wrapper.h"
#include "capture/signal_wrapper.h"
#include "core/config.h"
#include "core/telemetry.h"
#include "detection/logistic_model.h"
#include "detection/readout_features.h"
#include "detection/scorer.h"
#include "features/extractor.h"
#include "features/flow_tracker.h"
#include "features/spike_encoder.h"
#include "neuromorphic/snn_core.h"
#include "neuromorphic/snn_readout.h"
#include <cmath>
#include <iomanip>
#include <iostream>
#include <pcap.h>
#include <string>
#include <unordered_map>
#include <vector>

// Global capture context and interval timing states
pcap_t *global_pcap_handle =
    nullptr; // Active live network capture interface handle
uint64_t g_capture_start_time =
    0; // Capture initiation timestamp in milliseconds
uint64_t g_last_telemetry_dump_ms =
    0; // Timestamp of previous telemetry log emission
uint64_t g_telemetry_interval_ms =
    3600000; // Periodic interval between JSON telemetry snapshots
uint64_t g_eval_interval_ms =
    0; // Interval between CSV benchmark evaluation records
uint64_t g_last_csv_dump_ms =
    0; // Timestamp of previous CSV evaluation log flush
uint64_t g_last_csv_packets =
    0; // Processed packet counter snapshot at previous CSV log

// Diagnostic breakdown registries
extern std::unordered_map<uint64_t, uint64_t> fp_by_pair;
extern std::unordered_map<uint16_t, uint64_t> fp_by_svc_port;
extern std::unordered_map<uint64_t, uint64_t> fn_by_pair;
extern std::unordered_map<uint16_t, uint64_t> fn_by_svc_port;

/* @brief Resets ground truth classification counters to baseline */
void init_matrix() {
  gt_true_positives = 0;
  gt_true_negatives = 0;
  gt_false_positives = 0;
  gt_false_negatives = 0;
}

/* @brief Forces ground truth evaluation and metric commitment across all active
 * flows */
void evaluate_flows() {
  for (auto &[hash, flow] : active_flows) {
    commit_flow_ground_truth(flow);
  }
}

/* @brief Outputs formatted runtime, neuromorphic, and classification metrics to
 * stdout and telemetry file */
void print_telemetry() {
  uint64_t elapsed_ms = (get_time_us() / 1000) - g_capture_start_time;
  g_runtime_stats.malformed_packets = get_malformed_count();

  // Retrieve interface drop counters in live mode, or compute totals for
  // offline replays
  if (global_pcap_handle) {
    pcap_stat stats;
    if (dyn_pcap_stats(global_pcap_handle, &stats) == 0) {
      g_runtime_stats.packets_received = stats.ps_recv;
      g_runtime_stats.packets_dropped = stats.ps_drop;
    }
  } else {
    g_runtime_stats.packets_received = g_runtime_stats.packets_processed +
                                       g_runtime_stats.skipped_packets +
                                       g_runtime_stats.malformed_packets;
  }

  // Retrieve neuromorphic activity counters from SNN core
  uint64_t t_spikes = 0, t_synops = 0, t_weights = 0;
  uint32_t t_neurons = 0;
  snn_get_telemetry_flat(&t_spikes, &t_synops, &t_weights, &t_neurons);

  // Compute latency percentiles
  uint64_t p50 = compute_percentile(0.50);
  uint64_t p95 = compute_percentile(0.95);
  uint64_t p99 = compute_percentile(0.99);

  uint64_t avg_latency = (g_runtime_stats.packets_processed > 0)
                             ? (g_runtime_stats.total_latency_us /
                                g_runtime_stats.packets_processed)
                             : 0;
  float fp_reduction_rate =
      (g_context_stats.anomalies_detected > 0)
          ? (static_cast<float>(g_context_stats.anomalies_dismissed) /
             g_context_stats.anomalies_detected) *
                100.0f
          : 0.0f;

  uint64_t ram_mb = sys_get_ram_usage_bytes() / (1024 * 1024);
  uint64_t h = elapsed_ms / 3600000;
  uint64_t m = (elapsed_ms % 3600000) / 60000;
  uint64_t s = (elapsed_ms % 60000) / 1000;

  std::cout << std::fixed << std::setprecision(2);
  std::cout << "\n=======================================================\n"
            << "               cppIDS Telemetry Report                \n"
            << "=======================================================\n"
            << "\n[SYSTEM & RUNTIME METRICS]\n"
            << "Uptime:                    " << h << "h " << m << "min " << s
            << "secs (" << elapsed_ms << " ms)\n"
            << "Packets Received (OS):     " << g_runtime_stats.packets_received
            << "\n"
            << "Packets Processed:         "
            << g_runtime_stats.packets_processed << "\n"
            << "Packets Dropped:           " << g_runtime_stats.packets_dropped
            << "\n"
            << "Malformed Packets:         "
            << g_runtime_stats.malformed_packets << "\n"
            << "Avg Processing Latency:    " << avg_latency << " us\n"
            << "Median Latency (P50):      " << p50 << " us\n"
            << "P95 Latency:               " << p95 << " us\n"
            << "P99 Latency:               " << p99 << " us\n"
            << "Max Processing Latency:    " << g_runtime_stats.max_latency_us
            << " us\n"
            << "RAM Usage:                 " << ram_mb << " MB\n";

  if (elapsed_ms > 0) {
    uint64_t pps = (g_runtime_stats.packets_received * 1000) / elapsed_ms;
    std::cout << "Throughput:                " << pps << " PPS\n";
  }

  std::cout << "\n[SNN NEUROMORPHIC DYNAMICS]\n"
            << "Total Spikes Emitted:      " << t_spikes << "\n"
            << "Synaptic Operations:       " << t_synops << "\n"
            << "Plastic Weight Updates:    " << t_weights << "\n"
            << "Firing Neurons (Current):  " << t_neurons << "\n";

  float rounded_pot = std::round(snn_get_max_potential() * 100.0f) / 100.0f;
  std::cout
      << "Max SNN Membrane Pot.:     " << rounded_pot << "\n"
      << "\n[CONTEXTUAL DECISION & EPISODES]\n"
      << "Anomalies Detected (SNN):  " << g_context_stats.anomalies_detected
      << "\n"
      << "Anomalies Dismissed (Ctx): " << g_context_stats.anomalies_dismissed
      << "\n"
      << "Threats Confirmed:         " << g_context_stats.threats_confirmed
      << "\n"
      << "Context Matches:           " << g_context_stats.context_matches
      << "\n"
      << "Context Mismatches:        " << g_context_stats.context_mismatches
      << "\n"
      << "Context FP Reduction Rate: " << fp_reduction_rate << "%\n"
      << "Episodes Started:          " << g_context_stats.episodes_started
      << "\n"
      << "Episodes Resolved:         " << g_context_stats.episodes_resolved
      << "\n"
      << "\n[GROUND TRUTH EVALUATION]\n"
      << "True Positives:            " << g_context_stats.true_positives << "\n"
      << "False Positives:           " << g_context_stats.false_positives
      << "\n"
      << "True Negatives:            " << g_context_stats.true_negatives << "\n"
      << "False Negatives:           " << g_context_stats.false_negatives
      << "\n"
      << "=======================================================\n";

  // Append snapshot to disk
  log_telemetry_snapshot(elapsed_ms, g_runtime_stats.packets_processed,
                         g_runtime_stats.packets_dropped, p50, p99, ram_mb,
                         t_spikes, g_context_stats.anomalies_detected,
                         g_context_stats.threats_confirmed);
}

/* @brief Callback invoked by libpcap for each captured frame to execute
 * extraction and telemetry */
void on_packet_received(u_char *user, const struct pcap_pkthdr *h,
                        const u_char *bytes) {
  (void)user;

  // Break processing loop if termination interrupt was signaled
  if (shutdown_was_requested()) {
    dyn_pcap_breakloop(global_pcap_handle);
    return;
  }

  uint64_t start_us = get_time_us();

  uint32_t len = h->caplen;
  uint64_t pkt_time_us =
      (static_cast<uint64_t>(h->ts.tv_sec) * 1000000) + h->ts.tv_usec;

  // Ingest frame into decoding and flow tracking pipeline
  process_packet(bytes, len, pkt_time_us);

  // Measure per-packet processing duration and record latency distribution
  uint64_t latency = get_time_us() - start_us;
  record_latency_bin(latency);
  g_runtime_stats.packets_processed++;

  uint64_t current_ms = get_time_us() / 1000;

  // Periodic evaluation CSV metric export
  if (g_eval_interval_ms > 0) {
    if (g_last_csv_dump_ms == 0) {
      g_last_csv_dump_ms = current_ms;
      g_last_csv_packets = g_runtime_stats.packets_processed;
    } else if ((current_ms - g_last_csv_dump_ms) >= g_eval_interval_ms) {
      uint64_t throughput_pps =
          ((g_runtime_stats.packets_processed - g_last_csv_packets) * 1000) /
          (current_ms - g_last_csv_dump_ms);
      uint64_t t_spikes = 0, t_synops = 0, t_weights = 0;
      uint32_t t_neurons = 0;
      snn_get_telemetry_flat(&t_spikes, &t_synops, &t_weights, &t_neurons);

      uint32_t current_flow_count = 0;
      for (const auto &[hash, record] : active_flows) {
        if (record.packet_count > 0)
          current_flow_count++;
      }

      log_evaluation_csv(
          (current_ms >= g_capture_start_time)
              ? current_ms - g_capture_start_time
              : 0,
          g_runtime_stats.packets_processed, current_flow_count, t_spikes,
          t_synops, t_weights, 0, latency, throughput_pps,
          g_context_stats.threats_confirmed, g_context_stats.true_positives,
          g_context_stats.false_positives, g_context_stats.true_negatives,
          g_context_stats.false_negatives);
      g_last_csv_dump_ms = current_ms;
      g_last_csv_packets = g_runtime_stats.packets_processed;
    }
  }

  // Periodic telemetry log commitment to JSONL
  if (g_telemetry_interval_ms > 0) {
    if (g_last_telemetry_dump_ms == 0)
      g_last_telemetry_dump_ms = current_ms;
    else if ((current_ms - g_last_telemetry_dump_ms) >=
             g_telemetry_interval_ms) {
      std::cout << "\n[SYSTEM] Telemetry interval reached. Committing snapshot "
                   "to JSON...\n";
      print_telemetry();
      g_last_telemetry_dump_ms = current_ms;
    }
  }

  // Garbage collection sweep on neural states every 5,000 packets
  if (g_runtime_stats.packets_processed % 5000 == 0) {
    uint64_t sweep_start = get_time_us();
    snn_sweep_stale(60.0f, pkt_time_us);
    if ((get_time_us() - sweep_start) > 50000) {
      std::cout << "[WARNING] Garbage Collection stall: "
                << (get_time_us() - sweep_start) << " us\n";
    }
  }
}

/* @brief Application entry point: parses flags, initializes subsystems, and
 * starts capture */
int main(int argc, char **argv) {
  CLI::App app{"cppIDS: Neuromorphic Intrusion Detection Daemon"};

  std::vector<std::string> pcap_files;
  std::string active_interface = "";
  std::string active_bpf = "";
  std::string config_file = "ids_config.ini";
  std::string attackers_csv = "172.16.0.1";
  std::string victims_csv = "";
  std::string ports_csv = "";
  std::string base_model_path = "";
  uint32_t eval_seconds = 0;
  uint32_t telemetry_minutes = 60;

  std::string mode = "stdp";
  std::string model_path = "model.bin";

  app.add_option("pcaps", pcap_files,
                 "Input PCAP files (leave empty for live network sniffing)");
  app.add_option("-i,--interface", active_interface,
                 "Network interface to sniff");
  app.add_option("-f,--filter", active_bpf, "BPF capture filter");
  app.add_option("-c,--config", config_file, "Path to configuration INI");
  app.add_option("--eval", eval_seconds,
                 "Evaluation metrics export interval (seconds)");
  app.add_option("--telemetry", telemetry_minutes,
                 "Telemetry JSON snapshot interval (minutes)");
  app.add_option("--attackers", attackers_csv, "CSV list of attacker IPs");
  app.add_option("--victims", victims_csv, "CSV list of victim IPs");
  app.add_option("--ports", ports_csv, "CSV list of target ports");
  app.add_option("--base-model", base_model_path,
                 "Path to pre-trained base model");

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

  std::cout << "--- cppIDS: Neuromorphic Intrusion Detection Daemon ---\n";

  // Dynamically load Npcap capture library
  if (!load_npcap_dll()) {
    return 1;
  }

  g_eval_interval_ms = eval_seconds * 1000;
  g_telemetry_interval_ms = telemetry_minutes * 60000;

  if (g_eval_interval_ms > 0)
    std::cout
        << "[SYSTEM] Evaluation mode active. Writing metrics to CSV every "
        << eval_seconds << " seconds.\n";
  if (g_telemetry_interval_ms > 0)
    std::cout << "[SYSTEM] Telemetry snapshots will be generated every "
              << telemetry_minutes << " minutes.\n";
  else
    std::cout << "[SYSTEM] Periodic telemetry snapshots are disabled.\n";

  // Hydrate configurations from INI file
  IDSConfig cfg;
  load_default_config(cfg);
  load_config_file(config_file, cfg);

  // Initialize tracking telemetry, matrices, and evaluation filters
  init_telemetry();
  init_matrix();
  parse_and_register_attackers(attackers_csv);
  parse_and_register_victims(victims_csv);
  parse_and_register_ports(ports_csv);
  std::cout << "[SYSTEM] Ground Truth Attackers Registered: " << attackers_csv
            << "\n";

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

  // Initialize readout layers
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
                 true); // Freeze reservoir weights to provide stable inputs
    snn_readout_set_mode(true, true); // Enable readout R-STDP training
    std::cout << "[SYSTEM] Mode: TRAIN SNN READOUT (R-STDP Active)\n";
  } else if (mode == "test_snn_readout") {
    snn_set_mode(false, true);
    snn_readout_load_model(model_path);
    snn_readout_set_mode(true,
                         false); // Enable readout inference with frozen weights
    std::cout << "[SYSTEM] Mode: TEST SNN READOUT (Neuromorphic Inference)\n";
  } else if (mode == "train_lr") {
    snn_set_mode(false, true);       // Freeze SNN baseline weights
    lr_readout_set_mode(true, true); // Collect labeled flow samples in memory
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

  // Register termination handler and configure algorithmic cores
  register_sigint_handler(nullptr);
  snn_seed_rng(static_cast<uint32_t>(get_time_us()));
  snn_configure(cfg.tau, cfg.fire_threshold, cfg.debug_mode);
  init_scorer();
  set_scorer_config(cfg.alert_threshold, cfg.fire_threshold,
                    cfg.alert_cooldown_ms);
  configure_tracker(cfg.expiration_seconds, cfg.prediction_alpha,
                    cfg.drift_lock_threshold, cfg.episode_timeout_ms,
                    cfg.max_active_flows);

  g_capture_start_time = get_time_us() / 1000;

  // Execute packet capture loop: Offline PCAP replay vs Live interface sniffing
  if (pcap_files.empty()) {
    std::cout << "[SYSTEM] Live interface mode active.\n";
    if (active_interface.empty()) {
      active_interface = get_first_active_interface();
      if (active_interface.empty()) {
        std::cerr << "[FATAL] No valid network interfaces found.\n";
        return 1;
      }
    }
#ifdef _WIN32
    else if (active_interface.find("\\Device\\NPF_") == std::string::npos) {
      active_interface = "\\Device\\NPF_" + active_interface;
    }
#endif

    char errbuf[PCAP_ERRBUF_SIZE];
    global_pcap_handle =
        dyn_pcap_open_live(active_interface.c_str(), 65536, 0, 1000, errbuf);
    if (!global_pcap_handle) {
      std::cerr << "[FATAL] Capture initialization failed.\n[PCAP ERROR] "
                << errbuf << "\n";
      return 1;
    }

    // Compile and apply Berkeley Packet Filter (BPF) rule
    bpf_program fp;
    if (dyn_pcap_compile(global_pcap_handle, &fp, active_bpf.c_str(), 0,
                         PCAP_NETMASK_UNKNOWN) != -1) {
      dyn_pcap_setfilter(global_pcap_handle, &fp);
      dyn_pcap_freecode(&fp);
    } else {
      std::cout << "[WARNING] Failed to apply BPF filter. Capture will proceed "
                   "without filtering.\n";
    }

    std::cout << "Monitoring live traffic. Active SNN logging enabled.\n";

    // Continuous capture loop with auto-reconnection recovery
    while (true) {
      int status =
          dyn_pcap_loop(global_pcap_handle, 0, on_packet_received, nullptr);
      if (status == -1) {
        std::cout << "[ERROR] Interface lost. Attempting capture recovery in 2 "
                     "seconds...\n";
        dyn_pcap_close(global_pcap_handle);
        while (true) {
          uint64_t wait_start = get_time_us();
          while ((get_time_us() - wait_start) < 2000000) {
          }
          global_pcap_handle = dyn_pcap_open_live(active_interface.c_str(),
                                                  65536, 0, 1000, errbuf);
          if (global_pcap_handle) {
            std::cout << "[SYSTEM] Interface recovered! Re-applying BPF filter "
                         "and resuming capture...\n";
            if (dyn_pcap_compile(global_pcap_handle, &fp, active_bpf.c_str(), 0,
                                 PCAP_NETMASK_UNKNOWN) != -1) {
              dyn_pcap_setfilter(global_pcap_handle, &fp);
              dyn_pcap_freecode(&fp);
            }
            break;
          }
        }
      } else
        break;
    }
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
      pcap_loop(pcap_h, -1, on_packet_received, nullptr);
      pcap_close(pcap_h);
    }
  }

  // Flush remaining in-memory flow states
  evaluate_flows();
  std::cout << "\n[SYSTEM] Generating final telemetry report before exit...\n";
  print_telemetry();

  // Train and persist Logistic Regression readout model if requested
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

  // Export trained SNN model weights
  if (mode == "train") {
    if (snn_export_model(model_path)) {
      std::cout << "[SYSTEM] Successfully exported Threat Baseline to "
                << model_path << "\n";
    }
  }

  // Export trained neuromorphic readout synaptic weights
  if (mode == "train_snn_readout") {
    if (snn_readout_export_model(model_path)) {
      std::cout << "[SYSTEM] Successfully exported Spiking Readout to "
                << model_path << "\n";
    }
  }

  std::cout << "Closing capture handles and freeing SNN state...\n";
  snn_reset_state();
  if (global_pcap_handle)
    dyn_pcap_close(global_pcap_handle);
  std::cout << "Daemon exited cleanly.\n";
  return 0;
}
