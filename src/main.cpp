#include "alerting/logger.h"
#include "capture/pcap_wrapper.h"
#include "capture/signal_wrapper.h"
#include "core/config.h"
#include "core/telemetry.h"
#include "detection/scorer.h"
#include "features/extractor.h"
#include "features/flow_tracker.h"
#include "features/spike_encoder.h"
#include "neuromorphic/snn_core.h"
#include <cmath>
#include <iomanip>
#include <iostream>
#include <pcap.h>
#include <string>

pcap_t *global_pcap_handle = nullptr;
uint64_t g_capture_start_time = 0;
uint64_t g_last_telemetry_dump_ms = 0;
uint64_t g_telemetry_interval_ms = 3600000;
uint64_t g_eval_interval_ms = 0;
uint64_t g_last_csv_dump_ms = 0;
uint64_t g_last_csv_packets = 0;

void print_telemetry() {
  uint64_t elapsed_ms = (get_time_us() / 1000) - g_capture_start_time;
  g_runtime_stats.malformed_packets = get_malformed_count();

  if (global_pcap_handle) {
    pcap_stat stats;
    if (dyn_pcap_stats(global_pcap_handle, &stats) == 0) {
      g_runtime_stats.packets_received = stats.ps_recv;
      g_runtime_stats.packets_dropped = stats.ps_drop;

      uint64_t t_spikes = 0, t_synops = 0, t_weights = 0;
      uint32_t t_neurons = 0;
      snn_get_telemetry_flat(&t_spikes, &t_synops, &t_weights, &t_neurons);

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
                << "               cppIDS Telemetry Report               \n"
                << "=======================================================\n"
                << "\n[SYSTEM & RUNTIME METRICS]\n"
                << "Uptime:                    " << h << "h " << m << "min "
                << s << "secs (" << elapsed_ms << " ms)\n"
                << "Packets Received (OS):     "
                << g_runtime_stats.packets_received << "\n"
                << "Packets Processed:         "
                << g_runtime_stats.packets_processed << "\n"
                << "Packets Dropped:           "
                << g_runtime_stats.packets_dropped << "\n"
                << "Malformed Packets:         "
                << g_runtime_stats.malformed_packets << "\n"
                << "Avg Processing Latency:    " << avg_latency << " us\n"
                << "Median Latency (P50):      " << p50 << " us\n"
                << "P95 Latency:               " << p95 << " us\n"
                << "P99 Latency:               " << p99 << " us\n"
                << "Max Processing Latency:    "
                << g_runtime_stats.max_latency_us << " us\n"
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
          << "Anomalies Dismissed (Ctx): "
          << g_context_stats.anomalies_dismissed << "\n"
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
          << "True Positives:            " << g_context_stats.true_positives
          << "\n"
          << "False Positives:           " << g_context_stats.false_positives
          << "\n"
          << "True Negatives:            " << g_context_stats.true_negatives
          << "\n"
          << "False Negatives:           " << g_context_stats.false_negatives
          << "\n"
          << "=======================================================\n";

      log_telemetry_snapshot(elapsed_ms, g_runtime_stats.packets_processed,
                             g_runtime_stats.packets_dropped, p50, p99, ram_mb,
                             t_spikes, g_context_stats.anomalies_detected,
                             g_context_stats.threats_confirmed);
    }
  }
}

void on_packet_received(u_char *user, const struct pcap_pkthdr *h,
                        const u_char *bytes) {
  (void)user;

  if (shutdown_was_requested()) {
    dyn_pcap_breakloop(global_pcap_handle);
    return;
  }

  uint64_t start_us = get_time_us();

  uint32_t len = h->caplen;
  uint64_t pkt_time_us =
      (static_cast<uint64_t>(h->ts.tv_sec) * 1000000) + h->ts.tv_usec;

  process_packet(bytes, len, pkt_time_us);

  uint64_t latency = get_time_us() - start_us;
  record_latency_bin(latency);
  g_runtime_stats.packets_processed++;

  uint64_t current_ms = get_time_us() / 1000;

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

  if (g_runtime_stats.packets_processed % 5000 == 0) {
    uint64_t sweep_start = get_time_us();
    snn_sweep_stale(60.0f, pkt_time_us);
    if ((get_time_us() - sweep_start) > 50000) {
      std::cout << "[WARNING] Garbage Collection stall: "
                << (get_time_us() - sweep_start) << " us\n";
    }
  }
}

int main(int argc, char **argv) {
  std::cout << "--- cppIDS: Neuromorphic Intrusion Detection Daemon ---\n";

  if (!load_npcap_dll()) {
    return 1;
  }

  std::string active_interface = "{08D239B7-26E7-46F4-AA21-736B552AA740}";
  std::string active_bpf = "";
  std::string config_file = "ids_config.ini";
  uint32_t eval_seconds = 0;
  uint32_t telemetry_minutes = 60;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "-i" && i + 1 < argc)
      active_interface = argv[++i];
    else if (arg == "-filter" && i + 1 < argc)
      active_bpf = argv[++i];
    else if (arg == "--config" && i + 1 < argc)
      config_file = argv[++i];
    else if (arg == "--eval" && i + 1 < argc)
      eval_seconds = std::stoul(argv[++i]);
    else if (arg == "--telemetry" && i + 1 < argc)
      telemetry_minutes = std::stoul(argv[++i]);
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

  IDSConfig cfg;
  load_default_config(cfg);
  load_config_file(config_file, cfg);

  register_sigint_handler(nullptr);
  snn_seed_rng(static_cast<uint32_t>(get_time_us()));
  snn_configure(cfg.tau, cfg.fire_threshold, cfg.debug_mode);
  init_scorer();
  set_scorer_config(cfg.alert_threshold, cfg.fire_threshold,
                    cfg.alert_cooldown_ms);
  configure_tracker(cfg.expiration_seconds, cfg.prediction_alpha,
                    cfg.drift_lock_threshold, cfg.episode_timeout_ms,
                    cfg.max_active_flows);

  if (active_interface.empty()) {
    active_interface = get_first_active_interface();
    if (active_interface.empty()) {
      std::cerr << "[FATAL] No valid network interfaces found.\n";
      return 1;
    }
  } else if (active_interface.find("\\Device\\NPF_") == std::string::npos) {
    active_interface = "\\Device\\NPF_" + active_interface;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  global_pcap_handle =
      dyn_pcap_open_live(active_interface.c_str(), 65536, 0, 1000, errbuf);
  if (!global_pcap_handle) {
    std::cerr << "[FATAL] Capture initialization failed.\n[PCAP ERROR] "
              << errbuf << "\n";
    return 1;
  }

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
  g_capture_start_time = get_time_us() / 1000;

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
        global_pcap_handle = dyn_pcap_open_live(active_interface.c_str(), 65536,
                                                0, 1000, errbuf);
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

  print_telemetry();
  std::cout << "Closing capture handles and freeing SNN state...\n";
  snn_reset_state();
  if (global_pcap_handle)
    dyn_pcap_close(global_pcap_handle);
  std::cout << "Daemon exited cleanly.\n";
  return 0;
}
