#include "engine_runner.h"
#include "gui_state.h"

// Backend Engine Headers
#include "capture/pcap_wrapper.h"
#include "core/config.h"
#include "core/telemetry.h"
#include "detection/logistic_model.h"
#include "detection/scorer.h"
#include "features/extractor.h"
#include "features/flow_tracker.h"
#include "neuromorphic/snn_core.h"
#include "neuromorphic/snn_readout.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iostream>
#include <pcap.h>
#include <string>
#include <thread>
#include <unordered_set>

// Backend Ground Truth Globals
extern uint64_t gt_true_positives;
extern uint64_t gt_true_negatives;
extern uint64_t gt_false_positives;
extern uint64_t gt_false_negatives;

namespace engine_runner {

std::thread daemon_thread;
std::unordered_set<uint64_t>
    alerted_flows; // Tracks which threats have already been displayed

/* @brief Helper to convert raw IP integers to readable strings */
static std::string ip_to_string(uint32_t ip) {
  return std::to_string((ip >> 24) & 255) + "." +
         std::to_string((ip >> 16) & 255) + "." +
         std::to_string((ip >> 8) & 255) + "." + std::to_string(ip & 255);
}

/* @brief Helper to format epoch milliseconds to HH:MM:SS */
static std::string format_time(uint64_t time_ms) {
  time_t seconds = time_ms / 1000;
  struct tm *tm_info = localtime(&seconds);
  char buffer[26];
  strftime(buffer, 26, "%H:%M:%S", tm_info);
  return std::string(buffer);
}

/* @brief Core execution loop for the background packet processing engine */
void DaemonWorker() {
  // 1. Initialize Npcap Library (Windows only)
  if (!load_npcap_dll()) {
    std::cerr << "[GUI ENGINE] Failed to load Npcap DLL.\n";
    g_state.is_engine_running = false;
    return;
  }

  // 2. Load Configuration from GUI State
  IDSConfig cfg;
  load_default_config(cfg);
  if (strlen(g_state.config_path) > 0) {
    load_config_file(g_state.config_path, cfg);
  }

  // --- CRITICAL FIX: Fully purge stale backend states from previous runs ---
  snn_reset_state();
  active_flows.clear();

  // Reset core metrics for a fresh run
  init_telemetry();
  gt_true_positives = 0;
  gt_true_negatives = 0;
  gt_false_positives = 0;
  gt_false_negatives = 0;

  parse_and_register_attackers(g_state.attackers_list);
  parse_and_register_victims(g_state.victims_list);
  parse_and_register_ports(g_state.target_ports);

  // 3. Configure Neuromorphic Reservoir Modes
  if (strlen(g_state.base_model_path) > 0 &&
      g_state.res_mode != ReservoirMode::STDP_ONLINE) {
    snn_load_model(g_state.base_model_path);
  }

  snn_readout_init();
  lr_readout_init();

  if (g_state.res_mode == ReservoirMode::TEST_FROZEN)
    snn_set_mode(false, true);
  else if (g_state.res_mode == ReservoirMode::TRANSFER)
    snn_set_mode(true, true);
  else if (g_state.res_mode == ReservoirMode::TRAIN)
    snn_set_mode(true, false);
  else
    snn_set_mode(true, false); // STDP_ONLINE default

  // Configure Readout Modes
  if (g_state.read_mode == ReadoutMode::TRAIN_SNN) {
    snn_set_mode(false, true);
    snn_readout_set_mode(true, true);
  } else if (g_state.read_mode == ReadoutMode::TEST_SNN) {
    snn_set_mode(false, true);
    snn_readout_set_mode(true, false);
  } else if (g_state.read_mode == ReadoutMode::TRAIN_LR) {
    snn_set_mode(false, true);
    lr_readout_set_mode(true, true);
  } else if (g_state.read_mode == ReadoutMode::TEST_LR) {
    snn_set_mode(false, true);
    lr_readout_set_mode(true, false);
  }

  snn_seed_rng(static_cast<uint32_t>(get_time_us()));
  snn_configure(cfg.tau, cfg.fire_threshold, cfg.debug_mode);
  init_scorer();
  set_scorer_config(cfg.alert_threshold, cfg.fire_threshold,
                    cfg.alert_cooldown_ms);
  configure_tracker(cfg.expiration_seconds, cfg.prediction_alpha,
                    cfg.drift_lock_threshold, cfg.episode_timeout_ms,
                    cfg.max_active_flows);

  // 4. Open Network Interface OR Initialize Offline Queue
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = nullptr;

  // Identify if we are running from Replay Tab (Interface string is empty,
  // Queue has files)
  bool is_offline =
      (strlen(g_state.interface_name) == 0 && !g_state.pcap_files.empty());
  size_t current_file_idx = 0;

  if (is_offline) {
    handle =
        pcap_open_offline(g_state.pcap_files[current_file_idx].c_str(), errbuf);
    if (!handle) {
      std::cerr << "[GUI ENGINE] Could not open dataset file: " << errbuf
                << "\n";
      g_state.is_engine_running = false;
      return;
    }
  } else {
    std::string iface = g_state.interface_name;
#ifdef _WIN32
    if (iface.find("\\Device\\NPF_") == std::string::npos) {
      iface = "\\Device\\NPF_" + iface;
    }
#endif
    handle = dyn_pcap_open_live(iface.c_str(), 65536, 0, 10, errbuf);
    if (!handle) {
      std::cerr << "[GUI ENGINE] PCAP Open Live failed: " << errbuf << "\n";
      g_state.is_engine_running = false;
      return;
    }
  }

  // Apply BPF Filter
  if (strlen(g_state.bpf_filter) > 0) {
    bpf_program fp;
    if (dyn_pcap_compile(handle, &fp, g_state.bpf_filter, 0,
                         PCAP_NETMASK_UNKNOWN) != -1) {
      dyn_pcap_setfilter(handle, &fp);
      dyn_pcap_freecode(&fp);
    }
  }

  uint64_t start_capture_time = get_time_us();
  uint64_t last_ui_update = start_capture_time;

  // 5. Execution Loop (Non-blocking)
  while (g_state.is_engine_running && !g_state.stop_requested) {
    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    int res = pcap_next_ex(handle, &header, &pkt_data);

    if (res == 1) {
      // Packet successfully captured
      uint64_t start_us = get_time_us();
      uint64_t pkt_time_us =
          (static_cast<uint64_t>(header->ts.tv_sec) * 1000000) +
          header->ts.tv_usec;

      process_packet(pkt_data, header->caplen, pkt_time_us);

      uint64_t latency = get_time_us() - start_us;
      record_latency_bin(latency);
      g_runtime_stats.packets_processed++;

      // Neural garbage collection
      if (g_runtime_stats.packets_processed % 5000 == 0) {
        snn_sweep_stale(60.0f, pkt_time_us);
      }
    } else if (res == -1 || res == -2) {
      // Interface error or End Of File
      if (is_offline) {
        // Safe standard PCAP close for offline files to fix the crash
        pcap_close(handle);
        handle = nullptr;
        current_file_idx++;

        if (current_file_idx < g_state.pcap_files.size()) {
          handle = pcap_open_offline(
              g_state.pcap_files[current_file_idx].c_str(), errbuf);
          if (handle && strlen(g_state.bpf_filter) > 0) {
            bpf_program fp;
            if (dyn_pcap_compile(handle, &fp, g_state.bpf_filter, 0,
                                 PCAP_NETMASK_UNKNOWN) != -1) {
              dyn_pcap_setfilter(handle, &fp);
              dyn_pcap_freecode(&fp);
            }
          }
          continue;
        } else {
          break; // Queue finished!
        }
      } else {
        std::cerr << "[GUI ENGINE] Capture interface error or EOF.\n";
        break;
      }
    }

    // 6. UI Telemetry Synchronization (Updates at 10Hz)
    uint64_t now = get_time_us();
    if ((now - last_ui_update) > 100000) {
      if (!is_offline && handle != nullptr) {
        struct pcap_stat stats;
        // Use dyn_pcap_stats for live hardware queries
        if (dyn_pcap_stats(handle, &stats) == 0) {
          g_runtime_stats.packets_received = stats.ps_recv;
          g_runtime_stats.packets_dropped = stats.ps_drop;
        }
      } else {
        // In offline mode, assume OS drops are zero and all packets were
        // received
        g_runtime_stats.packets_received = g_runtime_stats.packets_processed;
      }

      g_runtime_stats.malformed_packets = get_malformed_count();

      float elapsed_sec = (now - start_capture_time) / 1000000.0f;
      if (elapsed_sec > 0.0f) {
        g_state.current_pps.store(g_runtime_stats.packets_processed /
                                  elapsed_sec);
      }

      g_state.total_packets.store(g_runtime_stats.packets_processed);
      g_state.active_flows.store(active_flows.size());

      float avg_latency = g_runtime_stats.packets_processed > 0
                              ? (float)g_runtime_stats.total_latency_us /
                                    g_runtime_stats.packets_processed / 1000.0f
                              : 0.0f;
      g_state.processing_latency_ms.store(avg_latency);

      float max_pot = snn_get_max_potential();
      float overflow = max_pot - cfg.fire_threshold;
      float score = 0.0f;

      if (overflow > 0.0f) {
        score = (overflow / (cfg.fire_threshold * 0.5f)) * 100.0f;
      }
      g_state.current_anomaly_score.store(score);

      for (const auto &[hash, flow] : active_flows) {
        if (flow.threat_confirmed == 1 &&
            alerted_flows.find(hash) == alerted_flows.end()) {
          alerted_flows.insert(hash);

          std::string threat_name = "Malicious Anomaly";
          if (flow.confirmed_channel == 0)
            threat_name = "Payload Prediction Error";
          else if (flow.confirmed_channel == 1)
            threat_name = "Temporal Rhythm Divergence";
          else if (flow.confirmed_channel == 2)
            threat_name = "Protocol State Violation";
          else if (flow.confirmed_channel == 3)
            threat_name = "Volumetric Rate Surge";
          else if (flow.confirmed_channel == 4)
            threat_name = "Structural Variance Anomaly";
          else if (flow.confirmed_channel == 5)
            threat_name = "Directional Asymmetry";

          std::lock_guard<std::mutex> lock(g_state.dashboard_mutex);
          GuiState::Alert new_alert = {
              format_time(flow.episode_start_time), ip_to_string(flow.src_ip),
              ip_to_string(flow.dest_ip), threat_name,
              static_cast<float>(flow.episode_peak_magnitude)};
          g_state.active_alerts.push_front(new_alert);

          if (g_state.active_alerts.size() > 100)
            g_state.active_alerts.pop_back();
        }
      }

      last_ui_update = now;
    }
  }

  // 8. Final Report Sync and Cleanup
  if (handle != nullptr) {
    if (!is_offline) {
      struct pcap_stat stats;
      if (dyn_pcap_stats(handle, &stats) == 0) {
        g_runtime_stats.packets_received = stats.ps_recv;
        g_runtime_stats.packets_dropped = stats.ps_drop;
      }
      dyn_pcap_close(handle); // Dynamic close for Live handle
    } else {
      g_runtime_stats.packets_received = g_runtime_stats.packets_processed;
      pcap_close(handle); // Standard close for Offline handle
    }
    handle = nullptr;
  }

  g_runtime_stats.malformed_packets = get_malformed_count();

  // Evaluate ground truth matrix for final report metrics
  for (auto &[hash, flow] : active_flows) {
    commit_flow_ground_truth(flow);
  }

  g_state.is_engine_running = false;
}

/* @brief Triggers the background worker thread for capturing and processing */
void StartLiveCapture() {
  if (daemon_thread.joinable()) {
    daemon_thread.join();
  }

  g_state.current_pps = 0.0f;
  g_state.total_packets = 0;
  g_state.active_flows = 0;
  g_state.current_anomaly_score = 0.0f;
  alerted_flows.clear();
  {
    std::lock_guard<std::mutex> lock(g_state.dashboard_mutex);
    g_state.active_alerts.clear();
  }

  daemon_thread = std::thread(DaemonWorker);
}

/* @brief Flags the execution loop to halt processing cleanly */
void StopCapture() { g_state.stop_requested = true; }

/* @brief Ensures the daemon thread is properly joined and resources are
 * released upon exit */
void ShutdownEngine() {
  g_state.stop_requested = true; // Signal the loop to break
  if (daemon_thread.joinable()) {
    daemon_thread.join(); // Wait for the thread to safely finish
  }
}

} // namespace engine_runner
