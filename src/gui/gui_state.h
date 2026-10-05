#pragma once
#include <atomic>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

/* @brief Defines the operational mode of the SNN reservoir */
enum class ReservoirMode { STDP_ONLINE, TRAIN, TRANSFER, TEST_FROZEN };

/* @brief Defines the classification mechanism reading from the reservoir */
enum class ReadoutMode { NONE, TRAIN_SNN, TEST_SNN, TRAIN_LR, TEST_LR };

/* @brief Global state container shared across GUI tabs and the backend engine
 */
struct GuiState {
  // Execution Control
  std::atomic<bool> is_engine_running{false};
  std::atomic<bool> stop_requested{false};
  std::atomic<bool> show_dashboard{false};

  // Tab 1: Live Capture
  char interface_name[128] = "";
  char bpf_filter[256] = "";

  // Tab 2: Replay
  std::vector<std::string> pcap_files;

  // Shared Configuration
  char config_path[256] = "config/ids_config.ini";
  int eval_interval_sec = 60;
  int telemetry_interval_min = 5;

  ReservoirMode res_mode = ReservoirMode::STDP_ONLINE;
  ReadoutMode read_mode = ReadoutMode::NONE;

  char base_model_path[256] = "";
  char export_features_path[256] = "";

  // Ground Truth (Presets will populate these)
  char attackers_list[512] = "";
  char victims_list[512] = "";
  char target_ports[256] = "";

  // --- Real-time Telemetry (Written by Engine, Read by UI) ---
  std::atomic<float> current_pps{0.0f};
  std::atomic<uint64_t> total_packets{0}; // New Packet Counter
  std::atomic<int> active_flows{0};
  std::atomic<float> current_anomaly_score{0.0f};
  std::atomic<float> processing_latency_ms{0.0f};

  // --- Real-time Plotting & Alerts ---
  std::mutex dashboard_mutex;
  std::deque<float> score_history; // Feeds ImPlot

  /* @brief Represents a single intrusion alert to be displayed in the UI */
  struct Alert {
    std::string timestamp;
    std::string src_ip;
    std::string dst_ip;
    std::string threat_type;
    float score;
  };
  std::deque<Alert> active_alerts; // Feeds the Table
};

// Global instance accessible by UI tabs and the engine runner
extern GuiState g_state;
