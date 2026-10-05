#include "widget_metrics.h"
#include "../gui_state.h"
#include "core/telemetry.h"
#include "imgui.h"
#include "neuromorphic/snn_core.h"

// Backend Ground Truth Globals
extern uint64_t gt_true_positives;
extern uint64_t gt_true_negatives;
extern uint64_t gt_false_positives;
extern uint64_t gt_false_negatives;

namespace widget_metrics {

/* @brief Renders the real-time telemetry metrics table during live capture */
void Render() {
  ImGui::SeparatorText("Live Engine Metrics");

  if (ImGui::BeginTable("MetricsTable", 5, ImGuiTableFlags_BordersInnerV)) {
    ImGui::TableNextRow();

    ImGui::TableSetColumnIndex(0);
    ImGui::TextDisabled("Throughput");
    ImGui::TextColored(ImVec4(0.4f, 0.8f, 0.4f, 1.0f), "%.1f pps",
                       g_state.current_pps.load());

    ImGui::TableSetColumnIndex(1);
    ImGui::TextDisabled("Total Packets");
    ImGui::TextColored(ImVec4(0.8f, 0.6f, 1.0f, 1.0f), "%llu",
                       g_state.total_packets.load());

    ImGui::TableSetColumnIndex(2);
    ImGui::TextDisabled("Active Flows");
    ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "%d",
                       g_state.active_flows.load());

    ImGui::TableSetColumnIndex(3);
    ImGui::TextDisabled("SNN Anomaly Score");
    ImGui::TextColored(ImVec4(0.9f, 0.4f, 0.4f, 1.0f), "%.1f",
                       g_state.current_anomaly_score.load());

    ImGui::TableSetColumnIndex(4);
    ImGui::TextDisabled("Processing Latency");
    ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.8f, 1.0f), "%.3f ms",
                       g_state.processing_latency_ms.load());

    ImGui::EndTable();
  }
}

/* @brief Renders the comprehensive post-capture evaluation and statistics
 * report */
void RenderReport() {
  ImGui::Spacing();
  ImGui::SeparatorText("Post-Capture Telemetry & Evaluation Report");
  ImGui::Spacing();

  ImGui::Columns(2, "ReportColumns", false);

  // ==========================================
  // ROW 1, COLUMN 1 (Top Left)
  // ==========================================
  ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f),
                     "System & Runtime Metrics");
  ImGui::Separator();

  uint64_t avg_lat =
      g_runtime_stats.packets_processed > 0
          ? g_runtime_stats.total_latency_us / g_runtime_stats.packets_processed
          : 0;
  uint64_t p50 = compute_percentile(0.50);
  uint64_t p95 = compute_percentile(0.95);
  uint64_t p99 = compute_percentile(0.99);
  uint64_t ram_mb = sys_get_ram_usage_bytes() / (1024 * 1024);

  if (ImGui::BeginTable("RuntimeStats", 2, ImGuiTableFlags_RowBg)) {
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Packets Received (OS):");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu", g_runtime_stats.packets_received);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Packets Processed:");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu", g_runtime_stats.packets_processed);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Packets Dropped:");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu", g_runtime_stats.packets_dropped);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Malformed Packets:");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu", g_runtime_stats.malformed_packets);

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Avg Processing Latency:");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu us", avg_lat);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Median Latency (P50):");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu us", p50);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("P95 Latency:");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu us", p95);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("P99 Latency:");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu us", p99);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Max Latency:");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu us", g_runtime_stats.max_latency_us);

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Total Process RAM:");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu MB", ram_mb);
    ImGui::EndTable();
  }

  ImGui::NextColumn();

  // ==========================================
  // ROW 1, COLUMN 2 (Top Right)
  // ==========================================
  ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.4f, 1.0f),
                     "Contextual Decision & Episodes");
  ImGui::Separator();

  float fp_reduction_rate =
      (g_context_stats.anomalies_detected > 0)
          ? (static_cast<float>(g_context_stats.anomalies_dismissed) /
             g_context_stats.anomalies_detected) *
                100.0f
          : 0.0f;

  if (ImGui::BeginTable("ThreatStats", 2, ImGuiTableFlags_RowBg)) {
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Anomalies Detected (SNN):");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu", g_context_stats.anomalies_detected);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Anomalies Dismissed (Ctx):");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu", g_context_stats.anomalies_dismissed);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Threats Confirmed:");
    ImGui::TableSetColumnIndex(1);
    ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "%llu",
                       g_context_stats.threats_confirmed);

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Context Matches:");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu", g_context_stats.context_matches);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Context Mismatches:");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu", g_context_stats.context_mismatches);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Context FP Reduction Rate:");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%.1f%%", fp_reduction_rate);

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Episodes Started:");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu", g_context_stats.episodes_started);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Episodes Resolved:");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu", g_context_stats.episodes_resolved);
    ImGui::EndTable();
  }

  ImGui::NextColumn();

  // ==========================================
  // ROW 2, COLUMN 1 (Bottom Left)
  // ==========================================
  ImGui::Spacing();
  ImGui::TextColored(ImVec4(0.8f, 0.4f, 1.0f, 1.0f),
                     "SNN Neuromorphic Dynamics");
  ImGui::Separator();

  uint64_t t_spikes = 0, t_synops = 0, t_weights = 0;
  uint32_t t_neurons = 0;
  snn_get_telemetry_flat(&t_spikes, &t_synops, &t_weights, &t_neurons);

  if (ImGui::BeginTable("SNNStats", 2, ImGuiTableFlags_RowBg)) {
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Total Spikes Emitted:");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu", t_spikes);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Synaptic Operations:");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu", t_synops);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Plastic Weight Updates:");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%llu", t_weights);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("Firing Neurons (Current):");
    ImGui::TableSetColumnIndex(1);
    ImGui::Text("%u", t_neurons);
    ImGui::EndTable();
  }

  ImGui::NextColumn();

  // ==========================================
  // ROW 2, COLUMN 2 (Bottom Right)
  // ==========================================
  ImGui::Spacing();
  ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.6f, 1.0f), "Ground Truth Evaluation");
  ImGui::Separator();

  // Machine Learning Metric Math
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

  // 4-Column Presentation Matrix
  if (ImGui::BeginTable("GTStats", 4,
                        ImGuiTableFlags_RowBg |
                            ImGuiTableFlags_BordersInnerV)) {
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("True Positives (TP):");
    ImGui::TableSetColumnIndex(1);
    ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "%llu",
                       gt_true_positives);
    ImGui::TableSetColumnIndex(2);
    ImGui::Text("Precision:");
    ImGui::TableSetColumnIndex(3);
    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "%.2f%%", precision);

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("False Positives (FP):");
    ImGui::TableSetColumnIndex(1);
    ImGui::TextColored(ImVec4(0.8f, 0.2f, 0.2f, 1.0f), "%llu",
                       gt_false_positives);
    ImGui::TableSetColumnIndex(2);
    ImGui::Text("Recall / TPR:");
    ImGui::TableSetColumnIndex(3);
    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "%.2f%%", recall);

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("True Negatives (TN):");
    ImGui::TableSetColumnIndex(1);
    ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "%llu",
                       gt_true_negatives);
    ImGui::TableSetColumnIndex(2);
    ImGui::Text("F1-Score:");
    ImGui::TableSetColumnIndex(3);
    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "%.2f%%", f1);

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("False Negatives (FN):");
    ImGui::TableSetColumnIndex(1);
    ImGui::TextColored(ImVec4(0.8f, 0.4f, 0.1f, 1.0f), "%llu",
                       gt_false_negatives);
    ImGui::TableSetColumnIndex(2);
    ImGui::Text("Accuracy:");
    ImGui::TableSetColumnIndex(3);
    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "%.2f%%", accuracy);

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("False Pos. Rate (FPR):");
    ImGui::TableSetColumnIndex(1);
    ImGui::TextColored(ImVec4(0.8f, 0.4f, 0.4f, 1.0f), "%.2f%%", fpr);
    ImGui::TableSetColumnIndex(2);
    ImGui::Text("False Neg. Rate (FNR):");
    ImGui::TableSetColumnIndex(3);
    ImGui::TextColored(ImVec4(0.8f, 0.4f, 0.4f, 1.0f), "%.2f%%", fnr);

    ImGui::EndTable();
  }

  ImGui::Columns(1);
  ImGui::Spacing();
}
} // namespace widget_metrics
