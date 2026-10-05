#include "widget_alerts.h"
#include "../gui_state.h"
#include "imgui.h"
#include <mutex>

namespace widget_alerts {

/* @brief Renders the scrolling intrusion alerts table populated by the backend
 */
void Render() {
  ImGui::Spacing();
  ImGui::SeparatorText("Intrusion Alerts");

  static ImGuiTableFlags flags =
      ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
      ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV |
      ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
      ImGuiTableFlags_Hideable;

  // Table dynamically stretches to the bottom of the remaining content region
  if (ImGui::BeginTable("AlertsTable", 5, flags,
                        ImVec2(0.0f, ImGui::GetContentRegionAvail().y))) {
    ImGui::TableSetupScrollFreeze(0, 1); // Freeze header
    ImGui::TableSetupColumn("Timestamp", ImGuiTableColumnFlags_DefaultSort |
                                             ImGuiTableColumnFlags_WidthFixed);
    ImGui::TableSetupColumn("Source IP");
    ImGui::TableSetupColumn("Dest IP");
    ImGui::TableSetupColumn("Threat Type");
    ImGui::TableSetupColumn("Score", ImGuiTableColumnFlags_WidthFixed);
    ImGui::TableHeadersRow();

    // Lock the mutex to read the active alerts safely from the background
    // thread
    std::lock_guard<std::mutex> lock(g_state.dashboard_mutex);

    for (const auto &alert : g_state.active_alerts) {
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::Text("%s", alert.timestamp.c_str());
      ImGui::TableSetColumnIndex(1);
      ImGui::Text("%s", alert.src_ip.c_str());
      ImGui::TableSetColumnIndex(2);
      ImGui::Text("%s", alert.dst_ip.c_str());
      ImGui::TableSetColumnIndex(3);
      ImGui::Text("%s", alert.threat_type.c_str());

      ImGui::TableSetColumnIndex(4);
      ImGui::TableSetBgColor(
          ImGuiTableBgTarget_CellBg,
          ImGui::GetColorU32(
              ImVec4(0.8f, 0.2f, 0.2f, 0.3f))); // Light red highlight
      ImGui::Text("%.1f", alert.score);
    }
    ImGui::EndTable();
  }
}
} // namespace widget_alerts
