#include "tab_replay.h"
#include "../gui_state.h"
#include "../widgets/widget_alerts.h"
#include "../widgets/widget_metrics.h"
#include "../widgets/widget_plots.h"
#include "../widgets/widget_shared.h"
#include "imgui.h"
#include "portable-file-dialogs.h"
#include <algorithm>

namespace tab_replay {

/* @brief Main ImGui render loop for the Offline PCAP Replay tab */
void Render() {
  if (ImGui::BeginTable("ReplayLayout", 2,
                        ImGuiTableFlags_BordersInnerV |
                            ImGuiTableFlags_Resizable)) {
    ImGui::TableSetupColumn("Sidebar", ImGuiTableColumnFlags_WidthFixed,
                            320.0f);
    ImGui::TableSetupColumn("MainView", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableNextRow();

    // ==========================================
    // COLUMN 1: PERSISTENT SIDEBAR
    // ==========================================
    ImGui::TableSetColumnIndex(0);
    ImGui::BeginChild("SidebarChildR",
                      ImVec2(0, ImGui::GetContentRegionAvail().y - 45));

    if (g_state.is_engine_running)
      ImGui::BeginDisabled();

    ImGui::SeparatorText("Files, replayed in order");
    if (ImGui::Button("Add PCAP(s)", ImVec2(-1, 0))) {
      auto sel = pfd::open_file("Select PCAP Datasets", ".",
                                {"PCAPs", "*.pcap *.pcapng", "All", "*"},
                                pfd::opt::multiselect)
                     .result();
      for (const auto &f : sel) {
        if (std::find(g_state.pcap_files.begin(), g_state.pcap_files.end(),
                      f) == g_state.pcap_files.end()) {
          g_state.pcap_files.push_back(f);
        }
      }
    }
    if (ImGui::IsItemHovered())
      ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);

    if (ImGui::BeginListBox("##PCAPQueue", ImVec2(-1, 80))) {
      for (size_t i = 0; i < g_state.pcap_files.size(); i++) {
        ImGui::Selectable(g_state.pcap_files[i].c_str(), false);
      }
      if (ImGui::IsItemHovered())
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
      ImGui::EndListBox();
    }
    if (ImGui::Button("Clear Queue", ImVec2(-1, 0)))
      g_state.pcap_files.clear();
    if (ImGui::IsItemHovered())
      ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    ImGui::Spacing();

    widget_shared::RenderConfigSettings();

    if (g_state.is_engine_running)
      ImGui::EndDisabled();
    ImGui::EndChild();

    widget_shared::RenderPinnedControls(false);

    // ==========================================
    // COLUMN 2: MAIN DASHBOARD VIEW
    // ==========================================
    ImGui::TableSetColumnIndex(1);
    ImGui::BeginChild("MainContentChildR", ImVec2(0, 0));

    if (g_state.show_dashboard) {
      if (g_state.is_engine_running) {
        widget_plots::Render();
        ImGui::Separator();
        widget_metrics::Render();
      } else {
        widget_metrics::RenderReport();
      }
      widget_alerts::Render();
    } else {
      ImGui::SeparatorText("Pipeline");
      ImGui::TextWrapped("Ready. Load PCAP datasets in the left sidebar and "
                         "click 'Start replay'.");

      ImGui::Spacing();
      ImGui::Spacing();
      ImGui::TextDisabled("Command Preview");
      std::string cmd = widget_shared::GenerateCommandPreview(false);
      ImGui::InputTextMultiline("##cmdR", (char *)cmd.c_str(), cmd.size(),
                                ImVec2(-1, 80), ImGuiInputTextFlags_ReadOnly);
    }

    ImGui::EndChild();
    ImGui::EndTable();
  }
}

} // namespace tab_replay
