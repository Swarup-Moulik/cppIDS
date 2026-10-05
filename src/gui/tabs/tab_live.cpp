#include "tab_live.h"
#include "../gui_state.h"
#include "../widgets/widget_alerts.h"
#include "../widgets/widget_metrics.h"
#include "../widgets/widget_plots.h"
#include "../widgets/widget_shared.h"
#include "imgui.h"
#include <algorithm>
#include <pcap.h>
#include <sstream>
#include <stdio.h>
#include <vector>

namespace tab_live {

/* @brief Holds display name and description for a discovered network adapter */
struct AdapterInfo {
  std::string name;
  std::string description;
};

static std::vector<AdapterInfo> cached_adapters;
static int selected_adapter_idx = -1;

/* @brief Fallback method to fetch network adapters via OS commands
 * (PowerShell/ip) if PCAP fails */
static void FetchAdaptersViaOS() {
#ifdef _WIN32
  std::string cmd = "powershell -NoProfile -Command \"Get-NetAdapter | "
                    "Select-Object Name, InterfaceDescription, InterfaceGuid | "
                    "ConvertTo-Csv -NoTypeInformation\"";
  FILE *pipe = _popen(cmd.c_str(), "r");
  if (!pipe)
    return;
  char buffer[512];
  bool is_header = true;
  while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
    std::string line(buffer);
    if (is_header) {
      is_header = false;
      continue;
    }
    std::vector<std::string> cols;
    std::stringstream ss(line);
    std::string item;
    while (std::getline(ss, item, ',')) {
      item.erase(std::remove(item.begin(), item.end(), '"'), item.end());
      item.erase(std::remove(item.begin(), item.end(), '\r'), item.end());
      item.erase(std::remove(item.begin(), item.end(), '\n'), item.end());
      cols.push_back(item);
    }
    if (cols.size() >= 3) {
      AdapterInfo info;
      info.name = cols[2];
      info.description = cols[0] + " (" + cols[1] + ")";
      cached_adapters.push_back(info);
    }
  }
  _pclose(pipe);
#else
  FILE *pipe = popen("ip -o link show | awk -F': ' '{print $2}'", "r");
  if (!pipe)
    return;
  char buffer[128];
  while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
    std::string line(buffer);
    line.erase(std::remove(line.begin(), line.end(), '\n'), line.end());
    if (line != "lo") {
      AdapterInfo info;
      info.name = line;
      info.description = "System Interface";
      cached_adapters.push_back(info);
    }
  }
  pclose(pipe);
#endif
}

/* @brief Queries the OS for available network interfaces using Npcap/libpcap
 * with OS fallbacks */
void RefreshAdapters() {
  cached_adapters.clear();
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs = nullptr;

  if (pcap_findalldevs(&alldevs, errbuf) == 0 && alldevs != nullptr) {
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
      AdapterInfo info;
      std::string dev_name = d->name ? d->name : "Unknown";
      const std::string prefix = "\\Device\\NPF_";
      if (dev_name.find(prefix) == 0) {
        dev_name = dev_name.substr(prefix.length());
      }
      info.name = dev_name;
      info.description =
          d->description ? d->description : "No description available";
      cached_adapters.push_back(info);
    }
    pcap_freealldevs(alldevs);
  } else {
    FetchAdaptersViaOS();
  }

  if (!cached_adapters.empty()) {
    selected_adapter_idx = 0;
    snprintf(g_state.interface_name, sizeof(g_state.interface_name), "%s",
             cached_adapters[0].name.c_str());
  } else {
    selected_adapter_idx = -1;
    snprintf(g_state.interface_name, sizeof(g_state.interface_name), "");
  }
}

/* @brief Main ImGui render loop for the Live Capture tab */
void Render() {
  static bool init = false;
  if (!init) {
    RefreshAdapters();
    init = true;
  }

  // 2-Column Split: Sidebar (320px) | Main Content (Rest)
  if (ImGui::BeginTable("LiveLayout", 2,
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
    ImGui::BeginChild("SidebarChild",
                      ImVec2(0, ImGui::GetContentRegionAvail().y - 45));

    if (g_state.is_engine_running)
      ImGui::BeginDisabled();

    ImGui::SeparatorText("Source");
    ImGui::SetNextItemWidth(-1);

    bool is_combo_open =
        ImGui::BeginCombo("##AdapterList", g_state.interface_name);
    if (ImGui::IsItemHovered())
      ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);

    if (is_combo_open) {
      for (int i = 0; i < (int)cached_adapters.size(); i++) {
        if (ImGui::Selectable((cached_adapters[i].name + "\n{" +
                               cached_adapters[i].description + "}")
                                  .c_str())) {
          selected_adapter_idx = i;
          snprintf(g_state.interface_name, sizeof(g_state.interface_name), "%s",
                   cached_adapters[i].name.c_str());
        }
        if (ImGui::IsItemHovered())
          ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
      }
      ImGui::EndCombo();
    }
    ImGui::Spacing();

    widget_shared::RenderConfigSettings();

    if (g_state.is_engine_running)
      ImGui::EndDisabled();
    ImGui::EndChild();

    widget_shared::RenderPinnedControls(true);

    // ==========================================
    // COLUMN 2: MAIN DASHBOARD VIEW
    // ==========================================
    ImGui::TableSetColumnIndex(1);
    ImGui::BeginChild("MainContentChild", ImVec2(0, 0));

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
      ImGui::TextWrapped("Ready. Review parameters in the left sidebar and "
                         "click 'Start capture'.");

      ImGui::Spacing();
      ImGui::Spacing();
      ImGui::TextDisabled("Command Preview");
      std::string cmd = widget_shared::GenerateCommandPreview(true);
      ImGui::InputTextMultiline("##cmd", (char *)cmd.c_str(), cmd.size(),
                                ImVec2(-1, 80), ImGuiInputTextFlags_ReadOnly);
    }

    ImGui::EndChild();
    ImGui::EndTable();
  }
}

} // namespace tab_live
