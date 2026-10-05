#include "widget_shared.h"
#include "../engine_runner.h"
#include "../gui_state.h"
#include "imgui.h"
#include <sstream>

namespace widget_shared {

/* @brief Generates the terminal CLI equivalent of the current GUI state */
std::string GenerateCommandPreview(bool is_live) {
  std::ostringstream cmd;
  cmd << "./cppids";
  if (is_live && strlen(g_state.interface_name) > 0)
    cmd << " -i \"" << g_state.interface_name << "\"";
  if (strlen(g_state.bpf_filter) > 0)
    cmd << " -filter \"" << g_state.bpf_filter << "\"";
  if (strlen(g_state.config_path) > 0 &&
      strcmp(g_state.config_path, "config/ids_config.ini") != 0)
    cmd << " --config \"" << g_state.config_path << "\"";
  if (g_state.res_mode == ReservoirMode::TRAIN)
    cmd << " --train \"" << g_state.base_model_path << "\"";
  else if (g_state.res_mode == ReservoirMode::TRANSFER)
    cmd << " --transfer \"" << g_state.base_model_path << "\"";
  else if (g_state.res_mode == ReservoirMode::TEST_FROZEN)
    cmd << " --test \"" << g_state.base_model_path << "\"";
  else
    cmd << " --stdp";

  if (g_state.read_mode == ReadoutMode::TRAIN_SNN)
    cmd << " --train-snn-readout";
  else if (g_state.read_mode == ReadoutMode::TEST_SNN)
    cmd << " --test-snn-readout";
  else if (g_state.read_mode == ReadoutMode::TRAIN_LR)
    cmd << " --train-lr";
  else if (g_state.read_mode == ReadoutMode::TEST_LR)
    cmd << " --test-lr";

  if (strlen(g_state.attackers_list) > 0)
    cmd << " --attackers " << g_state.attackers_list;
  if (strlen(g_state.victims_list) > 0)
    cmd << " --victims " << g_state.victims_list;
  if (strlen(g_state.target_ports) > 0)
    cmd << " --ports " << g_state.target_ports;
  if (!is_live) {
    for (const auto &file : g_state.pcap_files) {
      cmd << " \"" << file << "\"";
    }
  }
  return cmd.str();
}

/* @brief Renders the shared BPF, Neuromorphic, Readout, and Ground Truth
 * configurations */
void RenderConfigSettings() {
  // BPF Filter
  ImGui::TextDisabled("BPF filter");
  ImGui::SetNextItemWidth(-1);
  ImGui::InputText("##BPF Filter", g_state.bpf_filter,
                   sizeof(g_state.bpf_filter));
  ImGui::Spacing();

  // Config File
  ImGui::TextDisabled("Config file");
  ImGui::SetNextItemWidth(-1);
  ImGui::InputText("##Config File", g_state.config_path,
                   sizeof(g_state.config_path));
  ImGui::Spacing();

  // Reservoir Mode
  ImGui::SeparatorText("Reservoir");
  int res_mode = static_cast<int>(g_state.res_mode);
  ImGui::RadioButton("STDP Online\t\t--stdp", &res_mode, 0);
  if (ImGui::IsItemHovered())
    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
  ImGui::RadioButton("Train\t\t\t--train", &res_mode, 1);
  if (ImGui::IsItemHovered())
    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
  ImGui::RadioButton("Transfer\t\t--transfer", &res_mode, 2);
  if (ImGui::IsItemHovered())
    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
  ImGui::RadioButton("Test, frozen\t\t--test", &res_mode, 3);
  if (ImGui::IsItemHovered())
    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
  g_state.res_mode = static_cast<ReservoirMode>(res_mode);

  if (g_state.res_mode != ReservoirMode::STDP_ONLINE) {
    ImGui::Spacing();
    ImGui::TextDisabled("Base model");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##BaseModel", "Model path...",
                             g_state.base_model_path,
                             sizeof(g_state.base_model_path));
  }
  ImGui::Spacing();

  // Readout Mode
  ImGui::SeparatorText("Readout");
  int read_mode = static_cast<int>(g_state.read_mode);
  ImGui::RadioButton("None", &read_mode, 0);
  if (ImGui::IsItemHovered())
    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
  ImGui::RadioButton("SNN, train\t--train-snn-readout", &read_mode, 1);
  if (ImGui::IsItemHovered())
    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
  ImGui::RadioButton("SNN, test\t--test-snn-readout", &read_mode, 2);
  if (ImGui::IsItemHovered())
    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
  ImGui::RadioButton("Logistic, train\t--train-lr", &read_mode, 3);
  if (ImGui::IsItemHovered())
    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
  ImGui::RadioButton("Logistic, test\t--test-lr", &read_mode, 4);
  if (ImGui::IsItemHovered())
    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
  g_state.read_mode = static_cast<ReadoutMode>(read_mode);
  ImGui::Spacing();

  // Ground Truth
  bool is_header_open = ImGui::CollapsingHeader("Ground truth and advanced",
                                                ImGuiTreeNodeFlags_DefaultOpen);
  if (ImGui::IsItemHovered())
    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);

  if (is_header_open) {
    ImGui::TextDisabled("Attackers");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##Attackers", "172.16.0.1",
                             g_state.attackers_list,
                             sizeof(g_state.attackers_list));

    ImGui::TextDisabled("Victims");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##Victims", "optional", g_state.victims_list,
                             sizeof(g_state.victims_list));

    ImGui::TextDisabled("Ports");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##Ports", "optional", g_state.target_ports,
                             sizeof(g_state.target_ports));
  }
}

/* @brief Renders the pinned start/stop execution buttons dynamically based on
 * engine state */
void RenderPinnedControls(bool is_live) {
  const char *start_lbl = is_live ? "Start capture" : "Start replay";
  const char *stop_lbl = is_live ? "Stop capture" : "Stop replay";

  // Force text to black for the bright amber button
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 0.0f, 0.0f, 1.0f));

  if (g_state.is_engine_running) {
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                          ImVec4(0.4f, 0.4f, 0.4f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                          ImVec4(0.2f, 0.2f, 0.2f, 1.0f));
    // -1 stretches button to max column width
    if (ImGui::Button(stop_lbl, ImVec2(-1, 35))) {
      engine_runner::StopCapture();
    }
    if (ImGui::IsItemHovered())
      ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
  } else {
    // Amber Color Palette
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.95f, 0.65f, 0.05f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                          ImVec4(1.00f, 0.75f, 0.15f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                          ImVec4(0.85f, 0.55f, 0.00f, 1.0f));

    bool can_start = is_live ? (strlen(g_state.interface_name) > 0)
                             : !g_state.pcap_files.empty();
    if (!can_start)
      ImGui::BeginDisabled();

    if (ImGui::Button(start_lbl, ImVec2(-1, 35))) {
      if (!is_live)
        snprintf(g_state.interface_name, sizeof(g_state.interface_name), "");
      g_state.show_dashboard = true;
      g_state.is_engine_running = true;
      g_state.stop_requested = false;
      engine_runner::StartLiveCapture();
    }
    if (ImGui::IsItemHovered())
      ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    if (!can_start)
      ImGui::EndDisabled();
  }
  ImGui::PopStyleColor(4);
}

} // namespace widget_shared
