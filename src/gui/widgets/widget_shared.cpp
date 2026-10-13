#include "widget_shared.h"
#include "../engine_runner.h"
#include "../gui_state.h"
#include "imgui.h"
#include "portable-file-dialogs.h"
#include <sstream>
#include <string>

extern bool g_disable_whitelist;

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

  // Append the ablation flag to the command preview if checked
  if (g_disable_whitelist) {
    cmd << " --no-whitelist";
  }

  // Construct the full target model path for saving/loading
  std::string full_target_path = g_state.train_model_dir;
  if (!full_target_path.empty() && full_target_path.back() != '/' &&
      full_target_path.back() != '\\') {
    full_target_path += "/";
  }
  full_target_path += g_state.train_model_name;

  bool is_readout = (g_state.read_mode != ReadoutMode::NONE);

  if (is_readout) {
    // Readout modes strictly require a base model for the reservoir
    if (strlen(g_state.base_model_path) > 0)
      cmd << " --base-model \"" << g_state.base_model_path << "\"";

    if (g_state.read_mode == ReadoutMode::TRAIN_SNN)
      cmd << " --train-snn-readout \"" << full_target_path << "\"";
    else if (g_state.read_mode == ReadoutMode::TEST_SNN)
      cmd << " --test-snn-readout \"" << full_target_path << "\"";
    else if (g_state.read_mode == ReadoutMode::TRAIN_LR)
      cmd << " --train-lr \"" << full_target_path << "\"";
    else if (g_state.read_mode == ReadoutMode::TEST_LR)
      cmd << " --test-lr \"" << full_target_path << "\"";
  } else {
    // Reservoir-only execution modes
    if (g_state.res_mode == ReservoirMode::TRAIN)
      cmd << " --train \"" << full_target_path << "\"";
    else if (g_state.res_mode == ReservoirMode::TRANSFER)
      cmd << " --transfer \"" << g_state.base_model_path << "\"";
    else if (g_state.res_mode == ReservoirMode::TEST_FROZEN)
      cmd << " --test \"" << g_state.base_model_path << "\"";
    else
      cmd << " --stdp";
  }

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
  if (ImGui::Button("Browse Config", ImVec2(-1, 0))) {
    auto sel =
        pfd::open_file("Select Configuration INI", "",
                       {"INI Files", "*.ini", "All", "*"}, pfd::opt::none)
            .result();
    if (!sel.empty()) {
      snprintf(g_state.config_path, sizeof(g_state.config_path), "%s",
               sel[0].c_str());
    }
  }
  if (ImGui::IsItemHovered())
    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);

  ImGui::SetNextItemWidth(-1);
  ImGui::InputTextWithHint("##ConfigFile", "Select an ids_config.ini...",
                           g_state.config_path, sizeof(g_state.config_path));
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

  // Determine required file pickers based on the active CLI mode combinations
  bool needs_base_model = (g_state.res_mode == ReservoirMode::TRANSFER ||
                           g_state.res_mode == ReservoirMode::TEST_FROZEN ||
                           g_state.read_mode != ReadoutMode::NONE);

  bool is_saving = (g_state.res_mode == ReservoirMode::TRAIN ||
                    g_state.read_mode == ReadoutMode::TRAIN_SNN ||
                    g_state.read_mode == ReadoutMode::TRAIN_LR);

  bool needs_target_model = (g_state.res_mode == ReservoirMode::TRAIN ||
                             g_state.read_mode != ReadoutMode::NONE);

  ImGui::SeparatorText("Model Weights");

  if (needs_base_model) {
    ImGui::TextDisabled("Base Model (Reservoir)");
    if (ImGui::Button("Browse Base Model", ImVec2(-1, 0))) {
      auto sel =
          pfd::open_file("Select Base Model", "",
                         {"Model Files", "*.bin", "All", "*"}, pfd::opt::none)
              .result();
      if (!sel.empty()) {
        snprintf(g_state.base_model_path, sizeof(g_state.base_model_path), "%s",
                 sel[0].c_str());
      }
    }
    if (ImGui::IsItemHovered())
      ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);

    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##BaseModel", "Path to existing baseline...",
                             g_state.base_model_path,
                             sizeof(g_state.base_model_path));
    ImGui::Spacing();
  }

  if (needs_target_model) {
    ImGui::TextDisabled(is_saving ? "Save Target" : "Readout Model");
    if (ImGui::Button(is_saving ? "Select Save Location"
                                : "Select Readout File",
                      ImVec2(-1, 0))) {
      if (is_saving) {
        auto sel =
            pfd::save_file("Select Save Location & Model Name", "",
                           {"Model Files", "*.bin", "All", "*"}, pfd::opt::none)
                .result();
        if (!sel.empty()) {
          size_t pos = sel.find_last_of("/\\");
          if (pos != std::string::npos) {
            snprintf(g_state.train_model_dir, sizeof(g_state.train_model_dir),
                     "%s", sel.substr(0, pos).c_str());
            snprintf(g_state.train_model_name, sizeof(g_state.train_model_name),
                     "%s", sel.substr(pos + 1).c_str());
          }
        }
      } else {
        auto sel =
            pfd::open_file("Select Readout Model", "",
                           {"Model Files", "*.bin", "All", "*"}, pfd::opt::none)
                .result();
        if (!sel.empty()) {
          size_t pos = sel[0].find_last_of("/\\");
          if (pos != std::string::npos) {
            snprintf(g_state.train_model_dir, sizeof(g_state.train_model_dir),
                     "%s", sel[0].substr(0, pos).c_str());
            snprintf(g_state.train_model_name, sizeof(g_state.train_model_name),
                     "%s", sel[0].substr(pos + 1).c_str());
          }
        }
      }
    }
    if (ImGui::IsItemHovered())
      ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);

    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##TargetDir", "Directory path...",
                             g_state.train_model_dir,
                             sizeof(g_state.train_model_dir));

    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##TargetName", "e.g. target_model.bin",
                             g_state.train_model_name,
                             sizeof(g_state.train_model_name));
  }
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

    ImGui::Spacing();
    ImGui::Checkbox("Disable service-port damping (--no-whitelist)",
                    &::g_disable_whitelist);
    if (ImGui::IsItemHovered()) {
      ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
      ImGui::SetTooltip("Bypass the contextual prior. Improves raw detection "
                        "but increases False Positives.");
    }
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

    // Prevent execution if a required save directory path is missing
    bool is_saving = (g_state.res_mode == ReservoirMode::TRAIN ||
                      g_state.read_mode == ReadoutMode::TRAIN_SNN ||
                      g_state.read_mode == ReadoutMode::TRAIN_LR);

    if (is_saving && strlen(g_state.train_model_dir) == 0) {
      can_start = false;
    }

    // Prevent execution if base model is required but missing
    bool needs_base_model = (g_state.res_mode == ReservoirMode::TRANSFER ||
                             g_state.res_mode == ReservoirMode::TEST_FROZEN ||
                             g_state.read_mode != ReadoutMode::NONE);

    if (needs_base_model && strlen(g_state.base_model_path) == 0) {
      can_start = false;
    }

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
