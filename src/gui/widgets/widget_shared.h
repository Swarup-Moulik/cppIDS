#pragma once
#include <string>

namespace widget_shared {
/* @brief Renders the shared BPF, Neuromorphic, Readout, and Ground Truth
 * configurations */
void RenderConfigSettings();

/* @brief Renders the pinned start/stop execution buttons dynamically based on
 * engine state */
void RenderPinnedControls(bool is_live);

/* @brief Generates the terminal CLI equivalent of the current GUI state */
std::string GenerateCommandPreview(bool is_live);
} // namespace widget_shared
