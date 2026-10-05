#pragma once
#include <string>

namespace tab_live {
/* @brief Queries the OS for available network interfaces using Npcap/libpcap
 * with OS fallbacks */
void RefreshAdapters();

/* @brief Main ImGui render loop for the Live Capture tab */
void Render();
} // namespace tab_live
