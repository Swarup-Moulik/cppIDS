#include "widget_plots.h"
#include "../gui_state.h"
#include "imgui.h"
#include "implot.h"
#include <algorithm>

namespace widget_plots {

/* @brief Ring buffer structure for efficiently managing scrolling plot data
 * points */
struct ScrollingBuffer {
  int MaxSize;
  int Offset;
  ImVector<ImVec2> Data;
  ScrollingBuffer(int max_size = 2000) {
    MaxSize = max_size;
    Offset = 0;
    Data.reserve(MaxSize);
  }
  void AddPoint(float x, float y) {
    if (Data.size() < MaxSize)
      Data.push_back(ImVec2(x, y));
    else {
      Data[Offset] = ImVec2(x, y);
      Offset = (Offset + 1) % MaxSize;
    }
  }
  void Erase() {
    if (Data.size() > 0) {
      Data.shrink(0);
      Offset = 0;
    }
  }
};

/* @brief Renders the real-time reservoir anomaly score line chart */
void Render() {
  static ScrollingBuffer sdata;
  static float t = 0;
  static bool was_running = false;

  // Reset graph cleanly on new capture
  if (g_state.is_engine_running && !was_running) {
    sdata.Erase();
    t = 0;
  }
  was_running = g_state.is_engine_running;

  // Only scroll time and add data if engine is actually running
  if (g_state.is_engine_running) {
    t += ImGui::GetIO().DeltaTime;
    sdata.AddPoint(t, g_state.current_anomaly_score.load());
  }

  // Calculate dynamic max Y to ensure the line doesn't vanish off the top edge
  float max_y = 100.0f; // Minimum ceiling to prevent graph from looking empty
  for (int i = 0; i < sdata.Data.size(); ++i) {
    if (sdata.Data[i].y > max_y) {
      max_y = sdata.Data[i].y;
    }
  }

  ImGui::SeparatorText(g_state.is_engine_running
                           ? "Reservoir Dynamics (Real-Time)"
                           : "Reservoir Dynamics (Post-Run Report)");

  if (ImPlot::BeginPlot("##AnomalyScore", ImVec2(-1, 250))) {

    // X-axis scrolls automatically
    ImPlot::SetupAxisLimits(ImAxis_X1, t - 10.0, t, ImGuiCond_Always);

    // Y-axis uses our manual max_y, multiplied by 1.15 to give 15% empty visual
    // space above the line
    ImPlot::SetupAxisLimits(ImAxis_Y1, 0.0, max_y * 1.15f, ImGuiCond_Always);

    // Apply the amber accent color to the line
    ImPlot::SetNextLineStyle(ImVec4(0.95f, 0.65f, 0.05f, 1.0f), 2.0f);
    ImPlot::PlotLine("Threat Level", &sdata.Data[0].x, &sdata.Data[0].y,
                     sdata.Data.size(), 0, sdata.Offset, 2 * sizeof(float));

    // Add a modern shaded gradient fill under the line (20% opacity)
    ImPlot::SetNextFillStyle(ImVec4(0.95f, 0.65f, 0.05f, 0.20f));
    ImPlot::PlotShaded("Threat Level", &sdata.Data[0].x, &sdata.Data[0].y,
                       sdata.Data.size(), -INFINITY, 0, sdata.Offset,
                       2 * sizeof(float));

    ImPlot::EndPlot();
  }
}
} // namespace widget_plots
