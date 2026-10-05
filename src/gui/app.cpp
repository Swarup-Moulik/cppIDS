#include "app.h"
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include "engine_runner.h"
#include "gui_state.h"
#include "imgui.h"
#include "implot.h"
#include "tabs/tab_live.h"
#include "tabs/tab_replay.h"
#include <GLFW/glfw3.h>
#include <iostream>

GuiState g_state; // Define the global state

/* @brief Callback to handle and log GLFW framework errors */
static void glfw_error_callback(int error, const char *description) {
  std::cerr << "GLFW Error " << error << ": " << description << "\n";
}

/* @brief Applies the custom cppIDS color palette and styling for Light or Dark
 * mode */
void ApplyTheme(bool dark_mode) {
  ImGuiStyle &style = ImGui::GetStyle();
  ImVec4 *colors = style.Colors;

  ImVec4 accent_primary = ImVec4(0.95f, 0.65f, 0.05f, 1.00f);
  ImVec4 accent_hovered = ImVec4(1.00f, 0.75f, 0.15f, 1.00f);
  ImVec4 accent_active = ImVec4(0.85f, 0.55f, 0.00f, 1.00f);
  ImVec4 accent_faint =
      ImVec4(0.95f, 0.65f, 0.05f, 0.30f); // Used for highlights

  if (dark_mode) {
    ImGui::StyleColorsDark(&style);
    colors[ImGuiCol_WindowBg] = ImVec4(0.08f, 0.08f, 0.09f, 1.00f);
    colors[ImGuiCol_ChildBg] = ImVec4(0.11f, 0.11f, 0.12f, 1.00f);
    colors[ImGuiCol_PopupBg] = ImVec4(0.11f, 0.11f, 0.12f, 0.95f);

    colors[ImGuiCol_FrameBg] = ImVec4(0.15f, 0.15f, 0.17f, 1.00f);
    colors[ImGuiCol_FrameBgHovered] = ImVec4(0.20f, 0.20f, 0.22f, 1.00f);
    colors[ImGuiCol_FrameBgActive] = ImVec4(0.25f, 0.25f, 0.27f, 1.00f);

    colors[ImGuiCol_Header] = ImVec4(0.18f, 0.18f, 0.20f, 1.00f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(0.25f, 0.25f, 0.28f, 1.00f);
    colors[ImGuiCol_HeaderActive] = accent_active; // Changed to amber

    colors[ImGuiCol_Button] = ImVec4(0.18f, 0.18f, 0.20f, 1.00f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(0.25f, 0.25f, 0.28f, 1.00f);
    colors[ImGuiCol_ButtonActive] = ImVec4(0.15f, 0.15f, 0.17f, 1.00f);

    colors[ImGuiCol_CheckMark] = accent_primary;
    colors[ImGuiCol_SliderGrab] = accent_primary;
    colors[ImGuiCol_SliderGrabActive] = accent_active;
    colors[ImGuiCol_TextSelectedBg] =
        accent_faint; // Replaces default blue text highlight
  } else {
    ImGui::StyleColorsLight(&style);
    colors[ImGuiCol_WindowBg] = ImVec4(0.95f, 0.95f, 0.96f, 1.00f);
    colors[ImGuiCol_ChildBg] = ImVec4(0.90f, 0.90f, 0.92f, 1.00f);

    colors[ImGuiCol_FrameBg] = ImVec4(0.85f, 0.85f, 0.88f, 1.00f);
    colors[ImGuiCol_FrameBgHovered] = ImVec4(0.80f, 0.80f, 0.83f, 1.00f);
    colors[ImGuiCol_FrameBgActive] = ImVec4(0.75f, 0.75f, 0.78f, 1.00f);

    // Overriding Light Mode default blues with amber tints
    colors[ImGuiCol_Header] = accent_faint;
    colors[ImGuiCol_HeaderHovered] = ImVec4(0.95f, 0.65f, 0.05f, 0.50f);
    colors[ImGuiCol_HeaderActive] = accent_active;

    colors[ImGuiCol_Button] = ImVec4(0.85f, 0.85f, 0.88f, 1.00f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(0.80f, 0.80f, 0.83f, 1.00f);
    colors[ImGuiCol_ButtonActive] = ImVec4(0.75f, 0.75f, 0.78f, 1.00f);

    colors[ImGuiCol_CheckMark] = accent_active;
    colors[ImGuiCol_SliderGrab] = accent_active;
    colors[ImGuiCol_SliderGrabActive] = accent_primary;
    colors[ImGuiCol_TextSelectedBg] =
        accent_faint; // Replaces default blue text highlight
  }

  style.WindowRounding = 6.0f;
  style.FrameRounding = 4.0f;
  style.GrabRounding = 4.0f;
  style.TabRounding = 4.0f;
  style.ItemSpacing = ImVec2(10.0f, 8.0f);
  style.FramePadding = ImVec2(8.0f, 6.0f);
}

/* @brief Renders a custom animated sliding toggle switch for binary states */
void RenderToggleButton(const char *str_id, bool *v) {
  ImVec2 p = ImGui::GetCursorScreenPos();
  ImDrawList *draw_list = ImGui::GetWindowDrawList();
  float height = ImGui::GetFrameHeight() * 0.85f;
  float width = height * 1.8f;
  float radius = height * 0.50f;

  ImGui::InvisibleButton(str_id, ImVec2(width, height));
  if (ImGui::IsItemHovered())
    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
  if (ImGui::IsItemClicked())
    *v = !*v;

  ImU32 col_bg;
  if (ImGui::IsItemHovered())
    col_bg = *v ? IM_COL32(255, 190, 50, 255) : IM_COL32(130, 130, 130, 255);
  else
    col_bg = *v ? IM_COL32(242, 165, 13, 255) : IM_COL32(90, 90, 90, 255);

  draw_list->AddRectFilled(p, ImVec2(p.x + width, p.y + height), col_bg,
                           height * 0.5f);
  draw_list->AddCircleFilled(
      ImVec2(p.x + radius + (*v ? 1 : 0) * (width - radius * 2.0f),
             p.y + radius),
      radius - 1.5f, IM_COL32(255, 255, 255, 255));
}

/* @brief Main application loop managing the rendering window and UI event
 * polling */
int RunGUI() {
  glfwSetErrorCallback(glfw_error_callback);
  if (!glfwInit())
    return 1;

  const char *glsl_version = "#version 130";
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

  GLFWwindow *window = glfwCreateWindow(
      1280, 800, "cppIDS - Neuromorphic Threat Hunt", nullptr, nullptr);
  if (window == nullptr) {
    glfwTerminate();
    return 1;
  }
  glfwMakeContextCurrent(window);
  glfwSwapInterval(1);

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImPlot::CreateContext();

  ImGuiIO &io = ImGui::GetIO();
  (void)io;
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

  ImFont *main_font = io.Fonts->AddFontFromFileTTF(
      "../assets/fonts/Raleway-SemiBold.ttf", 18.0f);
  if (!main_font) {
    io.Fonts->AddFontDefault();
  }

  static bool is_dark_mode = true;
  ApplyTheme(is_dark_mode);

  ImGui_ImplGlfw_InitForOpenGL(window, true);
  ImGui_ImplOpenGL3_Init(glsl_version);

  // Variable to track our custom active tab (0 = Live, 1 = Replay)
  static int active_tab = 0;

  while (!glfwWindowShouldClose(window)) {
    glfwPollEvents();

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    const ImGuiViewport *viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);

    ImGuiWindowFlags window_flags =
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus;

    ImGui::Begin("Main Dashboard", nullptr, window_flags);

    ImVec2 start_pos = ImGui::GetCursorPos();
    ImVec2 screen_pos = ImGui::GetCursorScreenPos();

    // We establish a single absolute horizontal center-line for the entire top
    // bar
    float bar_center_y = start_pos.y + 16.0f;
    float absolute_center_y = screen_pos.y + 16.0f;
    float text_half_height = ImGui::GetTextLineHeight() * 0.5f;

    // --- LOGO & TITLE (Left) ---
    // Triangle mathematically centered on the Y-axis
    ImGui::GetWindowDrawList()->AddTriangleFilled(
        ImVec2(screen_pos.x + 15.0f, absolute_center_y + 7.0f), // Bottom left
        ImVec2(screen_pos.x + 23.0f, absolute_center_y - 7.0f), // Top middle
        ImVec2(screen_pos.x + 31.0f, absolute_center_y + 7.0f), // Bottom right
        IM_COL32(242, 165, 13, 255));

    // Title Text centered vertically
    ImGui::SetCursorPos(
        ImVec2(start_pos.x + 40.0f, bar_center_y - text_half_height));
    ImGui::PushStyleColor(ImGuiCol_Text, is_dark_mode
                                             ? ImVec4(1.0f, 1.0f, 1.0f, 1.0f)
                                             : ImVec4(0.0f, 0.0f, 0.0f, 1.0f));
    ImGui::Text("cppIDS");
    ImGui::PopStyleColor();

    // --- CUSTOM TAB BAR (Center-Left) ---
    // Set height exactly to 30px to perfectly balance the 18px font and 6px
    // vertical padding
    ImVec2 tab_size = ImVec2(130, 30);

    // Align the button's exact center to our bar_center_y
    ImGui::SetCursorPos(
        ImVec2(start_pos.x + 140.0f, bar_center_y - (tab_size.y * 0.5f)));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);

    // TAB 1: Live Capture
    bool is_live_active = (active_tab == 0);
    if (is_live_active) {
      if (is_dark_mode) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                              ImVec4(0.1f, 0.1f, 0.1f, 0.5f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
      } else {
        ImGui::PushStyleColor(ImGuiCol_Button,
                              ImVec4(0.40f, 0.40f, 0.42f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                              ImVec4(0.45f, 0.45f, 0.48f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                              ImVec4(0.40f, 0.40f, 0.42f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
      }
    } else {
      ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
      ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                            is_dark_mode ? ImVec4(0.15f, 0.15f, 0.15f, 0.5f)
                                         : ImVec4(0.85f, 0.85f, 0.85f, 0.5f));
      ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0, 0, 0, 0));
      ImGui::PushStyleColor(ImGuiCol_Text,
                            is_dark_mode ? ImVec4(0.5f, 0.5f, 0.55f, 1.0f)
                                         : ImVec4(0.4f, 0.4f, 0.45f, 1.0f));
    }
    if (ImGui::Button("Live Capture", tab_size))
      active_tab = 0;
    if (ImGui::IsItemHovered())
      ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    ImGui::PopStyleColor(4);

    // TAB 2: PCAP Replay
    // We explicitly set the cursor again to prevent SameLine() from drooping
    // the baseline
    ImGui::SetCursorPos(ImVec2(start_pos.x + 140.0f + tab_size.x + 8.0f,
                               bar_center_y - (tab_size.y * 0.5f)));

    bool is_replay_active = (active_tab == 1);
    if (is_replay_active) {
      if (is_dark_mode) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                              ImVec4(0.1f, 0.1f, 0.1f, 0.5f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
      } else {
        ImGui::PushStyleColor(ImGuiCol_Button,
                              ImVec4(0.40f, 0.40f, 0.42f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                              ImVec4(0.45f, 0.45f, 0.48f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                              ImVec4(0.40f, 0.40f, 0.42f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
      }
    } else {
      ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
      ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                            is_dark_mode ? ImVec4(0.15f, 0.15f, 0.15f, 0.5f)
                                         : ImVec4(0.85f, 0.85f, 0.85f, 0.5f));
      ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0, 0, 0, 0));
      ImGui::PushStyleColor(ImGuiCol_Text,
                            is_dark_mode ? ImVec4(0.5f, 0.5f, 0.55f, 1.0f)
                                         : ImVec4(0.4f, 0.4f, 0.45f, 1.0f));
    }
    if (ImGui::Button("PCAP Replay", tab_size))
      active_tab = 1;
    if (ImGui::IsItemHovered())
      ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    ImGui::PopStyleColor(4);

    ImGui::PopStyleVar(); // Pop FrameRounding

    // --- DARK/LIGHT MODE TOGGLE (Far Right) ---
    float toggle_height = ImGui::GetFrameHeight() * 0.85f;

    // Set Toggle Switch centered on the Y-axis
    ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 120.0f,
                               bar_center_y - (toggle_height * 0.5f)));
    RenderToggleButton("##dark_toggle", &is_dark_mode);
    if (ImGui::IsItemClicked()) {
      ApplyTheme(is_dark_mode);
    }

    // Set Text centered on the Y-axis
    ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 65.0f,
                               bar_center_y - text_half_height));
    ImGui::PushStyleColor(ImGuiCol_Text,
                          is_dark_mode ? ImVec4(1.0f, 1.0f, 1.0f, 1.0f)
                                       : ImVec4(0.15f, 0.15f, 0.15f, 1.0f));
    ImGui::Text("%s", is_dark_mode ? "Dark" : "Light");
    ImGui::PopStyleColor();

    // Line separator beneath the header
    ImGui::SetCursorPos(ImVec2(start_pos.x, start_pos.y + 34.0f));
    ImGui::Separator();

    // Render the active tab content
    if (active_tab == 0) {
      tab_live::Render();
    } else {
      tab_replay::Render();
    }

    ImGui::End();

    ImGui::Render();
    int display_w, display_h;
    glfwGetFramebufferSize(window, &display_w, &display_h);
    glViewport(0, 0, display_w, display_h);
    if (is_dark_mode) {
      glClearColor(0.08f, 0.08f, 0.09f, 1.00f);
    } else {
      glClearColor(0.95f, 0.95f, 0.96f, 1.00f);
    }
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    glfwSwapBuffers(window);
  }

  engine_runner::ShutdownEngine();

  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplGlfw_Shutdown();
  ImPlot::DestroyContext();
  ImGui::DestroyContext();

  glfwDestroyWindow(window);
  glfwTerminate();

  return 0;
}
