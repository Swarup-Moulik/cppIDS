cmake_minimum_required(VERSION 3.20)
project(cppIDS VERSION 1.0.0 LANGUAGES CXX C) # C language required to build GLFW

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-Wall -Wextra -Wpedantic -O3)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_link_options(-fuse-ld=lld) # Use LLVM's linker to support LTO
  endif()
elseif(MSVC)
  add_compile_options(/W4 /O2)
endif()

# We only need the headers since wpcap.dll/libpcap.so is loaded dynamically
find_path(PCAP_INCLUDE_DIR pcap.h)
if(NOT PCAP_INCLUDE_DIR)
  message(FATAL_ERROR "pcap.h not found. Ensure Npcap SDK / libpcap-dev is installed and in your PATH.")
endif()

include_directories(src utils ${PCAP_INCLUDE_DIR})

# ==========================================
# 0. Dependencies via FetchContent
# ==========================================
include(FetchContent)

# Silence the FetchContent_Populate deprecation warnings
if(POLICY CMP0169)
  cmake_policy(SET CMP0169 OLD)
endif()

# Fetch and build GLFW (MakeAvailable is fine here because GLFW's CMake is modern)
FetchContent_Declare(glfw GIT_REPOSITORY https://github.com/glfw/glfw.git GIT_TAG 3.4)
set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(glfw)

# Fetch Dear ImGui, ImPlot, and Portable File Dialogs (Source ONLY via Populate)
FetchContent_Declare(imgui GIT_REPOSITORY https://github.com/ocornut/imgui.git GIT_TAG v1.90.4)
FetchContent_GetProperties(imgui)
if(NOT imgui_POPULATED)
  FetchContent_Populate(imgui)
endif()

FetchContent_Declare(implot GIT_REPOSITORY https://github.com/epezent/implot.git GIT_TAG v0.16)
FetchContent_GetProperties(implot)
if(NOT implot_POPULATED)
  FetchContent_Populate(implot)
endif()

FetchContent_Declare(pfd GIT_REPOSITORY https://github.com/samhocevar/portable-file-dialogs.git GIT_TAG main)
FetchContent_GetProperties(pfd)
if(NOT pfd_POPULATED)
  FetchContent_Populate(pfd)
endif()

# Find native OpenGL (provided by OS / Windows SDK)
find_package(OpenGL REQUIRED)

# ==========================================
# 1. Source File Management
# ==========================================
file(GLOB_RECURSE CORE_SOURCES
    "src/alerting/*.cpp"
    "src/capture/*.cpp"
    "src/core/*.cpp"
    "src/detection/*.cpp"
    "src/features/*.cpp"
    "src/neuromorphic/*.cpp"
)

# ==========================================
# 2. Main IDS Daemon (CLI)
# ==========================================
add_executable(cppids src/main_cli.cpp ${CORE_SOURCES})

# ==========================================
# 3. Benchmark Evaluation Harness
# ==========================================
add_executable(eval_harness tests/evaluation_harness.cpp ${CORE_SOURCES})

# ==========================================
# 4. Telemetry Dashboard (GUI)
# ==========================================
file(GLOB_RECURSE GUI_SOURCES CONFIGURE_DEPENDS "src/gui/*.cpp")

add_executable(cppids_gui
    src/main_gui.cpp
    ${GUI_SOURCES}
    ${CORE_SOURCES}
    # ImGui source files
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
    # ImPlot source files
    ${implot_SOURCE_DIR}/implot.cpp
    ${implot_SOURCE_DIR}/implot_items.cpp
)

target_include_directories(cppids_gui PRIVATE
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
    ${implot_SOURCE_DIR}
    ${pfd_SOURCE_DIR}
)

# ==========================================
# 5. OS-Specific Linking
# ==========================================
target_link_libraries(cppids_gui PRIVATE glfw OpenGL::GL)

if(WIN32)
  target_link_libraries(cppids PRIVATE psapi pcap)
  target_link_libraries(eval_harness PRIVATE psapi pcap)
  target_link_libraries(cppids_gui PRIVATE psapi pcap)
elseif(UNIX AND NOT APPLE)
  target_link_libraries(cppids PRIVATE dl pcap)
  target_link_libraries(eval_harness PRIVATE dl pcap)
  target_link_libraries(cppids_gui PRIVATE dl pcap)
endif()

# ==========================================
# 6. Generate LLVM IR (.ll) Target
# ==========================================
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_custom_target(emit_ir
        COMMAND ${CMAKE_CXX_COMPILER} -S -emit-llvm
                -std=c++20 -O3
                -I${CMAKE_SOURCE_DIR}/src
                -I${PCAP_INCLUDE_DIR}
                ${CORE_SOURCES} ${CMAKE_SOURCE_DIR}/src/main_cli.cpp
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Generating .ll files in the build directory..."
    )
endif()
