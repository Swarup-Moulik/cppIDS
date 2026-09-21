cmake_minimum_required(VERSION 3.20)
project(cppIDS VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-Wall -Wextra -Wpedantic -O3 -flto)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
      add_link_options(-fuse-ld=lld) # Use LLVM's linker to support LTO
  endif()
elseif(MSVC)
  add_compile_options(/W4 /O2 /GL)
endif()

# We only need the headers since wpcap.dll is loaded dynamically
find_path(PCAP_INCLUDE_DIR pcap.h)
if(NOT PCAP_INCLUDE_DIR)
  message(FATAL_ERROR "pcap.h not found. Ensure Npcap SDK is installed and in your PATH.")
endif()

include_directories(src utils ${PCAP_INCLUDE_DIR})

# Grab all core files, but exclude main.cpp to prevent duplicate main() definitions
file(GLOB_RECURSE CORE_SOURCES "src/*.cpp")
list(FILTER CORE_SOURCES EXCLUDE REGEX "src/main\\.cpp$")

# ==========================================
# 1. Main IDS Daemon
# ==========================================
add_executable(cppids src/main.cpp ${CORE_SOURCES})

# ==========================================
# 2. Benchmark Evaluation Harness
# ==========================================
add_executable(eval_harness tests/evaluation_harness.cpp ${CORE_SOURCES})

# Link psapi for Windows RAM usage tracking, and pcap for the evaluation harness
if(WIN32)
  target_link_libraries(cppids PRIVATE psapi)
  target_link_libraries(eval_harness PRIVATE psapi pcap)
endif()

# ==========================================
# 3. Generate LLVM IR (.ll) Target
# ==========================================
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_custom_target(emit_ir
        # Force Clang to output LLVM IR instead of machine code
        COMMAND ${CMAKE_CXX_COMPILER} -S -emit-llvm
                -std=c++20 -O3
                -I${CMAKE_SOURCE_DIR}/src
                -I${PCAP_INCLUDE_DIR}
                ${CORE_SOURCES} ${CMAKE_SOURCE_DIR}/src/main.cpp
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Generating .ll files in the build directory..."
    )
endif()
