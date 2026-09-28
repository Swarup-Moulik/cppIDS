#include "pcap_wrapper.h"
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

// Dynamic function pointers for Npcap/libpcap runtime resolution
pcap_t *(*dyn_pcap_open_live)(const char *, int, int, int, char *) = nullptr;
int (*dyn_pcap_compile)(pcap_t *, struct bpf_program *, const char *, int,
                        bpf_u_int32) = nullptr;
int (*dyn_pcap_setfilter)(pcap_t *, struct bpf_program *) = nullptr;
void (*dyn_pcap_freecode)(struct bpf_program *) = nullptr;
int (*dyn_pcap_loop)(pcap_t *, int, pcap_handler, u_char *) = nullptr;
void (*dyn_pcap_breakloop)(pcap_t *) = nullptr;
void (*dyn_pcap_close)(pcap_t *) = nullptr;
int (*dyn_pcap_stats)(pcap_t *, struct pcap_stat *) = nullptr;
int (*dyn_pcap_findalldevs)(pcap_if_t **, char *) = nullptr;
void (*dyn_pcap_freealldevs)(pcap_if_t *) = nullptr;

/* @brief Dynamically loads wpcap.dll (Windows) or libpcap.so (Linux) and
 * maps function pointers */
bool load_npcap_dll() {
  static bool initialized = false;
  if (initialized)
    return true;

#ifdef _WIN32
  // Attempt to load wpcap.dll from the default dynamic library search path
  HMODULE hModule = LoadLibraryA("wpcap.dll");
  if (!hModule) {
    // If not found, look inside the default Npcap system folder
    SetDllDirectoryA("C:\\Windows\\System32\\Npcap");
    hModule = LoadLibraryA("wpcap.dll");
    SetDllDirectoryA(NULL);
  }

  // Abort initialization if Npcap runtime libraries are missing
  if (!hModule) {
    std::cerr << "[FATAL] Could not load wpcap.dll. Is Npcap installed?"
              << std::endl;
    return false;
  }

  // Resolve and map exported capture symbols to their dynamic function pointers
  dyn_pcap_open_live = (decltype(dyn_pcap_open_live))(void *)GetProcAddress(
      hModule, "pcap_open_live");
  dyn_pcap_compile = (decltype(dyn_pcap_compile))(void *)GetProcAddress(
      hModule, "pcap_compile");
  dyn_pcap_setfilter = (decltype(dyn_pcap_setfilter))(void *)GetProcAddress(
      hModule, "pcap_setfilter");
  dyn_pcap_freecode = (decltype(dyn_pcap_freecode))(void *)GetProcAddress(
      hModule, "pcap_freecode");
  dyn_pcap_loop =
      (decltype(dyn_pcap_loop))(void *)GetProcAddress(hModule, "pcap_loop");
  dyn_pcap_breakloop = (decltype(dyn_pcap_breakloop))(void *)GetProcAddress(
      hModule, "pcap_breakloop");
  dyn_pcap_close =
      (decltype(dyn_pcap_close))(void *)GetProcAddress(hModule, "pcap_close");
  dyn_pcap_stats =
      (decltype(dyn_pcap_stats))(void *)GetProcAddress(hModule, "pcap_stats");
  dyn_pcap_findalldevs = (decltype(dyn_pcap_findalldevs))(void *)GetProcAddress(
      hModule, "pcap_findalldevs");
  dyn_pcap_freealldevs = (decltype(dyn_pcap_freealldevs))(void *)GetProcAddress(
      hModule, "pcap_freealldevs");
#else
  // Attempt to load libpcap.so from standard dynamic library paths
  void *hModule = dlopen("libpcap.so.1", RTLD_LAZY);
  if (!hModule) {
    hModule = dlopen("libpcap.so", RTLD_LAZY);
  }

  // Abort initialization if libpcap runtime library is missing
  if (!hModule) {
    std::cerr << "[FATAL] Could not load libpcap.so. Is libpcap-dev installed?"
              << std::endl;
    return false;
  }

  // Resolve and map exported capture symbols to their dynamic function pointers
  dyn_pcap_open_live =
      (decltype(dyn_pcap_open_live))dlsym(hModule, "pcap_open_live");
  dyn_pcap_compile = (decltype(dyn_pcap_compile))dlsym(hModule, "pcap_compile");
  dyn_pcap_setfilter =
      (decltype(dyn_pcap_setfilter))dlsym(hModule, "pcap_setfilter");
  dyn_pcap_freecode =
      (decltype(dyn_pcap_freecode))dlsym(hModule, "pcap_freecode");
  dyn_pcap_loop = (decltype(dyn_pcap_loop))dlsym(hModule, "pcap_loop");
  dyn_pcap_breakloop =
      (decltype(dyn_pcap_breakloop))dlsym(hModule, "pcap_breakloop");
  dyn_pcap_close = (decltype(dyn_pcap_close))dlsym(hModule, "pcap_close");
  dyn_pcap_stats = (decltype(dyn_pcap_stats))dlsym(hModule, "pcap_stats");
  dyn_pcap_findalldevs =
      (decltype(dyn_pcap_findalldevs))dlsym(hModule, "pcap_findalldevs");
  dyn_pcap_freealldevs =
      (decltype(dyn_pcap_freealldevs))dlsym(hModule, "pcap_freealldevs");
#endif

  // Verify that mandatory capture functions are resolved
  if (!dyn_pcap_open_live || !dyn_pcap_findalldevs) {
    std::cerr
        << "[FATAL] Capture library is missing required capture functions."
        << std::endl;
    return false;
  }

  initialized = true;
  return true;
}

/* @brief Discovers and returns the system identifier of the first active
 * network interface */
std::string get_first_active_interface() {
  // Ensure the capture library is loaded before device discovery
  if (!load_npcap_dll())
    return "";

  pcap_if_t *alldevs;
  char errbuf[PCAP_ERRBUF_SIZE];

  // Enumerate all available network devices on the host machine
  if (dyn_pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == nullptr) {
    std::cerr << "[PCAP ERROR] Could not find devices: " << errbuf << std::endl;
    return "";
  }

  // Select the first valid interface device identifier
  std::string dev_name = alldevs->name;

  std::cout << "[SYSTEM] Auto-discovered network interface: ";
  if (alldevs->description) {
    std::cout << alldevs->description << " ";
  }
  std::cout << "(" << dev_name << ")\n";

  // Free the device list allocated by pcap_findalldevs
  dyn_pcap_freealldevs(alldevs);
  return dev_name;
}
