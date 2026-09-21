#include "pcap_wrapper.h"
#include <iostream>
#include <windows.h>

// Initialize pointers
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

bool load_npcap_dll() {
  static bool initialized = false;
  if (initialized)
    return true;

  HMODULE hModule = LoadLibraryA("wpcap.dll");
  if (!hModule) {
    SetDllDirectoryA("C:\\Windows\\System32\\Npcap");
    hModule = LoadLibraryA("wpcap.dll");
    SetDllDirectoryA(NULL);
  }

  if (!hModule) {
    std::cerr << "[FATAL] Could not load wpcap.dll. Is Npcap installed?"
              << std::endl;
    return false;
  }

  // Map the function pointers using an intermediate (void*) cast to silence
  // MinGW warnings
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

  if (!dyn_pcap_open_live || !dyn_pcap_findalldevs) {
    std::cerr << "[FATAL] wpcap.dll is missing required capture functions."
              << std::endl;
    return false;
  }

  initialized = true;
  return true;
}

std::string get_first_active_interface() {
  if (!load_npcap_dll())
    return "";

  pcap_if_t *alldevs;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (dyn_pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == nullptr) {
    std::cerr << "[PCAP ERROR] Could not find devices: " << errbuf << std::endl;
    return "";
  }

  std::string dev_name =
      alldevs
          ->name; // Grabs the first valid interface (e.g., \Device\NPF_{...})

  std::cout << "[SYSTEM] Auto-discovered network interface: ";
  if (alldevs->description) {
    std::cout << alldevs->description << " ";
  }
  std::cout << "(" << dev_name << ")\n";

  dyn_pcap_freealldevs(alldevs);
  return dev_name;
}
