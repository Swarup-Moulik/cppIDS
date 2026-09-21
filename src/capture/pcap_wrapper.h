#pragma once
#include <pcap.h>
#include <string>

bool load_npcap_dll();
std::string get_first_active_interface();

// Expose dynamic function pointers
extern pcap_t *(*dyn_pcap_open_live)(const char *, int, int, int, char *);
extern int (*dyn_pcap_compile)(pcap_t *, struct bpf_program *, const char *,
                               int, bpf_u_int32);
extern int (*dyn_pcap_setfilter)(pcap_t *, struct bpf_program *);
extern void (*dyn_pcap_freecode)(struct bpf_program *);
extern int (*dyn_pcap_loop)(pcap_t *, int, pcap_handler, u_char *);
extern void (*dyn_pcap_breakloop)(pcap_t *);
extern void (*dyn_pcap_close)(pcap_t *);
extern int (*dyn_pcap_stats)(pcap_t *, struct pcap_stat *);
extern int (*dyn_pcap_findalldevs)(pcap_if_t **, char *);
extern void (*dyn_pcap_freealldevs)(pcap_if_t *);
