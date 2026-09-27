#pragma once
#include <pcap.h>
#include <string>

/* @brief Dynamically loads wpcap.dll (Windows) or libpcap.so (Linux) and
 * resolves capture runtime function pointers */
bool load_npcap_dll();

/* @brief Discovers and returns the system identifier of the first active
 * network interface */
std::string get_first_active_interface();

/* @brief Dynamic function pointer to pcap_open_live */
extern pcap_t *(*dyn_pcap_open_live)(const char *, int, int, int, char *);

/* @brief Dynamic function pointer to pcap_compile */
extern int (*dyn_pcap_compile)(pcap_t *, struct bpf_program *, const char *,
                               int, bpf_u_int32);

/* @brief Dynamic function pointer to pcap_setfilter */
extern int (*dyn_pcap_setfilter)(pcap_t *, struct bpf_program *);

/* @brief Dynamic function pointer to pcap_freecode */
extern void (*dyn_pcap_freecode)(struct bpf_program *);

/* @brief Dynamic function pointer to pcap_loop */
extern int (*dyn_pcap_loop)(pcap_t *, int, pcap_handler, u_char *);

/* @brief Dynamic function pointer to pcap_breakloop */
extern void (*dyn_pcap_breakloop)(pcap_t *);

/* @brief Dynamic function pointer to pcap_close */
extern void (*dyn_pcap_close)(pcap_t *);

/* @brief Dynamic function pointer to pcap_stats */
extern int (*dyn_pcap_stats)(pcap_t *, struct pcap_stat *);

/* @brief Dynamic function pointer to pcap_findalldevs */
extern int (*dyn_pcap_findalldevs)(pcap_if_t **, char *);

/* @brief Dynamic function pointer to pcap_freealldevs */
extern void (*dyn_pcap_freealldevs)(pcap_if_t *);
