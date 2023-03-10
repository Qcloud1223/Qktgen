#ifndef QKTGEN_HEADER
#define QKTGEN_HEADER

// for u_char in pcap.h
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <netinet/in.h>
#include <signal.h>
#include <pcap.h>

#include <rte_ethdev.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <rte_malloc.h>

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#ifdef __cplusplus
extern "C" {
#endif
struct pkt_config
{
    // config for single packet
    uint16_t length;
    
    struct rte_ether_addr smac;
    struct rte_ether_addr dmac;

    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    uint8_t proto;
};

enum flow_aggregation_pattern {
    FLOW_AGGREGATE_NONE,
    FLOW_AGGREGATE_SOURCE,
    FLOW_AGGREGATE_DEST,
    FLOW_AGGREGATE_FULL
};

// TODO: allow distribution
struct traffic_config
{
    // TODO: use one argument to generate range traffic, instead of a bunch of them
    // uint32_t active_flows;
    
    struct rte_ether_addr smac;
    struct rte_ether_addr dmac;

    uint32_t sip_l, sip_h, dip_l, dip_h;
    uint16_t sport_l, sport_h, dport_l, dport_h;
    uint8_t proto;

    enum flow_aggregation_pattern pattern;
    /* flow aggregation needs a buffer time, i.e. max time for sorting
       For example, if the traffic comes in 5M pps, and buffer for 100us,
       then we ensure every 500 packets are aggregated by certain field. 
       
       This is useful when we want a fair comparison between different 
       aggregation plans: if we promise the indentical packet pools,
       with the same buffer time we can compare the plans
       */
    uint16_t buffer_time;
    uint64_t seed;

    const char *pcap_path;
    uint16_t buffer_number;
};

struct flow_config
{
    uint32_t pps;
};

struct rte_mempool *glb_pkt_pool;
struct rte_eth_dev_tx_buffer *tx_buffer;
int force_quit;
uint64_t packet_dropped;

void init_dpdk();
uint32_t pktgen(struct traffic_config *, struct rte_mbuf **, uint16_t);
uint16_t do_tx(struct traffic_config *, uint16_t, uint16_t, struct rte_mbuf **, uint16_t);
void sort_packets(struct rte_mbuf **buf, uint32_t len, enum flow_aggregation_pattern p);

#ifdef __cplusplus
}
#endif
#endif