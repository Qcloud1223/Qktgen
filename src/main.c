#include "Qktgen.h"
// optarg is complaining...
#include <getopt.h>

// handle error options and print usage
void usage(char erropt)
{
    if (erropt != '\0')
        fprintf(stderr, "Qktgen: unknown option -%c\n", erropt);
    printf("-f PCAP_FILE: replay from a packet capture file\n"
    "   - if not specified, packets will be generated randomly\n"
    "-t PKT_TYPE: generate certain type of packets,"
    "supported types are: tcp udp\n"
    "-p PORTMASK: bitmask of available ports\n"
    );
}

void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM)
    {
        fflush(stdout);
        fflush(stderr);
        if (force_quit)
        {
            printf("Exit ungracefully now, should check for blocking/looping in code.\n");
            abort();
        }
        printf("Signal %d received, preparing to exit...\n",
               signum);
        force_quit = true;
    }
}

void parse_arg(int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "f:t:p:")) != -1) {
        switch (opt)
        {
        case 'f':
            printf("using pcap: %s\n", optarg);
            break;
        
        case 't':
            printf("using packet type: %s\n", optarg);
            break;

        case 'p':
            printf("using port mask: %s\n", optarg);
            break;

        default:
            break;
        }
    }
}

void main_send_loop(struct traffic_config *t_conf)
{
    // TODO: dynamic sizing according to buffer time
    struct rte_mbuf *pkt_burst[32];
    uint16_t port_id = 0;
    uint16_t queue_id = 0;

    uint64_t prev_tsc, curr_tsc;
    uint64_t tsc_hz = rte_get_tsc_hz();
    prev_tsc = rte_rdtsc();

    static uint64_t prof_pps, prof_bps;
    while (!force_quit)
    {
        uint16_t nb_gen = pktgen(t_conf, pkt_burst, 32);
        if (nb_gen == 0)
            continue;
        uint16_t nb_tx  = rte_eth_tx_burst(port_id, queue_id, pkt_burst, nb_gen);
        prof_pps += nb_tx;
        for(int i = 0; i < nb_tx; i++) {
            prof_bps += rte_pktmbuf_pkt_len(pkt_burst[i]) * 8;
        }

        // TODO: move to another core since printf might cause jitter in tx core
        curr_tsc = rte_rdtsc();
        if (unlikely((curr_tsc - prev_tsc) > tsc_hz * 1)) {
            double interval = (double)1 * (curr_tsc - prev_tsc) / tsc_hz;
            printf("Core #%d: %fMpps, %fMbps\n", rte_lcore_id(), (double)prof_pps / interval / 1e6, (double)prof_bps / interval / 1e6);
            prof_pps = 0;
            prof_bps = 0;
            prev_tsc = curr_tsc;
        }
    }
    
}

int main(int argc, char *argv[])
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    // parse_arg(argc, argv);
    // signal(SIGINT, signal_handler);
    // signal(SIGTERM, signal_handler);
    init_dpdk();

    struct traffic_config t_conf = {
        .sip_l = 0xc0a80001,
        .sip_h = 0xc0a80001,
        .dip_l = 0xc0a80002,
        .dip_h = 0xc0a80002,
        .sport_l = 12340,
        .sport_h = 23450,
        .dport_l = 34560,
        .dport_h = 34560,
        .proto = IPPROTO_TCP
    };
    unsigned char smac[6] = {0x00, 0x1b, 0x21, 0xbb, 0xf2, 0x38}, dmac[6] = {0x90, 0xe2, 0xba, 0x8a, 0xfe, 0x08};
    memcpy(&t_conf.smac, smac, 6);
    memcpy(&t_conf.dmac, dmac, 6);
    
    char ip_p[INET_ADDRSTRLEN];
    printf("sip: %s -- ", inet_ntop(AF_INET, &t_conf.sip_l, ip_p, INET_ADDRSTRLEN));
    printf("%s\n", inet_ntop(AF_INET, &t_conf.sip_h, ip_p, INET_ADDRSTRLEN));
    printf("dip: %s -- ", inet_ntop(AF_INET, &t_conf.dip_l, ip_p, INET_ADDRSTRLEN));
    printf("%s\n", inet_ntop(AF_INET, &t_conf.dip_h, ip_p, INET_ADDRSTRLEN));
    printf("sport: %" PRIu16 " -- %" PRIu16 "\n", t_conf.sport_l, t_conf.sport_h);
    printf("dport: %" PRIu16 " -- %" PRIu16 "\n", t_conf.dport_l, t_conf.dport_h);
    printf("state space: %lu\n", 1UL*(t_conf.sip_h - t_conf.sip_l + 1) * 
        (t_conf.dip_h - t_conf.dip_l + 1) * 
        (t_conf.sport_h - t_conf.sport_l + 1) * 
        (t_conf.dport_h - t_conf.dport_l + 1));

    main_send_loop(&t_conf);

    return 0;
}