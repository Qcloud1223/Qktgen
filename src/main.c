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

struct
{
    const char *pcap_path;
    uint8_t proto;
    unsigned portmask;
} qktgen_buf;

void parse_arg(int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "f:t:p:")) != -1) {
        switch (opt)
        {
        case 'f':
            printf("using pcap: %s\n", optarg);
            qktgen_buf.pcap_path = optarg;
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

/* convert an mbuf to readable packet,
   which is extremely useful when debugging */
static void debug_print(struct rte_mbuf *pkt)
{
    struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

    char ip_p[INET_ADDRSTRLEN];
    printf("sip: %s, ", inet_ntop(AF_INET, &ip_hdr->src_addr, ip_p, INET_ADDRSTRLEN));
    fflush(stdout);
    printf("dip: %s, ", inet_ntop(AF_INET, &ip_hdr->dst_addr, ip_p, INET_ADDRSTRLEN));
    fflush(stdout);
    printf("sport: %u, dport: %u, length: %u\n", rte_cpu_to_be_16(tcp_hdr->src_port), rte_cpu_to_be_16(tcp_hdr->dst_port), pkt->data_len);
}

// TODO: check if this is large enough to prevent overflow
#define SEND_BUF_SIZE (8*1024)
static struct rte_mbuf *send_buf[SEND_BUF_SIZE];
/* counter of sorted packets */
static volatile uint64_t finish_idx;
static volatile uint64_t last_tx;

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

#define MAX_SEND_BURST 32
static void sender_loop()
{
    // FIXME
    uint16_t port_id = 0;
    uint16_t queue_id = 0;

    uint64_t prev_tsc, curr_tsc;
    uint64_t tsc_hz = rte_get_tsc_hz();

    static uint64_t prof_pps, prof_bps;
    unsigned lcore_id = rte_lcore_id();

    printf("lcore#%u entering sender loop\n", lcore_id);
    prev_tsc = rte_rdtsc();
    while (!force_quit) {
        /* busy waiting for available packets */
        if (last_tx >= finish_idx) {
            continue;
        }
        uint64_t gap = finish_idx - last_tx;
        uint16_t real_idx = last_tx % SEND_BUF_SIZE;
        uint16_t real_send_size = (gap > MAX_SEND_BURST) ? MAX_SEND_BURST : (uint16_t)gap;

        /* send packets from global send buffer.
           Note that in send side we want best performance, therefore we don't copy descriptors. */
        uint16_t nb_tx = 0;
        if (real_idx + real_send_size <= SEND_BUF_SIZE) {
            nb_tx = rte_eth_tx_burst(port_id, queue_id, send_buf + real_idx, real_send_size);
            if (unlikely(nb_tx != real_send_size)) {
                /* The CPU would send much faster than the NIC when it's slow (e.g., 10G)
                   Therefore, sometimes the tx queue is full and the sender should wait for it,
                   since we don't want to drop any packet.
                   This happens when the worker has prepared a whole lot of packets
                   before the sender can start. When the sender starts sending,
                   it will immediately take up the whole tx queue.
                   This branch will never be executed under 100G NIC but very frequently under 10G one,
                   yet both of them are resolved when the worker becomes bottleneck. */
                
                // printf("port cannot TX, full queue?\n");
                // printf("stats: last_tx: %lu, finish_idx: %lu, gap: %lu, real_idx: %u, real_send_size:%u, actually sent: %u\n",
                //     last_tx, finish_idx, gap, real_idx, real_send_size, nb_tx);
                // printf("faulty mbuf pointers:\n");
                // for (int i = 0; i < real_send_size; i++){
                //     printf("%p, pkt_len: %u\n", *(send_buf + real_idx + i), send_buf[real_idx + i]->pkt_len);
                // }
                // exit(-1);
                rte_delay_us_block(160);
            }
            for(int i = 0; i < nb_tx; i++) {
                prof_bps += rte_pktmbuf_pkt_len(*(send_buf + real_idx + i)) * 8;
            }
        }
        /* rewind */
        else {
            int i, j;
            nb_tx += rte_eth_tx_burst(port_id, queue_id, send_buf + real_idx, SEND_BUF_SIZE - real_idx);
            for(i = 0; i < nb_tx; i++) {
                prof_bps += rte_pktmbuf_pkt_len(*(send_buf + real_idx + i)) * 8;
            }
            nb_tx += rte_eth_tx_burst(port_id, queue_id, send_buf, real_send_size - (SEND_BUF_SIZE - real_idx));
            for(j = 0; j < nb_tx - i; j++) {
                prof_bps += rte_pktmbuf_pkt_len(*(send_buf + j)) * 8;
            }
        }

        last_tx += nb_tx;
        prof_pps += nb_tx;

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

/* read packets and sort them */
static void worker_loop(struct traffic_config *t_conf)
{
    unsigned lcore_id = rte_lcore_id();
    uint16_t buffer_number = t_conf->buffer_number;
    struct rte_mbuf **sort_buf = malloc(buffer_number * sizeof(struct rte_mbuf *));
    static uint32_t buf_idx;
    int ret;
    
    printf("lcore #%u entering worker loop\n", lcore_id);
    while (!force_quit) {
        /* Though not that possible, during debug we may run the sender loop real slow.
           Rewind can only happen when the worker (sorter) is SEND_BUF_SIZE away,
           AND the sender has finished its own buffer number */
        if (unlikely(last_tx + SEND_BUF_SIZE - buffer_number <= finish_idx)) {
            rte_delay_us_block(10);
            continue;
        }

        ret = rte_pktmbuf_alloc_bulk(glb_pkt_pool, sort_buf, buffer_number);
        if (ret) {
            /* not enough mbuf for a bulk, busy wait.
               TODO: check if polling a mempool will bring problem */
            rte_delay_us_block(10);
            continue;
        }

        for (int i = 0; i < buffer_number; i++) {
            struct rte_mbuf *pkt = sort_buf[i];
            struct pcap_pkthdr* pcap_hdr;
            const u_char *pkt_data;
            int ret;
        try:
            ret = pcap_next_ex(t_conf->handle, &pcap_hdr, &pkt_data);
            /* no more packets to read, maybe open rewind the pcap */
            if (unlikely (ret == PCAP_ERROR_BREAK)) {
                printf("reaching the end of packet capture!\n");
                FILE *pcap_fp = pcap_file(t_conf->handle);
                /* FIXME: though runs w/o any problem, we cannot simply assume
                   SEEK_SET points exactly to where pcap_next_ex can recognize.
                   So a better approach should record the offset before any packet is processed. */
                fseek(pcap_fp, 0, SEEK_SET);
                goto try;
            }
            if (unlikely (ret == PCAP_ERROR)) {
                printf("generic error when reading packets, worker exit\n");
                return;
            }

            char *mbuf_data = rte_pktmbuf_mtod(pkt, char *);
            memcpy(mbuf_data, pkt_data, pcap_hdr->len);

            pkt->pkt_len = pcap_hdr->len;
            pkt->data_len = pcap_hdr->len;
            
            struct rte_ether_hdr *e_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
            if (likely(e_hdr->ether_type == RTE_ETHER_TYPE_IPV4)) {
                struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
                switch (ip_hdr->next_proto_id) {
                    case IPPROTO_TCP:
                        pkt->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
                        break;
                    case IPPROTO_UDP:
                        pkt->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
                        break;
                    default:
                        pkt->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
                }
            }
            // TODO: mac address
        }

        sort_packets(sort_buf, buffer_number, t_conf->pattern);
        // printf("=======finish sorting=======\n");
        // for (int i = 0; i < buffer_number; i++)
        //     debug_print(sort_buf[i]);

        // unlock it for the send core
        // TODO: prevent copy if it is slow
        // TODO: extend to multi-core
        uint16_t real_idx = finish_idx % SEND_BUF_SIZE;
        if (real_idx + buffer_number < SEND_BUF_SIZE) {
            memcpy(send_buf + real_idx, sort_buf, sizeof(struct rte_mbuf *) * buffer_number);
            
            // printf("[Worker #%u] filling: %d -- %d\n", rte_lcore_id(), real_idx, real_idx + buffer_number);
            // printf("=======finish copying=======\n");
            // for (int i = 0; i < buffer_number; i++)
            //     debug_print(send_buf[i] + real_idx);
            // fflush(stdout);
        }
        else {
            /* rewind ring buffer */
            uint32_t remain = SEND_BUF_SIZE - real_idx;
            memcpy(send_buf + real_idx, sort_buf, sizeof(struct rte_mbuf *) * remain);
            memcpy(send_buf, sort_buf + remain, sizeof(struct rte_mbuf *) * (buffer_number - remain));
            
            // printf("[Worker #%u] filling: %d -- %d(rewind)\n", rte_lcore_id(), real_idx, buffer_number-remain);
        }
        /* finish idx is non-descending */
        finish_idx += buffer_number;
    }
}

static int worker_loop_wrapper(void *arg)
{
    worker_loop(arg);

    return 0;
}

int main(int argc, char *argv[])
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    parse_arg(argc, argv);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
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

    char errbuf[1000];
    pcap_t *handle = pcap_open_offline(qktgen_buf.pcap_path, errbuf);
    if (handle == NULL) {
        exit(-1);
    }
    
    t_conf.handle = handle;
    // FIXME
    t_conf.buffer_number = 1024;

    rte_eal_mp_remote_launch(worker_loop_wrapper, &t_conf, SKIP_MAIN);
    
    sender_loop();

    unsigned lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id){
        if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
    }

    return 0;
}