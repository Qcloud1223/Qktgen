#include "Qktgen.h"

// #include <iostream>
#include <random>
#include <unordered_map>
#include <boost/functional/hash.hpp>
#include <algorithm>

struct five_tuple
{
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    uint8_t proto;

    bool operator==(const five_tuple &other) const{
        return (sip == other.sip &&
                dip == other.dip &&
                sport == other.sport &&
                dport == other.dport &&
                proto == other.proto);
    }
    void operator=(const five_tuple &other)
    {
        this->sip = other.sip;
        this->dip = other.dip;
        this->sport = other.sport;
        this->dport = other.dport;
        this->proto = other.proto;
    }
};

/* careful hashing the five tuple */
template<>
struct std::hash<five_tuple>
{
    std::size_t operator()(five_tuple const &ft) const noexcept
    {
        std::size_t seed = 0;
        if (ft.sip < ft.dip) {
            boost::hash_combine(seed, ft.dip);
            boost::hash_combine(seed, ft.sip);
            boost::hash_combine(seed, ft.dport);
            boost::hash_combine(seed, ft.sport);
        } else {
            boost::hash_combine(seed, ft.sip);
            boost::hash_combine(seed, ft.dip);
            boost::hash_combine(seed, ft.sport);
            boost::hash_combine(seed, ft.dport);
        }
        boost::hash_combine(seed, ft.proto);

        return seed;
    }
};

std::unordered_map<five_tuple, uint32_t> flow_seq;

static void fill_packet(struct rte_mbuf *pkt, struct pkt_config *p_conf)
{
    /* TODO: check if it is bad to leave out mbuf metadata */
    pkt->pkt_len = p_conf->length;
    pkt->data_len = p_conf->length;

    // TODO: use memcpy instead of endless assignment
    /* L2 */
    struct rte_ether_hdr *ether_hdr;
    ether_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    memset(ether_hdr, 0, p_conf->length);
    rte_ether_addr_copy(&p_conf->smac, &ether_hdr->s_addr);
    rte_ether_addr_copy(&p_conf->dmac, &ether_hdr->d_addr);
    ether_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    
    /* L3 */
    struct rte_ipv4_hdr *ip_hdr;
    ip_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    ip_hdr->type_of_service = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live = 64;
    ip_hdr->next_proto_id = p_conf->proto;
    ip_hdr->packet_id = 0;
    ip_hdr->version_ihl = (1 << 6) + 5;
    ip_hdr->total_length = rte_cpu_to_be_16(p_conf->length - sizeof(struct rte_ether_hdr));
    ip_hdr->src_addr = rte_cpu_to_be_32(p_conf->sip);
    ip_hdr->dst_addr = rte_cpu_to_be_32(p_conf->dip);
    ip_hdr->hdr_checksum = 0;

    /* L4 */
    switch (p_conf->proto) {
        case IPPROTO_TCP:
            {
                struct rte_tcp_hdr *tcp_hdr = 
                    rte_pktmbuf_mtod_offset(pkt, struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
                tcp_hdr->data_off = ((sizeof(struct rte_tcp_hdr) / sizeof(uint32_t)) << 4);
                tcp_hdr->src_port = rte_cpu_to_be_16(p_conf->sport);
                tcp_hdr->dst_port = rte_cpu_to_be_16(p_conf->dport);
                // 0x10, ACK
                tcp_hdr->tcp_flags = (1 << 4);
                // steal from pktgen, default arguments
                tcp_hdr->sent_seq = rte_cpu_to_be_32(0x012345678);
                tcp_hdr->recv_ack = rte_cpu_to_be_32(0x012345690);
                tcp_hdr->rx_win = rte_cpu_to_be_16(8192);

                // payload
                char *payload = (char *)(tcp_hdr + 1);
                uint16_t p_len = p_conf->length - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_tcp_hdr);
                memset(payload, 'Q', p_len);

                // offload
                pkt->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;

                // TODO: check if this hurt performance much  
                five_tuple ft;
                ft.sip = p_conf->sip;
                ft.dip = p_conf->dip;
                ft.sport = p_conf->sport;
                ft.dport = p_conf->dport;
                ft.proto = p_conf->proto;

                std::unordered_map<five_tuple, uint32_t>::iterator res;
                if ((res = flow_seq.find(ft)) == flow_seq.end()) {
                    tcp_hdr->sent_seq = rte_cpu_to_be_32(0x012345678);
                    flow_seq.insert(std::make_pair(ft, 0x012345678));
                }
                else {
                    (*res).second += p_len;
                    tcp_hdr->sent_seq = rte_cpu_to_be_32((*res).second);
                }
                break;
            }
        
        case IPPROTO_UDP:
            {
                struct rte_udp_hdr *udp_hdr = 
                    rte_pktmbuf_mtod_offset(pkt, struct rte_udp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
                udp_hdr->src_port = rte_cpu_to_be_16(p_conf->sport);
                udp_hdr->dst_port = rte_cpu_to_be_16(p_conf->dport);
                udp_hdr->dgram_cksum = 0;
                // NB: datagram length include header
                udp_hdr->dgram_len = p_conf->length - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);

                // payload
                char *payload = (char *)(udp_hdr + 1);
                uint16_t p_len = p_conf->length - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_udp_hdr);
                memset(payload, 'Q', p_len);

                // offload
                pkt->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
                break;
            }
        
        default:
            break;
    }
}

std::mt19937 rng;

__attribute__((constructor))
static void init_random_generator()
{
    /* The correct way using 624 bytes of seed */
    // std::random_device rd;
    // std::seed_seq::result_type long_seed[std::mt19937::state_size];
    // std::generate_n(long_seed, std::mt19937::state_size, std::ref(rd));
    // std::seed_seq prng_seed(long_seed, long_seed + std::mt19937::state_size);
    // rng.seed(prng_seed);

    /* The wrong (insufficient seed length) but handy way to seed using time */
    /* Time at 20:36 Feb. 16, 2023 */
    std::seed_seq time_seed{1676551010};
    rng.seed(time_seed);
    // std::cout << "random seed initialized" << std::endl;
    printf("random seed initialized with 1676551010\n");
}

/* read a traffic profile, and then fill in *burst_size* packets */
uint32_t pktgen(struct traffic_config *t_conf, struct rte_mbuf **burst, uint16_t burst_size)
{
    std::uniform_int_distribution<uint32_t> sip(t_conf->sip_l, t_conf->sip_h);
    std::uniform_int_distribution<uint32_t> dip(t_conf->dip_l, t_conf->dip_h);
    std::uniform_int_distribution<uint32_t> sport(t_conf->sport_l, t_conf->sport_h);
    std::uniform_int_distribution<uint32_t> dport(t_conf->dport_l, t_conf->dport_h);

    if (rte_pktmbuf_alloc_bulk(glb_pkt_pool, burst, burst_size)) {
        fprintf(stderr, "cannot get packets\n");
        exit(-1);
    }
    /* create fixed fields for a packet */
    struct pkt_config conf;
    // TODO:
    conf.proto = t_conf->proto;
    conf.length = 60;
    rte_ether_addr_copy(&t_conf->smac, &conf.smac);
    rte_ether_addr_copy(&t_conf->dmac, &conf.dmac);


    for (int i = 0; i < burst_size; i++) {
        // only modify variable fields here
        conf.sip = sip(rng);
        conf.dip = dip(rng);
        conf.sport = sport(rng);
        conf.dport = dport(rng);

        fill_packet(burst[i], &conf);
    }

    return burst_size;
}

static int cmp_mbuf(const void *a, const void *b)
{
    struct rte_mbuf **a_mbuf = (struct rte_mbuf **)a;
    struct rte_mbuf **b_mbuf = (struct rte_mbuf **)b;
    struct rte_ipv4_hdr *a_hdr = rte_pktmbuf_mtod_offset(*a_mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_ipv4_hdr *b_hdr = rte_pktmbuf_mtod_offset(*b_mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    // TODO: udp support
    struct rte_tcp_hdr *a_tcp =  (struct rte_tcp_hdr *)((char *)a_hdr + sizeof(struct rte_ipv4_hdr));
    struct rte_tcp_hdr *b_tcp =  (struct rte_tcp_hdr *)((char *)b_hdr + sizeof(struct rte_ipv4_hdr));

    five_tuple a_ft, b_ft;

    a_ft.sip = a_hdr->src_addr;
    a_ft.dip = a_hdr->dst_addr;
    a_ft.sport = a_tcp->src_port;
    a_ft.dport = a_tcp->dst_port;
    a_ft.proto = a_hdr->next_proto_id;
    
    b_ft.sip = b_hdr->src_addr;
    b_ft.dip = b_hdr->dst_addr;
    b_ft.sport = b_tcp->src_port;
    b_ft.dport = b_tcp->dst_port;
    b_ft.proto = b_hdr->next_proto_id;

    /* elements will be quite likely the same, so we first check that */
    std::size_t a_hash = std::hash<five_tuple>{}(a_ft);
    std::size_t b_hash = std::hash<five_tuple>{}(b_ft);
    
    // if ((a_ft.sip == b_ft.dip) && (a_ft.sport == b_ft.dport)){
    //     return 0;
    // }

    if (a_hash == b_hash)
        return 0;
    else if (a_hash < b_hash)
        return -1;
    else
        return 1;
} 

void sort_packets(struct rte_mbuf **buf, uint32_t len, enum flow_aggregation_pattern p)
{
    std::qsort(buf, len, sizeof(struct rte_mbuf *), cmp_mbuf);
    return;
}