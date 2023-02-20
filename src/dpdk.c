#include "Qktgen.h"

// TODO: check if we need more argument in port conf, e.g. RSS
struct rte_eth_conf port_conf = {
    // enable checksum offload for throughput
    .rxmode = {
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        .offloads = DEV_RX_OFFLOAD_CHECKSUM,
    },
    .txmode = {.mq_mode = ETH_MQ_TX_NONE}
};

void init_dpdk()
{
    // check available ports
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No enough Ethernet ports - bye\n");
    
    // TODO: extend it to support multi-port
    uint16_t curr_port = 0;
    struct rte_eth_dev_info info;
    rte_eth_dev_info_get(curr_port, &info);
    printf("rx & tx at port 0: %s\n", info.device->name);
    struct rte_ether_addr mac;
    rte_eth_macaddr_get(curr_port, &mac);
    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        mac.addr_bytes[0],
        mac.addr_bytes[1],
        mac.addr_bytes[2],
        mac.addr_bytes[3],
        mac.addr_bytes[4],
        mac.addr_bytes[5]);
    
    // setup packet pool
    // TODO: resize according to user input
    unsigned nb_mbuf = 1024 * 1024;
    unsigned mbuf_cache = 256;
    glb_pkt_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbuf, mbuf_cache, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!glb_pkt_pool) {
        exit(-1);
    }

    // setup port with various info (e.g. RSS)
    int ret = 0;
    // TODO: unsymmetric RX/TX config
    // TODO: check main/worker or RTC
    // Currently, we only rx/tx on one core 
    unsigned queue_count = 1;
    ret = rte_eth_dev_configure(curr_port, queue_count, queue_count, &port_conf);
    if (ret < 0) {
        exit(-1);
    }

    // setup RX/TX queue
    unsigned rx_desc = 1024;
    unsigned tx_desc = 1024;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    rxq_conf = info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;
    txq_conf = info.default_txconf;
    txq_conf.offloads = port_conf.txmode.offloads;
    for (int q = 0; q < queue_count; q++) {
        // TODO: check if we need separate mempool for rx/tx
        ret = rte_eth_rx_queue_setup(curr_port, q, rx_desc, rte_eth_dev_socket_id(curr_port), &rxq_conf, glb_pkt_pool);
        if (ret < 0) {
            exit(-1);
        }
    }
    for (int q = 0; q < queue_count; q++) {
        ret = rte_eth_tx_queue_setup(curr_port, q, tx_desc, rte_eth_dev_socket_id(curr_port), &txq_conf);
        if (ret < 0) {
            exit(-1);
        }
    }

    ret = rte_eth_promiscuous_enable(curr_port);
    if (ret < 0) {
        exit(-1);
    }

    ret = rte_eth_dev_start(curr_port);
    if (ret < 0) {
        exit(-1);
    }
}

// TODO: extract 'burst' size automatically from traffic config 
uint16_t do_tx(struct traffic_config *t_conf, uint16_t port, uint16_t queue, struct rte_mbuf **pkt_burst, uint16_t burst_size)
{
    uint16_t real_burst_size = (burst_size > 32) ? 32 : burst_size;
    uint16_t nb_gen = pktgen(t_conf, pkt_burst, burst_size);
    uint16_t nb_tx =  rte_eth_tx_burst(port, queue, pkt_burst, nb_gen);

    return nb_tx;
}