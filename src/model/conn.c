#include "model/conn.h"

#include <netinet/tcp.h>

conn_t connection_from_packet(packet_t *pkt) {
    conn_t key = {
        .src_port = ntohs(pkt->l4_packet.pkt.tcp->th_sport),
        .dst_port = ntohs(pkt->l4_packet.pkt.tcp->th_dport),
    };

    switch (pkt->l3_packet.proto) {
        case l3_proto_ipv4:
            key.dst_addr.ipv4 = pkt->l3_packet.pkt.ipv4->ip_dst;
            key.src_addr.ipv4 = pkt->l3_packet.pkt.ipv4->ip_src;
            break;
        case l3_proto_ipv6:
            key.dst_addr.ipv6 = pkt->l3_packet.pkt.ipv6->ip6_dst;
            key.src_addr.ipv6 = pkt->l3_packet.pkt.ipv6->ip6_src;
            break;
    }

    return key;
}
