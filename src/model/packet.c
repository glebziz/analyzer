#include "model/packet.h"

int16_t packet_read(const packet_t *pkt, void *buf, const uint16_t buf_len) {
    if (!pkt) {
        return -1;
    }

    return reader_read(pkt->base, buf, buf_len);
}

int16_t packet_seek(const packet_t *pkt, const int16_t offset) {
    if (!pkt) {
        return -1;
    }

    return reader_seek(pkt->base, offset);
}

int16_t packet_len(const packet_t *pkt) {
    if (!pkt) {
        return -1;
    }

    return reader_len(pkt->base);
}

void packet_close(const packet_t *pkt) {
    if (!pkt) {
        return;
    }

    reader_close(pkt->base);
}

uint32_t packet_pop_descriptor(const packet_t *pkt) {
    if (!pkt) {
        return 0;
    }

    return reader_pop_descriptor(pkt->base);
}

ip_set_element_t packet_to_ip_set_element(packet_t *pkt) {
    switch (pkt->l3_packet.proto) {
        case l3_proto_ipv4:
            return ip_set_element_ipv4(pkt->l3_packet.pkt.ipv4->ip_dst);
        case l3_proto_ipv6:
            return ip_set_element_ipv6(pkt->l3_packet.pkt.ipv6->ip6_dst);
    }

    return (ip_set_element_t){};
}
