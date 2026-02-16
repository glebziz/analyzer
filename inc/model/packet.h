#pragma once

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "ip_set.h"
#include "reader.h"
#include "tls_packet.h"

#define l3_packet_ipv4(PTR) (l3_packet_t){  \
    .pkt.ipv4 = (PTR),                      \
    .proto = l3_proto_ipv4,                 \
}

#define l3_packet_ipv6(PTR) (l3_packet_t){  \
    .pkt.ipv6 = (PTR),                      \
    .proto = l3_proto_ipv6,                 \
}

#define l4_packet_tcp(PTR) (l4_packet_t){   \
    .pkt.tcp = (PTR),                       \
    .proto = l4_proto_tcp,                  \
}

#define payload_packet_tls_client_hello(PTR) (payload_packet_t){    \
    .proto = payload_proto_tls_client_hello,                        \
    .pkt.server_name = (PTR),                                       \
}

#define payload_packet_tls_common() (payload_packet_t){ \
    .proto = payload_proto_tls_common,                  \
}

#define packet_read_byte(PKT) ({                                \
    uint8_t byte;                                               \
    int16_t read_len = packet_read((PKT), &byte, sizeof(byte)); \
    if (read_len != sizeof(byte)) {                             \
        byte = 0;                                               \
    }                                                           \
    byte;                                                       \
})

#define packet_read_word(PKT) ({                                \
    uint16_t word;                                              \
    int16_t read_len = packet_read((PKT), &word, sizeof(word)); \
    if (read_len != sizeof(word)) {                             \
        word = 0;                                               \
    }                                                           \
    word;                                                       \
})

typedef struct {
    union {
        struct ip *ipv4;
        struct ip6_hdr *ipv6;
    } pkt;

    enum {
        l3_proto_ipv4,
        l3_proto_ipv6,
    } proto;
} l3_packet_t;

typedef struct {
    union {
        struct tcphdr *tcp;
    } pkt;

    enum {
        l4_proto_tcp,
    } proto;
} l4_packet_t;

typedef struct {
    union {
        tls_extension_server_name_t *server_name;
    } pkt;

    enum {
        payload_proto_other,
        payload_proto_tls_client_hello,
        payload_proto_tls_common,
    } proto;
} payload_packet_t;

typedef struct {
    reader_t base;

    l3_packet_t l3_packet;
    l4_packet_t l4_packet;
    payload_packet_t payload_packet;

    enum {
        verdict_accept,
        verdict_none,
    } verdict;
} packet_t;

int16_t packet_read(const packet_t *pkt, void *buf, uint16_t buf_len);

int16_t packet_seek(const packet_t *pkt, int16_t offset);

int16_t packet_len(const packet_t *pkt);

void packet_close(const packet_t *pkt);

uint32_t packet_pop_descriptor(const packet_t *pkt);

ip_set_element_t packet_to_ip_set_element(packet_t *pkt);
