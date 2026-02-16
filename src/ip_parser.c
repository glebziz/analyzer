#include "ip_parser.h"

#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "uthash.h"
#include "model/packet.h"

typedef struct {
    uint8_t proto;
    parser_t parser;
    UT_hash_handle hh;
} _parser_t;

typedef struct ip_parser_t {
    _parser_t *parsers;
} ip_parser_t;

static void parse(void *data, packet_t *pkt);

static void parse6(void *data, packet_t *pkt);

static void ip_parser_call(const ip_parser_t *p, uint8_t proto, packet_t *pkt);

ip_parser_t *ip_parser_init() {
    return calloc(1, sizeof(ip_parser_t));
}

void ip_parser_free(ip_parser_t **p) {
    if (!p || !*p) {
        return;
    }

    _parser_t *_p, *tmp;
    HASH_ITER(hh, (*p)->parsers, _p, tmp) {
        HASH_DEL((*p)->parsers, _p);
        free(_p);
    }

    free(*p);
    *p = NULL;
}

parser_t ip_parser(ip_parser_t *p) {
    if (!p) {
        return (parser_t){0};
    }

    return (parser_t){
        .data = p,
        .match = matcher_l2(ETHERTYPE_IP),
        .parse = parse,
    };
}

parser_t ip6_parser(ip_parser_t *p) {
    if (!p) {
        return (parser_t){0};
    }

    return (parser_t){
        .data = p,
        .match = matcher_l2(ETHERTYPE_IPV6),
        .parse = parse6,
    };
}

int ip_parser_add_parser(ip_parser_t *p, const parser_t parser) {
    if (!p) {
        return -1;
    }

    if (!parser_is_l3(parser)) {
        return -1;
    }

    _parser_t *_p = calloc(1, sizeof(_parser_t));
    if (!_p) {
        return -1;
    }

    _p->proto = parser_l3_proto(parser);
    _p->parser = parser;
    HASH_ADD(hh, p->parsers, proto, sizeof(uint8_t), _p);

    return 0;
}

static void parse(void *data, packet_t *pkt) {
    struct ip ip_pkt;

    int16_t read_len = packet_read(pkt, &ip_pkt, sizeof(ip_pkt));
    if (read_len != sizeof(ip_pkt)) {
        return;
    }

    pkt->l3_packet = l3_packet_ipv4(&ip_pkt);
    packet_seek(pkt, ip_pkt.ip_hl * 4 - sizeof(ip_pkt));
    ip_parser_call(data, ip_pkt.ip_p, pkt);
}

static void parse6(void *data, packet_t *pkt) {
    struct ip6_hdr ip6_pkt;

    int16_t read_len = packet_read(pkt, &ip6_pkt, sizeof(ip6_pkt));
    if (read_len != sizeof(ip6_pkt)) {
        return;
    }

    pkt->l3_packet = l3_packet_ipv6(&ip6_pkt);
    ip_parser_call(data, ip6_pkt.ip6_nxt, pkt);
}

static void ip_parser_call(const ip_parser_t *p, const uint8_t proto, packet_t *pkt) {
    _parser_t *_p;
    HASH_FIND(hh, p->parsers, &proto, sizeof(uint8_t), _p);
    if (!_p) {
        return;
    }

    parser_call(_p->parser, pkt);
}
