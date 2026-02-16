#include "tcp_parser.h"

#include <stdlib.h>
#include <netinet/tcp.h>

#include "model/packet.h"

#define DEFAULT_CAPACITY 4

typedef struct {
    parser_t *ps;
    size_t len;
    size_t cap;
} parsers_t;

typedef struct tcp_parser_t {
    processor_t stream_processor;
    parsers_t parsers;
} tcp_parser_t;

static void parse(void *data, packet_t *pkt);

tcp_parser_t *tcp_parser_init(const processor_t stream_processor) {
    tcp_parser_t *p = calloc(1, sizeof(tcp_parser_t));
    if (!p) {
        return NULL;
    }

    p->stream_processor = stream_processor;
    p->parsers.cap = DEFAULT_CAPACITY;
    p->parsers.ps = calloc(DEFAULT_CAPACITY, sizeof(parser_t));
    if (!p->parsers.ps) {
        free(p);
        return NULL;
    }

    return p;
}

void tcp_parser_free(tcp_parser_t **p) {
    if (!p || !*p) {
        return;
    }

    free((*p)->parsers.ps);
    free(*p);
    *p = NULL;
}

parser_t tcp_parser(tcp_parser_t *p) {
    return (parser_t){
        .data = p,
        .match = matcher_l3(IPPROTO_TCP),
        .parse = parse,
    };
}

int tcp_parser_add_parser(tcp_parser_t *p, const parser_t parser) {
    if (!p) {
        return -1;
    }

    if (!parser_is_l4(parser)) {
        return -1;
    }

    if (p->parsers.len == p->parsers.cap) {
        p->parsers.cap *= 2;
        parser_t *new_ps = realloc(p->parsers.ps, p->parsers.cap * sizeof(parser_t));
        if (!new_ps) {
            return -1;
        }

        p->parsers.ps = new_ps;
    }

    p->parsers.ps[p->parsers.len++] = parser;

    return 0;
}

static void parse(void *data, packet_t *pkt) {
    struct tcphdr tcp_pkt;

    int16_t read_len = packet_read(pkt, &tcp_pkt, sizeof(tcp_pkt));
    if (read_len != sizeof(tcp_pkt)) {
        return;
    }

    pkt->l4_packet = l4_packet_tcp(&tcp_pkt);
    packet_seek(pkt, tcp_pkt.th_off * 4 - sizeof(struct tcphdr));
    tcp_parser_t *p = data;

    if (!processor_call(p->stream_processor, pkt)) {
        return;
    }

    for (int i = 0; i < p->parsers.len; i++) {
        if (!l4_matcher_match(parser_l4_matcher(p->parsers.ps[i]), pkt)) {
            continue;
        }

        parser_call(p->parsers.ps[i], pkt);
        break;
    }
}
