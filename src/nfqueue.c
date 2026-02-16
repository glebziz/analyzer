#include "nfqueue.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <netinet/in.h>

#include "uthash.h"
#include "model/packet.h"

#define QUEUE_PACKET_SIZE 0xFFFF

typedef struct {
    uint16_t hw_proto;
    parser_t parser;
    UT_hash_handle hh;
} _parser_t;

typedef struct {
    uint32_t id;
    uint16_t hw_proto;

    uint8_t *data;
    uint16_t data_offset;
    uint16_t data_len;

    struct nfq_q_handle *qh;
} nfq_packet_t;

typedef struct nfqueue_t {
    atomic_bool stop;
    atomic_int fd;

    _parser_t *parsers;
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
} nfqueue_t;

static void nfqueue_clean_descriptor(void *data, uint32_t desc);

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *, struct nfq_data *nfqd, void *data);

static void call_parser(nfqueue_t *nfq, nfq_packet_t *nfq_pkt);

static void set_verdict(nfqueue_t *nfq, packet_t *pkt);

static int16_t nfq_packet_read(void *data, void *buf, uint16_t buf_len);

static int16_t nfq_packet_seek(void *data, int16_t offset);

static int16_t nfq_packet_len(void *data);

static void nfq_packet_close(void *data);

static uint32_t nfq_packet_pop_descriptor(void *data);

nfqueue_t *nfqueue_init(const nfqueue_config_t *cfg) {
    nfqueue_t *nfq = calloc(1, sizeof(nfqueue_t));
    if (!nfq) {
        return NULL;
    }

    nfq->h = nfq_open();
    if (!nfq->h) {
        goto errL;
    }

    if (nfq_unbind_pf(nfq->h, AF_INET)) {
        goto errL;
    }

    if (nfq_bind_pf(nfq->h, AF_INET)) {
        goto errL;
    }

    nfq->qh = nfq_create_queue(nfq->h, cfg->qnum, &cb, nfq);
    if (!nfq->qh) {
        goto errL;
    }

    if (nfq_set_mode(nfq->qh, NFQNL_COPY_PACKET, cfg->packet_size)) {
        goto errL;
    }

    if (nfq_set_queue_maxlen(nfq->qh, cfg->qlen)) {
        goto errL;
    }

    return nfq;

errL:

    if (nfq->qh) {
        nfq_destroy_queue(nfq->qh);
    }

    if (nfq->h) {
        nfq_close(nfq->h);
    }

    free(nfq);

    return NULL;
}

void nfqueue_free(nfqueue_t **nfq) {
    if (!nfq || !*nfq) {
        return;
    }

    _parser_t *p, *tmp;
    HASH_ITER(hh, (*nfq)->parsers, p, tmp) {
        HASH_DELETE(hh, (*nfq)->parsers, p);
        free(p);
    }

    nfq_destroy_queue((*nfq)->qh);
    nfq_close((*nfq)->h);
    free(*nfq);

    *nfq = NULL;
}

int nfqueue_run(nfqueue_t *nfq) {
    if (!nfq) {
        return -1;
    }
    char buf[QUEUE_PACKET_SIZE];
    nfq->fd = (atomic_int) nfq_fd(nfq->h);

    while (!nfq->stop) {
        const int rv = recv(nfq->fd, buf, sizeof(buf), 0);
        if (!rv) {
            continue;
        }

        if (nfq_handle_packet(nfq->h, buf, rv)) {
            return -1;
        }
    }

    return 0;
}

void nfqueue_stop(nfqueue_t *nfq) {
    if (!nfq) {
        return;
    }

    nfq->stop = (atomic_bool) true;
    close(nfq->fd);
}

int nfqueue_add_parser(nfqueue_t *nfq, const parser_t parser) {
    if (!nfq) {
        return -1;
    }

    if (!parser_is_l2(parser)) {
        return -1;
    }

    _parser_t *p = calloc(1, sizeof(_parser_t));
    if (!p) {
        return -1;
    }

    p->hw_proto = parser_l2_hw_proto(parser);
    p->parser = parser;
    HASH_ADD(hh, nfq->parsers, hw_proto, sizeof(uint16_t), p);

    return 0;
}

descriptor_cleaner_t nfqueue_descriptor_cleaner(nfqueue_t *nfq) {
    return (descriptor_cleaner_t){
        .data = nfq,
        .clean_descriptor = nfqueue_clean_descriptor,
    };
}

static void nfqueue_clean_descriptor(void *data, const uint32_t desc) {
    nfq_set_verdict(((nfqueue_t *) data)->qh, desc, NF_ACCEPT, 0, NULL);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *, struct nfq_data *nfqd, void *data) {
    nfqueue_t *nfq = data;

    struct nfqnl_msg_packet_hdr *hdr = nfq_get_msg_packet_hdr(nfqd);
    if (!hdr) {
        return -1;
    }

    nfq_packet_t pkt = {
        .id = ntohl(hdr->packet_id),
        .hw_proto = ntohs(hdr->hw_protocol),
        .data_len = nfq_get_payload(nfqd, &pkt.data),
        .qh = qh,
    };

    call_parser(nfq, &pkt);

    return 0;
}

static void call_parser(nfqueue_t *nfq, nfq_packet_t *nfq_pkt) {
    _parser_t *p;
    HASH_FIND(hh, nfq->parsers, &nfq_pkt->hw_proto, sizeof(uint16_t), p);
    if (!p) {
        nfq_set_verdict(nfq->qh, nfq_pkt->id, NF_ACCEPT, 0, NULL);
        return;
    }

    packet_t pkt = {
        .base = (reader_t){
            .data = nfq_pkt,
            .read = nfq_packet_read,
            .seek = nfq_packet_seek,
            .len = nfq_packet_len,
            .close = nfq_packet_close,
            .pop_descriptor = nfq_packet_pop_descriptor
        },
    };

    parser_call(p->parser, &pkt);
    set_verdict(nfq, &pkt);
}

static void set_verdict(nfqueue_t *nfq, packet_t *pkt) {
    if (pkt->verdict == verdict_none) {
        return;
    }

    uint32_t desc = 0;
    while ((desc = packet_pop_descriptor(pkt))) {
        nfq_set_verdict(nfq->qh, desc, NF_ACCEPT, 0, NULL);
    }

    packet_close(pkt);
}

static int16_t nfq_packet_read(void *data, void *buf, const uint16_t buf_len) {
    nfq_packet_t *pkt = data;

    int16_t real_len = pkt->data_len - pkt->data_offset < buf_len ? pkt->data_len - pkt->data_offset : buf_len;
    memcpy(buf, pkt->data + pkt->data_offset, real_len);
    pkt->data_offset += real_len;

    return real_len;
}

static int16_t nfq_packet_seek(void *data, const int16_t offset) {
    nfq_packet_t *pkt = data;

    if ((uint16_t) (offset + pkt->data_offset) > pkt->data_len) {
        return -1;
    }

    return pkt->data_offset += offset;
}

static int16_t nfq_packet_len(void *data) {
    const nfq_packet_t *pkt = data;

    return pkt->data_len - pkt->data_offset;
}

static void nfq_packet_close(void *data) {
    ((nfq_packet_t *) data)->id = 0;
}

static uint32_t nfq_packet_pop_descriptor(void *data) {
    nfq_packet_t *pkt = data;

    uint32_t desc = pkt->id;
    pkt->id = 0;

    return desc;
}
