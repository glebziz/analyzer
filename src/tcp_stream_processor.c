#include "tcp_stream_processor.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "log.h"
#include "uthash.h"
#include "model/conn.h"
#include "model/packet.h"
#include "model/utils.h"

typedef struct tcp_stream_t tcp_stream_t;
typedef struct tcp_segment_t tcp_segment_t;

typedef struct tcp_stream_processor_t {
    uint64_t clock;

    const tcp_stream_processor_config_t *cfg;
    descriptor_cleaner_t cleaner;
    ip_set_adder_t ip_set_adder;

    tcp_stream_t *streams;
} tcp_stream_processor_t;

typedef struct {
    tcp_segment_t *curr_seg;
    uint16_t len;
    uint16_t offset;
    uint16_t seg_offset;
} tcp_stream_reader_t;

typedef struct tcp_stream_t {
    uint64_t last_clock;
    uint32_t first_seq;
    uint8_t retransmit_count;

    tcp_segment_t *segments;
    conn_t key;

    tcp_stream_reader_t reader;

    tcp_stream_t *next;
    UT_hash_handle hh;
} tcp_stream_t;

typedef struct tcp_segment_t {
    uint32_t start_seq;
    uint32_t len;
    uint8_t *data;

    uint32_t descriptors[10];
    uint16_t descriptors_len;

    tcp_segment_t *next;
} tcp_segment_t;

static bool process(void *data, packet_t *pkt);

static bool handle_tcp_packet(tcp_stream_processor_t *p, tcp_stream_t *stream, packet_t *pkt);

static uint8_t *read_packet_data(const packet_t *pkt, uint16_t len);

static void free_segment(tcp_stream_processor_t *p, tcp_segment_t *seg);

static void free_stream(tcp_stream_processor_t *p, tcp_stream_t *stream);

static void free_old_streams(tcp_stream_processor_t *p);

static void segment_add_descriptors(tcp_segment_t *seg, const packet_t *pkt);

static tcp_segment_t *stream_first_segment(tcp_stream_t *stream);

static void handle_syn_retransmit(tcp_stream_processor_t *p, packet_t *pkt);

static ip_set_t ip_set_by_element(tcp_stream_processor_t *p, ip_set_element_t element);

static int16_t tcp_stream_read(void *data, void *buf, uint16_t buf_len);

static int16_t tcp_stream_seek(void *data, int16_t offset);

static int16_t tcp_stream_len(void *data);

static void tcp_stream_close(void *data);

static uint32_t tcp_stream_pop_descriptor(void *data);

tcp_stream_processor_t *tcp_stream_processor_init(
    const tcp_stream_processor_config_t *cfg,
    const ip_set_adder_t ip_set_adder,
    const descriptor_cleaner_t cleaner
) {
    tcp_stream_processor_t *p = calloc(1, sizeof(tcp_stream_processor_t));
    if (!p) {
        return NULL;
    }

    p->cfg = cfg;
    p->cleaner = cleaner;
    p->ip_set_adder = ip_set_adder;

    return p;
}

void tcp_stream_processor_free(tcp_stream_processor_t **p) {
    if (!p || !*p) {
        return;
    }

    tcp_stream_t *stream, *tmp;
    HASH_ITER(hh, (*p)->streams, stream, tmp) {
        HASH_DEL((*p)->streams, stream);
        free_stream(*p, stream);
    }

    free(*p);
    *p = NULL;
}

processor_t tcp_stream_processor(tcp_stream_processor_t *p) {
    return (processor_t){
        .data = p,
        .process = process,
    };
}

static bool process(void *data, packet_t *pkt) {
    tcp_stream_processor_t *p = data;
    p->clock++;

    free_old_streams(p);

    tcp_stream_t *stream;
    conn_t key = connection_from_packet(pkt);

    if (pkt->l4_packet.pkt.tcp->th_flags & TH_SYN) {
        HASH_FIND(hh, p->streams, &key, sizeof(conn_t), stream);
        if (stream && stream->first_seq == ntohl(pkt->l4_packet.pkt.tcp->th_seq) + 1) {
            stream->last_clock = p->clock;

            if (++stream->retransmit_count > p->cfg->syn_retransmit_limit) {
                handle_syn_retransmit(p, pkt);
                HASH_DEL(p->streams, stream);
                free_stream(p, stream);
            }

            return false;
        }

        stream = calloc(1, sizeof(tcp_stream_t));
        if (!stream) {
            return false;
        }

        stream->key = key;
        stream->last_clock = p->clock;
        stream->first_seq = ntohl(pkt->l4_packet.pkt.tcp->th_seq) + 1;

        tcp_stream_t *old;
        HASH_REPLACE(hh, p->streams, key, sizeof(conn_t), stream, old);

        free_stream(p, old);

        return false;
    }

    HASH_FIND(hh, p->streams, &key, sizeof(conn_t), stream);
    if (!stream) {
        return false;
    }

    if (pkt->l4_packet.pkt.tcp->th_flags & (TH_RST | TH_FIN)) {
        HASH_DEL(p->streams, stream);
        free_stream(p, stream);
        return false;
    }

    stream->last_clock = p->clock;
    if (!handle_tcp_packet(p, stream, pkt)) {
        return false;
    }

    stream->reader = (tcp_stream_reader_t){0};
    pkt->base = (reader_t){
        .data = stream,
        .read = tcp_stream_read,
        .seek = tcp_stream_seek,
        .len = tcp_stream_len,
        .close = tcp_stream_close,
        .pop_descriptor = tcp_stream_pop_descriptor,
    };
    return true;
}

static bool handle_tcp_packet(tcp_stream_processor_t *p, tcp_stream_t *stream, packet_t *pkt) {
    if (!packet_len(pkt)) {
        return false;
    }

    uint32_t seq = ntohl(pkt->l4_packet.pkt.tcp->th_seq);
    stream->first_seq = min(stream->first_seq, seq);

    if (!stream->segments || stream->segments->start_seq > seq) {
        tcp_segment_t *new_seg = calloc(1, sizeof(tcp_segment_t));
        if (!new_seg) {
            return false;
        }

        uint16_t real_len = min(packet_len(pkt), val_or_default(stream->segments, start_seq, ~0x00) - seq);
        *new_seg = (tcp_segment_t){
            .start_seq = seq,
            .len = real_len,
            .next = stream->segments,
            .data = read_packet_data(pkt, real_len),
        };

        if (!new_seg->data) {
            free_segment(p, new_seg);
            return false;
        }

        stream->segments = new_seg;
        seq += real_len;
    }

    tcp_segment_t *seg = stream->segments;
    while (seg->next && seg->next->start_seq < seq) {
        seg = seg->next;
    }

    while (packet_len(pkt)) {
        uint32_t real_start = max(seq, seg->start_seq + seg->len);
        if (real_start != seq) {
            if (packet_seek(pkt, real_start - seq) < 0) {
                break;
            }

            seq = real_start;
        }

        if (!packet_len(pkt)) {
            break;
        }

        int16_t real_len = min(packet_len(pkt), val_or_default(seg->next, start_seq, ~0x00) - seq);
        if (real_len <= 0) {
            if (packet_seek(pkt, seg->next->start_seq - seq + seg->next->len) < 0) {
                break;
            }

            seg = seg->next;
            seq = seg->start_seq + seg->len;

            continue;
        }

        tcp_segment_t *new_seg = calloc(1, sizeof(tcp_stream_t));
        if (!new_seg) {
            return false;
        }

        *new_seg = (tcp_segment_t){
            .start_seq = seq,
            .len = real_len,
            .next = seg->next,
            .data = read_packet_data(pkt, real_len),
        };

        if (!new_seg->data) {
            free_segment(p, new_seg);
            return false;
        }

        seg->next = new_seg;
        seg = new_seg;
        seq += real_len;
    }

    if (seg) {
        segment_add_descriptors(seg, pkt);
    }

    return true;
}

static uint8_t *read_packet_data(const packet_t *pkt, uint16_t len) {
    uint8_t *new_data = malloc(len);
    if (!new_data) {
        return NULL;
    }

    uint8_t *buf = new_data;
    while (len) {
        int16_t read_len = packet_read(pkt, buf, len);
        if (!read_len) {
            free(new_data);
            return NULL;
        }

        len -= read_len;
        buf += read_len;
    }

    return new_data;
}

static void free_segment(tcp_stream_processor_t *p, tcp_segment_t *seg) {
    if (!seg) {
        return;
    }

    for (int i = 0; i < seg->descriptors_len; i++) {
        descriptor_cleaner_clean(p->cleaner, seg->descriptors[i]);
    }

    free(seg->data);
    free(seg);
}

static void free_stream(tcp_stream_processor_t *p, tcp_stream_t *stream) {
    if (!stream) {
        return;
    }

    tcp_segment_t *seg = stream->segments;
    while (seg) {
        tcp_segment_t *next = seg->next;
        free_segment(p, seg);
        seg = next;
    }

    free(stream);
}

static void free_old_streams(tcp_stream_processor_t *p) {
    tcp_stream_t *stream, *tmp;
    HASH_ITER(hh, p->streams, stream, tmp) {
        if (p->clock - stream->last_clock < p->cfg->stream_ttl) {
            continue;
        }

        HASH_DEL(p->streams, stream);
        free_stream(p, stream);
    }
}

static void segment_add_descriptors(tcp_segment_t *seg, const packet_t *pkt) {
    uint32_t desc = 0;
    while (seg->descriptors_len < arr_len(seg->descriptors) && ((desc = packet_pop_descriptor(pkt)))) {
        seg->descriptors[seg->descriptors_len++] = desc;
    }
}

static tcp_segment_t *stream_first_segment(tcp_stream_t *stream) {
    tcp_segment_t *seg = stream->segments;
    while (seg && seg->start_seq < stream->first_seq) {
        seg = seg->next;
    }

    return val_or_default(seg, start_seq, ~0x00) == stream->first_seq ? seg : NULL;
}

void handle_syn_retransmit(tcp_stream_processor_t *p, packet_t *pkt) {
    if (pkt->l3_packet.proto == l3_proto_ipv4 && !p->cfg->set_inited) {
        return;
    }

    if (pkt->l3_packet.proto == l3_proto_ipv6 && !p->cfg->set6_inited) {
        return;
    }

    ip_set_element_t element = packet_to_ip_set_element(pkt);
    char buf[INET6_ADDRSTRLEN];
    ip_set_element_to_string(element, buf);
    ip_set_t set = ip_set_by_element(p, element);

    if (ip_set_adder_add_element(p->ip_set_adder, set, element)) {
        log_warn("Failed to add element to ipset %s.%s: %s", set.table, set.name, buf);
    }

    log_debug("Detect tcp.syn retransmit %s", buf);
}

static ip_set_t ip_set_by_element(tcp_stream_processor_t *p, const ip_set_element_t element) {
    switch (element.type) {
        case type_ipv4:
            return p->cfg->set;
        case type_ipv6:
            return p->cfg->set6;
    }

    return (ip_set_t){0};
}

static int16_t tcp_stream_read(void *data, void *buf, uint16_t buf_len) {
    tcp_stream_t *stream = data;

    tcp_segment_t *first_seg = stream_first_segment(stream);
    if (!first_seg) {
        return 0;
    }

    tcp_segment_t *seg = stream->reader.curr_seg;
    uint16_t seg_offset = stream->reader.seg_offset;
    if (!seg) {
        seg = first_seg;
        seg_offset = 0;
    }

    uint16_t offset = 0;
    while (buf_len) {
        uint16_t read_len = min(seg->len - seg_offset, buf_len);

        memcpy(buf + offset, seg->data + seg_offset, read_len);

        offset += read_len;
        buf_len -= read_len;
        seg_offset += read_len;

        if (seg->start_seq + seg->len != val_or_default(seg->next, start_seq, 0x00)) {
            break;
        }

        if (seg_offset == seg->len) {
            seg_offset = 0;
            seg = seg->next;
        }
    }

    stream->reader.curr_seg = seg;
    stream->reader.seg_offset = seg_offset;
    stream->reader.offset += offset;

    return offset;
}

static int16_t tcp_stream_seek(void *data, int16_t offset) {
    tcp_stream_t *stream = data;

    tcp_segment_t *first_seg = stream_first_segment(stream);
    if (!first_seg) {
        return -1;
    }

    tcp_stream_len(stream);
    if ((uint16_t) (offset + stream->reader.offset) > stream->reader.len) {
        return -1;
    }

    stream->reader.offset += offset;

    tcp_segment_t *seg = stream->reader.curr_seg;
    uint16_t seg_offset = stream->reader.seg_offset;
    if (!seg || offset < 0) {
        offset = stream->reader.offset;
        seg = first_seg;
        seg_offset = 0;
    }

    while (offset) {
        uint16_t seek_len = min(seg->len - seg_offset, offset);

        offset -= seek_len;
        seg_offset += seek_len;

        if (seg->start_seq + seg->len != val_or_default(seg->next, start_seq, 0x00)) {
            break;
        }

        if (seg_offset == seg->len) {
            seg_offset = 0;
            seg = seg->next;
        }
    }

    stream->reader.curr_seg = seg;
    stream->reader.seg_offset = seg_offset;

    return stream->reader.offset;
}

static int16_t tcp_stream_len(void *data) {
    tcp_stream_t *stream = data;

    tcp_segment_t *seg = stream_first_segment(stream);
    if (!stream->reader.len) {
        while (seg) {
            stream->reader.len += seg->len;

            if (seg->start_seq + seg->len != val_or_default(seg->next, start_seq, 0x00)) {
                break;
            }

            seg = seg->next;
        }
    }

    return stream->reader.len - stream->reader.offset;
}

static void tcp_stream_close(void *data) {
    tcp_stream_t *stream = data;

    tcp_segment_t *seg = stream_first_segment(stream);
    while (seg) {
        stream->reader.len += seg->len;

        uint32_t next_seq = val_or_default(seg->next, start_seq, ~0x00);
        if (seg->start_seq + seg->len != next_seq) {
            stream->first_seq = next_seq;
            break;
        }

        seg = seg->next;
    }
}

static uint32_t tcp_stream_pop_descriptor(void *data) {
    tcp_stream_t *stream = data;
    tcp_segment_t *seg = stream_first_segment(stream);
    while (seg) {
        if (seg->descriptors_len) {
            return seg->descriptors[--seg->descriptors_len];
        }

        if (seg->start_seq + seg->len != val_or_default(seg->next, start_seq, 0x00)) {
            break;
        }

        seg = seg->next;
    }

    return 0;
}
