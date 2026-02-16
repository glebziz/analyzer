#include "tls_parser.h"

#include <stdbool.h>
#include <netinet/tcp.h>

#include "uthash.h"
#include "model/packet.h"
#include "model/utils.h"

typedef struct buffer_t buffer_t;

typedef struct tls_parser_t {
    processor_t processor;

    buffer_t *buffer;
    reader_t base;
    uint16_t base_offset;
} tls_parser_t;

typedef struct buffer_t {
    uint8_t data[0xFFFF];
    uint16_t len;
    uint16_t offset;
} buffer_t;

static void parse(void *, packet_t *pkt);

static bool tls_matcher(packet_t *pkt);

static void parse_tls_handshake(tls_parser_t *p, packet_t *pkt, uint16_t tls_len);

static void parse_tls_common(tls_parser_t *p, packet_t *pkt, uint16_t tls_len);

static void parse_tls_client_hello(packet_t *pkt);

static void parse_tls_extension(packet_t *pkt);

static void parse_tls_extension_sni(packet_t *pkt);

static int16_t tls_parser_read(void *data, void *buf, uint16_t buf_len);

static int16_t tls_parser_seek(void *data, int16_t offset);

static int16_t tls_parser_len(void *data);

static void tls_parser_close(void *data);

static uint32_t tls_parser_pop_descriptor(void *data);

tls_parser_t *tls_parser_init(const processor_t processor) {
    tls_parser_t *p = calloc(1, sizeof(tls_parser_t));
    if (!p) {
        return NULL;
    }

    p->processor = processor;
    return p;
}

void tls_parser_free(tls_parser_t **p) {
    if (!p || !*p) {
        return;
    }

    free(*p);
    *p = NULL;
}

parser_t tls_parser(tls_parser_t *p) {
    return (parser_t){
        .data = p,
        .match = matcher_l4(tls_matcher),
        .parse = parse,
    };
}

static void parse(void *data, packet_t *pkt) {
    tls_parser_t *p = data;

    p->base = pkt->base;
    p->buffer = &(buffer_t){0};

    do {
        tls_header_t hdr;
        int16_t read_len = reader_read(p->base, &hdr, sizeof(hdr));
        if (read_len != sizeof(hdr)) {
            return;
        }

        if (reader_len(p->base) < ntohs(hdr.length)) {
            pkt->verdict = verdict_none;

            return;
        }

        pkt->verdict = verdict_accept;

        if (p->buffer->len) {
            pkt->base = (reader_t){
                .data = p,
                .read = tls_parser_read,
                .seek = tls_parser_seek,
                .len = tls_parser_len,
                .close = tls_parser_close,
                .pop_descriptor = tls_parser_pop_descriptor,
            };
        }

        switch (hdr.content_type) {
            case tls_content_type_handshake:
                parse_tls_handshake(p, pkt, ntohs(hdr.length) + p->buffer->len);
                break;
            default:
                parse_tls_common(p, pkt, ntohs(hdr.length) + p->buffer->len);
        }
    } while (packet_len(pkt));
}

static bool tls_matcher(packet_t *pkt) {
    tls_header_t hdr;

    int16_t read_len = packet_read(pkt, &hdr, sizeof(hdr));
    if (read_len != sizeof(hdr)) {
        return false;
    }

    return tls_header_valid(&hdr);
}

static void parse_tls_handshake(tls_parser_t *p, packet_t *pkt, const uint16_t tls_len) {
    tls_handshake_header_t hdr;

    int16_t read_len = packet_read(pkt, &hdr, sizeof(hdr));
    if (read_len != sizeof(hdr)) {
        return;
    }

    if (hdr.type == tls_handshake_type_encrypted_message) {
        packet_seek(pkt, tls_len - sizeof(hdr));
        return;
    }

    if (tls_len - sizeof(hdr) < normalize_tls_handshake_len(hdr.length)) {
        pkt->verdict = verdict_none;

        if (!p->buffer->len) {
            memcpy(p->buffer->data, &hdr, sizeof(hdr));
            p->buffer->len += sizeof(hdr);
        }

        p->buffer->len += reader_read(p->base, p->buffer->data + p->buffer->len, tls_len - p->buffer->len);
        p->base_offset = reader_seek(p->base, 0);
        p->buffer->offset = 0;

        return;
    }

    tls_extension_server_name_t payload = {0};

    uint16_t cur_offset = packet_seek(pkt, 0);
    switch (hdr.type) {
        case tls_handshake_type_client_hello:
            pkt->payload_packet = payload_packet_tls_client_hello(&payload);
            parse_tls_client_hello(pkt);
            break;
        default:
            pkt->payload_packet = payload_packet_tls_common();
            packet_seek(pkt, normalize_tls_handshake_len(hdr.length));
    }

    packet_seek(pkt, normalize_tls_handshake_len(hdr.length) - (packet_seek(pkt, 0) - cur_offset));

    processor_call(p->processor, pkt);
}

static void parse_tls_common(tls_parser_t *p, packet_t *pkt, const uint16_t tls_len) {
    pkt->payload_packet = payload_packet_tls_common();

    reader_seek(p->base, tls_len);
    processor_call(p->processor, pkt);
}

static void parse_tls_client_hello(packet_t *pkt) {
    packet_seek(pkt, 2); // Skip version
    packet_seek(pkt, 32); // Skip random

    packet_seek(pkt, packet_read_byte(pkt)); // Skip session_id
    packet_seek(pkt, ntohs(packet_read_word(pkt))); // Skip cipher_suites
    packet_seek(pkt, packet_read_byte(pkt)); // Skip compression_methods

    uint16_t ext_len = ntohs(packet_read_word(pkt));
    uint16_t cur_offset = packet_seek(pkt, 0);

    while (packet_seek(pkt, 0) - cur_offset < ext_len) {
        parse_tls_extension(pkt);
    }
}

static void parse_tls_extension(packet_t *pkt) {
    tls_extension_header_t hdr;

    packet_read(pkt, &hdr, sizeof(hdr));
    switch (ntohs(hdr.type)) {
        case tls_extension_server_name:
            parse_tls_extension_sni(pkt);
            break;
        default:
            packet_seek(pkt, ntohs(hdr.length));
            break;
    }
}

static void parse_tls_extension_sni(packet_t *pkt) {
#define sn payload_packet.pkt.server_name

    uint16_t sni_len = ntohs(packet_read_word(pkt));
    uint16_t cur_offset = packet_seek(pkt, 0);

    while (packet_seek(pkt, 0) - cur_offset < sni_len) {
        if (pkt->sn->len >= arr_len(pkt->sn->sni)) {
            packet_seek(pkt, packet_seek(pkt, 0) - cur_offset + sni_len);
            continue;
        }

        packet_seek(pkt, 1); // Skip name_type

        uint16_t name_len = ntohs(packet_read_word(pkt));

        packet_read(pkt, pkt->sn->sni[pkt->sn->len], min(sizeof(pkt->sn->sni[pkt->sn->len]), name_len));
        pkt->sn->sni[pkt->sn->len++][name_len] = '\0';
    }
}

int16_t tls_parser_read(void *data, void *buf, uint16_t buf_len) {
    tls_parser_t *p = data;

    uint16_t read_len = min(p->buffer->len - p->buffer->offset, buf_len);
    memcpy(buf, p->buffer->data + p->buffer->offset, read_len);
    p->buffer->offset += read_len;

    if (buf_len - read_len) {
        read_len += p->base.read(p->base.data, buf + read_len, buf_len - read_len);
    }

    return read_len;
}

int16_t tls_parser_seek(void *data, const int16_t offset) {
    tls_parser_t *p = data;
    if (offset < 0) {
        return -1;
    }

    p->buffer->offset += offset;

    uint16_t base_offset = p->base.seek(p->base.data, 0);
    if (p->buffer->offset > p->buffer->len) {
        base_offset = p->base.seek(p->base.data, p->buffer->offset - p->buffer->len);
        p->buffer->offset = p->buffer->len;
    }

    return p->buffer->offset + (base_offset - p->base_offset);
}

int16_t tls_parser_len(void *data) {
    tls_parser_t *p = data;

    return p->base.len(p->base.data) + p->buffer->len - p->buffer->offset;
}

void tls_parser_close(void *data) {
    tls_parser_t *p = data;
    p->base.close(p->base.data);
}

uint32_t tls_parser_pop_descriptor(void *data) {
    tls_parser_t *p = data;

    return p->base.pop_descriptor(p->base.data);
}
