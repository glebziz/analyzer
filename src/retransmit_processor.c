#include "retransmit_processor.h"

#include <stdio.h>
#include <stdlib.h>
#include <netinet/tcp.h>

#include "log.h"
#include "uthash.h"
#include "model/conn.h"

typedef struct connection_t connection_t;

typedef struct retransmit_processor_t {
    uint64_t clock;

    ip_set_adder_t ip_set_adder;
    const retransmit_processor_config_t *cfg;

    connection_t *connections;
} retransmit_processor_t;

typedef struct connection_t {
    uint32_t seq;
    uint8_t retransmit_count;
    uint64_t last_clock;

    conn_t key;
    UT_hash_handle hh;
} connection_t;

static bool process(void *data, packet_t *pkt);

static void free_old_connections(retransmit_processor_t *p);

static ip_set_t ip_set_by_element(retransmit_processor_t *p, ip_set_element_t element);

retransmit_processor_t *retransmit_processor_init(
    const retransmit_processor_config_t *cfg,
    const ip_set_adder_t ip_set_adder
) {
    retransmit_processor_t *p = calloc(1, sizeof(retransmit_processor_t));
    if (!p) {
        return NULL;
    }

    p->cfg = cfg;
    p->ip_set_adder = ip_set_adder;

    return p;
}

void retransmit_processor_free(retransmit_processor_t **p) {
    if (!p || !*p) {
        return;
    }
    connection_t *conn, *tmp;
    HASH_ITER(hh, (*p)->connections, conn, tmp) {
        HASH_DEL((*p)->connections, conn);
        free(conn);
    }

    free(*p);
    *p = NULL;
}

processor_t retransmit_processor(retransmit_processor_t *p) {
    return (processor_t){
        .data = p,
        .process = process
    };
}

static bool process(void *data, packet_t *pkt) {
    retransmit_processor_t *p = data;
    p->clock++;

    free_old_connections(p);

    if (pkt->l3_packet.proto == l3_proto_ipv4 && !p->cfg->set_inited) {
        return false;
    }

    if (pkt->l3_packet.proto == l3_proto_ipv6 && !p->cfg->set6_inited) {
        return false;
    }

    if (pkt->payload_packet.proto != payload_proto_tls_client_hello) {
        return false;
    }

    conn_t key = connection_from_packet(pkt);
    connection_t *conn;
    HASH_FIND(hh, p->connections, &key, sizeof(conn_t), conn);
    if (!conn) {
        if (pkt->payload_packet.proto != payload_proto_tls_client_hello) {
            return false;
        }

        conn = calloc(1, sizeof(connection_t));
        *conn = (connection_t){
            .seq = ntohl(pkt->l4_packet.pkt.tcp->th_seq),
            .last_clock = p->clock,
            .key = key,
        };

        HASH_ADD(hh, p->connections, key, sizeof(conn_t), conn);
        return false;
    }

    conn->last_clock = p->clock;
    switch (pkt->payload_packet.proto) {
        case payload_proto_tls_client_hello:
            if (conn->seq != ntohl(pkt->l4_packet.pkt.tcp->th_seq)) {
                conn->retransmit_count = 0;
                conn->seq = ntohl(pkt->l4_packet.pkt.tcp->th_seq);
                break;
            }

            if (++conn->retransmit_count < p->cfg->limit) {
                break;
            }

            ip_set_element_t element = packet_to_ip_set_element(pkt);
            char buf[INET6_ADDRSTRLEN];
            ip_set_element_to_string(element, buf);
            ip_set_t set = ip_set_by_element(p, element);

            if (ip_set_adder_add_element(p->ip_set_adder, set, element)) {
                log_warn("Failed to add element to ipset %s.%s: %s", set.table, set.name, buf);
                return false;
            }

            log_debug("Detect retransmit %s", buf);
            HASH_DELETE(hh, p->connections, conn);
            free(conn);

            return true;
        default:
            HASH_DELETE(hh, p->connections, conn);
            free(conn);
    }
    return false;
}

static void free_old_connections(retransmit_processor_t *p) {
    connection_t *conn, *tmp;
    HASH_ITER(hh, p->connections, conn, tmp) {
        if (p->clock - conn->last_clock < p->cfg->conn_ttl) {
            continue;
        }

        HASH_DEL(p->connections, conn);
        free(conn);
    }
}

static ip_set_t ip_set_by_element(retransmit_processor_t *p, const ip_set_element_t element) {
    switch (element.type) {
        case type_ipv4:
            return p->cfg->set;
        case type_ipv6:
            return p->cfg->set6;
    }

    return (ip_set_t){0};
}
