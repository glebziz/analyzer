#pragma once

#include <netinet/in.h>

#include "packet.h"

typedef union {
    struct in_addr ipv4;
    struct in6_addr ipv6;
} conn_addr_t;

typedef struct {
    conn_addr_t src_addr;
    conn_addr_t dst_addr;

    uint16_t src_port;
    uint16_t dst_port;
} conn_t;

conn_t connection_from_packet(packet_t *pkt);
