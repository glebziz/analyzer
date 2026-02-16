#pragma once

#include <stdbool.h>

#include "model/ip_set.h"

typedef struct {
    int16_t qnum;
    uint32_t qlen;
    uint32_t packet_size;
} nfqueue_config_t;

typedef struct {
    bool set_inited;
    bool set6_inited;

    ip_set_t set;
    ip_set_t set6;

    uint64_t stream_ttl;
    uint8_t syn_retransmit_limit;
} tcp_stream_processor_config_t;

typedef struct {
    bool set_inited;
    bool set6_inited;

    ip_set_t set;
    ip_set_t set6;

    char domains[100][256];
    int domains_len;
} domain_processor_config_t;

typedef struct {
    bool set_inited;
    bool set6_inited;

    ip_set_t set;
    ip_set_t set6;

    uint8_t limit;
    uint64_t conn_ttl;
} retransmit_processor_config_t;

typedef struct config_t {
    nfqueue_config_t nfqueue;
    tcp_stream_processor_config_t tcp_stream_processor;
    domain_processor_config_t domain_processor;
    retransmit_processor_config_t retransmit_processor;
} config_t;

int parse_config(const char *filename, config_t *conf);
