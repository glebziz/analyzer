#include "domain_processor.h"

#include <stdlib.h>

#include "log.h"
#include "model/utils.h"

typedef struct domain_processor_t {
    ip_set_adder_t ip_set_adder;

    const domain_processor_config_t *cfg;
} domain_processor_t;

static bool process(void *data, packet_t *pkt);

static void add_element(domain_processor_t *p, packet_t *pkt, const char *domain);

static ip_set_t ip_set_by_element(domain_processor_t *p, ip_set_element_t element);

domain_processor_t *domain_processor_init(const domain_processor_config_t *cfg, const ip_set_adder_t ip_set_adder) {
    domain_processor_t *p = calloc(1, sizeof(domain_processor_t));
    if (!p) {
        return NULL;
    }

    p->ip_set_adder = ip_set_adder;
    p->cfg = cfg;

    return p;
}

void domain_processor_free(domain_processor_t **p) {
    if (!p || !*p) {
        return;
    }
    free(*p);
    *p = NULL;
}

processor_t domain_processor(domain_processor_t *p) {
    return (processor_t){
        .data = p,
        .process = process,
    };
}

static bool process(void *data, packet_t *pkt) {
    domain_processor_t *p = data;

    if (p->cfg->domains_len == 0) {
        return false;
    }

    if (pkt->l3_packet.proto == l3_proto_ipv4 && !p->cfg->set_inited) {
        return false;
    }

    if (pkt->l3_packet.proto == l3_proto_ipv6 && !p->cfg->set6_inited) {
        return false;
    }

    if (pkt->payload_packet.proto != payload_proto_tls_client_hello) {
        return false;
    }

    if (pkt->payload_packet.pkt.server_name->len == 0) {
        return false;
    }

    for (int i = 0; i < p->cfg->domains_len; i++) {
        for (int j = 0; j < pkt->payload_packet.pkt.server_name->len; j++) {
            if (is_subdomain(pkt->payload_packet.pkt.server_name->sni[j], p->cfg->domains[i])) {
                add_element(p, pkt, pkt->payload_packet.pkt.server_name->sni[j]);
                return true;
            }
        }
    }

    return false;
}

static void add_element(domain_processor_t *p, packet_t *pkt, const char *domain) {
    ip_set_element_t element = packet_to_ip_set_element(pkt);
    char buf[INET6_ADDRSTRLEN];
    ip_set_element_to_string(element, buf);
    ip_set_t set = ip_set_by_element(p, element);

    if (ip_set_adder_add_element(p->ip_set_adder, set, element)) {
        log_warn("Failed to add element to ipset %s.%s: %s", set.table, set.name, buf);
    }

    log_debug("Add ipset element %s, domain: %s", buf, domain);
}

static ip_set_t ip_set_by_element(domain_processor_t *p, const ip_set_element_t element) {
    switch (element.type) {
        case type_ipv4:
            return p->cfg->set;
        case type_ipv6:
            return p->cfg->set6;
    }

    return (ip_set_t){0};
}
