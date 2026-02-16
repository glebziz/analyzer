#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "toml.h"
#include "model/utils.h"

#define DEFAULT_QNUM 300
#define DEFAULT_QLEN 50
#define DEFAULT_PACKET_SIZE 65535

#define DEFAULT_TCP_STREAM_TTL 15
#define DEFAULT_SYN_RETRANSMIT_LIMIT 5

#define DEFAULT_RETRANSMIT_LIMIT 5
#define DEFAULT_RETRANSMIT_CONN_TTL 15

static void parse_queue_config(toml_table_t *t, nfqueue_config_t *conf);

static void parse_tcp_stream_processor_config(toml_table_t *t, tcp_stream_processor_config_t *conf);

static void parse_domain_processor_config(toml_table_t *t, domain_processor_config_t *conf);

static void parse_retransmit_processor_config(toml_table_t *t, retransmit_processor_config_t *conf);

static bool parse_ip_set(toml_table_t *t, ip_set_t *set);

static int toml_read_string(toml_table_t *t, const char *key, char *dst, size_t dst_len);

int parse_config(const char *filename, config_t *conf) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        return -1;
    }

    toml_table_t *root = toml_parse_file(fp, NULL, 0);
    fclose(fp);
    if (!root) {
        return -1;
    }

    memset(conf, 0, sizeof(config_t));
    parse_queue_config(toml_table_in(root, "nfqueue"), &conf->nfqueue);

    toml_table_t *processors = toml_table_in(root, "processors");
    if (!processors) {
        goto freeL;
    }

    parse_tcp_stream_processor_config(toml_table_in(processors, "tcp_stream"), &conf->tcp_stream_processor);
    parse_domain_processor_config(toml_table_in(processors, "domain"), &conf->domain_processor);
    parse_retransmit_processor_config(toml_table_in(processors, "retransmit"), &conf->retransmit_processor);

freeL:

    toml_free(root);

    return 0;
}

static void parse_queue_config(toml_table_t *t, nfqueue_config_t *conf) {
    if (!t) {
        conf->qnum = DEFAULT_QNUM;
        conf->qlen = DEFAULT_QLEN;
        conf->packet_size = DEFAULT_PACKET_SIZE;
        return;
    }

    toml_datum_t v = toml_int_in(t, "qnum");
    conf->qnum = v.ok ? v.u.i : DEFAULT_QNUM;

    v = toml_int_in(t, "qlen");
    conf->qlen = v.ok ? v.u.i : DEFAULT_QLEN;

    v = toml_int_in(t, "packet_size");
    conf->packet_size = v.ok ? v.u.i : DEFAULT_PACKET_SIZE;
}

void parse_tcp_stream_processor_config(toml_table_t *t, tcp_stream_processor_config_t *conf) {
    if (!t) {
        return;
    }

    conf->set_inited = parse_ip_set(toml_table_in(t, "set"), &conf->set);
    conf->set6_inited = parse_ip_set(toml_table_in(t, "set6"), &conf->set6);

    toml_datum_t v = toml_int_in(t, "stream_ttl");
    conf->stream_ttl = v.ok ? v.u.i : DEFAULT_TCP_STREAM_TTL;

    v = toml_int_in(t, "syn_retransmit_limit");
    conf->syn_retransmit_limit = v.ok ? v.u.i : DEFAULT_SYN_RETRANSMIT_LIMIT;
}

static void parse_domain_processor_config(toml_table_t *t, domain_processor_config_t *conf) {
    if (!t) {
        return;
    }

    conf->set_inited = parse_ip_set(toml_table_in(t, "set"), &conf->set);
    conf->set6_inited = parse_ip_set(toml_table_in(t, "set6"), &conf->set6);

    char domains_list_path[255];
    if (toml_read_string(t, "domains_list", domains_list_path, sizeof(domains_list_path))) {
        return;
    }

    FILE *fp = fopen(domains_list_path, "r");
    if (!fp) {
        return;
    }

    while (fgets(conf->domains[conf->domains_len], sizeof(conf->domains[conf->domains_len]), fp)) {
        conf->domains[conf->domains_len][strcspn(conf->domains[conf->domains_len], "\r\n")] = '\0';

        if (conf->domains[conf->domains_len][0] == '#' || conf->domains[conf->domains_len][0] == '\0') {
            continue;
        }

        if (++conf->domains_len >= arr_len(conf->domains)) {
            log_warn("Trim len of domains to %d", conf->domains_len);
            break;
        }
    }

    fclose(fp);
}

static void parse_retransmit_processor_config(toml_table_t *t, retransmit_processor_config_t *conf) {
    if (!t) {
        return;
    }

    conf->set_inited = parse_ip_set(toml_table_in(t, "set"), &conf->set);
    conf->set6_inited = parse_ip_set(toml_table_in(t, "set6"), &conf->set6);

    toml_datum_t v = toml_int_in(t, "limit");
    conf->limit = v.ok ? v.u.i : DEFAULT_RETRANSMIT_LIMIT;

    v = toml_int_in(t, "conn_ttl");
    conf->conn_ttl = v.ok ? v.u.i : DEFAULT_RETRANSMIT_CONN_TTL;
}

static bool parse_ip_set(toml_table_t *t, ip_set_t *set) {
    if (!t) {
        return false;
    }

    if (toml_read_string(t, "table", set->table, sizeof(set->table))) {
        return false;
    }

    if (toml_read_string(t, "name", set->name, sizeof(set->name))) {
        return false;
    }

    char family[64];
    if (toml_read_string(t, "family", family, sizeof(family))) {
        return false;
    }

    if (!strcmp(family, "inet")) {
        set->family = family_inet;
    } else if (!strcmp(family, "ip")) {
        set->family = family_ip;
    } else if (!strcmp(family, "ip6")) {
        set->family = family_ip6;
    } else {
        log_error("Unknown family: %s", family);
        return false;
    }

    return true;
}

static int toml_read_string(toml_table_t *t, const char *key, char *dst, size_t dst_len) {
    toml_datum_t v = toml_string_in(t, key);
    if (!v.ok) {
        return -1;
    }

    strncpy(dst, v.u.s, dst_len - 1);
    dst[dst_len - 1] = 0;
    free(v.u.s);

    return 0;
}
