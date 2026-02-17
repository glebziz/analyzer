#include "app.h"

#include <signal.h>
#include <stdlib.h>

#include "common_processor.h"
#include "domain_processor.h"
#include "ip_parser.h"
#include "log.h"
#include "nfqueue.h"
#include "nftables.h"
#include "retransmit_processor.h"
#include "tcp_parser.h"
#include "tcp_stream_processor.h"
#include "tls_parser.h"

typedef struct app_t {
    nfqueue_t *nfq;
    nftables_t *nft;

    ip_parser_t *ip;
    tcp_parser_t *tcp;
    tls_parser_t *tls;

    tcp_stream_processor_t *stream;

    common_processor_t *common;
    retransmit_processor_t *retransmit;
    domain_processor_t *domain;
} app_t;

app_t *app_init(const config_t *cfg) {
    app_t *app = calloc(1, sizeof(app_t));
    if (!app) {
        return NULL;
    }

    app->nfq = nfqueue_init(&cfg->nfqueue);
    if (!app->nfq) {
        log_error("failed to initialize nfqueue");
        goto errL;
    }

    app->nft = nftables_init();
    if (!app->nft) {
        log_error("failed to initialize nftables");
        goto errL;
    }

    app->ip = ip_parser_init();
    if (!app->ip) {
        log_error("failed to initialize ip parser");
        goto errL;
    }

    app->stream = tcp_stream_processor_init(&cfg->tcp_stream_processor, nftables_ip_set_adder(app->nft),
                                            nfqueue_descriptor_cleaner(app->nfq));
    if (!app->stream) {
        log_error("failed to initialize tcp stream processor");
        goto errL;
    }

    app->tcp = tcp_parser_init(tcp_stream_processor(app->stream));
    if (!app->tcp) {
        log_error("failed to initialize tcp parser");
        goto errL;
    }

    app->common = common_processor_init();
    if (!app->common) {
        log_error("failed to initialize common processor");
        goto errL;
    }

    app->tls = tls_parser_init(common_processor(app->common));
    if (!app->tls) {
        log_error("failed to initialize tls parser");
        goto errL;
    }

    app->retransmit = retransmit_processor_init(&cfg->retransmit_processor, nftables_ip_set_adder(app->nft));
    if (!app->retransmit) {
        log_error("failed to initialize retransmit processor");
        goto errL;
    }

    app->domain = domain_processor_init(&cfg->domain_processor, nftables_ip_set_adder(app->nft));
    if (!app->domain) {
        log_error("failed to initialize domain processor");
        goto errL;
    }

    if (nfqueue_add_parser(app->nfq, ip_parser(app->ip))) {
        log_error("failed to add ip parser to nfqueue");
        goto errL;
    }

    if (ip_parser_add_parser(app->ip, tcp_parser(app->tcp))) {
        log_error("failed to add tcp parser to ip parser");
        goto errL;
    }

    if (tcp_parser_add_parser(app->tcp, tls_parser(app->tls))) {
        log_error("failed to add tls parser to tcp parser");
        goto errL;
    }

    if (common_processor_add_processor(app->common, domain_processor(app->domain))) {
        log_error("failed to add domain processor to common processor");
        goto errL;
    }

    if (common_processor_add_processor(app->common, retransmit_processor(app->retransmit))) {
        log_error("failed to add retransmit processor to common processor");
        goto errL;
    }

    if (cfg->tcp_stream_processor.set_inited && nftables_add_set(app->nft, cfg->tcp_stream_processor.set)) {
        log_error("failed to add ip_set %s/%s to nftables", cfg->tcp_stream_processor.set.table,
                  cfg->tcp_stream_processor.set.name);
        goto errL;
    }

    if (cfg->tcp_stream_processor.set6_inited && nftables_add_set(app->nft, cfg->tcp_stream_processor.set6)) {
        log_error("failed to add ip_set %s/%s to nftables", cfg->tcp_stream_processor.set6.table,
                  cfg->tcp_stream_processor.set6.name);
        goto errL;
    }

    if (cfg->retransmit_processor.set_inited && nftables_add_set(app->nft, cfg->retransmit_processor.set)) {
        log_error("failed to add ip_set %s/%s to nftables", cfg->retransmit_processor.set.table,
                  cfg->retransmit_processor.set.name);
        goto errL;
    }

    if (cfg->retransmit_processor.set6_inited && nftables_add_set(app->nft, cfg->retransmit_processor.set6)) {
        log_error("failed to add ip_set %s/%s to nftables", cfg->retransmit_processor.set6.table,
                  cfg->retransmit_processor.set6.name);
        goto errL;
    }

    if (cfg->domain_processor.set_inited && nftables_add_set(app->nft, cfg->domain_processor.set)) {
        log_error("failed to add ip_set %s/%s to nftables", cfg->domain_processor.set.table,
                  cfg->domain_processor.set.name);
        goto errL;
    }

    if (cfg->domain_processor.set6_inited && nftables_add_set(app->nft, cfg->domain_processor.set6)) {
        log_error("failed to add ip_set %s/%s to nftables", cfg->domain_processor.set6.table,
                  cfg->domain_processor.set6.name);
        goto errL;
    }

    return app;

errL:
    common_processor_free(&app->common);
    retransmit_processor_free(&app->retransmit);
    domain_processor_free(&app->domain);

    tls_parser_free(&app->tls);
    tcp_parser_free(&app->tcp);
    ip_parser_free(&app->ip);

    tcp_stream_processor_free(&app->stream);

    nfqueue_free(&app->nfq);
    nftables_free(&app->nft);

    free(app);

    return NULL;
}

int app_run(const app_t *a) {
    signal(SIGINT, ( {
        void handle_sigint(int) {
            nfqueue_stop(a->nfq);
        }
        (void(*)(int)) handle_sigint;
    }));

    return nfqueue_run(a->nfq);
}

void app_free(app_t **a) {
    if (!a || !*a) {
        return;
    }

    common_processor_free(&(*a)->common);
    retransmit_processor_free(&(*a)->retransmit);
    domain_processor_free(&(*a)->domain);

    tls_parser_free(&(*a)->tls);
    tcp_parser_free(&(*a)->tcp);
    ip_parser_free(&(*a)->ip);

    tcp_stream_processor_free(&(*a)->stream);

    nfqueue_free(&(*a)->nfq);
    nftables_free(&(*a)->nft);

    free(*a);
    *a = NULL;
}
