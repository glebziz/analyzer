#pragma once

#include "config.h"
#include "model/descriptor_cleaner.h"
#include "model/parser.h"

typedef struct nfqueue_t nfqueue_t;

nfqueue_t *nfqueue_init(const nfqueue_config_t *cfg);

void nfqueue_free(nfqueue_t **nfq);

int nfqueue_run(nfqueue_t *nfq);

void nfqueue_stop(nfqueue_t *nfq);

int nfqueue_add_parser(nfqueue_t *nfq, parser_t parser);

descriptor_cleaner_t nfqueue_descriptor_cleaner(nfqueue_t *nfq);
