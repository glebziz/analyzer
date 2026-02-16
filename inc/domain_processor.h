#pragma once

#include "config.h"
#include "model/ip_set.h"
#include "model/processor.h"

typedef struct domain_processor_t domain_processor_t;

domain_processor_t *domain_processor_init(const domain_processor_config_t *cfg, ip_set_adder_t ip_set_adder);

void domain_processor_free(domain_processor_t **p);

processor_t domain_processor(domain_processor_t *p);
