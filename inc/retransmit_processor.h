#pragma once

#include "config.h"
#include "model/ip_set.h"
#include "model/processor.h"

typedef struct retransmit_processor_t retransmit_processor_t;

retransmit_processor_t *retransmit_processor_init(
    const retransmit_processor_config_t *cfg,
    ip_set_adder_t ip_set_adder
);

void retransmit_processor_free(retransmit_processor_t **p);

processor_t retransmit_processor(retransmit_processor_t *p);
