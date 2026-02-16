#pragma once

#include "config.h"
#include "model/descriptor_cleaner.h"
#include "model/processor.h"

typedef struct tcp_stream_processor_t tcp_stream_processor_t;

tcp_stream_processor_t *tcp_stream_processor_init(
    const tcp_stream_processor_config_t *cfg,
    ip_set_adder_t ip_set_adder, descriptor_cleaner_t cleaner
);

void tcp_stream_processor_free(tcp_stream_processor_t **p);

processor_t tcp_stream_processor(tcp_stream_processor_t *p);
