#pragma once

#include "packet.h"

typedef struct {
    void *data;

    bool (*process)(void *data, packet_t *pkt);
} processor_t;

bool processor_call(processor_t processor, packet_t *pkt);
