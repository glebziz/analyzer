#pragma once

#include "model/processor.h"

typedef struct common_processor_t common_processor_t;

common_processor_t *common_processor_init();

void common_processor_free(common_processor_t **p);

processor_t common_processor(common_processor_t *p);

int common_processor_add_processor(common_processor_t *p, processor_t processor);
