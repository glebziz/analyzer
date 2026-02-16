#pragma once
#include <stdint.h>

typedef struct {
    void *data;

    void (*clean_descriptor)(void *data, uint32_t desc);
} descriptor_cleaner_t;

void descriptor_cleaner_clean(descriptor_cleaner_t c, uint32_t desc);
