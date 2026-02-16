#include "common_processor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_CAPACITY 4

typedef struct {
    processor_t *ps;
    size_t len;
    size_t cap;
} processors_t;

typedef struct common_processor_t {
    processors_t processors;
} common_processor_t;

static bool process(void *data, packet_t *pkt);

common_processor_t *common_processor_init() {
    common_processor_t *p = calloc(1, sizeof(common_processor_t));
    if (!p) {
        return NULL;
    }

    p->processors.cap = DEFAULT_CAPACITY;
    p->processors.ps = calloc(DEFAULT_CAPACITY, sizeof(processor_t));
    if (!p->processors.ps) {
        free(p);
        return NULL;
    }
    return p;
}

void common_processor_free(common_processor_t **p) {
    if (!p || !*p) {
        return;
    }

    free((*p)->processors.ps);
    free(*p);
    *p = NULL;
}

processor_t common_processor(common_processor_t *p) {
    return (processor_t){
        .data = p,
        .process = process,
    };
}

int common_processor_add_processor(common_processor_t *p, const processor_t processor) {
    if (!p) {
        return -1;
    }

    if (p->processors.len == p->processors.cap) {
        p->processors.cap *= 2;
        processor_t *new_ps = realloc(p->processors.ps, p->processors.cap * sizeof(processor_t));
        if (!new_ps) {
            return -1;
        }

        p->processors.ps = new_ps;
    }

    p->processors.ps[p->processors.len++] = processor;

    return 0;
}

static bool process(void *data, packet_t *pkt) {
    common_processor_t *p = data;

    for (size_t i = 0; i < p->processors.len; i++) {
        if (processor_call(p->processors.ps[i], pkt)) {
            break;
        }
    }

    return true;
}
