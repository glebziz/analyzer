#pragma once

#include <stdint.h>

typedef struct {
    void *data;

    int16_t (*read)(void *data, void *buf, uint16_t buf_len);

    int16_t (*seek)(void *data, int16_t offset);

    int16_t (*len)(void *data);

    void (*close)(void *data);

    uint32_t (*pop_descriptor)(void *data);
} reader_t;

int16_t reader_read(reader_t r, void *buf, uint16_t buf_len);

int16_t reader_seek(reader_t r, int16_t offset);

int16_t reader_len(reader_t r);

void reader_close(reader_t r);

uint32_t reader_pop_descriptor(reader_t r);
