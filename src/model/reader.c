#include "model/reader.h"

int16_t reader_read(const reader_t r, void *buf, const uint16_t buf_len) {
    return r.read(r.data, buf, buf_len);
}

int16_t reader_seek(const reader_t r, const int16_t offset) {
    return r.seek(r.data, offset);
}

int16_t reader_len(const reader_t r) {
    return r.len(r.data);
}

void reader_close(const reader_t r) {
    r.close(r.data);
}

uint32_t reader_pop_descriptor(const reader_t r) {
    return r.pop_descriptor(r.data);
}
