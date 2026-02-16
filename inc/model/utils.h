#pragma once

#include <stdbool.h>

#define max(a,b) ({          \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b;       \
})

#define min(a,b) ({          \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b;       \
})

#define arr_len(arr) (sizeof(arr) / sizeof(arr[0]))

#define val_or_default(ptr, field, default) ((ptr)? ((ptr)->field) : (default))

bool is_subdomain(const char *sub, const char *domain);
