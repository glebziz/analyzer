#pragma once

#include <stdbool.h>

#include "packet.h"

#define matcher_l2(HW_PROTO) (matcher){ \
    .m.l2_hw_proto = (HW_PROTO),        \
    .lvl = matcher_lvl_l2               \
}

#define matcher_l3(PROTO) (matcher){    \
    .m.l3_proto = (PROTO),              \
    .lvl = matcher_lvl_l3               \
}

#define matcher_l4(MATCHER) (matcher){  \
    .m.l4_matcher = (MATCHER),          \
    .lvl = matcher_lvl_l4               \
}

#define parser_is_l2(P) ((P).match.lvl == matcher_lvl_l2)
#define parser_is_l3(P) ((P).match.lvl == matcher_lvl_l3)
#define parser_is_l4(P) ((P).match.lvl == matcher_lvl_l4)

#define parser_l2_hw_proto(P) ((P).match.m.l2_hw_proto)
#define parser_l3_proto(P) ((P).match.m.l3_proto)
#define parser_l4_matcher(P) ((P).match.m.l4_matcher)

typedef bool (*l4_matcher)(packet_t *pkt);

typedef struct {
    union {
        uint16_t l2_hw_proto;
        uint8_t l3_proto;
        l4_matcher l4_matcher;
    } m;

    enum {
        matcher_lvl_l2,
        matcher_lvl_l3,
        matcher_lvl_l4
    } lvl;
} matcher;

typedef struct {
    void *data;
    matcher match;

    void (*parse)(void *data, packet_t *pkt);
} parser_t;

bool l4_matcher_match(l4_matcher m, packet_t *pkt);

void parser_call(parser_t parser, packet_t *pkt);
