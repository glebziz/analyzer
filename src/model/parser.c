#include "model/parser.h"

bool l4_matcher_match(const l4_matcher m, packet_t *pkt) {
    const uint16_t off = packet_seek(pkt, 0);
    bool ok = m(pkt);
    packet_seek(pkt, off - packet_seek(pkt, 0));

    return ok;
}

void parser_call(const parser_t parser, packet_t *pkt) {
    parser.parse(parser.data, pkt);
}
