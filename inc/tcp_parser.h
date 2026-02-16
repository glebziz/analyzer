#pragma once

#include "model/parser.h"
#include "model/processor.h"

typedef struct tcp_parser_t tcp_parser_t;

tcp_parser_t *tcp_parser_init(processor_t stream_processor);

void tcp_parser_free(tcp_parser_t **p);

parser_t tcp_parser(tcp_parser_t *p);

int tcp_parser_add_parser(tcp_parser_t *p, parser_t parser);
