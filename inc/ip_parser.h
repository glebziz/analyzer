#pragma once

#include "model/parser.h"

typedef struct ip_parser_t ip_parser_t;

ip_parser_t *ip_parser_init();

void ip_parser_free(ip_parser_t **p);

int ip_parser_add_parser(ip_parser_t *p, parser_t parser);

parser_t ip_parser(ip_parser_t *p);

parser_t ip6_parser(ip_parser_t *p);
