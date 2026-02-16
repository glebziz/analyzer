#pragma once

#include "model/parser.h"
#include "model/processor.h"

typedef struct tls_parser_t tls_parser_t;

tls_parser_t *tls_parser_init(processor_t processor);

void tls_parser_free(tls_parser_t **p);

parser_t tls_parser(tls_parser_t *p);
