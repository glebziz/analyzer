#pragma once

#include "model/ip_set.h"

typedef struct nftables_t nftables_t;

nftables_t *nftables_init();

void nftables_free(nftables_t **nft);

int nftables_add_set(nftables_t *nft, ip_set_t set);

ip_set_adder_t nftables_ip_set_adder(nftables_t *nft);

int ip_set_adder_add_element(ip_set_adder_t adder, ip_set_t set, ip_set_element_t element);
