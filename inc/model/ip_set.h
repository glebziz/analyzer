#pragma once

#include <netinet/in.h>

#define ip_set_element_ipv4(ADDR) (ip_set_element_t){   \
    .element.ipv4 = (ADDR),                             \
    .type = type_ipv4,                                  \
}

#define ip_set_element_ipv6(ADDR) (ip_set_element_t){   \
    .element.ipv6 = (ADDR),                             \
    .type = type_ipv6,                                  \
}

typedef enum {
    family_inet,
    family_ip,
    family_ip6
} ip_set_family_t;

typedef struct {
    ip_set_family_t family;
    char table[256];
    char name[256];
} ip_set_t;

typedef struct {
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    } element;

    enum {
        type_ipv4,
        type_ipv6,
    } type;
} ip_set_element_t;

typedef struct {
    void *data;

    int (*add_element)(void *data, ip_set_t set, ip_set_element_t element);
} ip_set_adder_t;

int ip_set_adder_add_element(ip_set_adder_t adder, ip_set_t set, ip_set_element_t element);

void ip_set_element_to_string(ip_set_element_t element, char buf[INET6_ADDRSTRLEN]);
