#include "model/ip_set.h"

#include <stdio.h>
#include <arpa/inet.h>

int ip_set_adder_add_element(const ip_set_adder_t adder, const ip_set_t set, const ip_set_element_t element) {
    return adder.add_element(adder.data, set, element);
}

void ip_set_element_to_string(const ip_set_element_t element, char buf[INET6_ADDRSTRLEN]) {
    switch (element.type) {
        case type_ipv4:
            inet_ntop(AF_INET, &element.element.ipv4, buf, INET6_ADDRSTRLEN);
            break;
        case type_ipv6:
            inet_ntop(AF_INET6, &element.element.ipv6, buf, INET6_ADDRSTRLEN);
            break;
        default:
            sprintf(buf, "Unknown address");
    }
}
