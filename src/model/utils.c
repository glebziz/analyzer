#include "model/utils.h"

#include <string.h>

bool is_subdomain(const char *sub, const char *domain) {
    int sub_len = strlen(sub);
    int domain_len = strlen(domain);

    if (sub_len < domain_len) {
        return false;
    }

    const char *domain_start = sub + sub_len - domain_len;
    if (!strcmp(domain_start, domain)) {
        if (sub_len == domain_len || domain_start[-1] == '.') {
            return true;
        }
    }

    return false;
}
