#include "nftables.h"

#include <stdlib.h>
#include <libmnl/libmnl.h>
#include <libnftnl/set.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include "log.h"
#include "uthash.h"

typedef struct set_t set_t;

typedef struct nftables_t {
    uint64_t seq;

    uint32_t portid;
    struct mnl_socket *nl;

    set_t *sets;
} nftables_t;

typedef struct set_t {
    ip_set_t set;

    UT_hash_handle hh;
} set_t;

static int nftables_add_element(void *data, ip_set_t set, ip_set_element_t element);

static uint16_t map_family(ip_set_family_t family);

static char *family_str(ip_set_family_t family);

static size_t set_element_size(ip_set_element_t element);

static int send_and_receive(nftables_t *nft, void *req, size_t size);

nftables_t *nftables_init() {
    nftables_t *nft = calloc(1, sizeof(nftables_t));
    if (!nft) {
        return NULL;
    }

    nft->nl = mnl_socket_open(NETLINK_NETFILTER);
    if (!nft->nl) {
        goto errL;
    }

    if (mnl_socket_bind(nft->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        return NULL;
    }

    nft->portid = mnl_socket_get_portid(nft->nl);

    return nft;

errL:

    if (nft->nl) {
        mnl_socket_close(nft->nl);
    }

    free(nft);
    return NULL;
}

void nftables_free(nftables_t **nft) {
    if (!nft || !*nft) {
        return;
    }

    if ((*nft)->nl) {
        mnl_socket_close((*nft)->nl);
    }

    set_t *set, *tmp;
    HASH_ITER(hh, (*nft)->sets, set, tmp) {
        HASH_DELETE(hh, (*nft)->sets, set);
        free(set);
    }

    free(*nft);
    *nft = NULL;
}

int nftables_add_set(nftables_t *nft, ip_set_t set) {
    char buf[MNL_SOCKET_BUFFER_SIZE];

    if (!nft) {
        return -1;
    }

    set_t *s;
    HASH_FIND(hh, nft->sets, &set, sizeof(set), s);
    if (s) {
        return 0;
    }

    log_debug("Use nft set %s %s %s", family_str(set.family), set.table, set.name);

    uint32_t seq = nft->seq++;
    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETSET, map_family(set.family), NLM_F_ACK, seq);
    mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_TABLE, set.table);
    mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_SET, set.name);

    if (send_and_receive(nft, buf, sizeof(buf)) < 0) {
        return -1;
    }

    s = calloc(1, sizeof(set_t));
    if (!s) {
        return -1;
    }

    s->set = set;

    HASH_ADD(hh, nft->sets, set, sizeof(s->set), s);

    return 0;
}

ip_set_adder_t nftables_ip_set_adder(nftables_t *nft) {
    return (ip_set_adder_t){
        .data = nft,
        .add_element = nftables_add_element,
    };
}

static int nftables_add_element(void *data, ip_set_t set, ip_set_element_t element) {
    nftables_t *nft = data;
    char buf[MNL_SOCKET_BUFFER_SIZE];

    if (!nft) {
        return -1;
    }

    set_t *s;
    HASH_FIND(hh, nft->sets, &set, sizeof(set), s);
    if (!s) {
        return -1;
    }

    struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), nft->seq++);
    mnl_nlmsg_batch_next(batch);

    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(
        mnl_nlmsg_batch_current(batch),
        NFT_MSG_NEWSETELEM, map_family(set.family),
        NLM_F_ACK | NLM_F_CREATE,
        nft->seq++
    );

    mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_TABLE, set.table);
    mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_SET, set.name);

    struct nlattr *nest1 = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_LIST_ELEMENTS);
    struct nlattr *nest2 = mnl_attr_nest_start(nlh, 0);
    struct nlattr *nest3 = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_KEY);

    mnl_attr_put(nlh, NFTA_DATA_VALUE, set_element_size(element), &element.element);

    mnl_attr_nest_end(nlh, nest3);
    mnl_attr_nest_end(nlh, nest2);
    mnl_attr_nest_end(nlh, nest1);

    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), nft->seq++);
    mnl_nlmsg_batch_next(batch);

    void *req = mnl_nlmsg_batch_head(batch);
    size_t len = mnl_nlmsg_batch_size(batch);
    mnl_nlmsg_batch_stop(batch);

    return send_and_receive(nft, req, len);
}

static uint16_t map_family(const ip_set_family_t family) {
    switch (family) {
        case family_inet:
            return NFPROTO_INET;
        case family_ip:
            return NFPROTO_IPV4;
        case family_ip6:
            return NFPROTO_IPV6;
        default:
            return NFPROTO_UNSPEC;
    }
}

char *family_str(const ip_set_family_t family) {
    switch (family) {
        case family_inet:
            return "inet";
        case family_ip:
            return "ip";
        case family_ip6:
            return "ip6";
        default:
            return "unknown";
    }
}

static size_t set_element_size(const ip_set_element_t element) {
    switch (element.type) {
        case type_ipv4:
            return sizeof(element.element.ipv4);
        case type_ipv6:
            return sizeof(element.element.ipv6);
        default:
            return 0;
    }
}

static int send_and_receive(nftables_t *nft, void *req, const size_t size) {
    char buf[MNL_SOCKET_BUFFER_SIZE];

    int ret = mnl_socket_sendto(nft->nl, req, size);
    if (ret < 0) {
        return -1;
    }

    while ((ret = mnl_socket_recvfrom(nft->nl, buf, sizeof(buf))) > 0) {
        ret = mnl_cb_run(buf, ret, 0, nft->portid, NULL, NULL);
        if (ret <= 0) {
            break;
        }
    }

    return ret < 0 ? -1 : 0;
}
