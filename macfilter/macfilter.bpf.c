//
// Created by jannes on 15.09.23.
//
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

typedef unsigned int u32;
typedef unsigned char mac_addr_t[6];

struct callback_ctx {
    int allowed;
    mac_addr_t mac_addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, mac_addr_t);
} whitelist_map SEC(".maps");

int is_mac_addr_equal(unsigned char first_addr[6], unsigned char second_addr[6]) {
    for (int i = 0; i < 6; i++) {
        if (first_addr[i] != second_addr[i]) {
            return 0;
        }
    }
    return 1;
}

static __u64 check_filter(struct bpf_map_info *map, const void *key, void *value, struct callback_ctx *ctx) {
    mac_addr_t addr_from_map;
    bpf_probe_read_kernel(addr_from_map, 6, value);

    mac_addr_t curr_addr;
    bpf_probe_read_kernel(curr_addr, 6, ctx->mac_addr);

    if (is_mac_addr_equal(addr_from_map, curr_addr)) {
        ctx->allowed = 1;
        return 1;
    }
    return 0;
}

int is_mac_address_allowed(mac_addr_t mac_addr) {
    struct callback_ctx data;

    data.allowed = 0;
    bpf_probe_read_kernel(data.mac_addr, 6, mac_addr);

    bpf_for_each_map_elem(&whitelist_map, &check_filter, &data, 0);

    return data.allowed;
}

SEC("xdp")
int hello(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    unsigned char s_addr[6];

    bpf_probe_read_kernel(&s_addr, 6, &(eth->h_source));

    if (is_mac_address_allowed(s_addr)) {
        bpf_printk("Pass!");
        return XDP_PASS;
    }

    return XDP_ABORTED;
}

