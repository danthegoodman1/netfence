//go:build ignore

// eBPF program for filtering outbound network connections (TC-based)
// This program attaches to TC egress on specific network interfaces
// Use this for per-interface filtering (e.g., VM tap interfaces like fcr-*)

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// LPM trie key for IPv4 CIDR matching
struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

// LPM trie key for IPv6 CIDR matching
struct ipv6_lpm_key {
    __u32 prefixlen;
    __u32 addr[4];
};

// Map to store allowed IPv4 addresses/CIDRs (LPM trie for prefix matching)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allowed_ipv4 SEC(".maps");

// Map to store denied IPv4 addresses/CIDRs (LPM trie for prefix matching)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} denied_ipv4 SEC(".maps");

// Map to store allowed IPv6 addresses/CIDRs (LPM trie for prefix matching)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __type(key, struct ipv6_lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allowed_ipv6 SEC(".maps");

// Map to store denied IPv6 addresses/CIDRs (LPM trie for prefix matching)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __type(key, struct ipv6_lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} denied_ipv6 SEC(".maps");

// Policy mode:
// 0 = disabled (allow all)
// 1 = allowlist mode (only allowed IPs can be reached, deny all others)
// 2 = block all outbound
// 3 = denylist mode (block denied IPs, allow all others)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} policy_mode SEC(".maps");

// Statistics counters
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2); // 0 = allowed, 1 = blocked
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void increment_stat(__u32 idx)
{
    __u64 *count = bpf_map_lookup_elem(&stats, &idx);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

static __always_inline int is_localhost_v4(__be32 addr)
{
    // 127.0.0.0/8 - check first octet
    return (bpf_ntohl(addr) >> 24) == 127;
}

static __always_inline int is_link_local_v4(__be32 addr)
{
    // 169.254.0.0/16
    __u32 host_addr = bpf_ntohl(addr);
    return (host_addr >> 16) == 0xa9fe;
}

static __always_inline int is_localhost_v6(struct in6_addr *addr)
{
    // ::1
    return addr->in6_u.u6_addr32[0] == 0 && 
           addr->in6_u.u6_addr32[1] == 0 &&
           addr->in6_u.u6_addr32[2] == 0 && 
           addr->in6_u.u6_addr32[3] == bpf_htonl(1);
}

static __always_inline int is_link_local_v6(struct in6_addr *addr)
{
    // fe80::/10
    __u8 first_byte = addr->in6_u.u6_addr8[0];
    __u8 second_byte = addr->in6_u.u6_addr8[1];
    return first_byte == 0xfe && (second_byte & 0xc0) == 0x80;
}

static __always_inline int filter_ipv4(__be32 dst_addr, __u8 mode)
{
    // Always allow localhost and link-local
    if (is_localhost_v4(dst_addr) || is_link_local_v4(dst_addr)) {
        increment_stat(0);
        return TC_ACT_OK;
    }

    // Prepare LPM key - address should be in network byte order
    struct ipv4_lpm_key lpm_key = {
        .prefixlen = 32,
        .addr = dst_addr,
    };

    if (mode == 1) {
        // Allowlist mode
        if (bpf_map_lookup_elem(&allowed_ipv4, &lpm_key)) {
            increment_stat(0);
            return TC_ACT_OK;
        }
        increment_stat(1);
        return TC_ACT_SHOT;
    }

    if (mode == 3) {
        // Denylist mode
        if (bpf_map_lookup_elem(&denied_ipv4, &lpm_key)) {
            increment_stat(1);
            return TC_ACT_SHOT;
        }
        increment_stat(0);
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

static __always_inline int filter_ipv6(struct in6_addr *dst_addr, __u8 mode)
{
    // Always allow localhost and link-local
    if (is_localhost_v6(dst_addr) || is_link_local_v6(dst_addr)) {
        increment_stat(0);
        return TC_ACT_OK;
    }

    // Prepare LPM key
    struct ipv6_lpm_key lpm_key = {
        .prefixlen = 128,
    };
    lpm_key.addr[0] = dst_addr->in6_u.u6_addr32[0];
    lpm_key.addr[1] = dst_addr->in6_u.u6_addr32[1];
    lpm_key.addr[2] = dst_addr->in6_u.u6_addr32[2];
    lpm_key.addr[3] = dst_addr->in6_u.u6_addr32[3];

    if (mode == 1) {
        // Allowlist mode
        if (bpf_map_lookup_elem(&allowed_ipv6, &lpm_key)) {
            increment_stat(0);
            return TC_ACT_OK;
        }
        increment_stat(1);
        return TC_ACT_SHOT;
    }

    if (mode == 3) {
        // Denylist mode
        if (bpf_map_lookup_elem(&denied_ipv6, &lpm_key)) {
            increment_stat(1);
            return TC_ACT_SHOT;
        }
        increment_stat(0);
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

SEC("tc")
int filter_egress(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u8 *mode = bpf_map_lookup_elem(&policy_mode, &key);

    // If no policy mode set or mode is 0 (disabled), allow all
    if (!mode || *mode == 0) {
        return TC_ACT_OK;
    }

    // Mode 2 = block all outbound
    if (*mode == 2) {
        increment_stat(1);
        return TC_ACT_SHOT;
    }

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK; // Invalid packet, let it through
    }

    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    if (eth_proto == ETH_P_IP) {
        // IPv4
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) {
            return TC_ACT_OK;
        }
        return filter_ipv4(iph->daddr, *mode);
    } 
    else if (eth_proto == ETH_P_IPV6) {
        // IPv6
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) {
            return TC_ACT_OK;
        }
        return filter_ipv6(&ip6h->daddr, *mode);
    }

    // Non-IP traffic - allow
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
