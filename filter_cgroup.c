//go:build ignore

// eBPF program for filtering outbound network connections (cgroup-based)
// This program attaches to cgroup/connect4 and cgroup/connect6 to filter IPv4 and IPv6 connections
// Use this for container/cgroup-based isolation

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>

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
// Key: prefix length + IPv4 address
// Value: 1 (presence indicates allowed)
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

static __always_inline int is_localhost_v4(__u32 addr)
{
    // 127.0.0.0/8 - in network byte order, first byte is 0x7f
    return (addr & 0x000000ff) == 0x0000007f;
}

static __always_inline int is_link_local_v4(__u32 addr)
{
    // 169.254.0.0/16 - in network byte order: 0xa9fe....
    return (addr & 0x0000ffff) == 0x0000fea9;
}

static __always_inline int is_localhost_v6(__u32 *addr)
{
    // ::1
    return addr[0] == 0 && addr[1] == 0 && 
           addr[2] == 0 && addr[3] == __builtin_bswap32(1);
}

static __always_inline int is_link_local_v6(__u32 *addr)
{
    // fe80::/10
    __u8 first_byte = addr[0] & 0xff;
    __u8 second_byte = (addr[0] >> 8) & 0xff;
    return first_byte == 0xfe && (second_byte & 0xc0) == 0x80;
}

SEC("cgroup/connect4")
int restrict_connect4(struct bpf_sock_addr *ctx)
{
    __u32 key = 0;
    __u8 *mode = bpf_map_lookup_elem(&policy_mode, &key);

    // If no policy mode set or mode is 0 (disabled), allow all
    if (!mode || *mode == 0) {
        return 1;
    }

    // Mode 2 = block all outbound
    if (*mode == 2) {
        increment_stat(1); // blocked
        return 0;
    }

    __u32 dst_ip = ctx->user_ip4;

    // Always allow localhost and link-local
    if (is_localhost_v4(dst_ip) || is_link_local_v4(dst_ip)) {
        increment_stat(0); // allowed
        return 1;
    }

    // Prepare LPM key for lookup
    struct ipv4_lpm_key lpm_key = {
        .prefixlen = 32,
        .addr = dst_ip,
    };

    if (*mode == 1) {
        // Allowlist mode: check if in allowed list
        if (bpf_map_lookup_elem(&allowed_ipv4, &lpm_key)) {
            increment_stat(0); // allowed
            return 1;
        }
        // Not in allowlist - block
        increment_stat(1); // blocked
        return 0;
    }

    if (*mode == 3) {
        // Denylist mode: check if in denied list
        if (bpf_map_lookup_elem(&denied_ipv4, &lpm_key)) {
            increment_stat(1); // blocked
            return 0;
        }
        // Not in denylist - allow
        increment_stat(0); // allowed
        return 1;
    }

    // Unknown mode - default allow
    return 1;
}

SEC("cgroup/connect6")
int restrict_connect6(struct bpf_sock_addr *ctx)
{
    __u32 key = 0;
    __u8 *mode = bpf_map_lookup_elem(&policy_mode, &key);

    // If no policy mode set or mode is 0 (disabled), allow all
    if (!mode || *mode == 0) {
        return 1;
    }

    // Mode 2 = block all outbound
    if (*mode == 2) {
        increment_stat(1); // blocked
        return 0;
    }

    // Get IPv6 address from context
    __u32 dst_ip6[4];
    dst_ip6[0] = ctx->user_ip6[0];
    dst_ip6[1] = ctx->user_ip6[1];
    dst_ip6[2] = ctx->user_ip6[2];
    dst_ip6[3] = ctx->user_ip6[3];

    // Always allow localhost and link-local
    if (is_localhost_v6(dst_ip6) || is_link_local_v6(dst_ip6)) {
        increment_stat(0); // allowed
        return 1;
    }

    // Prepare LPM key for lookup
    struct ipv6_lpm_key lpm_key = {
        .prefixlen = 128,
    };
    lpm_key.addr[0] = dst_ip6[0];
    lpm_key.addr[1] = dst_ip6[1];
    lpm_key.addr[2] = dst_ip6[2];
    lpm_key.addr[3] = dst_ip6[3];

    if (*mode == 1) {
        // Allowlist mode: check if in allowed list
        if (bpf_map_lookup_elem(&allowed_ipv6, &lpm_key)) {
            increment_stat(0); // allowed
            return 1;
        }
        // Not in allowlist - block
        increment_stat(1); // blocked
        return 0;
    }

    if (*mode == 3) {
        // Denylist mode: check if in denied list
        if (bpf_map_lookup_elem(&denied_ipv6, &lpm_key)) {
            increment_stat(1); // blocked
            return 0;
        }
        // Not in denylist - allow
        increment_stat(0); // allowed
        return 1;
    }

    // Unknown mode - default allow
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
