//go:build ignore

// Frozen verbatim from bpf/filter_cgroup.c at d4f5151, before the exact DNS
// tier and pinned schema marker. Keep independent of production BPF sources.

// eBPF program for filtering outbound network connections (cgroup-based)
// This program attaches to cgroup/connect4 and cgroup/connect6 to filter IPv4 and IPv6
// connections, and to cgroup/sendmsg4 and cgroup/sendmsg6 to filter unconnected UDP
// sendto/sendmsg (which never passes through the connect hooks).
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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2); // 0 = allowed, 1 = blocked
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void increment_stat(__u32 idx)
{
    __u64 *count = bpf_map_lookup_elem(&stats, &idx);
    if (count) {
        *count += 1;
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

static __always_inline int is_link_local_multicast_v6(__u32 *addr)
{
    // ff02::/16 (link-local scope multicast, used by NDP)
    __u8 first_byte = addr[0] & 0xff;
    __u8 second_byte = (addr[0] >> 8) & 0xff;
    return first_byte == 0xff && second_byte == 0x02;
}

// Carve-out flags: destination ranges always allowed regardless of
// allowlist/denylist policy (block-all still drops before these checks).
// Must match the carveout* constants in pkg/filter/types.go.
#define CARVEOUT_LOCALHOST_V4  (1 << 0) // 127.0.0.0/8
#define CARVEOUT_LOCALHOST_V6  (1 << 1) // ::1
#define CARVEOUT_LINK_LOCAL_V4 (1 << 2) // 169.254.0.0/16 (incl. metadata service)
#define CARVEOUT_LINK_LOCAL_V6 (1 << 3) // fe80::/10 (NDP)
#define CARVEOUT_MULTICAST_V6  (1 << 4) // ff02::/16 (NDP)

// Set by userspace before load (pkg/filter Carveouts); the JIT folds this
// constant, so gating carve-outs on it costs nothing per packet. The
// initializer is the default posture (v4 link-local intentionally absent so
// the cloud metadata service is subject to policy).
volatile const __u32 carveout_flags = CARVEOUT_LOCALHOST_V4 | CARVEOUT_LOCALHOST_V6 |
                                      CARVEOUT_LINK_LOCAL_V6 | CARVEOUT_MULTICAST_V6;

static __always_inline int is_carved_out_v4(__u32 addr)
{
    if ((carveout_flags & CARVEOUT_LOCALHOST_V4) && is_localhost_v4(addr)) {
        return 1;
    }
    if ((carveout_flags & CARVEOUT_LINK_LOCAL_V4) && is_link_local_v4(addr)) {
        return 1;
    }
    return 0;
}

static __always_inline int is_carved_out_v6(__u32 *addr)
{
    if ((carveout_flags & CARVEOUT_LOCALHOST_V6) && is_localhost_v6(addr)) {
        return 1;
    }
    if ((carveout_flags & CARVEOUT_LINK_LOCAL_V6) && is_link_local_v6(addr)) {
        return 1;
    }
    if ((carveout_flags & CARVEOUT_MULTICAST_V6) && is_link_local_multicast_v6(addr)) {
        return 1;
    }
    return 0;
}

// Shared verdict for IPv4 destinations. Used by both the connect4 and
// sendmsg4 hooks so a rule applies identically to connect() and to
// unconnected UDP sendto/sendmsg. Returns 1 = allow, 0 = block.
static __always_inline int filter_dst4(struct bpf_sock_addr *ctx)
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

    // Configured carve-outs (localhost by default; see carveout_flags)
    if (is_carved_out_v4(dst_ip)) {
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

// Shared verdict for IPv6 destinations. Used by both the connect6 and
// sendmsg6 hooks. Returns 1 = allow, 0 = block.
static __always_inline int filter_dst6(struct bpf_sock_addr *ctx)
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

    // Configured carve-outs (localhost/link-local/ND-multicast by default;
    // see carveout_flags)
    if (is_carved_out_v6(dst_ip6)) {
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

SEC("cgroup/connect4")
int restrict_connect4(struct bpf_sock_addr *ctx)
{
    return filter_dst4(ctx);
}

SEC("cgroup/connect6")
int restrict_connect6(struct bpf_sock_addr *ctx)
{
    return filter_dst6(ctx);
}

// UDP sendto/sendmsg with an explicit destination address never passes
// through the connect hooks, so it must be filtered here. The kernel runs
// this hook whenever a destination address is supplied in the message,
// whether or not the socket is connected — so it also covers sendto() to a
// different address on an already-connected socket, which the connect hooks
// alone would miss. send()/write() on a connected socket supplies no address
// and skips this hook entirely, so the connected warm path is unaffected.
SEC("cgroup/sendmsg4")
int restrict_sendmsg4(struct bpf_sock_addr *ctx)
{
    return filter_dst4(ctx);
}

SEC("cgroup/sendmsg6")
int restrict_sendmsg6(struct bpf_sock_addr *ctx)
{
    return filter_dst6(ctx);
}

char LICENSE[] SEC("license") = "GPL";
