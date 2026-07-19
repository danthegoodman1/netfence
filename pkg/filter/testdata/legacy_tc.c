//go:build ignore

// Frozen verbatim from bpf/filter_tc.c at d4f5151, before the exact DNS tier
// and pinned schema marker. Keep independent of production BPF sources.

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

static __always_inline int is_link_local_multicast_v6(struct in6_addr *addr)
{
    // ff02::/16 (link-local scope multicast, used by NDP)
    return addr->in6_u.u6_addr8[0] == 0xff && addr->in6_u.u6_addr8[1] == 0x02;
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

static __always_inline int is_carved_out_v4(__be32 addr)
{
    if ((carveout_flags & CARVEOUT_LOCALHOST_V4) && is_localhost_v4(addr)) {
        return 1;
    }
    if ((carveout_flags & CARVEOUT_LINK_LOCAL_V4) && is_link_local_v4(addr)) {
        return 1;
    }
    return 0;
}

static __always_inline int is_carved_out_v6(struct in6_addr *addr)
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

static __always_inline int filter_ipv4(__be32 dst_addr, __u8 mode)
{
    // Configured carve-outs (localhost by default; see carveout_flags)
    if (is_carved_out_v4(dst_addr)) {
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
    // Configured carve-outs (localhost/link-local/ND-multicast by default;
    // see carveout_flags)
    if (is_carved_out_v6(dst_addr)) {
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

// 802.1Q/802.1AD VLAN tag as it appears in the packet payload (after the
// ethernet header, or after a preceding tag for QinQ).
struct vlan_tag {
    __be16 tci;
    __be16 encapsulated_proto;
};

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

    __u16 proto = bpf_ntohs(skb->protocol);

    // Kernel-identified IP. skb->protocol covers frames whose VLAN tag the
    // kernel already moved to skb metadata (single-tagged frames at ingress,
    // hardware-offloaded tags at egress) — there it is the INNER protocol —
    // as well as L3 devices (tun/wireguard) that have no ethernet header at
    // all. Reading relative to the kernel-set network header is correct for
    // every one of these without any offset math.
    if (proto == ETH_P_IP) {
        struct iphdr iph;
        if (bpf_skb_load_bytes_relative(skb, 0, &iph, sizeof(iph), BPF_HDR_START_NET)) {
            goto unidentified;
        }
        return filter_ipv4(iph.daddr, *mode);
    }
    if (proto == ETH_P_IPV6) {
        struct ipv6hdr ip6h;
        if (bpf_skb_load_bytes_relative(skb, 0, &ip6h, sizeof(ip6h), BPF_HDR_START_NET)) {
            goto unidentified;
        }
        return filter_ipv6(&ip6h.daddr, *mode);
    }

    // In-payload VLAN tag(s): QinQ frames after the kernel popped the outer
    // tag to metadata, or egress paths without tag offload. Walk the tag
    // chain from the MAC header and filter by the INNER destination address
    // so tagged traffic gets the same policy as untagged traffic.
    if (proto == ETH_P_8021Q || proto == ETH_P_8021AD) {
        __be16 encap;
        __u32 off = ETH_HLEN;

        if (bpf_skb_load_bytes_relative(skb, ETH_HLEN - sizeof(encap), &encap,
                                        sizeof(encap), BPF_HDR_START_MAC)) {
            goto unidentified;
        }

        __u16 inner = bpf_ntohs(encap);
#pragma unroll
        for (int i = 0; i < 2; i++) {
            if (inner != ETH_P_8021Q && inner != ETH_P_8021AD) {
                break;
            }
            struct vlan_tag vt;
            if (bpf_skb_load_bytes_relative(skb, off, &vt, sizeof(vt), BPF_HDR_START_MAC)) {
                goto unidentified;
            }
            inner = bpf_ntohs(vt.encapsulated_proto);
            off += sizeof(vt);
        }

        if (inner == ETH_P_IP) {
            struct iphdr iph;
            if (bpf_skb_load_bytes_relative(skb, off, &iph, sizeof(iph), BPF_HDR_START_MAC)) {
                goto unidentified;
            }
            return filter_ipv4(iph.daddr, *mode);
        }
        if (inner == ETH_P_IPV6) {
            struct ipv6hdr ip6h;
            if (bpf_skb_load_bytes_relative(skb, off, &ip6h, sizeof(ip6h), BPF_HDR_START_MAC)) {
                goto unidentified;
            }
            return filter_ipv6(&ip6h.daddr, *mode);
        }
        if (inner == ETH_P_ARP) {
            return TC_ACT_OK; // see ARP note below
        }
        goto unidentified;
    }

    // ARP must stay allowed in allowlist mode: without it the workload
    // cannot resolve its gateway/neighbor MACs and every allowlisted
    // destination becomes unreachable. (Block-all already dropped above.)
    if (proto == ETH_P_ARP) {
        return TC_ACT_OK;
    }

unidentified:
    // Allowlist mode fails CLOSED: any frame not positively identified as an
    // IP packet (unknown ethertypes, deeper-than-QinQ tag stacks,
    // unparseable headers) is dropped. Denylist/disabled keep the previous
    // allow behavior for non-IP traffic — only listed IPs are blocked there.
    if (*mode == 1) {
        increment_stat(1);
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
