#ifndef NETFENCE_FILTER_COMMON_H
#define NETFENCE_FILTER_COMMON_H

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>

// Byte-array addresses make the map ABI explicitly network-order on every
// userspace and BPF target. The layout remains prefixlen followed by 4/16
// address bytes, matching existing pinned maps.
struct ipv4_lpm_key {
    __u32 prefixlen;
    __u8 addr[4];
};

struct ipv6_lpm_key {
    __u32 prefixlen;
    __u8 addr[16];
};

_Static_assert(sizeof(struct ipv4_lpm_key) == 8, "IPv4 LPM key ABI changed");
_Static_assert(sizeof(struct ipv6_lpm_key) == 20, "IPv6 LPM key ABI changed");

#define LPM_MAP(name, key_type)                    \
struct {                                           \
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);           \
    __uint(max_entries, 4096);                     \
    __type(key, key_type);                         \
    __type(value, __u8);                           \
    __uint(map_flags, BPF_F_NO_PREALLOC);          \
} name SEC(".maps")

LPM_MAP(allowed_ipv4, struct ipv4_lpm_key);
LPM_MAP(denied_ipv4, struct ipv4_lpm_key);
LPM_MAP(allowed_ipv6, struct ipv6_lpm_key);
LPM_MAP(denied_ipv6, struct ipv6_lpm_key);

// DNS-derived hosts live in separate HASH maps. Userspace owns deterministic
// TTL/LRU reclamation; the kernel never evicts protected LPM entries.
#define EXACT_MAP(name, size)                      \
struct {                                           \
    __uint(type, BPF_MAP_TYPE_HASH);               \
    __uint(max_entries, 4096);                     \
    __type(key, __u8[size]);                       \
    __type(value, __u8);                           \
} name SEC(".maps")

EXACT_MAP(dns_allowed_ipv4, 4);
EXACT_MAP(dns_allowed_ipv6, 16);

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} policy_mode SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2); // 0 = allowed, 1 = blocked
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Commit-last pinned schema marker; not consulted on the packet path.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} pin_schema_version SEC(".maps");

#define CARVEOUT_LOCALHOST_V4  (1 << 0)
#define CARVEOUT_LOCALHOST_V6  (1 << 1)
#define CARVEOUT_LINK_LOCAL_V4 (1 << 2)
#define CARVEOUT_LINK_LOCAL_V6 (1 << 3)
#define CARVEOUT_MULTICAST_V6  (1 << 4)

// Userspace rewrites this load-time constant. IPv4 link-local is deliberately
// absent so the metadata service remains policy-controlled.
volatile const __u32 carveout_flags = CARVEOUT_LOCALHOST_V4 | CARVEOUT_LOCALHOST_V6 |
                                      CARVEOUT_LINK_LOCAL_V6 | CARVEOUT_MULTICAST_V6;

static __always_inline void increment_stat(__u32 idx)
{
    __u64 *count = bpf_map_lookup_elem(&stats, &idx);
    if (count) {
        *count += 1;
    }
}

static __always_inline int is_localhost_v4(const __u8 *addr)
{
    return addr[0] == 127;
}

static __always_inline int is_link_local_v4(const __u8 *addr)
{
    return addr[0] == 169 && addr[1] == 254;
}

static __always_inline int is_localhost_v6(const __u8 *addr)
{
    return addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0 &&
           addr[4] == 0 && addr[5] == 0 && addr[6] == 0 && addr[7] == 0 &&
           addr[8] == 0 && addr[9] == 0 && addr[10] == 0 && addr[11] == 0 &&
           addr[12] == 0 && addr[13] == 0 && addr[14] == 0 && addr[15] == 1;
}

static __always_inline int is_link_local_v6(const __u8 *addr)
{
    return addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80;
}

static __always_inline int is_link_local_multicast_v6(const __u8 *addr)
{
    return addr[0] == 0xff && addr[1] == 0x02;
}

static __always_inline int is_carved_out_v4(const __u8 *addr)
{
    return ((carveout_flags & CARVEOUT_LOCALHOST_V4) && is_localhost_v4(addr)) ||
           ((carveout_flags & CARVEOUT_LINK_LOCAL_V4) && is_link_local_v4(addr));
}

static __always_inline int is_carved_out_v6(const __u8 *addr)
{
    return ((carveout_flags & CARVEOUT_LOCALHOST_V6) && is_localhost_v6(addr)) ||
           ((carveout_flags & CARVEOUT_LINK_LOCAL_V6) && is_link_local_v6(addr)) ||
           ((carveout_flags & CARVEOUT_MULTICAST_V6) && is_link_local_multicast_v6(addr));
}

// Hook-independent destination verdict. Returns one to allow and zero to
// block; hook glue converts that result to its native return code.
static __always_inline int filter_ipv4_address(const __u8 *addr, __u8 mode)
{
    if (mode == 0) {
        return 1;
    }
    if (mode == 2) {
        increment_stat(1);
        return 0;
    }
    if (is_carved_out_v4(addr)) {
        increment_stat(0);
        return 1;
    }

    struct ipv4_lpm_key key = {.prefixlen = 32};
    __builtin_memcpy(key.addr, addr, sizeof(key.addr));
    if (mode == 1) {
        if (bpf_map_lookup_elem(&allowed_ipv4, &key) ||
            bpf_map_lookup_elem(&dns_allowed_ipv4, addr)) {
            increment_stat(0);
            return 1;
        }
        increment_stat(1);
        return 0;
    }
    if (mode == 3) {
        if (bpf_map_lookup_elem(&denied_ipv4, &key)) {
            increment_stat(1);
            return 0;
        }
        increment_stat(0);
    }
    return 1;
}

static __always_inline int filter_ipv6_address(const __u8 *addr, __u8 mode)
{
    if (mode == 0) {
        return 1;
    }
    if (mode == 2) {
        increment_stat(1);
        return 0;
    }
    if (is_carved_out_v6(addr)) {
        increment_stat(0);
        return 1;
    }

    struct ipv6_lpm_key key = {.prefixlen = 128};
    __builtin_memcpy(key.addr, addr, sizeof(key.addr));
    if (mode == 1) {
        if (bpf_map_lookup_elem(&allowed_ipv6, &key) ||
            bpf_map_lookup_elem(&dns_allowed_ipv6, addr)) {
            increment_stat(0);
            return 1;
        }
        increment_stat(1);
        return 0;
    }
    if (mode == 3) {
        if (bpf_map_lookup_elem(&denied_ipv6, &key)) {
            increment_stat(1);
            return 0;
        }
        increment_stat(0);
    }
    return 1;
}

#endif
