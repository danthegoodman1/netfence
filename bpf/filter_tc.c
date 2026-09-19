//go:build ignore

// TC packet filtering. Hook-independent policy lives in filter_common.h;
// this file only identifies the packet's destination address.

#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_endian.h>

#include "filter_common.h"

struct vlan_tag {
    __be16 tci;
    __be16 encapsulated_proto;
};

// Only resolver traffic needs transport parsing. Fragments and IPv6 extension
// chains at that address are rejected: their destination port cannot be proven
// without reassembly. Ordinary traffic retains the address-only fast path.
static __always_inline int resolver_transport(struct __sk_buff *skb,
        const struct resolver_endpoint_config *g, __u8 proto, __u32 off, __u32 base)
{
    if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) return 0;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) return 1;
    __be16 ports[2];
    if (bpf_skb_load_bytes_relative(skb, off, ports, sizeof(ports), base)) return 1;
    return resolver_wrong_port(g, bpf_ntohs(ports[1]));
}

static __always_inline int tc_ipv4(struct __sk_buff *skb, const struct iphdr *iph,
        __u8 mode, __u32 off, __u32 base, const struct resolver_endpoint_config *g)
{
    if (resolver_address4(g, (const __u8 *)&iph->daddr) &&
        (iph->version != 4 || iph->ihl < 5 || (bpf_ntohs(iph->frag_off) & 0x3fff) ||
         resolver_transport(skb, g, iph->protocol, off + iph->ihl * 4, base))) {
        increment_stat(1);
        return TC_ACT_SHOT;
    }
    return filter_ipv4_address((const __u8 *)&iph->daddr, mode) ? TC_ACT_OK : TC_ACT_SHOT;
}

static __always_inline int tc_ipv6(struct __sk_buff *skb, const struct ipv6hdr *iph,
        __u8 mode, __u32 off, __u32 base, const struct resolver_endpoint_config *g)
{
    if (resolver_address6(g, (const __u8 *)&iph->daddr) &&
        (iph->version != 6 || resolver_transport(skb, g, iph->nexthdr, off + sizeof(*iph), base))) {
        increment_stat(1);
        return TC_ACT_SHOT;
    }
    return filter_ipv6_address((const __u8 *)&iph->daddr, mode) ? TC_ACT_OK : TC_ACT_SHOT;
}

SEC("tc")
int filter_egress(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u8 *mode = bpf_map_lookup_elem(&policy_mode, &key);
    if (!mode) {
        return TC_ACT_OK;
    }
    // Block-all covers non-IP and malformed traffic before parsing.
    if (*mode == 2) {
        increment_stat(1);
        return TC_ACT_SHOT;
    }

    struct resolver_endpoint_config *g = resolver_config();
    if (*mode == 0 && (!g || !g->family)) return TC_ACT_OK;
    __u16 proto = bpf_ntohs(skb->protocol);
    if (proto == ETH_P_IP) {
        struct iphdr iph;
        if (bpf_skb_load_bytes_relative(skb, 0, &iph, sizeof(iph), BPF_HDR_START_NET)) {
            goto unidentified;
        }
        return tc_ipv4(skb, &iph, *mode, 0, BPF_HDR_START_NET, g);
    }
    if (proto == ETH_P_IPV6) {
        struct ipv6hdr ip6h;
        if (bpf_skb_load_bytes_relative(skb, 0, &ip6h, sizeof(ip6h), BPF_HDR_START_NET)) {
            goto unidentified;
        }
        return tc_ipv6(skb, &ip6h, *mode, 0, BPF_HDR_START_NET, g);
    }

    // Walk at most QinQ from the MAC header when VLAN tags remain in payload.
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
            struct vlan_tag tag;
            if (bpf_skb_load_bytes_relative(skb, off, &tag, sizeof(tag), BPF_HDR_START_MAC)) {
                goto unidentified;
            }
            inner = bpf_ntohs(tag.encapsulated_proto);
            off += sizeof(tag);
        }

        if (inner == ETH_P_IP) {
            struct iphdr iph;
            if (bpf_skb_load_bytes_relative(skb, off, &iph, sizeof(iph), BPF_HDR_START_MAC)) {
                goto unidentified;
            }
            return tc_ipv4(skb, &iph, *mode, off, BPF_HDR_START_MAC, g);
        }
        if (inner == ETH_P_IPV6) {
            struct ipv6hdr ip6h;
            if (bpf_skb_load_bytes_relative(skb, off, &ip6h, sizeof(ip6h), BPF_HDR_START_MAC)) {
                goto unidentified;
            }
            return tc_ipv6(skb, &ip6h, *mode, off, BPF_HDR_START_MAC, g);
        }
        if (inner == ETH_P_ARP) {
            return TC_ACT_OK;
        }
        goto unidentified;
    }

    // ARP remains available for neighbor/gateway resolution in allowlist.
    if (proto == ETH_P_ARP) {
        return TC_ACT_OK;
    }

unidentified:
    // Unidentified traffic is closed only in allowlist; denylist blocks only
    // identified IP destinations present in its deny maps.
    if (*mode == 1 || (g && g->family &&
        (proto == ETH_P_IP || proto == ETH_P_IPV6 ||
         proto == ETH_P_8021Q || proto == ETH_P_8021AD))) {
        increment_stat(1);
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
