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

static __always_inline int tc_ipv4(const __u8 *addr, __u8 mode)
{
    return filter_ipv4_address(addr, mode) ? TC_ACT_OK : TC_ACT_SHOT;
}

static __always_inline int tc_ipv6(const __u8 *addr, __u8 mode)
{
    return filter_ipv6_address(addr, mode) ? TC_ACT_OK : TC_ACT_SHOT;
}

SEC("tc")
int filter_egress(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u8 *mode = bpf_map_lookup_elem(&policy_mode, &key);
    if (!mode || *mode == 0) {
        return TC_ACT_OK;
    }
    // Block-all covers non-IP and malformed traffic before parsing.
    if (*mode == 2) {
        increment_stat(1);
        return TC_ACT_SHOT;
    }

    __u16 proto = bpf_ntohs(skb->protocol);
    if (proto == ETH_P_IP) {
        struct iphdr iph;
        if (bpf_skb_load_bytes_relative(skb, 0, &iph, sizeof(iph), BPF_HDR_START_NET)) {
            goto unidentified;
        }
        return tc_ipv4((const __u8 *)&iph.daddr, *mode);
    }
    if (proto == ETH_P_IPV6) {
        struct ipv6hdr ip6h;
        if (bpf_skb_load_bytes_relative(skb, 0, &ip6h, sizeof(ip6h), BPF_HDR_START_NET)) {
            goto unidentified;
        }
        return tc_ipv6((const __u8 *)&ip6h.daddr, *mode);
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
            return tc_ipv4((const __u8 *)&iph.daddr, *mode);
        }
        if (inner == ETH_P_IPV6) {
            struct ipv6hdr ip6h;
            if (bpf_skb_load_bytes_relative(skb, off, &ip6h, sizeof(ip6h), BPF_HDR_START_MAC)) {
                goto unidentified;
            }
            return tc_ipv6((const __u8 *)&ip6h.daddr, *mode);
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
    if (*mode == 1) {
        increment_stat(1);
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
