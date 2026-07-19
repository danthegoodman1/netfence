//go:build ignore

// Cgroup socket filtering for connect and unconnected-UDP sendmsg hooks.

#include "filter_common.h"

static __always_inline __u8 current_mode(void)
{
    __u32 key = 0;
    __u8 *mode = bpf_map_lookup_elem(&policy_mode, &key);
    return mode ? *mode : 0;
}

static __always_inline int filter_dst4(struct bpf_sock_addr *ctx)
{
    __u32 addr = ctx->user_ip4;
    return filter_ipv4_address((const __u8 *)&addr, current_mode());
}

static __always_inline int filter_dst6(struct bpf_sock_addr *ctx)
{
    __u32 addr[4] = {
        ctx->user_ip6[0], ctx->user_ip6[1],
        ctx->user_ip6[2], ctx->user_ip6[3],
    };
    return filter_ipv6_address((const __u8 *)addr, current_mode());
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

// An explicit destination on sendto/sendmsg bypasses the connect hooks.
// Connected send()/write() supplies no address and skips these hooks.
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
