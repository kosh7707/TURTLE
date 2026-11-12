// SPDX-License-Identifier: GPL-2.0
// 실행 소유 네임스페이스의 TCP 재전송과 지정 바이트 최초 손실만 관측합니다.
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// CO-RE가 실행 커널 BTF의 필드 위치를 결정합니다. 고정 오프셋이 아닙니다.
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
struct ns_common { unsigned int inum; };
struct net { struct ns_common ns; };
typedef struct { struct net *net; } possible_net_t;
struct sock_common {
    unsigned short skc_family;
    unsigned short skc_num, skc_dport;
    unsigned int skc_rcv_saddr, skc_daddr;
    possible_net_t skc_net;
};
struct sock { struct sock_common __sk_common; };
struct net_device { possible_net_t nd_net; int ifindex; };
struct sk_buff {
    char cb[48];
    struct net_device *dev;
    unsigned char *head;
    unsigned short network_header;
};
struct tcp_skb_cb { __u32 seq, end_seq; __u8 tcp_flags; };
#pragma clang attribute pop
enum skb_drop_reason { SKB_DROP_REASON_QDISC_DROP = 1 };

struct config {
    __u32 client_ns, server_ns, router_ns, c2s_ifindex, s2c_ifindex, reserved;
    __u64 c2s_target, s2c_target;
};
struct flow { __u32 saddr, daddr; __u16 sport, dport; };
struct flow_state { __u32 base, dropped; };
struct event {
    __u64 monotonic_ns;
    struct flow flow;
    __u32 kind, netns, ifindex, seq, end_seq, base, flags;
    __s32 result;
    __u32 reserved;
};
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct config); } settings SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 8192);
    __type(key, struct flow); __type(value, struct flow_state); } flows SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 22); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 3);
    __type(key, __u32); __type(value, __u64); } failures SEC(".maps");

static __always_inline void failure(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&failures, &index);
    if (value) __sync_fetch_and_add(value, 1);
}
static __always_inline void emit(struct event *value)
{
    struct event *entry = bpf_ringbuf_reserve(&events, sizeof(*entry), 0);
    if (!entry) { failure(0); return; }
    *entry = *value;
    bpf_ringbuf_submit(entry, 0);
}
static __always_inline int tls_flow(struct flow *flow)
{
    return (flow->saddr == bpf_htonl(0x0acb0102) && flow->daddr == bpf_htonl(0x0acb0202) &&
            flow->dport == 44330) ||
           (flow->saddr == bpf_htonl(0x0acb0202) && flow->daddr == bpf_htonl(0x0acb0102) &&
            flow->sport == 44330);
}

SEC("tc")
int targeted_drop(struct __sk_buff *skb)
{
    __u32 zero = 0;
    struct config *cfg = bpf_map_lookup_elem(&settings, &zero);
    if (!cfg || (skb->ifindex != cfg->c2s_ifindex && skb->ifindex != cfg->s2c_ifindex))
        return TC_ACT_OK;
    // 고정 veth Ethernet/IPv4/TCP이며 옵션 길이는 실제 헤더에서 읽습니다.
    __u8 eth[14], ip[20], tcp[20];
    if (bpf_skb_load_bytes(skb, 0, eth, sizeof(eth)) || eth[12] != 8 || eth[13] != 0)
        return TC_ACT_OK;
    if (bpf_skb_load_bytes(skb, 14, ip, sizeof(ip)) || (ip[0] >> 4) != 4 || ip[9] != 6)
        return TC_ACT_OK;
    __u32 ihl = (ip[0] & 15) * 4;
    if (ihl < 20 || (ip[6] & 0x3f) || ip[7]) { failure(2); return TC_ACT_OK; }
    if (bpf_skb_load_bytes(skb, 14 + ihl, tcp, sizeof(tcp))) { failure(2); return TC_ACT_OK; }
    struct event event = {};
    __builtin_memcpy(&event.flow.saddr, ip + 12, 4);
    __builtin_memcpy(&event.flow.daddr, ip + 16, 4);
    event.flow.sport = ((__u16)tcp[0] << 8) | tcp[1];
    event.flow.dport = ((__u16)tcp[2] << 8) | tcp[3];
    if (!tls_flow(&event.flow)) return TC_ACT_OK;
    event.seq = ((__u32)tcp[4] << 24) | ((__u32)tcp[5] << 16) | ((__u32)tcp[6] << 8) | tcp[7];
    event.flags = tcp[13];
    if (event.flags & 2) {
        struct flow_state initial = { .base = event.seq + 1 };
        struct flow_state *old = bpf_map_lookup_elem(&flows, &event.flow);
        if (!old || old->base != initial.base)
            if (bpf_map_update_elem(&flows, &event.flow, &initial, BPF_ANY)) failure(1);
        return TC_ACT_OK;
    }
    __u32 total = ((__u32)ip[2] << 8) | ip[3];
    __u32 thl = (tcp[12] >> 4) * 4;
    if (thl < 20 || total < ihl + thl) { failure(2); return TC_ACT_OK; }
    __u32 payload = total - ihl - thl;
    if (!payload) return TC_ACT_OK;
    struct flow_state *state = bpf_map_lookup_elem(&flows, &event.flow);
    if (!state) { failure(1); return TC_ACT_OK; }
    __u64 target = skb->ifindex == cfg->c2s_ifindex ? cfg->c2s_target : cfg->s2c_target;
    __u32 begin = event.seq - state->base;
    if (target == ~0ULL || begin > target || target >= (__u64)begin + payload)
        return TC_ACT_OK;
    if (__sync_val_compare_and_swap(&state->dropped, 0, 1) != 0) return TC_ACT_OK;
    event.monotonic_ns = bpf_ktime_get_ns();
    event.kind = 1; event.netns = cfg->router_ns; event.ifindex = skb->ifindex;
    event.base = state->base; event.reserved = 1;
    event.end_seq = event.seq + payload + !!(event.flags & 1);
    emit(&event);
    return TC_ACT_SHOT;
}

SEC("raw_tp/tcp_retransmit_skb")
int retransmit(struct bpf_raw_tracepoint_args *ctx)
{
    struct sock *sk = (void *)ctx->args[0];
    struct sk_buff *skb = (void *)ctx->args[1];
    __u32 zero = 0;
    struct config *cfg = bpf_map_lookup_elem(&settings, &zero);
    if (!cfg || !sk || !skb) return 0;
    struct event event = {};
    event.netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
    if (event.netns != cfg->client_ns && event.netns != cfg->server_ns) return 0;
    if (BPF_CORE_READ(sk, __sk_common.skc_family) != 2) return 0;
    event.flow.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    event.flow.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    event.flow.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    event.flow.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (!tls_flow(&event.flow)) return 0;
    struct tcp_skb_cb *cb = (void *)__builtin_preserve_access_index(&skb->cb);
    event.seq = BPF_CORE_READ(cb, seq);
    event.end_seq = BPF_CORE_READ(cb, end_seq);
    event.flags = BPF_CORE_READ(cb, tcp_flags);
    struct flow_state *state = bpf_map_lookup_elem(&flows, &event.flow);
    if (state) { event.base = state->base; event.reserved = 1; }
    event.kind = 2; event.monotonic_ns = bpf_ktime_get_ns(); event.result = ctx->args[2];
    emit(&event);
    return 0;
}

// netem의 실제 qdisc 제거를 기록합니다. TC_ACT_SHOT와 별도 종류입니다.
SEC("raw_tp/kfree_skb")
int qdisc_drop(struct bpf_raw_tracepoint_args *ctx)
{
    if (ctx->args[2] != bpf_core_enum_value(enum skb_drop_reason, SKB_DROP_REASON_QDISC_DROP)) return 0;
    struct sk_buff *skb = (void *)ctx->args[0];
    __u32 zero = 0;
    struct config *cfg = bpf_map_lookup_elem(&settings, &zero);
    if (!cfg || !skb) return 0;
    struct net_device *dev = BPF_CORE_READ(skb, dev);
    if (!dev) return 0;
    struct event event = {};
    event.netns = BPF_CORE_READ(dev, nd_net.net, ns.inum);
    if (event.netns != cfg->router_ns) return 0;
    event.ifindex = BPF_CORE_READ(dev, ifindex);
    if (event.ifindex != cfg->c2s_ifindex && event.ifindex != cfg->s2c_ifindex) return 0;
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 nh = BPF_CORE_READ(skb, network_header);
    __u8 ip[20], tcp[20];
    if (bpf_probe_read_kernel(ip, sizeof(ip), head + nh)) { failure(2); return 0; }
    if ((ip[0] >> 4) != 4 || ip[9] != 6) return 0;
    __u32 ihl = (ip[0] & 15) * 4;
    if (ihl < 20 || bpf_probe_read_kernel(tcp, sizeof(tcp), head + nh + ihl)) { failure(2); return 0; }
    __builtin_memcpy(&event.flow.saddr, ip + 12, 4);
    __builtin_memcpy(&event.flow.daddr, ip + 16, 4);
    event.flow.sport = ((__u16)tcp[0] << 8) | tcp[1];
    event.flow.dport = ((__u16)tcp[2] << 8) | tcp[3];
    if (!tls_flow(&event.flow)) return 0;
    event.seq = ((__u32)tcp[4] << 24) | ((__u32)tcp[5] << 16) | ((__u32)tcp[6] << 8) | tcp[7];
    event.flags = tcp[13];
    __u32 total = ((__u32)ip[2] << 8) | ip[3], thl = (tcp[12] >> 4) * 4;
    if (thl < 20 || total < ihl + thl) { failure(2); return 0; }
    event.end_seq = event.seq + total - ihl - thl + !!(event.flags & 2) + !!(event.flags & 1);
    struct flow_state *state = bpf_map_lookup_elem(&flows, &event.flow);
    if (state) { event.base = state->base; event.reserved = 1; }
    event.kind = 3; event.monotonic_ns = bpf_ktime_get_ns(); event.result = ctx->args[2];
    emit(&event);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
