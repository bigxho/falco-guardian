// SPDX-License-Identifier: GPL-2.0
/*
 * capture.bpf.c
 *
 * XDP program that inspects each inbound packet at kernel level, before the
 * network stack, and emits a compact event to a BPF ring buffer consumed by
 * the userspace loader (loader.c).
 *
 * Build note: requires vmlinux.h generated on the target machine with:
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 * (see ebpf/Makefile, target "vmlinux").
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16 MB */
} events SEC(".maps");

SEC("xdp")
int xdp_capture(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS; /* IPv4 only for now; IPv6 is a future extension */

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* ihl is expressed in 4-byte words; validate that it is plausible */
    if (ip->ihl < 5)
        return XDP_PASS;

    struct pkt_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return XDP_PASS; /* ring buffer full: prefer not to slow down network traffic */

    e->timestamp_ns = bpf_ktime_get_ns();
    e->src_ip       = ip->saddr;
    e->dst_ip       = ip->daddr;
    e->protocol     = ip->protocol;
    e->direction    = 0;
    e->pkt_len      = bpf_ntohs(ip->tot_len);
    e->src_port     = 0;
    e->dst_port     = 0;
    e->tcp_flags    = 0;

    void *l4 = (void *)ip + (ip->ihl * 4);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) <= data_end) {
            e->src_port  = bpf_ntohs(tcp->source);
            e->dst_port  = bpf_ntohs(tcp->dest);
            e->tcp_flags = (tcp->fin) | (tcp->syn << 1) | (tcp->rst << 2) |
                           (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) <= data_end) {
            e->src_port = bpf_ntohs(udp->source);
            e->dst_port = bpf_ntohs(udp->dest);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return XDP_PASS; /* never block here; enforcement is handled through iptables by Python */
}
