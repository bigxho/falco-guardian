#ifndef COMMON_H
#define COMMON_H

#include <linux/types.h>

/* Packet event shared between kernel (eBPF) and userspace (loader.c).
 * It must remain identical on both sides: no pointers, only fixed-size types,
 * for compatibility with the BPF ring buffer. */
struct pkt_event {
    __u64 timestamp_ns;   /* bpf_ktime_get_ns() at capture time */
    __u32 src_ip;         /* network byte order */
    __u32 dst_ip;         /* network byte order */
    __u16 src_port;       /* host byte order, 0 when not TCP/UDP */
    __u16 dst_port;       /* host byte order, 0 when not TCP/UDP */
    __u8  protocol;       /* IPPROTO_TCP / IPPROTO_UDP / IPPROTO_ICMP */
    __u8  direction;      /* 0 = ingress, 1 = egress (reserved for future TC use) */
    __u16 pkt_len;        /* total IP packet length */
    __u8  tcp_flags;      /* bit0 FIN,1 SYN,2 RST,3 PSH,4 ACK,5 URG */
    __u8  _pad[3];
};

#define FALCO_SOCK_PATH "/run/falco-guardian/capture.sock"

#endif /* COMMON_H */
