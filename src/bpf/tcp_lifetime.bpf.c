// SPDX-License-Identifier: GPL-2.0
// Copyright: Eishun Kondoh

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/version.h>

#define ETH_P_IP 0x0800
#define ETH_HLEN 14

struct session {
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;
};

struct tcp_lifetime {
  struct session session;
  u64 duration;
};

struct tcp_lifetime _event = {0};
struct session _session = {0};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct session);
  __type(value, u64);
} established SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("socket")
int measure_tcp_lifetime(struct __sk_buff *skb) {
  struct iphdr ip4;
  struct tcphdr tcp;

  if (bpf_ntohs(skb->protocol) != ETH_P_IP) return 0;
  if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip4, sizeof(ip4)) < 0) return 0;
  if (ip4.ihl != 5 || ip4.protocol != IPPROTO_TCP) return 0;
  if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(ip4), &tcp, sizeof(tcp)) < 0)
    return 0;

  struct session session = {.saddr = bpf_ntohl(ip4.saddr),
                            .daddr = bpf_ntohl(ip4.daddr),
                            .sport = bpf_ntohs(tcp.source),
                            .dport = bpf_ntohs(tcp.dest)};

  if (tcp.syn) {
    u64 curr = bpf_ktime_get_ns();
    bpf_map_update_elem(&established, &session, &curr, 0);
  }

  if (tcp.fin || tcp.rst) {
    u64 *time_syn;
    struct tcp_lifetime event = {};
    time_syn = bpf_map_lookup_elem(&established, &session);

    if (!time_syn) return 0;

    bpf_map_delete_elem(&established, &session);
    event.session = session;
    event.duration = bpf_ktime_get_ns() - *time_syn;
    int rc = bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event,
                                   sizeof(event));
    if (rc != 0) bpf_printk("perf event output failure: %d\n", rc);
  }

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
