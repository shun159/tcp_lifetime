// SPDX-License-Identifier: GPL-2.0
// Copyright: Eishun Kondoh

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/version.h>

#define TASK_COMM_LEN 16
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
  u32 pid;
  u8 task[TASK_COMM_LEN];
};

struct command {
  u32 pid;
  u8 task[TASK_COMM_LEN];
};

struct tcp_lifetime _event = {0};
struct session _session = {0};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct session);
  __type(value, u64);
} sessions SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct session);
  __type(value, struct command);
} commands SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u32);
  __type(value, struct sock *);
} socks SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int bpf_call_tcp_v4_connect(struct pt_regs *ctx) {
  struct sock *sk = (void *) PT_REGS_PARM1(ctx);

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tid = pid_tgid;
  
  bpf_map_update_elem(&socks, &tid, &sk, 0);
  return 0; 
}

SEC("kretprobe/tcp_v4_connect")
int bpf_exit_tcp_v4_connect(struct pt_regs *ctx) {
  int rc = PT_REGS_RC(ctx);

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = pid_tgid;

  if (rc != 0) {
    bpf_map_delete_elem(&socks, &tid);
    return 0;
  }

  struct sock **skp = bpf_map_lookup_elem(&socks, &tid);
  if (!skp) return 0;

  struct sock *sk = *skp;
  struct sock_common sc;
  bpf_probe_read(&sc, sizeof(sc), &sk->__sk_common);

  u32 saddr = sc.skc_rcv_saddr;
  u32 daddr = sc.skc_daddr;
  u16 sport = sc.skc_num;
  u16 dport = bpf_ntohs(sc.skc_dport);

  struct session session = {
    .saddr = bpf_ntohl(saddr),
    .daddr = bpf_ntohl(daddr),
    .sport = sport,
    .dport = dport,
  };

  struct command comm = {};
  bpf_get_current_comm(&comm.task, sizeof(comm.task));
  comm.pid = pid;

  bpf_map_update_elem(&commands, &session, &comm, 0);

  return 0;
}

SEC("socket")
int measure_tcp_lifetime(struct __sk_buff *skb) {
  struct iphdr ip4;
  struct tcphdr tcp;

  if (bpf_ntohs(skb->protocol) != ETH_P_IP) return 0;
  if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip4, sizeof(ip4)) < 0) return 0;
  if (ip4.ihl != 5 || ip4.protocol != IPPROTO_TCP) return 0;
  if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(ip4), &tcp, sizeof(tcp)) < 0)
    return 0;

  struct session session = {
    .saddr = bpf_ntohl(ip4.saddr),
    .daddr = bpf_ntohl(ip4.daddr),
    .sport = bpf_ntohs(tcp.source),
    .dport = bpf_ntohs(tcp.dest)
  };

  if (tcp.syn) {
    u64 curr = bpf_ktime_get_ns();
    bpf_map_update_elem(&sessions, &session, &curr, 0);
  }

  if (tcp.fin || tcp.rst) {
    u64 *time_syn;
    struct tcp_lifetime event = {};
    time_syn = bpf_map_lookup_elem(&sessions, &session);
    struct command *cmd = bpf_map_lookup_elem(&commands, &session);
    if (!time_syn) return 0;
    if (!cmd) return 0;

    event.session = session;
    event.pid = cmd->pid;
    bpf_probe_read_kernel_str(&event.task, sizeof(event.task), cmd->task);
    event.duration = bpf_ktime_get_ns() - *time_syn;
    int rc = bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    if (rc != 0) bpf_printk("perf event output failure: %d\n", rc);
    bpf_map_delete_elem(&commands, &session);
    bpf_map_delete_elem(&sessions, &session);
  }

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
