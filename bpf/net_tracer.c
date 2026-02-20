// SPDX-License-Identifier: GPL-2.0
// eBPF program for tracing Ceph network connections.
// Attaches to tcp_probe and tcp_retransmit_skb tracepoints,
// filters by Ceph port range, and tracks per-OSD RTT and retransmits.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_CONNECTIONS 256

// Ceph port range: msgr2 uses 3300, msgr1 uses 6789, OSDs use 6800+
#define CEPH_PORT_MIN 3300
#define CEPH_PORT_MAX 7300
#define CEPH_MON_PORT 6789
#define CEPH_MSGR2_PORT 3300

// Connection key: destination IP + port identifies an OSD/MON
struct conn_key {
	__u32 daddr;     // destination IPv4 address
	__u16 dport;     // destination port
	__u16 __pad;
};

// Per-connection stats
struct conn_stats {
	__u64 srtt_sum_us;   // sum of smoothed RTT samples in microseconds
	__u64 srtt_count;    // number of RTT samples
	__u32 srtt_min_us;   // minimum observed RTT
	__u32 srtt_max_us;   // maximum observed RTT
	__u64 retransmits;   // retransmit count
	__u64 bytes_sent;    // data_len from tcp_probe (send path)
	__u32 last_cwnd;     // last seen congestion window
	__u32 last_snd_wnd;  // last seen send window
};

// Per-connection stats map
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CONNECTIONS);
	__type(key, struct conn_key);
	__type(value, struct conn_stats);
} ceph_conn_stats SEC(".maps");

static __always_inline int is_ceph_port(__u16 port) {
	// msgr2: 3300, msgr1: 6789, OSD/MDS: 6800-7300
	return (port == CEPH_MSGR2_PORT ||
		port == CEPH_MON_PORT ||
		(port >= 6800 && port <= CEPH_PORT_MAX));
}

// tcp_probe tracepoint context
// From /sys/kernel/debug/tracing/events/tcp/tcp_probe/format
struct tcp_probe_args {
	__u16 common_type;
	__u8  common_flags;
	__u8  common_preempt_count;
	__s32 common_pid;
	__u8  common_preempt_lazy_count;
	__u8  __pad_common[3];

	__u8  saddr[28];     // offset 12, sockaddr_in6 (28 bytes)
	__u8  daddr[28];     // offset 40, sockaddr_in6 (28 bytes)
	__u16 sport;         // offset 68
	__u16 dport;         // offset 70
	__u16 family;        // offset 72
	__u16 __pad1;
	__u32 mark;          // offset 76
	__u16 data_len;      // offset 80
	__u16 __pad2;
	__u32 snd_nxt;       // offset 84
	__u32 snd_una;       // offset 88
	__u32 snd_cwnd;      // offset 92
	__u32 ssthresh;      // offset 96
	__u32 snd_wnd;       // offset 100
	__u32 srtt;          // offset 104 (microseconds, already smoothed)
	__u32 rcv_wnd;       // offset 108
	__u64 sock_cookie;   // offset 112
};

// tcp_retransmit_skb tracepoint context
struct tcp_retransmit_args {
	__u16 common_type;
	__u8  common_flags;
	__u8  common_preempt_count;
	__s32 common_pid;
	__u8  common_preempt_lazy_count;
	__u8  __pad_common[3];
	__u32 __pad_ptr1;    // padding for skbaddr pointer (offset 12->16)

	__u64 skbaddr;       // offset 16 (const void *)
	__u64 skaddr;        // offset 24 (const void *)
	__s32 state;         // offset 32
	__u16 sport;         // offset 36
	__u16 dport;         // offset 38
	__u16 family;        // offset 40
	__u8  saddr[4];      // offset 42 (IPv4)
	__u8  daddr[4];      // offset 46 (IPv4)
	__u8  saddr_v6[16];  // offset 50
	__u8  daddr_v6[16];  // offset 66
};

SEC("tracepoint/tcp/tcp_probe")
int trace_tcp_probe(struct tcp_probe_args *ctx) {
	__u16 dport = ctx->dport;

	if (!is_ceph_port(dport))
		return 0;

	// Extract IPv4 dest address from sockaddr_in6
	// For AF_INET, the IPv4 address is at offset 4 in the sockaddr_in structure
	// sockaddr_in: family(2) + port(2) + addr(4)
	__u32 daddr = 0;
	if (ctx->family == 2) { // AF_INET
		// daddr field contains sockaddr_in6 but for IPv4, address is at bytes 4-7
		daddr = *(__u32 *)&ctx->daddr[4];
	} else {
		return 0; // skip IPv6 for now
	}

	struct conn_key key;
	__builtin_memset(&key, 0, sizeof(key));
	key.daddr = daddr;
	key.dport = dport;

	__u32 srtt = ctx->srtt; // already in microseconds

	struct conn_stats *stats = bpf_map_lookup_elem(&ceph_conn_stats, &key);
	if (stats) {
		__sync_fetch_and_add(&stats->srtt_sum_us, srtt);
		__sync_fetch_and_add(&stats->srtt_count, 1);
		__sync_fetch_and_add(&stats->bytes_sent, ctx->data_len);

		// Update min/max (racy but acceptable for monitoring)
		if (srtt < stats->srtt_min_us || stats->srtt_min_us == 0)
			stats->srtt_min_us = srtt;
		if (srtt > stats->srtt_max_us)
			stats->srtt_max_us = srtt;

		stats->last_cwnd = ctx->snd_cwnd;
		stats->last_snd_wnd = ctx->snd_wnd;
	} else {
		struct conn_stats new_stats;
		__builtin_memset(&new_stats, 0, sizeof(new_stats));
		new_stats.srtt_sum_us = srtt;
		new_stats.srtt_count = 1;
		new_stats.srtt_min_us = srtt;
		new_stats.srtt_max_us = srtt;
		new_stats.bytes_sent = ctx->data_len;
		new_stats.last_cwnd = ctx->snd_cwnd;
		new_stats.last_snd_wnd = ctx->snd_wnd;
		bpf_map_update_elem(&ceph_conn_stats, &key, &new_stats, BPF_NOEXIST);
	}

	return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int trace_tcp_retransmit(struct tcp_retransmit_args *ctx) {
	__u16 dport = ctx->dport;

	if (!is_ceph_port(dport))
		return 0;

	if (ctx->family != 2) // AF_INET only
		return 0;

	__u32 daddr = *(__u32 *)ctx->daddr;

	struct conn_key key;
	__builtin_memset(&key, 0, sizeof(key));
	key.daddr = daddr;
	key.dport = dport;

	struct conn_stats *stats = bpf_map_lookup_elem(&ceph_conn_stats, &key);
	if (stats) {
		__sync_fetch_and_add(&stats->retransmits, 1);
	} else {
		// Create entry even if we haven't seen a tcp_probe yet
		struct conn_stats new_stats;
		__builtin_memset(&new_stats, 0, sizeof(new_stats));
		new_stats.retransmits = 1;
		bpf_map_update_elem(&ceph_conn_stats, &key, &new_stats, BPF_NOEXIST);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
