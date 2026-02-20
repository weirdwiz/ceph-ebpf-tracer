// SPDX-License-Identifier: GPL-2.0
// eBPF program for tracing Ceph RBD block I/O latency and throughput.
// Attaches to block layer tracepoints and filters by RBD device major number.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES 10240
#define MAX_DEVICES 64
#define LOG2_BUCKET_COUNT 32
#define IOSIZE_BUCKET_COUNT 16

#define OP_READ  0
#define OP_WRITE 1
#define OP_OTHER 0xFF

#define MAX_LATENCY_NS (30ULL * 1000000000ULL)

struct inflight_key {
	__u64 sector;
	__u32 dev;
	__u32 __pad;
};

struct inflight_val {
	__u64 start_ns;
	__u32 bytes;
	__u8  op;
	__u8  __pad[3];
};

struct dev_op_key {
	__u32 dev;
	__u8  op;
	__u8  pad[3];
};

struct dev_key {
	__u32 dev;
	__u32 __pad;
};

struct latency_hist {
	__u64 buckets[LOG2_BUCKET_COUNT];
	__u64 total_ns;
	__u64 count;
};

struct io_stats {
	__u64 bytes;
	__u64 ops;
};

struct iosize_hist {
	__u64 read_buckets[IOSIZE_BUCKET_COUNT];
	__u64 write_buckets[IOSIZE_BUCKET_COUNT];
	__u64 read_sum_bytes;
	__u64 write_sum_bytes;
};

struct queue_depth {
	__s64 inflight;
	__u64 errors;
};

const volatile __u32 rbd_major = 252;

// --- Maps ---

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct inflight_key);
	__type(value, struct inflight_val);
} inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DEVICES);
	__type(key, struct dev_op_key);
	__type(value, struct latency_hist);
} io_latency SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_DEVICES);
	__type(key, struct dev_op_key);
	__type(value, struct io_stats);
} io_throughput SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DEVICES);
	__type(key, struct dev_key);
	__type(value, struct iosize_hist);
} io_size_dist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DEVICES);
	__type(key, struct dev_key);
	__type(value, struct queue_depth);
} io_queue_depth SEC(".maps");

// Scratch space for initializing large structs without blowing the 512-byte stack.
// Index 0 = latency_hist scratch, Index 1 = iosize_hist scratch.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct latency_hist); // largest struct (272 bytes)
} scratch SEC(".maps");

static __always_inline __u8 parse_op(const char *rwbs) {
	if (rwbs[0] == 'W')
		return OP_WRITE;
	if (rwbs[0] == 'R')
		return OP_READ;
	// Discard ('D'), flush ('F'), and other ops aren't RBD I/O we care about
	return OP_OTHER;
}

static __always_inline __u32 log2_u64(__u64 v) {
	__u32 r = 0;
	#pragma unroll
	for (int i = 0; i < 32; i++) {
		if (v > 1) {
			v >>= 1;
			r++;
		}
	}
	return r;
}

struct block_rq_issue_args {
	__u16 common_type;
	__u8  common_flags;
	__u8  common_preempt_count;
	__s32 common_pid;
	__u8  common_preempt_lazy_count;
	__u8  __pad[3];
	__u32 dev;
	__u64 sector;
	__u32 nr_sector;
	__u32 bytes;
	__u16 ioprio;
	char rwbs[8];
};

struct block_rq_complete_args {
	__u16 common_type;
	__u8  common_flags;
	__u8  common_preempt_count;
	__s32 common_pid;
	__u8  common_preempt_lazy_count;
	__u8  __pad[3];
	__u32 dev;
	__u64 sector;
	__u32 nr_sector;
	__s32 error;
	__u16 ioprio;
	char rwbs[8];
};

SEC("tracepoint/block/block_rq_issue")
int trace_block_rq_issue(struct block_rq_issue_args *ctx) {
	__u32 dev = ctx->dev;
	if ((dev >> 20) != rbd_major)
		return 0;

	__u8 op = parse_op(ctx->rwbs);
	if (op == OP_OTHER)
		return 0;

	__u32 bytes = ctx->bytes;

	// Track inflight request
	struct inflight_key key;
	__builtin_memset(&key, 0, sizeof(key));
	key.sector = ctx->sector;
	key.dev    = dev;

	struct inflight_val val;
	__builtin_memset(&val, 0, sizeof(val));
	val.start_ns = bpf_ktime_get_ns();
	val.bytes    = bytes;
	val.op       = op;

	bpf_map_update_elem(&inflight, &key, &val, BPF_ANY);

	// Increment queue depth
	struct dev_key dk;
	__builtin_memset(&dk, 0, sizeof(dk));
	dk.dev = dev;

	struct queue_depth *qd = bpf_map_lookup_elem(&io_queue_depth, &dk);
	if (qd) {
		__sync_fetch_and_add(&qd->inflight, 1);
	} else {
		struct queue_depth new_qd = { .inflight = 1 };
		bpf_map_update_elem(&io_queue_depth, &dk, &new_qd, BPF_NOEXIST);
	}

	// I/O size distribution
	struct iosize_hist *sh = bpf_map_lookup_elem(&io_size_dist, &dk);
	if (sh) {
		__u32 bucket = log2_u64(bytes);
		if (bucket >= IOSIZE_BUCKET_COUNT)
			bucket = IOSIZE_BUCKET_COUNT - 1;
		if (op == OP_WRITE) {
			__sync_fetch_and_add(&sh->write_buckets[bucket], 1);
			__sync_fetch_and_add(&sh->write_sum_bytes, bytes);
		} else {
			__sync_fetch_and_add(&sh->read_buckets[bucket], 1);
			__sync_fetch_and_add(&sh->read_sum_bytes, bytes);
		}
	} else {
		// Use scratch map to avoid stack allocation of iosize_hist (256 bytes)
		__u32 scratch_idx = 1;
		struct latency_hist *raw = bpf_map_lookup_elem(&scratch, &scratch_idx);
		if (!raw)
			return 0;
		struct iosize_hist *new_sh = (struct iosize_hist *)raw;
		__builtin_memset(new_sh, 0, sizeof(*new_sh));
		__u32 bucket = log2_u64(bytes);
		if (bucket >= IOSIZE_BUCKET_COUNT)
			bucket = IOSIZE_BUCKET_COUNT - 1;
		if (op == OP_WRITE) {
			new_sh->write_buckets[bucket] = 1;
			new_sh->write_sum_bytes = bytes;
		} else {
			new_sh->read_buckets[bucket] = 1;
			new_sh->read_sum_bytes = bytes;
		}
		bpf_map_update_elem(&io_size_dist, &dk, new_sh, BPF_NOEXIST);
	}

	return 0;
}

SEC("tracepoint/block/block_rq_complete")
int trace_block_rq_complete(struct block_rq_complete_args *ctx) {
	__u32 dev = ctx->dev;
	if ((dev >> 20) != rbd_major)
		return 0;

	// Decrement queue depth and track errors
	struct dev_key dk;
	__builtin_memset(&dk, 0, sizeof(dk));
	dk.dev = dev;

	struct queue_depth *qd = bpf_map_lookup_elem(&io_queue_depth, &dk);
	if (qd) {
		__sync_fetch_and_add(&qd->inflight, -1);
		if (ctx->error != 0)
			__sync_fetch_and_add(&qd->errors, 1);
	}

	// Look up inflight entry
	struct inflight_key ikey;
	__builtin_memset(&ikey, 0, sizeof(ikey));
	ikey.sector = ctx->sector;
	ikey.dev    = dev;

	struct inflight_val *val = bpf_map_lookup_elem(&inflight, &ikey);
	if (!val)
		return 0;

	__u64 delta_ns = bpf_ktime_get_ns() - val->start_ns;
	__u8 op = val->op;
	__u32 bytes = val->bytes;

	bpf_map_delete_elem(&inflight, &ikey);

	if (delta_ns > MAX_LATENCY_NS || delta_ns == 0)
		return 0;

	struct dev_op_key dkey;
	__builtin_memset(&dkey, 0, sizeof(dkey));
	dkey.dev = dev;
	dkey.op  = op;

	// Update latency histogram
	struct latency_hist *hist = bpf_map_lookup_elem(&io_latency, &dkey);
	if (hist) {
		__u32 bucket = log2_u64(delta_ns);
		if (bucket >= LOG2_BUCKET_COUNT)
			bucket = LOG2_BUCKET_COUNT - 1;
		__sync_fetch_and_add(&hist->buckets[bucket], 1);
		__sync_fetch_and_add(&hist->total_ns, delta_ns);
		__sync_fetch_and_add(&hist->count, 1);
	} else {
		// Use scratch map for stack-safe initialization
		__u32 scratch_idx = 0;
		struct latency_hist *new_hist = bpf_map_lookup_elem(&scratch, &scratch_idx);
		if (!new_hist)
			return 0;
		__builtin_memset(new_hist, 0, sizeof(*new_hist));
		__u32 bucket = log2_u64(delta_ns);
		if (bucket >= LOG2_BUCKET_COUNT)
			bucket = LOG2_BUCKET_COUNT - 1;
		new_hist->buckets[bucket] = 1;
		new_hist->total_ns = delta_ns;
		new_hist->count = 1;
		bpf_map_update_elem(&io_latency, &dkey, new_hist, BPF_NOEXIST);
	}

	// Update throughput counters
	struct io_stats *stats = bpf_map_lookup_elem(&io_throughput, &dkey);
	if (stats) {
		stats->bytes += bytes;
		stats->ops += 1;
	} else {
		struct io_stats new_stats = { .bytes = bytes, .ops = 1 };
		bpf_map_update_elem(&io_throughput, &dkey, &new_stats, BPF_NOEXIST);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
