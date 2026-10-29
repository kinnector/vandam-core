// SPDX-License-Identifier: GPL-2.0-only
// Cloud-tier collectors: per-process network
// accounting and ordinary-file-open folding. Observe-only: every LSM program
// returns 0 and nothing here can deny anything.
//
// A separate object from kinnector.bpf.c, on purpose:
//  * nothing here is pinned, so the links die with the loading process. A crash
//    or a SIGKILL of the daemon leaves no program behind on the machine;
//  * a verifier rejection of any program here can never take the enforcement
//    object down (which has happened before, see core/CLAUDE.md);
//  * it shares no map with the enforcement object, so it needs none of the
//    owner/user pinning semantics that ruled out splitting kinnector.bpf.c.
// Attribution is by (tgid, group-leader start_time). The agent joins that to its
// own process tree and lineage; the kernel knows neither.
//
// Costs, measured on kernel 6.18 (antitheft-cloud/bench/*/RESULTS.md): per-connection
// accounting about 6-8 us per connection, per-call UDP hooks 30-100 ns per call,
// lsm/file_open 26 ns floor plus about 250 ns to fold an in-scope open.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "kinnector/cloud_abi.h"

char LICENSE[] SEC("license") = "GPL";

#define C_AF_INET 2
#define C_AF_INET6 10
#define C_SOCK_STREAM 1
#define C_SOCK_DGRAM 2
#define C_S_IFMT 0170000
#define C_S_IFREG 0100000
#define C_FMODE_WRITE 0x2
#define C_ITER_UBUF 0
#define C_ITER_IOVEC 1
#define SCOPE_MAX_DEPTH 16

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

struct stamp {
	__u64 proc_start;
	__u64 cookie;
	__u64 start_ns;
	__u64 rep_tx;
	__u64 rep_rx;
	__u32 tgid;
	__u8 dir;
	__u8 pad[3];
	// The destination as connect() was asked for it. A refused or reset connect
	// goes through tcp_disconnect(), which zeroes the socket's own destination, so
	// by tcp_close the failed attempt would otherwise have no address at all.
	__u16 family;
	__u16 dport;  // host order
	__u8 daddr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct stamp);
} sk_stamp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, CLOUD_NET_RING_BYTES);
} cloud_rb SEC(".maps");

// Hands every stamped connection a unique id, so the agent can tell a live report
// from the close report of the same connection and turn cumulative counters into
// deltas. One increment per connection, not per packet.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} cookie_ctr SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CLOUD_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} cloud_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CLOUD_UDP_FOLD_MAX);
	__type(key, struct cloud_udp_key);
	__type(value, struct cloud_udp_val);
} udp_fold SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CLOUD_FILE_FOLD_MAX);
	__type(key, struct cloud_file_key);
	__type(value, struct cloud_file_val);
} file_fold SEC(".maps");

// Contract v10: which (process, inode, op) have already added their i_size to a file row, so a
// re-open adds nothing. Never drained (a process's set outlives the 30 s fold windows); an LRU,
// so the bound is machine-wide and an evicted entry just counts once more on its next open.
// The pattern follows Tetragon's ratelimit_map (bpf/process/ratelimit_maps.h), an LRU hash used
// as a "seen recently" set.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, CLOUD_FILE_SEEN_MAX);
	__type(key, struct cloud_file_seen_key);
	__type(value, __u8);
} file_seen SEC(".maps");

// Scope, filled by userspace and never learned: scope_roots are the home
// directories and user-data mounts (value is CLOUD_ROOT_*), skip_dirs are a
// minimal set of pinned locations (caches). Both keyed by (kernel dev, inode).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);  // written by userspace only, rarely
	__uint(max_entries, CLOUD_SCOPE_ROOTS_MAX);
	__type(key, struct cloud_dir_key);
	__type(value, __u8);
} scope_roots SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, CLOUD_SKIP_DIRS_MAX);
	__type(key, struct cloud_dir_key);
	__type(value, __u8);
} skip_dirs SEC(".maps");

struct scope_val {
	__u64 proj_ino;
	__u32 root_kind;
	__u32 in;
};

// The scope verdict is a pure function of the directory, so it is cached per
// leaf directory. A cache of a deterministic classification, not something
// learned. Userspace flushes it (by reloading nothing: it deletes keys) when the
// scope changes.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, CLOUD_SCOPE_CACHE_MAX);
	__type(key, struct cloud_dir_key);
	__type(value, struct scope_val);
} scope_cache SEC(".maps");

// One entry per project folder ever named, never drained: NO_PREALLOC, so its 264 bytes an entry
// are held only for the folders really seen, and a large bound costs nothing up front.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, CLOUD_PROJ_PATH_MAX);
	__type(key, struct cloud_dir_key);
	__type(value, struct cloud_proj_val);
} proj_path SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cloud_proj_val);
} proj_scratch SEC(".maps");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static __always_inline void stat_inc(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&cloud_stats, &idx);
	if (v)
		(*v)++;
}

// The GROUP LEADER's start_time: every per-process key is per process, never per
// thread (core/CLAUDE.md, fifth gotcha).
static __always_inline __u64 leader_start(void)
{
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct task_struct *l = BPF_CORE_READ(t, group_leader);
	return BPF_CORE_READ(l, start_time);
}

// ---------------------------------------------------------------------------
// TCP: stamp the owner at connect/accept, one record at close, a periodic scan
// ---------------------------------------------------------------------------

static __always_inline struct stamp *stamp_new(struct sock *sk, __u8 dir)
{
	struct stamp *s = bpf_sk_storage_get(&sk_stamp, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (!s) {
		stat_inc(CLOUD_STAT_STAMP_FAIL);
		return NULL;
	}
	s->tgid = bpf_get_current_pid_tgid() >> 32;
	s->proc_start = leader_start();
	s->start_ns = bpf_ktime_get_ns();
	s->dir = dir;
	__u32 zero = 0;
	__u64 *ctr = bpf_map_lookup_elem(&cookie_ctr, &zero);
	s->cookie = ctr ? __sync_fetch_and_add(ctr, 1) + 1 : 0;
	return s;
}

SEC("lsm/socket_connect")
int BPF_PROG(cloud_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	struct sock *sk = sock->sk;
	if (!sk)
		return 0;
	if (BPF_CORE_READ(sock, type) != C_SOCK_STREAM)
		return 0;
	unsigned short fam = 0;
	bpf_probe_read_kernel(&fam, sizeof(fam), &address->sa_family);
	if (fam != C_AF_INET && fam != C_AF_INET6)
		return 0;
	struct stamp *s = stamp_new(sk, CLOUD_DIR_OUT);
	if (!s)
		return 0;
	s->family = fam;
	if (fam == C_AF_INET) {
		struct sockaddr_in sin = {};
		bpf_probe_read_kernel(&sin, sizeof(sin), address);
		s->dport = bpf_ntohs(sin.sin_port);
		__builtin_memset(s->daddr, 0, sizeof(s->daddr));
		__builtin_memcpy(s->daddr, &sin.sin_addr, 4);
	} else {
		struct sockaddr_in6 sin6 = {};
		bpf_probe_read_kernel(&sin6, sizeof(sin6), address);
		s->dport = bpf_ntohs(sin6.sin6_port);
		__builtin_memcpy(s->daddr, &sin6.sin6_addr, 16);
	}
	return 0;
}

// The new socket does not exist yet at lsm/socket_accept, so this is the return
// of inet_csk_accept. Typed for 6.18 (arg struct proto_accept_arg); the loader
// treats a verifier rejection on another kernel as "no inbound coverage".
SEC("fexit/inet_csk_accept")
int BPF_PROG(cloud_accept, struct sock *sk, struct proto_accept_arg *arg, struct sock *newsk)
{
	if (!newsk)
		return 0;
	stamp_new(newsk, CLOUD_DIR_IN);
	return 0;
}

static __always_inline void fill_tcp(struct cloud_net_rec *r, struct sock_common *skc, struct tcp_sock *tp,
				     struct stamp *s, __u8 kind)
{
	__u16 fam = BPF_CORE_READ(skc, skc_family);
	r->family = fam;
	r->dport = bpf_ntohs(BPF_CORE_READ(skc, skc_dport));
	r->lport = BPF_CORE_READ(skc, skc_num);
	__builtin_memset(r->daddr, 0, sizeof(r->daddr));
	if (fam == C_AF_INET) {
		__u32 a = BPF_CORE_READ(skc, skc_daddr);
		__builtin_memcpy(r->daddr, &a, 4);
	} else if (fam == C_AF_INET6) {
		bpf_probe_read_kernel(r->daddr, 16, &skc->skc_v6_daddr);
	}
	// A failed connect() had its destination wiped by tcp_disconnect(): fall back
	// to the one recorded when the connect was issued.
	if (r->dport == 0 && s->dport != 0) {
		r->family = s->family;
		r->dport = s->dport;
		__builtin_memcpy(r->daddr, s->daddr, sizeof(r->daddr));
	}
	r->tx =bpf_core_field_exists(tp->bytes_sent) ? BPF_CORE_READ(tp, bytes_sent) : BPF_CORE_READ(tp, bytes_acked);
	r->rx = BPF_CORE_READ(tp, bytes_received);
	r->tgid = s->tgid;
	r->proc_start = s->proc_start;
	r->cookie = s->cookie;
	r->kind = kind;
	r->dir = s->dir;
	r->dur_ns = bpf_ktime_get_ns() - s->start_ns;
	r->flags = 0;
	r->err = 0;
	// rcv_nxt is only set once the peer's SYN (or, for a child socket, the
	// request) has been seen: zero means the handshake never completed.
	if (BPF_CORE_READ(tp, rcv_nxt) != 0)
		r->flags |= CLOUD_F_ESTABLISHED;
	int e = BPF_CORE_READ((struct sock *)skc, sk_err);
	if (e) {
		r->flags |= CLOUD_F_ERROR;
		r->err = e;
	}
}

SEC("fentry/tcp_close")
int BPF_PROG(cloud_tcp_close, struct sock *sk, long timeout)
{
	struct stamp *s = bpf_sk_storage_get(&sk_stamp, sk, 0, 0);
	if (!s)
		return 0;
	struct tcp_sock *tp = bpf_skc_to_tcp_sock(sk);
	if (!tp)
		return 0;
	struct cloud_net_rec *r = bpf_ringbuf_reserve(&cloud_rb, sizeof(*r), 0);
	if (!r) {
		stat_inc(CLOUD_STAT_NET_RING_FULL);
		return 0;
	}
	fill_tcp(r, (struct sock_common *)sk, tp, s, CLOUD_REC_TCP_CLOSE);
	bpf_ringbuf_submit(r, 0);
	return 0;
}

// Periodic scan of live connections, emitting only those whose counters changed
// since the last scan, so a long-lived transfer shows up while it is happening.
SEC("iter/tcp")
int cloud_tcp_scan(struct bpf_iter__tcp *ctx)
{
	struct sock_common *skc = ctx->sk_common;
	if (!skc)
		return 0;
	struct tcp_sock *tp = bpf_skc_to_tcp_sock(skc);
	if (!tp)
		return 0;
	struct stamp *s = bpf_sk_storage_get(&sk_stamp, skc, 0, 0);
	if (!s)
		return 0;
	__u64 tx = bpf_core_field_exists(tp->bytes_sent) ? BPF_CORE_READ(tp, bytes_sent) : BPF_CORE_READ(tp, bytes_acked);
	__u64 rx = BPF_CORE_READ(tp, bytes_received);
	if (tx == s->rep_tx && rx == s->rep_rx)
		return 0;
	struct cloud_net_rec *r = bpf_ringbuf_reserve(&cloud_rb, sizeof(*r), 0);
	if (!r) {
		stat_inc(CLOUD_STAT_NET_RING_FULL);
		return 0;
	}
	fill_tcp(r, skc, tp, s, CLOUD_REC_TCP_LIVE);
	// The records above carry cumulative counters; the scan advances the marker
	// so the next scan only reports connections that moved again. The close
	// record still carries the connection's full totals.
	s->rep_tx = tx;
	s->rep_rx = rx;
	bpf_ringbuf_submit(r, 0);
	return 0;
}

// ---------------------------------------------------------------------------
// UDP: the kernel keeps no per-socket byte counters, so per-call accounting is
// unavoidable here. Folded per (process, peer) in a map, drained by userspace.
// ---------------------------------------------------------------------------

struct peer {
	__u16 family;
	__u16 port;  // host order
	__u8 addr[16];
};

// Where a datagram goes (send) or came from (recv, valid after the call). Falls
// back to the socket's connected peer when the message carries no address.
static __always_inline int udp_peer(struct sock *sk, struct msghdr *msg, struct peer *p)
{
	__builtin_memset(p, 0, sizeof(*p));
	void *name = BPF_CORE_READ(msg, msg_name);
	if (name) {
		unsigned short fam = 0;
		bpf_probe_read_kernel(&fam, sizeof(fam), name);
		if (fam == C_AF_INET) {
			struct sockaddr_in sin = {};
			bpf_probe_read_kernel(&sin, sizeof(sin), name);
			p->family = C_AF_INET;
			p->port = bpf_ntohs(sin.sin_port);
			__builtin_memcpy(p->addr, &sin.sin_addr, 4);
			return 1;
		}
		if (fam == C_AF_INET6) {
			struct sockaddr_in6 sin6 = {};
			bpf_probe_read_kernel(&sin6, sizeof(sin6), name);
			p->family = C_AF_INET6;
			p->port = bpf_ntohs(sin6.sin6_port);
			__builtin_memcpy(p->addr, &sin6.sin6_addr, 16);
			return 1;
		}
	}
	__u16 fam = BPF_CORE_READ(sk, __sk_common.skc_family);
	__u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	if (!dport)
		return 0;  // unconnected and no address: nothing to attribute
	p->port = bpf_ntohs(dport);
	if (fam == C_AF_INET) {
		__u32 a = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		p->family = C_AF_INET;
		__builtin_memcpy(p->addr, &a, 4);
		return 1;
	}
	if (fam == C_AF_INET6) {
		p->family = C_AF_INET6;
		bpf_probe_read_kernel(p->addr, 16, &sk->__sk_common.skc_v6_daddr);
		return 1;
	}
	return 0;
}

static __always_inline void udp_account(struct sock *sk, struct msghdr *msg, long bytes, __u8 dir)
{
	if (bytes <= 0)
		return;
	struct peer p;
	if (!udp_peer(sk, msg, &p))
		return;
	struct cloud_udp_key k = {};
	k.proc_start = leader_start();
	k.tgid = bpf_get_current_pid_tgid() >> 32;
	k.dport = p.port;
	k.family = p.family;
	__builtin_memcpy(k.daddr, p.addr, 16);
	__u64 now = bpf_ktime_get_ns();

	struct cloud_udp_val *v = bpf_map_lookup_elem(&udp_fold, &k);
	if (!v) {
		struct cloud_udp_val nv = {};
		nv.first_ns = now;
		nv.dir = dir;
		nv.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
		if (bpf_map_update_elem(&udp_fold, &k, &nv, BPF_NOEXIST)) {
			v = bpf_map_lookup_elem(&udp_fold, &k);  // lost a race with another CPU
			if (!v) {
				stat_inc(CLOUD_STAT_UDP_MAP_FULL);
				return;
			}
		} else {
			v = bpf_map_lookup_elem(&udp_fold, &k);
			if (!v)
				return;
		}
	}
	if (dir == CLOUD_DIR_OUT)
		__sync_fetch_and_add(&v->tx, bytes);
	else
		__sync_fetch_and_add(&v->rx, bytes);
	__sync_fetch_and_add(&v->pkts, 1);
	v->last_ns = now;
}

SEC("fexit/udp_sendmsg")
int BPF_PROG(cloud_udp_send, struct sock *sk, struct msghdr *msg, size_t len, int ret)
{
	udp_account(sk, msg, ret, CLOUD_DIR_OUT);
	return 0;
}

SEC("fexit/udpv6_sendmsg")
int BPF_PROG(cloud_udp6_send, struct sock *sk, struct msghdr *msg, size_t len, int ret)
{
	udp_account(sk, msg, ret, CLOUD_DIR_OUT);
	return 0;
}

// udp_recvmsg lost its `int *addr_len` parameter in 6.13, so its arity differs
// across kernels. Only sk and msg are declared here; the return value comes from
// bpf_get_func_ret(), which does not care how many arguments there are (the same
// approach core/kinnector.bpf.c takes for vfs_symlink).
SEC("fexit/udp_recvmsg")
int BPF_PROG(cloud_udp_recv, struct sock *sk, struct msghdr *msg)
{
	__u64 ret = 0;
	if (bpf_get_func_ret(ctx, &ret))
		return 0;
	udp_account(sk, msg, (long)ret, CLOUD_DIR_IN);
	return 0;
}

SEC("fexit/udpv6_recvmsg")
int BPF_PROG(cloud_udp6_recv, struct sock *sk, struct msghdr *msg)
{
	__u64 ret = 0;
	if (bpf_get_func_ret(ctx, &ret))
		return 0;
	udp_account(sk, msg, (long)ret, CLOUD_DIR_IN);
	return 0;
}

// DNS names, so a destination is more than a bare address. The payload has to be
// read at ENTRY: by the time the call returns the iterator has been advanced past
// it. Only sends to port 53 are looked at.
static __always_inline void dns_capture(struct sock *sk, struct msghdr *msg, size_t len)
{
	if (len < 12)
		return;
	struct peer p;
	if (!udp_peer(sk, msg, &p) || p.port != 53)
		return;
	void *buf = NULL;
	__u8 it = BPF_CORE_READ(msg, msg_iter.iter_type);
	if (it == C_ITER_UBUF) {
		buf = BPF_CORE_READ(msg, msg_iter.ubuf);
	} else if (it == C_ITER_IOVEC) {
		const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
		if (iov)
			bpf_probe_read_kernel(&buf, sizeof(buf), &iov->iov_base);
	}
	if (!buf)
		return;
	struct cloud_dns_rec *r = bpf_ringbuf_reserve(&cloud_rb, sizeof(*r), 0);
	if (!r) {
		stat_inc(CLOUD_STAT_DNS_RING_FULL);
		return;
	}
	if (bpf_probe_read_user(r->payload, CLOUD_DNS_PAYLOAD, buf) < 0) {
		bpf_ringbuf_discard(r, 0);
		return;
	}
	r->kind = CLOUD_REC_DNS;
	r->pad = 0;
	r->len = len < CLOUD_DNS_PAYLOAD ? len : CLOUD_DNS_PAYLOAD;
	r->tgid = bpf_get_current_pid_tgid() >> 32;
	r->proc_start = leader_start();
	bpf_ringbuf_submit(r, 0);
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(cloud_dns4, struct sock *sk, struct msghdr *msg, size_t len)
{
	dns_capture(sk, msg, len);
	return 0;
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(cloud_dns6, struct sock *sk, struct msghdr *msg, size_t len)
{
	dns_capture(sk, msg, len);
	return 0;
}

// ---------------------------------------------------------------------------
// Files: fold ordinary opens by project folder
// ---------------------------------------------------------------------------

// Filesystems that are open storms with no user data: container layers, kernel
// pseudo filesystems, in-memory filesystems, read-only application images.
static __always_inline int skip_fs(unsigned long magic)
{
	switch (magic) {
	case 0x794c7630: /* overlayfs */
	case 0x9fa0:     /* proc */
	case 0x62656572: /* sysfs */
	case 0x01021994: /* tmpfs */
	case 0x858458f6: /* ramfs */
	case 0x27e0eb:   /* cgroup */
	case 0x63677270: /* cgroup2 */
	case 0x64626720: /* debugfs */
	case 0x74726163: /* tracefs */
	case 0x73636673: /* securityfs */
	case 0x6165676c: /* pstore */
	case 0xcafe4a11: /* bpf */
	case 0x1cd1:     /* devpts */
	case 0x73717368: /* squashfs */
		return 1;
	}
	return 0;
}

// 1 = in scope, with the project folder and root kind filled in. Walks at most
// SCOPE_MAX_DEPTH ancestors, starting at `start` (the immediate parent directory's own
// dentry): a skipped directory or the filesystem root ends it out of scope, a registered
// root ends it in scope. The project folder is the one two levels under the root (or the
// root's child, or the root itself), so node_modules, .git and build output fold into
// their project's row on their own. Factored out of resolve_scope() (v7) so
// the move/link/symlink hooks can scope-check a DESTINATION directory they only have as
// an (inode*, dentry*) pair, with no struct file* to derive one from.
static __always_inline int resolve_scope_from(struct dentry *start, __u64 dev, unsigned long magic,
					      struct scope_val *out)
{
	__builtin_memset(out, 0, sizeof(*out));
	if (skip_fs(magic))
		return 0;
	struct dentry *cur = start;
	struct cloud_dir_key k = { .dev = dev };
	__u64 a1 = 0, a2 = 0;
#pragma unroll
	for (int i = 0; i < SCOPE_MAX_DEPTH; i++) {
		if (!cur)
			return 0;
		struct inode *ci = BPF_CORE_READ(cur, d_inode);
		if (!ci)
			return 0;
		k.ino = BPF_CORE_READ(ci, i_ino);
		if (bpf_map_lookup_elem(&skip_dirs, &k))
			return 0;
		__u8 *rk = bpf_map_lookup_elem(&scope_roots, &k);
		if (rk) {
			out->in = 1;
			out->root_kind = *rk;
			out->proj_ino = a2 ? a2 : (a1 ? a1 : k.ino);
			return 1;
		}
		struct dentry *p = BPF_CORE_READ(cur, d_parent);
		if (!p || p == cur)
			return 0;  // reached the filesystem root without meeting a scope root
		a2 = a1;
		a1 = k.ino;
		cur = p;
	}
	return 0;
}

static __always_inline int resolve_scope(struct file *file, struct inode *inode, struct scope_val *out)
{
	struct dentry *d = BPF_CORE_READ(file, f_path.dentry);
	return resolve_scope_from(BPF_CORE_READ(d, d_parent), BPF_CORE_READ(inode, i_sb, s_dev),
				  BPF_CORE_READ(inode, i_sb, s_magic), out);
}

static __always_inline __u64 ext_class(const unsigned char *name, __u32 len)
{
	char nm[32] = {};
	__u32 off = len > 24 ? len - 24 : 0;
	__u32 n = len - off;
	if (n > 24)
		n = 24;
	bpf_probe_read_kernel(nm, 24, name + off);
	// Straight-line loops only: an early `break` made clang emit an unrolled form
	// whose indexing the verifier rejected ("invalid read from stack"). Bytes past
	// the name are zeroed, so the scans below stop at the end without needing n.
	int dot = -1;
#pragma unroll
	for (int i = 0; i < 24; i++) {
		if ((__u32)i >= n)
			nm[i] = 0;
		if (nm[i] == '.')
			dot = i;
	}
	// Up to 8 characters after the last dot (contract v6; 4 before): `.sqlite3`, `.jsonl`,
	// `.qcow2` and `.db-wal` no longer collide with their 4-character prefixes.
	__u64 ext = 0;
	int done = 0;
	if (dot >= 0) {
#pragma unroll
		for (int j = 0; j < 8; j++) {
			unsigned char c = nm[(dot + 1 + j) & 31];
			if (c == 0)
				done = 1;
			if (!done) {
				if (c >= 'A' && c <= 'Z')
					c += 32;
				ext |= ((__u64)c) << (8 * j);
			}
		}
	}
	return ext;
}

// The first file seen in a project folder names it for userspace. Written once.
static __always_inline void remember_project(struct file *file, __u64 dev, __u64 proj_ino, __u32 root_kind)
{
	struct cloud_dir_key pk = { .dev = dev, .ino = proj_ino };
	if (bpf_map_lookup_elem(&proj_path, &pk))
		return;
	__u32 zero = 0;
	struct cloud_proj_val *pv = bpf_map_lookup_elem(&proj_scratch, &zero);
	if (!pv)
		return;
	pv->root_kind = root_kind;
	pv->pad = 0;
	pv->path[0] = 0;
	if (bpf_d_path(&file->f_path, pv->path, sizeof(pv->path)) < 0)
		pv->path[0] = 0;
	if (bpf_map_update_elem(&proj_path, &pk, pv, BPF_NOEXIST) && !bpf_map_lookup_elem(&proj_path, &pk))
		stat_inc(CLOUD_STAT_PROJ_MAP_FULL);
}

// ---------------------------------------------------------------------------
// Directory rows for file names
// ---------------------------------------------------------------------------
//
// A record is keyed by (process, EXACT parent directory, operation). Only ELIGIBLE opens (an
// allowed extension, or else a matching name mask; every open when no policy is loaded) create or
// feed one. Per key, dir_state holds the count of eligible opens and two timestamps, and userspace
// drains it like the fold map. For a sample of the eligible opens (the first names_first, then a
// reservoir of names_rand: see want_name) the full path is resolved with bpf_d_path (allowed in
// this LSM hook, already used for the project folder) straight into the reserved record of a
// separate ring buffer, together with the directory key, the open's number and CLOUD_NAME_F_MASKED
// (whether the mask, not the extension whitelist, is why it was eligible), so the agent can split
// it into directory and basename, weigh it and attach it to the right record. A masked open skips
// the reservoir and is always emitted (masks are rare; the point is a name like wallet.dat never
// loses a coin flip to a directory of ordinary whitelisted-extension files - see cloud_abi.h). The
// sample sizes, the measurement-only mode "all" (a record for EVERY eligible open), whether a
// policy is on and the cheap early rejects of the policy are load-time constants written into
// .rodata by the loader: with names off the verifier removes the whole mechanism. A record that
// does not fit is dropped and counted, never waited for. See cloud_abi.h for the bounds and the
// accounting.

#define NAMES_RING_BYTES (8 * 1024 * 1024)  // the agent may set its own size
#define C_ENAMETOOLONG 36

// Load-time configuration (struct cloud_cfg). The loader overwrites this before the load.
volatile const struct cloud_cfg cloud_cfg = { .dir_rows_on = 0,
					      .policy_on = 0,
					      .dir_proc_max = CLOUD_DIR_PROC_DEFAULT };

// The extension whitelist and the exact-name set (the confirmation behind the two bloom filters
// of cloud_cfg), filled by the loader after the load and never learned. The sizes below are the
// defaults: the loader grows each map to the policy's own size before the load
// (PrepareCloudObject), and counts any entry that still could not be stored (cloud_policy_stats).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CLOUD_NAME_EXTS);
	__type(key, __u64);
	__type(value, __u8);
} name_ext_ok SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CLOUD_NAME_EXACT_ENTRIES);  // below the default policy's 106 names
	__type(key, struct cloud_name_exact);
	__type(value, __u8);
} name_exact SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, NAMES_RING_BYTES);
} names_rb SEC(".maps");

// The directory keys: eligible-open counter and timestamps. Drained (deleted on read) by userspace.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CLOUD_DIR_STATE_MAX);
	__type(key, struct cloud_dirid);
	__type(value, struct cloud_dir_val);
} dir_state SEC(".maps");

// Per process: how many new directory keys it has created in this drain epoch, and what the
// bound refused. Drained (before dir_state) by userspace, which starts a new epoch.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CLOUD_DIR_PROC_MAX);
	__type(key, struct cloud_dir_proc_key);
	__type(value, struct cloud_dir_proc_val);
} dir_proc SEC(".maps");

// Directory rows v2 (cloud_abi.h): the extension and prefix breakdown maps and
// the distinct-file HLL sketch. Drained (delete on read) like dir_state; each is its own fixed-size
// map, so a key that does not fit is dropped and counted rather than growing the map unboundedly.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CLOUD_DIR_EXT_FOLD_MAX);
	__type(key, struct cloud_dir_ext_key);
	__type(value, struct cloud_dir_bytes_val);
} dir_ext_fold SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CLOUD_DIR_PREFIX_FOLD_MAX);
	__type(key, struct cloud_dir_prefix_key);
	__type(value, struct cloud_dir_bytes_val);
} dir_prefix_fold SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CLOUD_DIR_STATE_MAX);  // one sketch per directory key, same ceiling as dir_state
	__type(key, struct cloud_dirid);
	__type(value, struct cloud_dir_hll_val);
} dir_distinct_hll SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CLOUD_NAME_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} name_stats SEC(".maps");

static __always_inline void name_stat_inc(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&name_stats, &idx);
	if (v)
		(*v)++;
}

// Never wake the reader for a name (it consumes every 100 ms), unless a quarter of the ring
// is waiting: a sweep of thousands of files must not outrun it.
static __always_inline __u64 names_wake(void)
{
	return bpf_ringbuf_query(&names_rb, BPF_RB_AVAIL_DATA) > NAMES_RING_BYTES / 4 ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

static __always_inline void emit_name(struct file *file, const struct cloud_dirid *key, __u64 now, __u64 nth, int masked)
{
	struct cloud_name_rec *r = bpf_ringbuf_reserve(&names_rb, sizeof(*r), 0);
	if (!r) {
		name_stat_inc(CLOUD_NAME_STAT_RING_FULL);
		return;
	}
	long n = bpf_d_path(&file->f_path, r->path, CLOUD_NAME_PATH_MAX + 1);
	if (n <= 1) {
		bpf_ringbuf_discard(r, 0);
		name_stat_inc(n == -C_ENAMETOOLONG ? CLOUD_NAME_STAT_TOO_LONG : CLOUD_NAME_STAT_DPATH_FAIL);
		return;
	}
	__builtin_memcpy(&r->key, key, sizeof(r->key));
	r->ts_ns = now;
	r->len = n - 1;  // n counts the NUL
	r->flags = masked ? CLOUD_NAME_F_MASKED : 0;
	r->nth = nth > 0xffffffffULL ? 0xffffffffU : (__u32)nth;
	bpf_ringbuf_submit(r, names_wake());
	name_stat_inc(CLOUD_NAME_STAT_EMITTED);
}

// Sent exactly once, when a directory key is genuinely created (never on a race loss, never on a
// repeat open of an existing key): the DIRECTORY's own full path, CLOUD_NAME_F_DIRPATH set, `nth`
// 0. This is the only path source for a directory that is eligible only via the extension or
// dir-prefix route (no mask match, ever) - see cloud_abi.h's comment on the flag.
//
// bpf_d_path requires a TRUSTED struct path* (a verifier-tracked kernel pointer): a stack-local
// struct path built from file->f_path.mnt + the parent dentry is NOT trusted and the load is
// rejected ("R1 type=fp expected=ptr_, trusted_ptr_, rcu_ptr_" - hit and fixed). So
// this resolves the FILE's own full path (the same trusted &file->f_path every other call here
// uses) and reports only its directory portion: the file's basename is always exactly `blen`
// bytes at the end, so the directory's length is the path length minus the basename minus the
// separating slash, floored at 1 for a root-level file ("/foo" -> dir "/", not "").
static __always_inline void emit_dir_path(struct file *file, __u32 blen, const struct cloud_dirid *key, __u64 now)
{
	struct cloud_name_rec *r = bpf_ringbuf_reserve(&names_rb, sizeof(*r), 0);
	if (!r) {
		name_stat_inc(CLOUD_NAME_STAT_RING_FULL);
		return;
	}
	long n = bpf_d_path(&file->f_path, r->path, CLOUD_NAME_PATH_MAX + 1);
	if (n <= 1) {
		bpf_ringbuf_discard(r, 0);
		name_stat_inc(n == -C_ENAMETOOLONG ? CLOUD_NAME_STAT_TOO_LONG : CLOUD_NAME_STAT_DPATH_FAIL);
		return;
	}
	__u32 flen = (__u32)(n - 1);  // n counts the NUL
	if (flen <= blen) {
		// the basename does not fit inside the resolved path: something is inconsistent, never trust it
		bpf_ringbuf_discard(r, 0);
		name_stat_inc(CLOUD_NAME_STAT_DPATH_FAIL);
		return;
	}
	__u32 slash_idx = flen - blen - 1;  // index of the '/' just before the basename
	__builtin_memcpy(&r->key, key, sizeof(r->key));
	r->ts_ns = now;
	r->len = (__u16)(slash_idx == 0 ? 1 : slash_idx);  // "/foo" -> dir "/" (len 1), not ""
	r->flags = CLOUD_NAME_F_DIRPATH;
	r->nth = 0;
	bpf_ringbuf_submit(r, names_wake());
	name_stat_inc(CLOUD_NAME_STAT_EMITTED);
}

// The bytes of a name of length `len` that are kept in u64 word number `word` (0..3): all of them
// for a word wholly inside the name, the low bytes for the word the name ends in, none past it.
static __always_inline __u64 keep_mask(__u32 len, __u32 word)
{
	__u32 lo = word * 8;
	if (len <= lo)
		return 0;
	__u32 rem = len - lo;
	if (rem >= 8)
		return ~0ULL;
	return (1ULL << (rem * 8)) - 1;
}

// Does the file's NAME (the basename) match the policy's name mask: an exact-name set plus a few
// prefix masks, at most 32 bytes read, straight-line code (an early `break` in an unrolled loop
// failed the verifier before). This runs on every open whose extension did not match, so it is
// built to reject early and cheaply: (1) with no prefix mask, a name whose length is outside the
// range of the exact names is rejected without reading a byte; (2) the name is read once as four
// u64 words and masked by its length (no per-byte loop); (3) the prefix masks are constants in
// .rodata, no map; (4) the exact set is behind a bloom filter in .rodata, so the hash-map lookup
// runs only for a probable member. Building with -DCLOUD_EXP_NO_EARLY removes (1) and (4): a
// measurement switch, never the default.
static __always_inline int name_masked(const unsigned char *name, __u32 len)
{
	if (len == 0)
		return 0;
#ifndef CLOUD_EXP_NO_EARLY
	if (!cloud_cfg.prefix_any && (len < cloud_cfg.name_len_min || len > cloud_cfg.name_len_max))
		return 0;
#endif
	// A short name lives in the dentry's inline buffer (d_iname is 40 bytes) and a longer one is
	// at least 40 bytes, so reading 32 bytes from its start stays inside valid memory. A name of
	// more than 31 bytes can equal no stored name (they are at most 31 bytes); the prefix masks
	// only look at the first 8 bytes and apply to any length.
	__u64 w[4] = {};
	bpf_probe_read_kernel(w, sizeof(w), name);
	w[0] &= keep_mask(len, 0);
	w[1] &= keep_mask(len, 1);
	w[2] &= keep_mask(len, 2);
	w[3] &= keep_mask(len, 3);
	int hit = 0;
#pragma unroll
	for (int i = 0; i < CLOUD_NAME_PREFIXES; i++) {
		__u64 m = cloud_cfg.prefixes[i].mask;
		if (m && (w[0] & m) == cloud_cfg.prefixes[i].bits)
			hit = 1;
	}
	if (hit || len > CLOUD_NAME_EXACT_MAX)
		return hit;
#ifndef CLOUD_EXP_NO_EARLY
	__u32 bi = cloud_bloom_name(w[0], w[1], w[2], w[3]);
	if (!((cloud_cfg.name_bloom[(bi >> 6) & (CLOUD_BLOOM_WORDS - 1)] >> (bi & 63)) & 1))
		return 0;
#endif
	struct cloud_name_exact ex;
	__builtin_memcpy(&ex, w, sizeof(ex));
	return bpf_map_lookup_elem(&name_exact, &ex) ? 1 : 0;
}

// Which of the three eligibility routes let an open through (cloud_abi.h "Directory rows v2").
// EXT and PREFIX feed the byte/count breakdown maps; MASK sends a name, unconditionally, same as
// before. NONE means the open is not eligible at all.
enum { CLOUD_DIR_ROUTE_NONE = 0, CLOUD_DIR_ROUTE_EXT, CLOUD_DIR_ROUTE_MASK, CLOUD_DIR_ROUTE_PREFIX };

// The broader, separate dir-eligibility prefix policy (cloud_cfg.dir_prefixes - NOT the name mask's
// own prefix list): does the file's name match one of them? Only the first 8 bytes are ever looked
// at (same reasoning as the name mask's own prefixes), so a single word read is enough - no need for
// the exact-name machinery name_masked() also carries. Returns the matching slot index, or -1.
static __always_inline int dir_prefix_match(const unsigned char *name, __u32 len)
{
	if (len == 0 || !cloud_cfg.dir_prefix_any)
		return -1;
	__u64 w0 = 0;
	bpf_probe_read_kernel(&w0, sizeof(w0), name);
	w0 &= keep_mask(len, 0);
	int hit = -1;
#pragma unroll
	for (int i = 0; i < CLOUD_DIR_PREFIXES; i++) {
		__u64 m = cloud_cfg.dir_prefixes[i].mask;
		if (m && (w0 & m) == cloud_cfg.dir_prefixes[i].bits)
			hit = i;
	}
	return hit;
}

// Is this open eligible for a directory record, and through which route? With no policy loaded
// every open is (the extension route, whatever the extension - never via the mask or the dir-prefix
// policy). Otherwise the extension whitelist goes first (a bloom filter in .rodata, then the exact
// hash map behind it); if it does not match, the name mask (sends a NAME, unconditionally); if that
// does not match either, the separate dir-eligibility prefix policy (no name, just a breakdown
// entry). `*prefix_id` is only meaningful when the return route is PREFIX.
static __always_inline int eligible(__u64 ext, const unsigned char *name, __u32 len, int *route, int *prefix_id)
{
	*prefix_id = -1;
	if (!cloud_cfg.policy_on) {
		*route = CLOUD_DIR_ROUTE_EXT;
		return 1;
	}
	if (ext) {
#ifndef CLOUD_EXP_NO_EARLY
		__u32 b = cloud_bloom_ext(ext);
		if ((cloud_cfg.ext_bloom[(b >> 6) & (CLOUD_BLOOM_WORDS - 1)] >> (b & 63)) & 1)
#endif
		{
			if (bpf_map_lookup_elem(&name_ext_ok, &ext)) {
				*route = CLOUD_DIR_ROUTE_EXT;
				return 1;
			}
		}
	}
	if (name_masked(name, len)) {
		*route = CLOUD_DIR_ROUTE_MASK;
		return 1;
	}
	int pid = dir_prefix_match(name, len);
	if (pid >= 0) {
		*route = CLOUD_DIR_ROUTE_PREFIX;
		*prefix_id = pid;
		return 1;
	}
	*route = CLOUD_DIR_ROUTE_NONE;
	return 0;
}

// A straight-line (no loop, no builtin) count of leading zero bits in a 32-bit word, 32 when it is
// zero. Used by the HLL sketch below; avoids depending on how clang lowers __builtin_clz for the
// BPF target.
static __always_inline __u32 clz32(__u32 w)
{
	__u32 n = 0;
	if (w == 0)
		return 32;
	if (!(w & 0xFFFF0000u)) { n += 16; w <<= 16; }
	if (!(w & 0xFF000000u)) { n += 8;  w <<= 8; }
	if (!(w & 0xF0000000u)) { n += 4;  w <<= 4; }
	if (!(w & 0xC0000000u)) { n += 2;  w <<= 2; }
	if (!(w & 0x80000000u)) { n += 1; }
	return n;
}

// A 32-bit hash of a file's own identity (dev, ino: two opens of the same file must count once for
// the distinct-file sketch), a standard 64-bit finalizer mix folded down.
static __always_inline __u32 hll_hash(__u64 dev, __u64 ino)
{
	__u64 x = dev * 0x9E3779B97F4A7C15ull + ino;
	x ^= x >> 33;
	x *= 0xff51afd7ed558ccdull;
	x ^= x >> 33;
	x *= 0xc4ceb9fe1a85ec53ull;
	x ^= x >> 33;
	return (__u32)(x >> 32) ^ (__u32)x;
}

// HyperLogLog-style register update: the top 6 bits of the hash (CLOUD_HLL_M = 64 registers) pick
// the bucket, the rest gives the rank (1 + the number of leading zero bits among the remaining
// bits). A bucket keeps the MAX rank ever seen, never decreasing - a plain max, not an atomic one:
// two CPUs updating the same directory's sketch for two different files at once can lose one
// update to the other's non-atomic read-modify-write, an imprecision on the same order as the
// sketch's own ~13% standard error, not a correctness bug.
// `reg` is CLOUD_HLL_M registers: a directory sketch (cloud_dir_hll_val.reg) or, since contract
// v10, a file row's own (cloud_file_val.hll).
static __always_inline void hll_update(__u8 *reg, __u32 h)
{
	__u32 idx = (h >> 26) & (CLOUD_HLL_M - 1);
	__u32 rest = h << 6;
	__u32 rank = clz32(rest) + 1;
	if (rank > 255)
		rank = 255;
	if (reg[idx] < (__u8)rank)
		reg[idx] = (__u8)rank;
}

static __always_inline void hll_account(const struct cloud_dirid *dk, __u64 dev, __u64 ino, __u64 now)
{
	(void)now;
	__u32 h = hll_hash(dev, ino);
	struct cloud_dir_hll_val *hv = bpf_map_lookup_elem(&dir_distinct_hll, dk);
	if (hv) {
		hll_update(hv->reg, h);
		return;
	}
	struct cloud_dir_hll_val nv = {};
	hll_update(nv.reg, h);
	if (bpf_map_update_elem(&dir_distinct_hll, dk, &nv, BPF_NOEXIST)) {
		hv = bpf_map_lookup_elem(&dir_distinct_hll, dk);  // lost a race with another CPU
		if (hv)
			hll_update(hv->reg, h);
		else
			name_stat_inc(CLOUD_NAME_STAT_HLL_MAP_FULL);
	}
}

// Look up-or-insert-then-fold one eligible open into a byte/count breakdown map (dir_ext_fold or
// dir_prefix_fold): the same lookup-then-atomic-add, retry-on-race-loss shape dir_state itself uses.
// nbytes is deliberately not named "bytes": the macro's own body writes the field ".bytes", and the
// preprocessor substitutes a parameter name wherever its token appears, dot-designator included -
// naming the parameter "bytes" would rewrite ".bytes" into the argument expression too.
#define BYTES_FOLD_ACCOUNT(map, key, nbytes, now, full_stat)                                 \
	do {                                                                                  \
		struct cloud_dir_bytes_val *_v = bpf_map_lookup_elem(&(map), (key));         \
		if (_v) {                                                                    \
			__sync_fetch_and_add(&_v->count, 1);                                 \
			__sync_fetch_and_add(&_v->bytes, (nbytes));                          \
			_v->last_ns = (now);                                                 \
		} else {                                                                     \
			struct cloud_dir_bytes_val _nv = {                                   \
				.count = 1, .bytes = (nbytes), .first_ns = (now), .last_ns = (now) \
			};                                                                    \
			if (bpf_map_update_elem(&(map), (key), &_nv, BPF_NOEXIST)) {         \
				_v = bpf_map_lookup_elem(&(map), (key));  /* lost a race */  \
				if (_v) {                                                    \
					__sync_fetch_and_add(&_v->count, 1);                 \
					__sync_fetch_and_add(&_v->bytes, (nbytes));          \
					_v->last_ns = (now);                                 \
				} else {                                                     \
					name_stat_inc(full_stat);                            \
				}                                                            \
			}                                                                    \
		}                                                                             \
	} while (0)

// One eligible open: count it in its directory key (unchanged accounting backbone), feed the
// distinct-file sketch (every route), and then route-specific work - EXT/PREFIX fold into their
// breakdown map with the file's i_size, MASK sends a name unconditionally. Every eligible open
// ends up in exactly one of: the key's counter, the per-process bound's drop counter, or one of
// the "map full" counters (see cloud_abi.h).
static __always_inline void dir_account(struct file *file, __u32 blen, const struct cloud_dirid *dk, __u64 now, int route,
					__u64 ext, int prefix_id, __u64 file_dev, __u64 file_ino, __u64 isize)
{
	name_stat_inc(CLOUD_NAME_STAT_ELIGIBLE);
	__u64 n;
	struct cloud_dir_val *v = bpf_map_lookup_elem(&dir_state, dk);
	if (v) {
		// The atomic's own result is this open's number in the key: unique per open.
		n = __sync_fetch_and_add(&v->opens, 1) + 1;
		v->last_ns = now;
	} else {
		// A directory this process has not touched since the last drain: a new key, subject to
		// the per-process bound.
		struct cloud_dir_proc_key pk = {};
		pk.proc_start = dk->proc_start;
		pk.tgid = dk->tgid;
		struct cloud_dir_proc_val *pv = bpf_map_lookup_elem(&dir_proc, &pk);
		if (!pv) {
			struct cloud_dir_proc_val z = {};
			bpf_map_update_elem(&dir_proc, &pk, &z, BPF_NOEXIST);
			pv = bpf_map_lookup_elem(&dir_proc, &pk);
			if (!pv) {
				name_stat_inc(CLOUD_NAME_STAT_DIR_PROC_FULL);
				return;
			}
		}
		if (__sync_fetch_and_add(&pv->created, 1) >= cloud_cfg.dir_proc_max) {
			__sync_fetch_and_add(&pv->drop_dirs, 1);
			__sync_fetch_and_add(&pv->drop_opens, 1);
			return;
		}
		struct cloud_dir_val nv = { .opens = 1, .first_ns = now, .last_ns = now };
		if (bpf_map_update_elem(&dir_state, dk, &nv, BPF_NOEXIST)) {
			v = bpf_map_lookup_elem(&dir_state, dk);  // lost a race with another CPU
			if (!v) {
				name_stat_inc(CLOUD_NAME_STAT_DIR_MAP_FULL);
				return;
			}
			n = __sync_fetch_and_add(&v->opens, 1) + 1;
			v->last_ns = now;
		} else {
			n = 1;
			emit_dir_path(file, blen, dk, now);  // genuinely new key: the only path source now
		}
	}

	hll_account(dk, file_dev, file_ino, now);

	if (route == CLOUD_DIR_ROUTE_MASK) {
		emit_name(file, dk, now, n, 1);
		return;
	}
	if (route == CLOUD_DIR_ROUTE_EXT) {
		struct cloud_dir_ext_key k = {};
		k.dir = *dk;
		k.ext = ext;
		BYTES_FOLD_ACCOUNT(dir_ext_fold, &k, isize, now, CLOUD_NAME_STAT_EXT_FOLD_FULL);
		return;
	}
	if (route == CLOUD_DIR_ROUTE_PREFIX) {
		struct cloud_dir_prefix_key k = {};
		k.dir = *dk;
		k.prefix_id = (__u32)prefix_id;
		BYTES_FOLD_ACCOUNT(dir_prefix_fold, &k, isize, now, CLOUD_NAME_STAT_PREFIX_FOLD_FULL);
		return;
	}
}

SEC("lsm/file_open")
int BPF_PROG(cloud_file_open, struct file *file)
{
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;
	if ((BPF_CORE_READ(inode, i_mode) & C_S_IFMT) != C_S_IFREG)
		return 0;
	stat_inc(CLOUD_STAT_FILE_OPENS);

	struct dentry *d = BPF_CORE_READ(file, f_path.dentry);
	struct dentry *parent = BPF_CORE_READ(d, d_parent);
	struct inode *pi = parent ? BPF_CORE_READ(parent, d_inode) : NULL;
	if (!pi)
		return 0;
	__u64 dev = BPF_CORE_READ(inode, i_sb, s_dev);
	struct cloud_dir_key ck = { .dev = dev, .ino = BPF_CORE_READ(pi, i_ino) };

	struct scope_val sv = {};
	struct scope_val *c = bpf_map_lookup_elem(&scope_cache, &ck);
	if (c) {
		sv = *c;
	} else {
		resolve_scope(file, inode, &sv);
		bpf_map_update_elem(&scope_cache, &ck, &sv, BPF_ANY);
		if (sv.in)
			remember_project(file, dev, sv.proj_ino, sv.root_kind);
	}
	if (!sv.in)
		return 0;
	stat_inc(CLOUD_STAT_FILE_IN_SCOPE);

	const unsigned char *bname = BPF_CORE_READ(d, d_name.name);
	__u32 blen = BPF_CORE_READ(d, d_name.len);
	struct cloud_file_key key = {};
	key.proc_start = leader_start();
	key.dev = dev;
	key.proj_ino = sv.proj_ino;
	key.tgid = bpf_get_current_pid_tgid() >> 32;
	key.ext = ext_class(bname, blen);
	key.op = (BPF_CORE_READ(file, f_mode) & C_FMODE_WRITE) ? CLOUD_OP_WRITE : CLOUD_OP_READ;

	// The coarse row, for EVERY in-scope open (unchanged by the directory model). Contract v9: it
	// also sums the file's i_size, the same size source the directory rows use, so a read of
	// documents that no name policy makes dir-eligible still carries its volume. Contract v10:
	// only the FIRST open of an inode by this process and op adds its size and its sketch bit
	// (file_seen, BPF_NOEXIST: exactly one of two racing CPUs wins the insert); `count` still
	// counts every open.
	__u64 now = bpf_ktime_get_ns();
	__u64 ino = BPF_CORE_READ(inode, i_ino);
	struct cloud_file_seen_key sk = { .proc_start = key.proc_start, .dev = dev, .ino = ino, .tgid = key.tgid, .op = key.op };
	__u8 one = 1;
	int first = bpf_map_update_elem(&file_seen, &sk, &one, BPF_NOEXIST) == 0;
	__u64 isize = first ? BPF_CORE_READ(inode, i_size) : 0;
	__u32 h = first ? hll_hash(dev, ino) : 0;
	struct cloud_file_val *v = bpf_map_lookup_elem(&file_fold, &key);
	if (v) {
		__sync_fetch_and_add(&v->count, 1);
		if (first) {
			__sync_fetch_and_add(&v->bytes, isize);
			hll_update(v->hll, h);
		}
		v->last_ns = now;
	} else {
		struct cloud_file_val nv = { .count = 1, .first_ns = now, .last_ns = now, .bytes = isize };
		if (first)
			hll_update(nv.hll, h);
		if (bpf_map_update_elem(&file_fold, &key, &nv, BPF_NOEXIST)) {
			v = bpf_map_lookup_elem(&file_fold, &key);  // lost a race with another CPU
			if (v) {
				__sync_fetch_and_add(&v->count, 1);
				if (first) {
					__sync_fetch_and_add(&v->bytes, isize);
					hll_update(v->hll, h);
				}
				v->last_ns = now;
			} else {
				stat_inc(CLOUD_STAT_FILE_MAP_FULL);
				// The row was dropped: forget the inode too, or its size would never be
				// counted (an undercount, the direction that can raise a false coupling).
				if (first)
					bpf_map_delete_elem(&file_seen, &sk);
			}
		}
	}

	// The directory record: only when the v2 mechanism is on, and only for an ELIGIBLE open.
	if (!cloud_cfg.dir_rows_on)
		return 0;
	int route, prefix_id;
	if (!eligible(key.ext, bname, blen, &route, &prefix_id))
		return 0;
	struct cloud_dirid dk = {};
	dk.proc_start = key.proc_start;
	dk.dev = dev;
	dk.ino = ck.ino;  // the parent directory's inode
	dk.tgid = key.tgid;
	dk.op = key.op;
	dir_account(file, blen, &dk, now, route, key.ext, prefix_id, dev, BPF_CORE_READ(inode, i_ino), isize);
	return 0;
}

// ---------------------------------------------------------------------------
// v7: move/rename/link/symlink rows (cloud_abi.h has the full design note)
// ---------------------------------------------------------------------------
//
// Raw ring buffer, one record per ELIGIBLE event - rare next to file opens, so no folding.
// Eligibility and scope are decided on the DESTINATION exactly like cloud_file_open decides
// them on the file being opened, reusing eligible()/resolve_scope_from() unchanged. Gated by
// the same cloud_cfg.dir_rows_on switch as directory rows: with it off the mechanism is
// skipped (not compiled out - unlike dir_rows_on's other uses this one is a plain runtime
// check, since these programs have no per-mode object variant to shrink).

#define MOVE_RING_BYTES (4 * 1024 * 1024)  // rare events: no reservoir, no folding needed (a git checkout renames thousands of files)

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MOVE_RING_BYTES);
} move_rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CLOUD_MOVE_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} move_stats SEC(".maps");

static __always_inline void move_stat_inc(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&move_stats, &idx);
	if (v)
		(*v)++;
}

static __always_inline void emit_move(__u8 op, __u8 flags, __u64 old_dev, __u64 old_ino, __u64 new_dev,
				      __u64 new_ino, const unsigned char *name, __u32 len)
{
	struct cloud_move_rec *r = bpf_ringbuf_reserve(&move_rb, sizeof(*r), 0);
	if (!r) {
		move_stat_inc(CLOUD_MOVE_STAT_RING_FULL);
		return;
	}
	r->ts_ns = bpf_ktime_get_ns();
	r->proc_start = leader_start();
	r->old_dev = old_dev;
	r->old_ino = old_ino;
	r->new_dev = new_dev;
	r->new_ino = new_ino;
	r->tgid = bpf_get_current_pid_tgid() >> 32;
	r->op = op;
	r->flags = flags;
	__u32 cap_len = len > CLOUD_NAME_EXACT_MAX ? CLOUD_NAME_EXACT_MAX : len;
	bpf_probe_read_kernel(r->name, CLOUD_NAME_EXACT_BUF, name);
	// Straight-line, matching ext_class()'s own reasoning: zero past cap_len so the ring's reused
	// memory never leaks an earlier record's bytes past the real name.
#pragma unroll
	for (int i = 0; i < CLOUD_NAME_EXACT_BUF; i++) {
		if ((__u32)i >= cap_len)
			r->name[i] = 0;
	}
	r->name_len = (__u16)cap_len;
	bpf_ringbuf_submit(r, 0);  // rare: never worth an extra IPI to force a wakeup
	move_stat_inc(CLOUD_MOVE_STAT_EMITTED);
}

// `old_dir` is NULL for symlink(2) (no source file - old_name is an unresolved string target,
// CLOUD_MOVE_F_NO_SOURCE reports that). `new_dentry` (the destination) always has a d_name even
// though its inode may not exist yet (rename's replacement target, link/symlink's negative
// dentry) - exactly what eligibility needs, no d_inode read required.
static __always_inline void move_account(__u8 op, struct inode *old_dir, struct inode *new_dir,
					 struct dentry *new_dentry)
{
	if (!cloud_cfg.dir_rows_on || !new_dir || !new_dentry)
		return;
	const unsigned char *dname = BPF_CORE_READ(new_dentry, d_name.name);
	__u32 dlen = BPF_CORE_READ(new_dentry, d_name.len);

	struct scope_val sv;
	resolve_scope_from(BPF_CORE_READ(new_dentry, d_parent), BPF_CORE_READ(new_dir, i_sb, s_dev),
			   BPF_CORE_READ(new_dir, i_sb, s_magic), &sv);
	if (!sv.in) {
		move_stat_inc(CLOUD_MOVE_STAT_OUT_OF_SCOPE);
		return;
	}

	__u64 ext = ext_class(dname, dlen);
	int route, prefix_id;
	if (!eligible(ext, dname, dlen, &route, &prefix_id)) {
		move_stat_inc(CLOUD_MOVE_STAT_NOT_ELIGIBLE);
		return;
	}

	__u8 flags = (route == CLOUD_DIR_ROUTE_MASK) ? CLOUD_MOVE_F_MASKED : 0;
	__u64 old_dev = 0, old_ino = 0;
	if (old_dir) {
		old_dev = BPF_CORE_READ(old_dir, i_sb, s_dev);
		old_ino = BPF_CORE_READ(old_dir, i_ino);
	} else {
		flags |= CLOUD_MOVE_F_NO_SOURCE;
	}
	emit_move(op, flags, old_dev, old_ino, BPF_CORE_READ(new_dir, i_sb, s_dev), BPF_CORE_READ(new_dir, i_ino),
		 dname, dlen);
}

// Same LSM hook, arguments and ordering already proven live in kinnector_container_lsm_hooks.h
// (this codebase's enforcement object) - reused here unchanged; multiple independent BPF LSM
// programs may attach to one hook (cloud_file_open already co-attaches to file_open the same way).
SEC("lsm/inode_rename")
int BPF_PROG(cloud_move_rename, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
	    struct dentry *new_dentry)
{
	move_account(CLOUD_MOVE_RENAME, old_dir, new_dir, new_dentry);
	return 0;
}

SEC("lsm/inode_link")
int BPF_PROG(cloud_move_link, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	// link(2)'s source (old_dentry) always has an inode; its parent directory is what "old dir"
	// means here, same identity resolve_scope_from's callers use elsewhere in this file.
	struct dentry *old_parent = old_dentry ? BPF_CORE_READ(old_dentry, d_parent) : NULL;
	struct inode *old_dir = old_parent ? BPF_CORE_READ(old_parent, d_inode) : NULL;
	move_account(CLOUD_MOVE_LINK, old_dir, dir, new_dentry);
	return 0;
}

SEC("lsm/inode_symlink")
int BPF_PROG(cloud_move_symlink, struct inode *dir, struct dentry *dentry, const char *old_name)
{
	move_account(CLOUD_MOVE_SYMLINK, NULL, dir, dentry);
	return 0;
}

// ---------------------------------------------------------------------------
// Process lifecycle: fork, exec (successful only, with the arguments) and exit
// ---------------------------------------------------------------------------
//
// Why here and not in kinnector.bpf.c: the enforcement object is shared with Warden and
// must not grow; these programs are observe-only, Optional, and have their own ring
// buffer and counters ("Phase 2, revised").
//
// * fork: tp_btf/sched_process_fork, only when the child is a new PROCESS (a thread
//   has the parent's tgid) and not a kernel thread.
// * exec: tp_btf/sched_process_exec fires after a SUCCESSFUL exec, so a failed
//   execve (every candidate of a PATH search that does not exist) can never appear.
//   The arguments are the bytes between mm->arg_start and mm->arg_end (what
//   /proc/<pid>/cmdline shows), copied with bpf_probe_read_user into a per-CPU
//   scratch and sent with a variable-length bpf_ringbuf_output. Bounded at
//   CLOUD_LIFE_ARGV_MAX; anything cut sets CLOUD_LIFE_F_ARGV_TRUNC. The environment
//   (mm->env_start .. env_end, what /proc/<pid>/environ shows) follows in the same record,
//   bounded at CLOUD_LIFE_ENV_MAX with CLOUD_LIFE_F_ENV_TRUNC. It is RAW here and may hold
//   secrets: the agent filters it before anything leaves the machine.
// * executable path: bpf_d_path is not allowed in tp_btf, so lsm/bprm_committed_creds
//   (which runs just before sched_process_exec, in the same task, after the point of
//   no return) resolves bprm->file into a per-task storage slot that the exec program
//   reads and deletes. bprm->file is what /proc/<pid>/exe will show (the interpreter
//   for a #! script). Without that program (Optional) the exec record carries
//   bprm->filename as the caller wrote it and CLOUD_LIFE_F_EXE_RAW.
// * exit: tp_btf/sched_process_exit when the LAST thread of the process leaves.
//
// Submits do not wake the reader (BPF_RB_NO_WAKEUP): waking it costs an IPI per event
// (measured: it roughly quadrupled the per-hook cost in the VM), and nothing here is urgent.
// The loader's poll loop consumes the ring at least every 100 ms. An exec record can be
// 25 KB (argv 8 KB, env 16 KB), so a burst could outrun that: once a quarter of the ring is
// waiting, the submit forces a wakeup (life_wake) instead.
//
// The scratch buffer is per CPU and safe here because a tracepoint handler runs with
// preemption disabled; nothing sleeps between the fill and the output.

#define C_PF_KTHREAD 0x00200000
#define C_SIGNAL_GROUP_EXIT 0x00000004
#define LIFE_RING_BYTES (16 * 1024 * 1024)  // a parallel build or a configure script execs thousands per second

_Static_assert(sizeof(struct cloud_life_rec) == 64, "cloud_life_rec size changed");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, LIFE_RING_BYTES);
} life_rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CLOUD_LIFE_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} life_stats SEC(".maps");

struct life_stash {
	__u32 len;  // bytes of path, no NUL; 0 when bpf_d_path failed
	__u32 pad;
	char path[CLOUD_LIFE_EXE_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct life_stash);
} life_stash_map SEC(".maps");

struct life_scratch {
	struct cloud_life_rec h;
	char data[CLOUD_LIFE_EXE_MAX + CLOUD_LIFE_ARGV_MAX + CLOUD_LIFE_ENV_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct life_scratch);
} life_scratch_map SEC(".maps");

static __always_inline void life_stat_inc(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&life_stats, &idx);
	if (v)
		(*v)++;
}

// The submit flag: never wake the reader, unless a quarter of the ring is waiting.
static __always_inline __u64 life_wake(void)
{
	return bpf_ringbuf_query(&life_rb, BPF_RB_AVAIL_DATA) > LIFE_RING_BYTES / 4 ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

// The header fields every record shares. `t` is the task whose process this is
// (the new child for a fork, the exec'ing or exiting task otherwise).
static __always_inline void life_fill(struct cloud_life_rec *h, __u8 kind, struct task_struct *t)
{
	h->ts_ns = bpf_ktime_get_ns();
	h->kind = kind;
	h->flags = 0;
	h->exe_len = 0;
	h->aux = 0;
	h->argv_len = 0;
	h->argv_total = 0;
	h->env_len = 0;
	h->env_total = 0;
	h->envc = 0;
	h->pad = 0;
	h->tgid = BPF_CORE_READ(t, tgid);
	struct task_struct *l = BPF_CORE_READ(t, group_leader);
	h->start = BPF_CORE_READ(l, start_time);
	struct task_struct *rp = BPF_CORE_READ(t, real_parent);
	h->ptgid = BPF_CORE_READ(rp, tgid);
	struct task_struct *pl = BPF_CORE_READ(rp, group_leader);
	h->pstart = pl ? BPF_CORE_READ(pl, start_time) : 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(cloud_life_fork, struct task_struct *parent, struct task_struct *child)
{
	// No null-check of the hook's own pointer arguments (core/CLAUDE.md, second gotcha).
	if (BPF_CORE_READ(child, tgid) == BPF_CORE_READ(parent, tgid))
		return 0;  // a new thread, not a new process
	if (BPF_CORE_READ(child, flags) & C_PF_KTHREAD)
		return 0;
	struct cloud_life_rec *r = bpf_ringbuf_reserve(&life_rb, sizeof(*r), 0);
	if (!r) {
		life_stat_inc(CLOUD_LIFE_STAT_FORK_DROP);
		return 0;
	}
	life_fill(r, CLOUD_LIFE_FORK, child);
	bpf_ringbuf_submit(r, life_wake());
	life_stat_inc(CLOUD_LIFE_STAT_FORKS);
	return 0;
}

SEC("lsm/bprm_committed_creds")
int BPF_PROG(cloud_life_exe, const struct linux_binprm *bprm)
{
	struct task_struct *cur = bpf_get_current_task_btf();
	struct life_stash *s = bpf_task_storage_get(&life_stash_map, cur, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!s)
		return 0;
	s->len = 0;
	long n = bpf_d_path((struct path *)&bprm->file->f_path, s->path, sizeof(s->path));
	if (n > 1 && n <= CLOUD_LIFE_EXE_MAX)
		s->len = n - 1;  // n counts the NUL
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(cloud_life_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	__u32 zero = 0;
	struct life_scratch *sc = bpf_map_lookup_elem(&life_scratch_map, &zero);
	if (!sc)
		return 0;
	struct cloud_life_rec *h = &sc->h;
	life_fill(h, CLOUD_LIFE_EXEC, p);
	h->aux = BPF_CORE_READ(bprm, argc);

	// The executable: the stash the LSM program left for this task, else the raw filename.
	__u32 exe_len = 0;
	struct life_stash *st = bpf_task_storage_get(&life_stash_map, p, 0, 0);
	if (st) {
		exe_len = st->len;
		if (exe_len > CLOUD_LIFE_EXE_MAX - 1)
			exe_len = CLOUD_LIFE_EXE_MAX - 1;
		if (exe_len)
			bpf_probe_read_kernel(sc->data, exe_len, st->path);
		bpf_task_storage_delete(&life_stash_map, p);
	}
	if (!exe_len) {
		const char *fn = BPF_CORE_READ(bprm, filename);
		long n = fn ? bpf_probe_read_kernel_str(sc->data, CLOUD_LIFE_EXE_MAX, fn) : 0;
		if (n > 1) {
			exe_len = n - 1;
			h->flags |= CLOUD_LIFE_F_EXE_RAW;
			life_stat_inc(CLOUD_LIFE_STAT_EXE_RAW);
		} else {
			h->flags |= CLOUD_LIFE_F_EXE_NONE;
		}
	}
	if (exe_len > CLOUD_LIFE_EXE_MAX - 1)
		exe_len = CLOUD_LIFE_EXE_MAX - 1;

	// The arguments: the same bytes /proc/<pid>/cmdline shows.
	struct mm_struct *mm = BPF_CORE_READ(p, mm);
	unsigned long a0 = BPF_CORE_READ(mm, arg_start);
	unsigned long a1 = BPF_CORE_READ(mm, arg_end);
	__u32 total = 0;
	if (a1 > a0)
		total = (a1 - a0) > 0x7fffffffUL ? 0x7fffffff : (__u32)(a1 - a0);
	__u32 take = total;
	if (take > CLOUD_LIFE_ARGV_MAX) {
		take = CLOUD_LIFE_ARGV_MAX;
		h->flags |= CLOUD_LIFE_F_ARGV_TRUNC;
		life_stat_inc(CLOUD_LIFE_STAT_ARGV_TRUNC);
	}
	if (take && bpf_probe_read_user(&sc->data[exe_len & (CLOUD_LIFE_EXE_MAX - 1)], take, (void *)a0) < 0) {
		take = 0;
		h->flags |= CLOUD_LIFE_F_ARGV_FAIL;
		life_stat_inc(CLOUD_LIFE_STAT_ARGV_FAIL);
	}
	h->exe_len = exe_len;
	h->argv_len = take;
	h->argv_total = total;

	// The environment, after the arguments. Compiled out with -DCLOUD_LIFE_ENV_MAX=0.
	__u32 env_take = 0;
#if CLOUD_LIFE_ENV_MAX > 0
	h->envc = BPF_CORE_READ(bprm, envc);
	unsigned long e0 = BPF_CORE_READ(mm, env_start);
	unsigned long e1 = BPF_CORE_READ(mm, env_end);
	__u32 env_total = 0;
	if (e1 > e0)
		env_total = (e1 - e0) > 0x7fffffffUL ? 0x7fffffff : (__u32)(e1 - e0);
	env_take = env_total;
	if (env_take > CLOUD_LIFE_ENV_MAX) {
		env_take = CLOUD_LIFE_ENV_MAX;
		h->flags |= CLOUD_LIFE_F_ENV_TRUNC;
		life_stat_inc(CLOUD_LIFE_STAT_ENV_TRUNC);
	}
	__u32 env_off = (exe_len & (CLOUD_LIFE_EXE_MAX - 1)) + take;
	if (env_off > CLOUD_LIFE_EXE_MAX - 1 + CLOUD_LIFE_ARGV_MAX)
		env_take = 0;
	if (env_take && bpf_probe_read_user(&sc->data[env_off], env_take, (void *)e0) < 0) {
		env_take = 0;
		h->flags |= CLOUD_LIFE_F_ENV_FAIL;
		life_stat_inc(CLOUD_LIFE_STAT_ENV_FAIL);
	}
	h->env_len = env_take;
	h->env_total = env_total;
#endif

	__u32 size = sizeof(*h) + (exe_len & (CLOUD_LIFE_EXE_MAX - 1)) + take + env_take;
	if (size > sizeof(*h) + (CLOUD_LIFE_EXE_MAX - 1) + CLOUD_LIFE_ARGV_MAX + CLOUD_LIFE_ENV_MAX)
		return 0;
	if (bpf_ringbuf_output(&life_rb, h, size, life_wake()))
		life_stat_inc(CLOUD_LIFE_STAT_EXEC_DROP);
	else
		life_stat_inc(CLOUD_LIFE_STAT_EXECS);
	return 0;
}

// Only the exit of the LAST thread matters: one record per process. `group_dead` is
// the second argument on this kernel (6.10 and later); the first is the task.
SEC("tp_btf/sched_process_exit")
int BPF_PROG(cloud_life_exit, struct task_struct *p, bool group_dead)
{
	if (!group_dead)
		return 0;
	if (BPF_CORE_READ(p, flags) & C_PF_KTHREAD)
		return 0;
	struct cloud_life_rec *r = bpf_ringbuf_reserve(&life_rb, sizeof(*r), 0);
	if (!r) {
		life_stat_inc(CLOUD_LIFE_STAT_EXIT_DROP);
		return 0;
	}
	life_fill(r, CLOUD_LIFE_EXIT, p);
	// The status the parent's wait() will see: a group exit's code if the whole group
	// was told to exit (exit_group, a fatal signal), else the leader's own exit code.
	struct signal_struct *sig = BPF_CORE_READ(p, signal);
	struct task_struct *leader = BPF_CORE_READ(p, group_leader);
	int st;
	if (BPF_CORE_READ(sig, flags) & C_SIGNAL_GROUP_EXIT)
		st = BPF_CORE_READ(sig, group_exit_code);
	else
		st = BPF_CORE_READ(leader, exit_code);
	r->aux = (__u32)st;
	bpf_ringbuf_submit(r, life_wake());
	life_stat_inc(CLOUD_LIFE_STAT_EXITS);
	return 0;
}
