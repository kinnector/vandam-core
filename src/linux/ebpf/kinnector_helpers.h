// SPDX-License-Identifier: GPL-2.0-only
#ifndef KINNECTOR_BPF_HELPERS_H
#define KINNECTOR_BPF_HELPERS_H

// Shared helpers: hashing, namespace/container identification, resource
// identity (process_key, resource_id), mode gating (is_admin_session,
// is_install_session, is_antitheft_mode), and privilege-exemption checks.
// Verbatim split out of kinnector.bpf.c - see that file's header comment.
// Corresponds to the original "Helpers" and "Container Identification &
// Privilege Exemption Helpers" section banners.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// bpf_d_path() is rejected by the verifier when called from an LSM context
// on some kernels - confirmed live on 5.10.268 ("helper call is not allowed
// in probe"), which fails file_open's load entirely since it's Required
// (see core/CLAUDE.md's Known debt, core_linux_5_10_bpf_d_path_gap memory).
// Tetragon avoids the kernel helper altogether (bpf/lib/bpf_d_path.h, its
// own dentry/vfsmount walk via probe_read) - not ported here, that's a
// ~350-line undertaking. This tier is the smaller fix: omit every
// bpf_d_path() call so the programs that need it can still load, at the
// cost of an empty path string in the handful of telemetry events that
// used it - the same fallback these call sites already use for `!file`.
// Selected reactively by EbpfLoader after a real load failure (see
// SelectObjectPath/LoadTolerantly), the same way the small-tier fallback
// already handles the E2BIG case - a verifier rejection can only be
// observed by a real load attempt, never predicted from a version number
// (this project probes features, never versions).
#ifdef __KINN_NO_DPATH
#define KINN_D_PATH(path_ptr, buf, buflen) do { (buf)[0] = '\0'; } while (0)
#else
#define KINN_D_PATH(path_ptr, buf, buflen) bpf_d_path((path_ptr), (buf), (buflen))
#endif

// Is this tmpfs-backed file genuinely FILELESS - self-staged code with no name
// in any directory - as opposed to an ordinary file that merely happens to sit
// on a tmpfs mount?
//
// The distinction is the whole basis of the self-exec deny, and it used to be
// missing. `mmap_file` denied PROT_EXEC for ANY file whose superblock magic was
// TMPFS_MAGIC. That is wrong, and wrong in a way that could only show up off
// this developer machine: this host's /tmp is ext4, but a systemd-style host
// (and both LVH test VMs) mounts /tmp as tmpfs, and there a protected
// app could not exec ANYTHING out of /tmp. Worse, because the deny fires inside
// the ELF loader past execve's point of no return, the kernel cannot fail the
// syscall cleanly and force-SIGSEGVs the process instead. Measured:
// 7 of 9 enforcement-e2e failures on BOTH 6.18 and 7.2 traced to exactly this.
//
// "The filesystem is tmpfs" was never the property worth denying on. "This
// mapping has no on-disk identity anyone could have vetted" is. So:
//   * memfd_create() names its dentry "memfd:<name>" verbatim, and that IS the
//     standard fileless loader.
//   * SysV shared-memory segments are named "SYSV<8 hex>". (SHM_EXEC also has
//     its own lsm/shm_shmat hook; this is the mmap-path counterpart.)
//   * A file unlinked while still open has i_nlink == 0 and no reachable name.
// An ordinary named file under a tmpfs /tmp matches none of these and falls
// through to the broader foreign-untrusted-file gate further down mmap_file,
// which judges it on ownership and origin exactly as it would on ext4.
// Pre-6.4 name of iov_iter's iovec member. CO-RE "flavor": the ___suffix is
// stripped when matching against the running kernel's BTF, so this lets us name
// a member that the build host's vmlinux.h (generated from a NEWER kernel) no
// longer has. Without it, 5.15 - where the member is still `iov` - is
// unreachable, because naming a field absent from vmlinux.h does not compile
// and naming `__iov` fails to relocate there.
struct iov_iter___pre64 {
    const struct iovec *iov;
} __attribute__((preserve_access_index));

// Extract the user-space buffer and length an iov_iter describes.
//
// `struct iov_iter` changed three times in the range we support, and each
// change breaks a different thing:
//   * `ubuf`/ITER_UBUF exist only from 6.0;
//   * the iovec member was renamed `iov` -> `__iov` in 6.4;
//   * the iter_type CONSTANTS differ, so `iter_type == 4` is ITER_UBUF from 6.0
//     but ITER_BVEC on 5.15 - the same test means different things.
// Every read is therefore guarded by bpf_core_field_exists(), and the ubuf
// branch is taken only where `ubuf` actually exists, so the ambiguous constant
// is never consulted on a kernel where it means something else.
//
// Returns NULL when the layout is one we cannot read safely. Callers must treat
// that as "capture nothing" - a missing capture is a bounded loss, a buffer
// read through the wrong member is fabricated data in an alert.
static __always_inline void *iov_iter_user_buf(struct iov_iter *iter, uint32_t *out_len) {
    void *buf = 0;
    uint64_t len = 0;
    if (!iter) { *out_len = 0; return 0; }

    if (bpf_core_field_exists(iter->count))
        len = BPF_CORE_READ(iter, count);

    // The iter_type CONSTANTS are not stable across kernels - ITER_UBUF is 0 on
    // 6.4+ but the enumerators were ordered differently when ITER_UBUF was
    // introduced in 6.0, and on 5.15 there is no ITER_UBUF at all (4 is
    // ITER_BVEC there). A hardcoded `== 4` is therefore wrong on every kernel
    // in a different way, which is precisely why this captured nothing.
    // bpf_core_enum_value() resolves the enumerator against the RUNNING
    // kernel's BTF, so the comparison means the same thing everywhere.
    if (bpf_core_field_exists(iter->ubuf) &&
        bpf_core_enum_value_exists(enum iter_type, ITER_UBUF)) {
        uint8_t t = BPF_CORE_READ(iter, iter_type);
        if (t == bpf_core_enum_value(enum iter_type, ITER_UBUF))
            buf = BPF_CORE_READ(iter, ubuf);
    }
    if (!buf) {
        const struct iovec *iov = 0;
        if (bpf_core_field_exists(iter->__iov))
            iov = BPF_CORE_READ(iter, __iov);
        else
            iov = BPF_CORE_READ((struct iov_iter___pre64 *)iter, iov);
        if (iov) {
            buf = BPF_CORE_READ(iov, iov_base);
            if (!len)
                len = BPF_CORE_READ(iov, iov_len);
        }
    }

    *out_len = len > 1023 ? 1023 : (uint32_t)len;
    return buf;
}

// Read a capability set as a plain u64, portably across the kernel_cap_t
// layout change.
//
// `kernel_cap_t` is 8 bytes at offset 0 on every kernel we care about, but its
// MEMBER NAME changed: <6.3 it is `struct { __u32 cap[2]; }`, 6.3+ it is
// `struct { __u64 val; }`. vmlinux.h is generated from the BUILD host, so a
// build on a modern kernel bakes in `.val` - and naming `.val` makes CO-RE emit
// a relocation for a field that does not exist on 5.15, which libbpf then
// poisons and the verifier rejects:
//
//   failed to resolve CO-RE relocation <byte_off> [337] typedef kernel_cap_t.val
//
// That single relocation is what stopped TEN programs from loading on 5.15
// (Ubuntu 22.04 LTS), including the Required bprm_creds_for_exec, which meant
// no enforcement at all on that kernel.
//
// The fix, which is exactly what cilium/tetragon does
// (`BPF_CORE_READ_INTO(&permitted, task, cred, cap_permitted)` into a __u64 in
// bpf_execve_bprm_commit_creds.c): relocate the CAP FIELD ITSELF, which exists
// under both layouts, and never name the member inside it. On little-endian the
// old `__u32 cap[2]` has the same bit order as the new `__u64 val`, so the
// value is identical either way.
//
// Rule for anything added here: never name a member of kernel_cap_t.
#define KINN_READ_CAP_U64(dst_u64, ...) \
    BPF_CORE_READ_INTO(&(dst_u64), __VA_ARGS__)

static __always_inline bool is_fileless_tmpfs_mapping(struct file *file,
                                                      struct inode *inode) {
    if (!file || !inode)
        return false;

    // Unlinked while open: no name in any directory, nothing to have vetted.
    if (BPF_CORE_READ(inode, i_nlink) == 0)
        return true;

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return false;
    struct qstr dname = BPF_CORE_READ(dentry, d_name);

    // Deliberately tiny: this runs on every PROT_EXEC mapping and mmap_file is
    // already the heaviest LSM program here. Long enough for "memfd:"/"SYSV".
    char nbuf[10] = {};
    if (bpf_probe_read_kernel_str(nbuf, sizeof(nbuf), dname.name) < 5)
        return false;

    if (nbuf[0] == 'm' && nbuf[1] == 'e' && nbuf[2] == 'm' && nbuf[3] == 'f' &&
        nbuf[4] == 'd' && nbuf[5] == ':')
        return true;
    if (nbuf[0] == 'S' && nbuf[1] == 'Y' && nbuf[2] == 'S' && nbuf[3] == 'V')
        return true;
    return false;
}

static __always_inline bool is_env_file(const char *name) {
    #pragma unroll
    for (int i = 0; i < 28; i++) {
        if (name[i] == '.' && name[i+1] == 'e' && name[i+2] == 'n' && name[i+3] == 'v') {
            return true;
        }
        if (name[i] == '\0') break;
    }
    return false;
}

static __always_inline bool is_git_file(const char *name) {
    #pragma unroll
    for (int i = 0; i < 28; i++) {
        if (name[i] == '.' && name[i+1] == 'g' && name[i+2] == 'i' && name[i+3] == 't') {
            return true;
        }
        if (name[i] == '\0') break;
    }
    return false;
}
static __always_inline bool is_private_ip(uint32_t ip_be) {
    uint32_t ip = __builtin_bswap32(ip_be);
    if ((ip & 0xFF000000) == 0x7F000000) return true;
    if ((ip & 0xFF000000) == 0x0A000000) return true;
    if ((ip & 0xFFF00000) == 0xAC100000) return true;
    if ((ip & 0xFFFF0000) == 0xC0A80000) return true;
    if ((ip & 0xFFFF0000) == 0xA9FE0000) return true;
    return false;
}

static __always_inline uint32_t get_current_mnt_ns_inum() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy) return 0;
    struct mnt_namespace *mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns);
    if (!mnt_ns) return 0;
    return BPF_CORE_READ(mnt_ns, ns.inum);
}

static __always_inline uint32_t get_current_pid_ns_inum() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    struct pid *pid = BPF_CORE_READ(task, thread_pid);
    if (!pid) return 0;
    unsigned int level = BPF_CORE_READ(pid, level);
    if (level > 4) return 0;
    struct pid_namespace *pid_ns = BPF_CORE_READ(pid, numbers[level].ns);
    if (!pid_ns) return 0;
    return BPF_CORE_READ(pid_ns, ns.inum);
}

static __always_inline uint32_t get_current_net_ns_inum() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy) return 0;
    struct net *net = BPF_CORE_READ(nsproxy, net_ns);
    if (!net) return 0;
    return BPF_CORE_READ(net, ns.inum);
}

// ---------------------------------------------------------------------------
// Container Identification & Privilege Exemption Helpers
// ---------------------------------------------------------------------------

static __always_inline int is_container_process() {
    uint32_t host_mnt_ns_idx = CONFIG_HOST_MNT_NS;
    uint32_t *host_mnt_ns = bpf_map_lookup_elem(&config_map, &host_mnt_ns_idx);
    if (host_mnt_ns && *host_mnt_ns > 0) {
        uint32_t current_mnt_ns = get_current_mnt_ns_inum();
        if (current_mnt_ns != *host_mnt_ns) {
            return 1;
        }
    }
    return 0;
}

// Forward declaration: is_antitheft_mode() is defined further down, next to
// the rest of the deployment-mode helpers, but the mode audit's gate is
// needed here first.
static __always_inline int is_antitheft_mode();

static __always_inline int is_container_restricted() {
    // MODE AUDIT: Warden's container hardening, not antitheft's.
    // Gated at this chokepoint rather than at each of its three call sites
    // (sb_mount, path_chroot, and bprm's privileged-container exec deny) so a
    // future call site inherits the gate instead of re-introducing the leak.
    //
    // No behaviour change today - the whole family is already dormant in an
    // antitheft deployment because it keys off CONFIG_HOST_MNT_NS, which only
    // Warden sets. That dormancy is exactly the hazard: it is armed and
    // waiting, and `trusted_ancestor_roots` (the only escape hatch) has no
    // agent-side populator at all, so the day anything sets that config every
    // flatpak/bwrap exec on the machine starts failing. Verified live before
    // this gate: flatpak execs succeed, 0 alerts.
    if (is_antitheft_mode()) {
        return 0;
    }
    if (!is_container_process()) {
        return 0; // Not inside a container namespace
    }

    uint32_t host_pid_ns_idx = CONFIG_HOST_PID_NS;
    uint32_t *host_pid_ns = bpf_map_lookup_elem(&config_map, &host_pid_ns_idx);
    uint32_t host_net_ns_idx = CONFIG_HOST_NET_NS;
    uint32_t *host_net_ns = bpf_map_lookup_elem(&config_map, &host_net_ns_idx);

    if (host_pid_ns && *host_pid_ns > 0) {
        if (get_current_pid_ns_inum() == *host_pid_ns) {
            return 0; // Exempt host-PID sharing containers (e.g. CSI/CNI drivers)
        }
    }
    if (host_net_ns && *host_net_ns > 0) {
        if (get_current_net_ns_inum() == *host_net_ns) {
            return 0; // Exempt host-NET sharing containers
        }
    }

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    if (current_task) {
        const struct cred *cred = BPF_CORE_READ(current_task, cred);
        if (cred) {
            uint64_t cap_effective = 0;
            KINN_READ_CAP_U64(cap_effective, cred, cap_effective);
            if (cap_effective & (1ULL << 21)) { // CAP_SYS_ADMIN
                return 0; // Exempt privileged admin containers
            }
        }
    }

    return 1; // Restricted container process
}

static __always_inline struct process_key get_current_process_key() {
    struct process_key key = {0};
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    key.pid = pid_tgid >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        bpf_probe_read_kernel(&key.start_time, sizeof(key.start_time), &task->start_time);
    }
    return key;
}

// AppImage protection plan: process_key's start_time component must be at
// the SAME identity level as its pid component (tgid, i.e. process-level) -
// but get_current_process_key() above reads bpf_get_current_task()'s OWN
// start_time, which is PER-THREAD (task_struct::start_time is set at that
// specific task's own clone()/fork() time, not shared across a thread
// group). Any userspace registration keyed off a process-level fact
// (ProcessCreateDetails::child_start_time, captured at exec time when the
// process is definitionally single-threaded) will silently never match a
// later get_current_process_key() lookup made from a DIFFERENT thread of
// that same process - not just a real multi-threaded target application,
// but even a single Rust test binary, whose own test harness runs each
// #[test] function on its own worker thread by default (confirmed live:
// this is what was actually happening when this helper was added, not a
// hypothetical). Use this instead of get_current_process_key() at any call
// site consulting a map keyed by a process-level (exec-time-captured)
// start_time - revoked_pid_map and protected_owner_pids's self-lookups
// specifically.
//
// Correction: the same applies to every map the fork handler
// propagates. tracepoint_sched_process_fork writes pid_tree_type_map,
// protected_owner_pids, trusted_ancestor_roots, process_threshold_map (and
// the rest) keyed on the GROUP LEADER's start_time, and a new thread's
// clone() is a self-rewrite of that same leader key - no thread ever gets an
// entry of its own. So a get_current_process_key() lookup of the CURRENT
// process against any of those maps matches from the main thread only.
// ptrace_access_check's tracer and task_kill's sender lookups did exactly
// that, and a worker thread of an admin-session process (every interactive
// terminal tree, via the login+TTY stamp in bprm_creds_for_exec) was refused
// /proc/<own child>/exe and kill(own child) as if it were an outsider - six
// cargo lib tests failed under a live daemon that way. Both now use this
// helper; the remaining get_current_process_key() call sites that consult a
// fork-propagated map (is_admin_session, is_install_session, the
// threshold/trusted lookups in the Warden hooks) carry the same latent
// mismatch for worker threads and have not been audited yet.
static __always_inline struct process_key get_current_group_leader_key() {
    struct process_key key = {0};
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    key.pid = pid_tgid >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *leader = task ? BPF_CORE_READ(task, group_leader) : NULL;
    if (leader) {
        bpf_probe_read_kernel(&key.start_time, sizeof(key.start_time), &leader->start_time);
    }
    return key;
}

// build the canonical (dev, ino) identity for
// a resolved struct inode. Returns a zeroed id (dev=0, ino=0) if inode is NULL
// or its superblock can't be read -- callers already guard on inode != NULL
// before calling this in every current use site, so a zero id is only reached
// on the (extremely rare) i_sb read failure, at which point it simply won't
// match any real registered resource.
static __always_inline struct resource_id make_resource_id(struct inode *inode) {
    struct resource_id id = {0};
    if (!inode)
        return id;
    id.ino = BPF_CORE_READ(inode, i_ino);
    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (sb) {
        id.dev = BPF_CORE_READ(sb, s_dev);
    }
    return id;
}

// Both of these consult pid_tree_type_map, which tracepoint_sched_process_fork
// writes keyed on the GROUP LEADER's start_time, so both must ask with the
// leader key - see get_current_group_leader_key()'s doc for why a thread never
// has an entry of its own. They were the two call sites 92c2f26 named as
// carrying the same latent mismatch as the ptrace/task_kill bug it fixed, and
// left unaudited; audited and corrected here.
//
// The mismatch is not symmetric, which is why it stayed invisible. A missed
// TREE_ADMIN_SESSION makes a worker thread of an interactive terminal tree look
// like an outsider, so it loses a bypass it should have had - enforcement
// STRICTER than designed, surfacing as inexplicable denials rather than as a
// hole. A missed TREE_INSTALL_CONTEXT goes the other way: the install-context
// checks exist to withdraw privileges from package-manager descendants
// (`is_admin_session() && !is_install_session()`), so a worker thread of an
// installer kept an admin bypass that the same process's main thread was
// correctly denied. That one IS a hole, and it is the reason to fix both
// together rather than only the one that produced visible failures.
static __always_inline int is_admin_session() {
    struct process_key key = get_current_group_leader_key();
    uint32_t *tree_type = bpf_map_lookup_elem(&pid_tree_type_map, &key);
    if (tree_type && (*tree_type & TREE_ADMIN_SESSION)) {
        return 1;
    }
    return 0;
}

static __always_inline int is_install_session() {
    struct process_key key = get_current_group_leader_key();
    uint32_t *tree_type = bpf_map_lookup_elem(&pid_tree_type_map, &key);
    if (tree_type && (*tree_type & TREE_INSTALL_CONTEXT)) {
        return 1;
    }
    return 0;
}

// true only for an antitheft-agent deployment
// that has set CONFIG_DEPLOYMENT_MODE == MODE_ANTITHEFT via set_config_value().
// A Warden deployment (mode unset, or explicitly MODE_WARDEN) always gets 0 here.
static __always_inline int is_antitheft_mode() {
    uint32_t idx = CONFIG_DEPLOYMENT_MODE;
    uint32_t *mode = bpf_map_lookup_elem(&config_map, &idx);
    return (mode && *mode == MODE_ANTITHEFT);
}

// True in an LSM deployment that is not antitheft (Warden, or a mode not set
// yet). A telemetry tracepoint that was historically attached only in fallback
// mode, and is now attached in LSM mode for antitheft, returns early on this so
// a Warden LSM deployment sees exactly what it saw before.
static __always_inline int is_lsm_non_antitheft_deployment() {
    uint32_t lsm_idx = CONFIG_LSM_ACTIVE;
    uint32_t *lsm_active = bpf_map_lookup_elem(&config_map, &lsm_idx);
    return lsm_active && *lsm_active == 1 && !is_antitheft_mode();
}

// CONFIG_BLOCKING_ENABLED: 0 is the agent's paused/audit-only state, where no
// hook may deny. Every antitheft deny site must be behind this.
static __always_inline int blocking_enabled_now(void) {
    uint32_t idx = CONFIG_BLOCKING_ENABLED;
    uint32_t *v = bpf_map_lookup_elem(&config_map, &idx);
    return v && *v == 1;
}

// Knuth multiplicative hash, folded into a 6-bit slot (0-63) for resource_owner_map's
// bitmask representation — see the map's declaration comment for the collision tradeoff.
static __always_inline uint32_t resource_owner_hash(uint64_t exec_ino) {
    return (uint32_t)((exec_ino * 2654435761ULL) & 0x3FULL);
}

// Phase 3's load-bearing check: is the *currently executing* process one of the
// configured legitimate owners of `resource`? Resources with no
// resource_owner_map entry at all are untouched by this phase (returns 1/allow) —
// Phase 3 only enforces the allowlist for resources Antitheft explicitly opted in.
// Phase 6: `resource` is the canonical (dev, ino) identity, not a bare inode.
// Chain identity (B1/B5): exact owner-set membership for one candidate
// identity - the composite (dev, ino) first, then the legacy bare-inode
// wildcard (owner_dev == 0) that core's own e2e test and the agent's older
// live tests still register through.
static __always_inline int exact_owner_member(struct resource_id id, uint64_t owner_dev, uint64_t owner_ino) {
    struct owner_link link = {0};
    link.dev = id.dev;
    link.ino = id.ino;
    link.owner_dev = owner_dev;
    link.owner_ino = owner_ino;
    uint8_t *member = bpf_map_lookup_elem(&resource_owner_exact, &link);
    if (member && *member == 1)
        return 1;
    link.owner_dev = 0;
    member = bpf_map_lookup_elem(&resource_owner_exact, &link);
    return member && *member == 1;
}

static __always_inline int is_resource_owner(struct resource_id resource) {
    uint64_t *owner_mask = bpf_map_lookup_elem(&resource_owner_map, &resource);
    if (!owner_mask) {
        return 1;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) return 0;
    struct file *exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file) return 0;
    struct inode *exe_inode = BPF_CORE_READ(exe_file, f_inode);
    if (!exe_inode) return 0;
    uint64_t exe_ino = BPF_CORE_READ(exe_inode, i_ino);
    struct super_block *exe_sb = BPF_CORE_READ(exe_inode, i_sb);
    uint64_t exe_dev = exe_sb ? BPF_CORE_READ(exe_sb, s_dev) : 0;

    // Chain identity (B5): the second identity this
    // process may claim - the owner image its exec chain started from. An
    // AppImage's inner python3, a script's interpreter, a helper the app
    // launched: none of them are the registered file themselves, all of
    // them carry it here.
    struct process_key leader_key = get_current_group_leader_key();
    struct exec_origin *origin = bpf_map_lookup_elem(&exec_origin_map, &leader_key);
    uint64_t origin_dev = origin ? origin->dev : 0;
    uint64_t origin_ino = origin ? origin->ino : 0;

    // Cheap negative pre-filter. A clear bit is conclusive - the mask is a
    // superset of the real owner set - so this rejects the common
    // not-an-owner case with one lookup. A set bit proves nothing on its
    // own (one in 64 inodes shares any given slot, and an attacker can
    // choose to), so it only means "ask the exact map".
    int exe_slot = (*owner_mask >> resource_owner_hash(exe_ino)) & 1;
    int origin_slot = origin ? (int)((*owner_mask >> resource_owner_hash(origin_ino)) & 1) : 0;
    if (!exe_slot && !origin_slot)
        return 0;

    // Follow carry-forward aliases to the identity that actually holds the
    // registered owner set. Bounded, because repeated swaps chain: a fixed
    // small number of hops keeps this verifier-friendly and cannot loop on a
    // cycle an attacker manufactures.
    struct resource_id id = resource;
    uint8_t *known = bpf_map_lookup_elem(&resource_exact_known, &id);
    #pragma unroll
    for (int hop = 0; hop < 4; hop++) {
        if (known)
            break;
        struct resource_id *alias_origin = bpf_map_lookup_elem(&resource_owner_alias, &id);
        if (!alias_origin)
            break;
        id = *alias_origin;
        known = bpf_map_lookup_elem(&resource_exact_known, &id);
    }

    if (known) {
        if (exe_slot && exact_owner_member(id, exe_dev, exe_ino))
            return 1;
        if (origin_slot && exact_owner_member(id, origin_dev, origin_ino))
            return 1;
        return 0;
    }

    // No exact information for this identity or anything it aliases to. The
    // mask bit (already checked above) is all there is. Reached only for an
    // identity the kernel protected during a swap whose alias has since been
    // evicted, or one registered by a path-name rule that predates the exact
    // map - deliberately preserved rather than failing closed, so a swap can
    // never lock a legitimate owner out of its own resource.
    return 1;
}

// Storage-dir write/mmap protection - is the current process a
// recognized owner of `dir_id`, a directory `ownership.rs` has registered as
// a storage dir? Returns 1 (owner - trust it), 0 (registered, but this
// process is not an owner - deny), or -1 (not a registered storage dir at
// all - callers should keep walking toward a more distant ancestor, or fall
// back to another trust source). Mirrors is_resource_owner()'s exe+chain-
// origin identity derivation against protected_dir_map/
// protected_dir_owner_exact instead of resource_owner_map/
// resource_owner_exact - see those maps' own declaration comment for why
// there is deliberately no alias-following here.
static __always_inline int dir_owner_verdict(struct resource_id dir_id) {
    uint64_t *owner_mask = bpf_map_lookup_elem(&protected_dir_map, &dir_id);
    if (!owner_mask)
        return -1;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) return 0;
    struct file *exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file) return 0;
    struct inode *exe_inode = BPF_CORE_READ(exe_file, f_inode);
    if (!exe_inode) return 0;
    uint64_t exe_ino = BPF_CORE_READ(exe_inode, i_ino);
    struct super_block *exe_sb = BPF_CORE_READ(exe_inode, i_sb);
    uint64_t exe_dev = exe_sb ? BPF_CORE_READ(exe_sb, s_dev) : 0;

    // Chain identity, same rationale as is_resource_owner(): an app's own
    // interpreter/AppImage-inner-process writing/loading its OWN storage
    // dir's `.so` must be recognized too, not just the literal registered
    // exe.
    struct process_key leader_key = get_current_group_leader_key();
    struct exec_origin *origin = bpf_map_lookup_elem(&exec_origin_map, &leader_key);
    uint64_t origin_dev = origin ? origin->dev : 0;
    uint64_t origin_ino = origin ? origin->ino : 0;

    int exe_slot = (*owner_mask >> resource_owner_hash(exe_ino)) & 1;
    int origin_slot = origin ? (int)((*owner_mask >> resource_owner_hash(origin_ino)) & 1) : 0;
    if (!exe_slot && !origin_slot)
        return 0;

    struct owner_link link = {0};
    link.dev = dir_id.dev;
    link.ino = dir_id.ino;
    if (exe_slot) {
        link.owner_dev = exe_dev;
        link.owner_ino = exe_ino;
        uint8_t *m = bpf_map_lookup_elem(&protected_dir_owner_exact, &link);
        if (m && *m == 1) return 1;
    }
    if (origin_slot) {
        link.owner_dev = origin_dev;
        link.owner_ino = origin_ino;
        uint8_t *m = bpf_map_lookup_elem(&protected_dir_owner_exact, &link);
        if (m && *m == 1) return 1;
    }
    return 0;
}

// How many ancestor levels to walk looking for a registered storage dir.
// This is a LOOKUP depth, measured from the file being accessed, and it is
// deliberately deeper than ownership.rs's STORAGE_DIR_WALK_DEPTH (4), which
// is a REGISTRATION depth measured from the corpus resource. The two answer
// different questions: registration climbs from `Login Data` up to
// `google-chrome/` (2 hops), but the file that later needs that
// registration can sit much further down - Chrome's own Widevine CDM is
// `google-chrome/WidevineCdm/<ver>/_platform_specific/linux_x64/
// libwidevinecdm.so`, 5 hops below the registered dir, and a 4-hop walk
// never reached it, so mmap_file denied Chrome its own DRM module while
// the comment two screens up promised exactly that case worked
// (live). Must stay >= the registration depth (a dir
// registered at hop 4 would never be found by a 3-hop walk) plus the
// deepest nesting any app keeps under its data root; 8 leaves headroom.
// Going deeper is safe under the nearest-registered-ancestor-wins rule
// below: an unregistered ancestor is simply skipped, and ownership.rs never
// registers anything as broad as ~/.config or $HOME.
// Tiered: see the __SMALL_BPF_PROG note at the top of this file. A shallower
// walk never produces a WRONG verdict - the nearest-registered-ancestor rule
// still holds - it just stops looking sooner, so a dir registered deeper than
// the bound goes unprotected rather than misprotected.
#ifdef __SMALL_BPF_PROG
#define STORAGE_DIR_WALK_DEPTH 4
#else
#define STORAGE_DIR_WALK_DEPTH 8
#endif

// Walks up from `file_dentry`'s parent looking for the NEAREST ancestor
// directory registered as a protected storage dir, and returns ITS verdict
// (1 = allow, 0 = deny) the moment one is found - a more distant
// ancestor's registration must never override a nearer, more specific one.
// This is what keeps one app's storage-dir protection from leaking onto an
// unrelated sibling directory nested under a shared parent (e.g. `~/.config`
// itself is never registered by ownership.rs, so Firefox's own protected
// `~/.mozilla/firefox/` can't be shadowed by some other app's broader
// registration, and vice versa). Returns -1 if nothing within the walked
// depth is registered at all - same bounded-ancestor-walk idiom already
// used by file_permission's DB-bypass-directories check above.
// A store the corpus names as a FOLDER (a leveldb directory, an extension's storage): the folder is
// the registered resource, and a file in it, or one folder down, is judged by the folder's owner
// set. `file_open` asks this only for a file with no protection of its own. Registering each file
// instead made every short-lived leveldb table an identity of its own, and leveldb's renames,
// deletes and ext4's reuse of freed numbers kept leaving one owned by the daemon alone: Chrome was
// refused its own wallet extension's files (antitheft dev stack). The folder's identity
// does not churn. A folder counts when it has an owner mask: a registered, denying resource. An
// audit-only folder has none, and neither has the parent of a `dir/*` glob, whose files are each
// registered.
#define STORE_DIR_WALK_DEPTH 2
static __always_inline int protected_store_dir_of(struct file *file, struct resource_id *out) {
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    #pragma unroll
    for (int i = 0; i < STORE_DIR_WALK_DEPTH; i++) {
        if (!dentry) return 0;
        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
        if (!parent || parent == dentry) return 0;
        struct inode *dir = BPF_CORE_READ(parent, d_inode);
        if (!dir) return 0;
        struct resource_id id = make_resource_id(dir);
        if (bpf_map_lookup_elem(&resource_owner_map, &id) && bpf_map_lookup_elem(&sensitive_inodes_map, &id)) {
            *out = id;
            return 1;
        }
        dentry = parent;
    }
    return 0;
}

static __always_inline int storage_dir_verdict(struct dentry *file_dentry) {
    struct dentry *dentry = file_dentry;
    #pragma unroll
    for (int i = 0; i < STORAGE_DIR_WALK_DEPTH; i++) {
        if (!dentry) break;
        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
        if (!parent) break;
        struct inode *dir_inode = BPF_CORE_READ(parent, d_inode);
        if (dir_inode) {
            struct resource_id dir_id = make_resource_id(dir_inode);
            int verdict = dir_owner_verdict(dir_id);
            if (verdict >= 0)
                return verdict;
        }
        dentry = parent;
    }
    return -1;
}

// Is the current process a registered antitheft-protected owner at all,
// regardless of the self-injection switch? Deliberately separate from
// protected_selfexec_forbidden(): that function answers "may this process
// build ITS OWN executable memory", a switchable, off-by-default question,
// which is a different one from "may this process load an arbitrary FOREIGN
// file it doesn't own as a shared library" - always denied, for a browser
// exactly as much as for a wallet, since no engine's code generation has
// anything to do with dlopen()-ing someone else's .so.
// OWNER_NO_EXTERNAL_INHERIT's "is this new image part of the same install?"
// test. Walks up from the image being exec'd looking for the origin image's
// own directory, so a helper beside the app binary
// (/opt/google/chrome/chrome -> chrome_crashpad_handler, chrome-sandbox) and
// one in a subdirectory of the app root (/opt/App/App -> /opt/App/sub/helper)
// both count as internal, while anything reached from elsewhere in the
// filesystem does not (a native messaging host under ~/.claude/chrome, a
// game under ~/.steam/steamapps).
//
// Returns 1 = internal (inherit as before), 0 = external (lives on its own).
// A zero origin dir means "unknown" and answers 1, so a chain stamped from
// userspace can never be dropped by a test it has no data for.
//
// KNOWN LIMIT, deliberate: an owner binary that lives in a SHARED directory
// makes that whole directory internal - /usr/bin would admit every binary in
// it. Only 2 of the 45 flagged corpus entries are shaped that way (the rest
// are /opt/<vendor>/<app> or /usr/lib/<app>), and the real fix for those is
// package identity, not a deeper walk. See config.rs's
// no_external_inheritance doc.
#ifdef __SMALL_BPF_PROG
#define OWNER_INHERIT_WALK_DEPTH 2
#else
#define OWNER_INHERIT_WALK_DEPTH 4
#endif
static __always_inline int image_is_internal_to_origin(struct dentry *img_dentry,
                                                      uint64_t origin_dir_dev,
                                                      uint64_t origin_dir_ino) {
    if (!origin_dir_ino)
        return 1; // unknown origin dir - never drop on a test we cannot run
    struct dentry *dentry = img_dentry;
    #pragma unroll
    for (int i = 0; i < OWNER_INHERIT_WALK_DEPTH; i++) {
        if (!dentry) break;
        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
        if (!parent || parent == dentry) break; // filesystem root
        struct inode *dir_inode = BPF_CORE_READ(parent, d_inode);
        if (dir_inode) {
            struct resource_id dir_id = make_resource_id(dir_inode);
            if (dir_id.dev == origin_dir_dev && dir_id.ino == origin_dir_ino)
                return 1;
        }
        dentry = parent;
    }
    return 0;
}

static __always_inline int is_protected_owner_process(void) {
    if (!is_antitheft_mode())
        return 0;
    struct process_key self_key = get_current_group_leader_key();
    uint8_t *self_protected = bpf_map_lookup_elem(&protected_owner_pids, &self_key);
    return self_protected && (*self_protected & OWNER_PROTECTED) ? 1 : 0;
}


// Cheap, bounded "does this filename look like a shared library" check -
// deliberately a substring scan, not a hard suffix match, so it also covers
// versioned SONAMEs (`libfoo.so.1`, `libfoo.so.2.0.0`), not just a bare
// `foo.so`. A false positive (an ordinary file whose name happens to
// contain ".so") fails safe here - the cost is one extra directory-owner
// check on an ordinary write, not a missed library.
//
// KNOWN LOW-SEVERITY OVER-MATCH (review note): ".so" is matched
// ANYWHERE in the name, so `foo.sock`, `bar.soap`, `x.sopolicy` also count as
// "libraries". The only consequence in the antitheft storage-dir `.so`-write
// gate is that a NON-OWNER writing such a (non-library) file into a
// registered storage dir is wrongly denied. Real-world impact is negligible
// (owners are unaffected; those names are rare inside a protected app's data
// dir), so this is left as-is; if it ever matters, tighten to a real suffix
// check (".so" at end, or ".so." followed by a version digit). Do NOT narrow
// to a bare-suffix `.so$` only - that would miss versioned SONAMEs above.
static __always_inline int dentry_name_has_so_extension(struct dentry *dentry) {
    struct qstr d_name;
    bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
    char fname[64];
    long n = bpf_probe_read_kernel_str(fname, sizeof(fname), d_name.name);
    if (n <= 0) return 0;
    #pragma unroll
    for (int i = 0; i + 2 < 64; i++) {
        if (fname[i] == '\0') break;
        if (fname[i] == '.' && fname[i + 1] == 's' && fname[i + 2] == 'o')
            return 1;
    }
    return 0;
}

// Firewall egress check — LPM longest-prefix lookup against fw_rules_v4/v6.
// dest_ip is 4 raw network-byte-order bytes (as already extracted by
// socket_connect's existing sin->sin_addr.s_addr read); dest_ip6 is 16 raw
// network-byte-order bytes. Only DENY is checked: there is no explicit
// ALLOW override at this layer (unlike IptablesBackend's -I precedent) —
// an eBPF-layer allowlist entry isn't written by warden today, so
// FW_ACTION_ALLOW values are reserved for future use and currently
// unreachable via the rule store.
static __always_inline int fw_check_egress(unsigned short family, uint32_t dest_ip, const uint8_t *dest_ip6) {
    if (family == 2) {
        struct fw_key4 key = {};
        key.prefixlen = 32;
        __builtin_memcpy(key.addr, &dest_ip, 4);
        struct fw_value *v = bpf_map_lookup_elem(&fw_rules_v4, &key);
        if (v && v->action == FW_ACTION_DENY) {
            return -EACCES;
        }
    } else if (family == 10 && dest_ip6) {
        struct fw_key6 key = {};
        key.prefixlen = 128;
        __builtin_memcpy(key.addr, dest_ip6, 16);
        struct fw_value *v = bpf_map_lookup_elem(&fw_rules_v6, &key);
        if (v && v->action == FW_ACTION_DENY) {
            return -EACCES;
        }
    }
    return 0;
}


// P2-9: Increment and return a monotonic sequence number
static __always_inline uint64_t next_seq() {
    uint32_t idx = 0;
    uint64_t *cnt = bpf_map_lookup_elem(&seq_counter, &idx);
    if (cnt) {
        (*cnt)++;
        return *cnt;
    }
    return 0;
}

// Initialise header fields common to all events
static __always_inline void fill_header(struct TelemetryEvent *ev,
                                        uint8_t event_type, uint8_t source,
                                        uint32_t pid) {
    ev->header.sequence_number = next_seq();
    ev->header.timestamp_ns    = bpf_ktime_get_ns();
    ev->header.pid             = pid;
    ev->header.event_type      = event_type;
    ev->header.source          = source;
    // ringbuf-reserved memory isn't guaranteed zeroed - set explicitly.
    ev->header.actor_sequence_number = 0;
}

// Supply-chain scoping: is the current process something a package manager
// FORKED during an install (pkg_lifecycle_pids depth >= 2), with blocking
// armed, in antitheft mode? The one predicate every persistence rule below
// is gated on - the package manager itself (depth 1) never is. Returns
// PKG_DESC_NONE, PKG_DESC_DENY (a language ecosystem's install script -
// refuse) or PKG_DESC_AUDIT (a distro maintainer script - report only, see
// PKG_LIFECYCLE_DISTRO's comment).
#define PKG_DESC_NONE  0
#define PKG_DESC_DENY  1
#define PKG_DESC_AUDIT 2
static __always_inline int pkg_descendant_kind(void) {
    if (!is_antitheft_mode()) return PKG_DESC_NONE;
    uint32_t config_idx = 0;
    uint32_t *mode_val = bpf_map_lookup_elem(&config_map, &config_idx);
    if (!mode_val || *mode_val != 1) return PKG_DESC_NONE;
    struct process_key pkg_key = get_current_group_leader_key();
    uint8_t *v = bpf_map_lookup_elem(&pkg_lifecycle_pids, &pkg_key);
    if (!v || (*v & PKG_LIFECYCLE_DEPTH_MASK) < PKG_LIFECYCLE_DESCENDANT) return PKG_DESC_NONE;
    return (*v & PKG_LIFECYCLE_DISTRO) ? PKG_DESC_AUDIT : PKG_DESC_DENY;
}

// Would the name `dentry` carries, placed in directory `dir`, land on a
// persistence location? Either `dir` is a registered drop dir
// (persistence_dirs_map: autostart, unit dirs, cron.d) or (dir, name) is a
// registered append-file (persistence_names_map: ~/.bashrc, /etc/crontab).
// `dir_id` receives the directory's identity for the deny telemetry.
//
// It runs for EVERY create/rename/link/unlink in antitheft mode
// (persistence_write_check), so the ordinary path is one lookup: persistence_dirs_map
// value 1 is a drop dir, value 2 a directory that holds a registered append-file name
// (EbpfLoader::AddPersistenceName marks it), and only those hash the name.
static __always_inline int is_persistence_target(struct inode *dir, struct dentry *dentry, struct resource_id *dir_id) {
    if (!dir) return 0;
    *dir_id = make_resource_id(dir);
    uint8_t *persist = bpf_map_lookup_elem(&persistence_dirs_map, dir_id);
    if (!persist) return 0;
    if (*persist == 1) return 1;
    if (!dentry) return 0;
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    uint64_t name_hash = fnv1a_hash_name(d_name.name);
    struct path_name_id name_id = { dir_id->dev, dir_id->ino, name_hash };
    uint8_t *named = bpf_map_lookup_elem(&persistence_names_map, &name_id);
    return named && *named == 1;
}

// FileOpenDetails::access_mode for a file an LSM hook is opening: read and
// write from f_mode (FMODE_READ 0x1 and FMODE_WRITE 0x2 have had these
// values on every kernel), truncation from f_flags (O_TRUNC, 01000 in the
// generic and x86/arm64 uapi; still set at security_file_open, which runs
// before do_dentry_open clears it). Read at the emission site, not once at
// the top of the hook, so no extra value stays live across file_open.
#define KINN_O_TRUNC 01000
static __always_inline uint8_t kinn_open_access(struct file *file) {
    uint32_t mode = BPF_CORE_READ(file, f_mode);
    uint32_t flags = BPF_CORE_READ(file, f_flags);
    uint8_t out = KINN_OPEN_KNOWN;
    if (mode & 0x1) out |= KINN_OPEN_READ;
    if (mode & 0x2) out |= KINN_OPEN_WRITE;
    if (flags & KINN_O_TRUNC) out |= KINN_OPEN_TRUNC;
    return out;
}

// One EVT_FILE_OPEN for every write into a persistence location, whichever
// hook saw it: verdict 5 = denied, 6 = observed only (a distro maintainer
// script, see PKG_LIFECYCLE_DISTRO), 8 = observed, written by anything else
// (7 is file_open's rename deny).
// resource_dev/ino carry the persistence DIRECTORY's identity (never a
// tracked resource - the agent resolves it through its own registration
// index), file_path the leaf name, pkg_lifecycle the writer's install mark
// and persist_op the operation.
// FileOpenDetails::parent_pid / process_start_time for the current process. Every EVT_FILE_OPEN site
// calls it: the ring buffer is not zeroed, so a site that skipped it would send garbage.
static __always_inline void kinn_file_open_actor(struct FileOpenDetails *d) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct process_key leader = get_current_group_leader_key();
    d->parent_pid = task ? BPF_CORE_READ(task, real_parent, tgid) : 0;
    d->process_start_time = leader.start_time;
}

static __always_inline void emit_persistence_deny(struct resource_id dir_id, struct dentry *dentry, uint32_t pid, uint8_t verdict, uint8_t pkg, uint8_t op) {
    struct TelemetryEvent *ev = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (!ev) return;
    fill_header(ev, EVT_FILE_OPEN, SRC_BPF_LSM, pid);
    kinn_file_open_actor(&ev->details.file_open);
    ev->details.file_open.resource_dev = dir_id.dev;
    ev->details.file_open.resource_ino = dir_id.ino;
    ev->details.file_open.verdict = verdict;
    ev->details.file_open.access_mode = 0; // a directory decision, no open mode
    ev->details.file_open.response = 0;
    ev->details.file_open.pkg_lifecycle = pkg;
    ev->details.file_open.persist_op = op;
    ev->details.file_open.file_path[0] = 0;
    if (dentry) {
        struct qstr d_name = BPF_CORE_READ(dentry, d_name);
        bpf_probe_read_kernel_str(ev->details.file_open.file_path, sizeof(ev->details.file_open.file_path), d_name.name);
    }
    bpf_ringbuf_submit(ev, 0);
}

// Every name-level write into a persistence location (create, mkdir, rename either way, link,
// symlink, unlink), for ANY process in antitheft mode. Before, only an install's
// descendant with blocking armed was reported, so the agent learned of a snap refresh's new unit
// files only by re-reading them later and named their READERS (systemctl, systemd) as the writer.
// Now the kernel names the writer and its install mark at the moment of the write, so the agent can
// tell a package manager's routine change from anything else without racing the writer's exit.
// The decision is the old one: an install's non-distro descendant is refused, nothing else is.
// The report and decision for a write already known to land in persistence directory `dir_id`.
static __always_inline int persistence_write_report(struct resource_id dir_id, struct dentry *dentry, uint32_t pid, uint8_t op) {
    int kind = pkg_descendant_kind();
    struct process_key pkg_key = get_current_group_leader_key();
    uint8_t *pkg = bpf_map_lookup_elem(&pkg_lifecycle_pids, &pkg_key);
    uint8_t verdict = kind == PKG_DESC_DENY ? 5 : kind == PKG_DESC_AUDIT ? 6 : 8;
    emit_persistence_deny(dir_id, dentry, pid, verdict, pkg ? *pkg : 0, op);
    return kind == PKG_DESC_DENY ? -EACCES : 0;
}

static __always_inline int persistence_write_check(struct inode *dir, struct dentry *dentry, uint32_t pid, uint8_t op) {
    if (!is_antitheft_mode()) return 0;
    struct resource_id dir_id = {0};
    if (!is_persistence_target(dir, dentry, &dir_id)) return 0;
    return persistence_write_report(dir_id, dentry, pid, op);
}

static __always_inline void format_ip_port(char *buf, unsigned char *b, uint16_t port) {
    int offset = 0;
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        unsigned char val = b[i];
        if (val >= 100) {
            buf[offset++] = '0' + (val / 100);
            buf[offset++] = '0' + ((val % 100) / 10);
            buf[offset++] = '0' + (val % 10);
        } else if (val >= 10) {
            buf[offset++] = '0' + (val / 10);
            buf[offset++] = '0' + (val % 10);
        } else {
            buf[offset++] = '0' + val;
        }
        if (i < 3) {
            buf[offset++] = '.';
        }
    }
    buf[offset++] = ':';

    uint16_t p = port;
    char port_digits[5];
    port_digits[4] = '0' + (p % 10); p /= 10;
    port_digits[3] = '0' + (p % 10); p /= 10;
    port_digits[2] = '0' + (p % 10); p /= 10;
    port_digits[1] = '0' + (p % 10); p /= 10;
    port_digits[0] = '0' + (p % 10);

    bool leading_zero = true;
    #pragma unroll
    for (int i = 0; i < 5; i++) {
        if (leading_zero && port_digits[i] == '0' && i < 4) {
            // skip
        } else {
            leading_zero = false;
            buf[offset++] = port_digits[i];
        }
    }
    buf[offset] = '\0';
}

// ABI FIX, added alongside format_ip_port above: dotted-decimal
// IPv4 text (no port suffix - NetworkConnectDetails carries destination_port
// as its own separate field already). Reuses the exact same verifier-proven
// digit-formatting loop as format_ip_port, since BPF can't call sprintf.
static __always_inline void format_ipv4_string(char *buf, unsigned char *b) {
    int offset = 0;
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        unsigned char val = b[i];
        if (val >= 100) {
            buf[offset++] = '0' + (val / 100);
            buf[offset++] = '0' + ((val % 100) / 10);
            buf[offset++] = '0' + (val % 10);
        } else if (val >= 10) {
            buf[offset++] = '0' + (val / 10);
            buf[offset++] = '0' + (val % 10);
        } else {
            buf[offset++] = '0' + val;
        }
        if (i < 3) {
            buf[offset++] = '.';
        }
    }
    buf[offset] = '\0';
}

// ABI FIX: 8 groups of 4 hex digits, colon-separated - valid
// IPv6 text but deliberately NOT RFC 5952 canonical (no `::` zero-run
// compression, which needs variable-length/conditional output that's much
// harder to keep verifier-simple). Good enough for logging/matching/display;
// a future pass can add compression if a consumer needs canonical form.
static __always_inline void format_ipv6_string(char *buf, unsigned char *b) {
    const char hex[] = "0123456789abcdef";
    int offset = 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        unsigned char hi = b[i * 2];
        unsigned char lo = b[i * 2 + 1];
        buf[offset++] = hex[(hi >> 4) & 0xF];
        buf[offset++] = hex[hi & 0xF];
        buf[offset++] = hex[(lo >> 4) & 0xF];
        buf[offset++] = hex[lo & 0xF];
        if (i < 7) {
            buf[offset++] = ':';
        }
    }
    buf[offset] = '\0';
}

// ABI FIX: PROT_READ(1)/PROT_WRITE(2)/PROT_EXEC(4) has exactly
// 8 combinations - a plain switch over compile-time-constant string literals
// (via __builtin_memcpy, already used elsewhere in this file for fixed-size
// copies) is simpler and more obviously verifier-safe than a general
// formatter for a 3-bit input.
static __always_inline void format_prot_flags(uint32_t prot, char *out) {
    switch (prot & 0x7) {
        case 0x0: __builtin_memcpy(out, "PROT_NONE", 10); break;
        case 0x1: __builtin_memcpy(out, "PROT_READ", 10); break;
        case 0x2: __builtin_memcpy(out, "PROT_WRITE", 11); break;
        case 0x3: __builtin_memcpy(out, "PROT_READ|PROT_WRITE", 21); break;
        case 0x4: __builtin_memcpy(out, "PROT_EXEC", 10); break;
        case 0x5: __builtin_memcpy(out, "PROT_READ|PROT_EXEC", 20); break;
        case 0x6: __builtin_memcpy(out, "PROT_WRITE|PROT_EXEC", 21); break;
        default:  __builtin_memcpy(out, "PROT_READ|PROT_WRITE|PROT_EXEC", 32); break;
    }
}

// ABI FIX: PTRACE_MODE_* is a wider bitmask (READ=0x1,
// ATTACH=0x2, plus FSCREDS/REALCREDS/NOAUDIT nuance bits) than prot's 3
// bits - this surfaces only the two operationally meaningful ones rather
// than fully enumerating every combination, which is honest simplification,
// not a hidden gap (the numeric value was never decodable as a string at
// all before this fix).
static __always_inline void format_ptrace_mode(unsigned int mode, char *out) {
    if (mode & 0x2) {
        __builtin_memcpy(out, "PTRACE_MODE_ATTACH", 20);
    } else if (mode & 0x1) {
        __builtin_memcpy(out, "PTRACE_MODE_READ", 17);
    } else {
        __builtin_memcpy(out, "PTRACE_MODE_UNKNOWN", 21);
    }
}

// fd -> file resolution. Neither
// sys_enter_dup2/dup3 nor sys_enter_listen are LSM hooks (they're raw
// syscall tracepoints with only integer fd arguments), so resolving an fd to
// its underlying struct file* in the *current* task needs a manual fd-table
// walk: task_struct -> files -> fdt -> fd[N], fdtable.max_fds bounds the
// array. Landed with no caller yet (Phase 2/3 wire it up) so a verifier
// rejection there doesn't entangle with this primitive's own compile check.
static __always_inline struct file *resolve_fd_to_file(unsigned int fd) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return NULL;
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files) return NULL;
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) return NULL;
    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    // Belt-and-suspenders clamp *in addition to* the runtime bounds check -
    // this file's own null-check-reread lesson applies to bounds proofs too:
    // a runtime `if` comparing against a CO-RE-read value isn't always
    // enough for the verifier to prove the subsequent fd_array[fd] pointer
    // arithmetic is bounded. Clamp fd to a small compile-time-provable range
    // first; only trust it further if the runtime max_fds check also passes.
    if (fd >= 4096) return NULL;
    fd &= 4095;
    if (fd >= max_fds) return NULL;
    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array) return NULL;
    struct file *file = NULL;
    bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
    return file;
}

enum FdKind { FD_UNKNOWN = 0, FD_FILE = 1, FD_SOCKET = 2, FD_PIPE = 3 };

// The address family of the socket behind a socket file (AF_UNIX 1, AF_INET 2, AF_INET6 10),
// 0 when unreadable. A sockfs file's private_data is its struct socket (the same
// sk->__sk_common.skc_family Tetragon's set_event_from_sock reads).
static __always_inline uint16_t resolve_socket_family(struct file *file) {
    struct socket *sock = BPF_CORE_READ(file, private_data);
    if (!sock) return 0;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk) return 0;
    return BPF_CORE_READ(sk, __sk_common.skc_family);
}

// `*family` is set only for FD_SOCKET (0 otherwise): libuv hands every child a
// socketpair(AF_UNIX) as stdio, so "a socket" alone does not mean the network.
static __always_inline uint8_t resolve_fd_kind(unsigned int fd, uint16_t *family) {
    *family = 0;
    struct file *file = resolve_fd_to_file(fd);
    if (!file) return FD_UNKNOWN;
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode) return FD_UNKNOWN;
    unsigned short mode = BPF_CORE_READ(inode, i_mode);
    unsigned short fmt = mode & 0170000; // S_IFMT
    if (fmt == 0140000) { // S_IFSOCK
        *family = resolve_socket_family(file);
        return FD_SOCKET;
    }
    if (fmt == 0010000) return FD_PIPE;   // S_IFIFO
    return FD_FILE;
}

static __always_inline void record_and_batch_event(uint32_t op_type, struct file *file, uint64_t ino, const char *direct_name) {
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    struct fs_batch_key key = {0};
    key.pid = pid;
    key.op_type = op_type;
    key.inode = ino;

    struct fs_batch_value *val = bpf_map_lookup_elem(&fs_batch_map, &key);
    uint64_t now = bpf_ktime_get_ns();

    if (val) {
        val->count++;
        // If 1 second (1,000,000,000 ns) has passed since last flush, or count > 500
        if (now - val->last_flush > 1000000000ULL || val->count > 500) {
            struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
            if (event) {
                fill_header(event, EVT_FILE_BATCH, SRC_BPF_LSM, pid);
                uint32_t *op_ptr = (uint32_t *)&event->details.details_buffer[0];
                uint32_t *cnt_ptr = (uint32_t *)&event->details.details_buffer[4];
                char *path_ptr = (char *)&event->details.details_buffer[8];

                *op_ptr = op_type;
                *cnt_ptr = (uint32_t)val->count;
                bpf_probe_read_kernel(path_ptr, 256, val->file_path);

                bpf_ringbuf_submit(event, 0);
            }
            val->count = 0;
            val->last_flush = now;
        }
    } else {
        uint32_t zero = 0;
        struct scratch_buf *buf = bpf_map_lookup_elem(&scratch_map, &zero);
        if (buf) {
            __builtin_memset(&buf->new_val, 0, sizeof(buf->new_val));
            buf->new_val.count = 1;
            buf->new_val.last_flush = now;
            if (file) {
                // bpf_d_path was
                // attempted here but REVERTED - real verifier rejection
                // ("helper call is not allowed in probe") confirmed this
                // kfunc is only callable from a subset of this file's LSM
                // attach points (file_open's own direct emit sites verified
                // to work; this shared helper is also inlined into
                // file_permission/bprm_check_security's call sites, which do
                // NOT accept it) - kept as the leaf-name capture it always
                // was. See kinnector.bpf.c's Phase 10 sites in file_open for
                // where the fix DID land. Real, stated gap, not silently
                // dropped - a future pass could special-case this helper by
                // attach type if the extra complexity is worth it.
                struct qstr d_name;
                bpf_probe_read_kernel(&d_name, sizeof(d_name), &BPF_CORE_READ(file, f_path.dentry)->d_name);
                bpf_probe_read_kernel_str(buf->new_val.file_path, sizeof(buf->new_val.file_path), d_name.name);
            } else if (direct_name) {
                bpf_probe_read_kernel_str(buf->new_val.file_path, sizeof(buf->new_val.file_path), direct_name);
            }
            bpf_map_update_elem(&fs_batch_map, &key, &buf->new_val, BPF_ANY);
        }
    }
}


#endif  // KINNECTOR_BPF_HELPERS_H
