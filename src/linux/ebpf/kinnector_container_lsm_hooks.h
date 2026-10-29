// SPDX-License-Identifier: GPL-2.0-only
#ifndef KINNECTOR_BPF_CONTAINER_LSM_HOOKS_H
#define KINNECTOR_BPF_CONTAINER_LSM_HOOKS_H

// Container sandboxing/escape-prevention LSM hooks (sb_mount, path_chroot,
// sb_pivotroot, socket_accept/sendmsg, the inode_* family and their
// lsm_d_instantiate companion, task_fix_setuid/setgid,
// capset, task_prctl, shm_shmat) plus the namespace/clone tracepoints and
// the iter/task program that are interleaved with them in the original
// source. Verbatim split out of kinnector.bpf.c - see that file's header
// comment. Corresponds to the original "Container Sandboxing & Escape
// Prevention LSM Hooks" section banner exactly (this section already mixed
// hook kinds in the monolithic file; this split does not re-sort them).

// ---------------------------------------------------------------------------
// Container Sandboxing & Escape Prevention LSM Hooks
// ---------------------------------------------------------------------------

// telemetry-only addition, appended
// after the existing is_container_restricted() enforcement - that check and
// its -EPERM/SIGKILL responses are not touched, reordered, or made
// conditional on anything new. Emits for every process, not just
// is_container_restricted() ones (a normal host process using these was
// previously entirely invisible).
static __always_inline void emit_namespace_change(uint8_t operation, uint64_t flags) {
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_NAMESPACE_CHANGE, SRC_BPF_LSM, pid);
        event->details.namespace_change.operation = operation;
        event->details.namespace_change.flags = flags;
        bpf_ringbuf_submit(event, 0);
    }
}

SEC("lsm/sb_mount")
int BPF_PROG(warden_sb_mount, const char *dev_name, const struct path *path,
             const char *type, unsigned long flags, void *data) {
    emit_namespace_change(2, 0); // 2=mount, no equivalent single flags value
    if (is_container_restricted()) {
        bpf_printk("[Warden LSM] Blocked mount attempt from restricted container namespace\n");
        return -EPERM;
    }
    return 0;
}

SEC("lsm/path_chroot")
int BPF_PROG(warden_path_chroot, const struct path *path) {
    emit_namespace_change(3, 0); // 3=chroot
    if (is_container_restricted()) {
        bpf_printk("[Warden LSM] Blocked chroot attempt from restricted container namespace\n");
        return -EPERM;
    }
    return 0;
}

// pivot_root - the container-grade
// sibling of chroot. Confirmed real LSM hook (sb_pivotroot), zero
// enforcement, matching this file's other new-hook-in-this-plan discipline.
SEC("lsm/sb_pivotroot")
int BPF_PROG(sb_pivotroot, const struct path *old_path, const struct path *new_path) {
    emit_namespace_change(4, 0); // 4=pivot_root
    return 0;
}

struct sys_enter_setns_args {
    unsigned long long pad;
    long syscall_nr;
    int fd;
    int flags; // confirmed real tracepoint field name is literally "flags"
};

SEC("tracepoint/syscalls/sys_enter_setns")
int tracepoint_sys_enter_setns(struct sys_enter_setns_args *ctx) {
    emit_namespace_change(0, (uint64_t)(unsigned long)ctx->flags); // 0=setns
    if (is_container_restricted()) {
        bpf_printk("[Warden LSM] Blocked setns attempt: killing container process\n");
        bpf_send_signal(9); // SIGKILL immediately to terminate breakout
    }
    return 0;
}

struct sys_enter_unshare_args {
    unsigned long long pad;
    long syscall_nr;
    unsigned long unshare_flags;
};

SEC("tracepoint/syscalls/sys_enter_unshare")
int tracepoint_sys_enter_unshare(struct sys_enter_unshare_args *ctx) {
    emit_namespace_change(1, (uint64_t)ctx->unshare_flags); // 1=unshare
    if (is_container_restricted()) {
        bpf_printk("[Warden LSM] Blocked unshare attempt: killing container process\n");
        bpf_send_signal(9); // SIGKILL immediately
    }
    return 0;
}

// CLONE_NEWUSER/CLONE_NEWNS/etc.
// can be requested directly at process-creation time via clone(2)/clone3(2),
// without ever calling unshare()/setns() afterward. Only emit when a
// namespace-creating flag is actually set - a plain thread/process clone is
// not namespace-relevant, don't emit noise.
#define CLONE_NEWNS      0x00020000
#define CLONE_NEWCGROUP  0x02000000
#define CLONE_NEWUTS     0x04000000
#define CLONE_NEWIPC     0x08000000
#define CLONE_NEWUSER    0x10000000
#define CLONE_NEWPID     0x20000000
#define CLONE_NEWNET     0x40000000
#define CLONE_NEWNS_MASK (CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | \
                           CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET)

struct sys_enter_clone_args {
    unsigned long long pad;
    long syscall_nr;
    unsigned long clone_flags;
    unsigned long newsp;
    int *parent_tidptr;
    int *child_tidptr;
    unsigned long tls;
};

SEC("tracepoint/syscalls/sys_enter_clone")
int tracepoint_sys_enter_clone(struct sys_enter_clone_args *ctx) {
    unsigned long flags = ctx->clone_flags;
    if (flags & CLONE_NEWNS_MASK) {
        emit_namespace_change(5, (uint64_t)flags); // 5=clone_ns
    }
    return 0;
}

struct clone_args_uapi {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
};

struct sys_enter_clone3_args {
    unsigned long long pad;
    long syscall_nr;
    struct clone_args_uapi *uargs;
    unsigned long size;
};

SEC("tracepoint/syscalls/sys_enter_clone3")
int tracepoint_sys_enter_clone3(struct sys_enter_clone3_args *ctx) {
    if (!ctx->uargs) return 0;
    uint64_t flags = 0;
    // clone_args->flags is the struct's first u64 field, in *user* memory
    // (clone3's uargs is a userspace pointer) - one bpf_probe_read_user
    // deref, same technique this file's envp scan already uses.
    bpf_probe_read_user(&flags, sizeof(flags), &ctx->uargs->flags);
    if (flags & CLONE_NEWNS_MASK) {
        emit_namespace_change(5, flags); // 5=clone_ns
    }
    return 0;
}

#ifndef bpf_ntohs
#define bpf_ntohs(x) (uint16_t)(((uint16_t)(x) >> 8) | ((uint16_t)(x) << 8))
#endif
#ifndef bpf_htons
#define bpf_htons(x) (uint16_t)(((uint16_t)(x) >> 8) | ((uint16_t)(x) << 8))
#endif

// Fix: this hook was originally written against a "socket_post_accept" LSM
// hook that does not exist in the kernel's LSM hook set (verified via BTF --
// no security_socket_post_accept symbol on any checked kernel) and whose
// 3-arg signature (sock, newsock, flags) doesn't match any real hook either.
// bpf_object__load() loads all programs in the object atomically, so this one
// bad definition silently failed the ENTIRE object's load -- every other
// program in this file, including every real enforcement hook, fell back to
// degraded tracepoint mode as a result. The real hook for "after an inbound
// connection is accepted" is security_socket_accept(sock, newsock) -- 2 args,
// confirmed against kernel BTF. Logic is unchanged: telemetry-only, always
// returns 0, per this file's own documented inbound-enforcement scope (see
// the FW_ACTION_* comment above -- inbound blocking stays iptables/nftables,
// not this hook).
SEC("lsm/socket_accept")
int BPF_PROG(socket_accept, struct socket *sock, struct socket *newsock) {
    if (!newsock) return 0;
    // Fix: null-check `sk` itself, not a second independent read of
    // newsock->sk -- the verifier doesn't carry the null-check from the
    // `newsock->sk` read above across to a *different* read of the same
    // field, so BPF_CORE_READ(sk, ...)'s internal pointer arithmetic on a
    // still-"maybe null" sk was rejected: "pointer arithmetic on
    // trusted_ptr_or_null_ prohibited, null-check it first."
    struct sock *sk = newsock->sk;
    if (!sk) return 0;
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    // Group-leader-keyed: process_threshold_map is fork-propagated on the
    // leader's start_time - see get_current_group_leader_key()'s doc.
    struct process_key key = get_current_group_leader_key();
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (!threshold) return 0;

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, 20, SRC_BPF_LSM, pid); // EVT_NETWORK_ACCEPT = 20
        uint16_t family = BPF_CORE_READ(sk, __sk_common.skc_family);
        event->details.details_buffer[0] = 0;

        uint16_t dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        uint16_t sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        bpf_probe_read_kernel(event->details.details_buffer + 46, 2, &dport);
        bpf_probe_read_kernel(event->details.details_buffer + 48, 2, &sport);

        if (family == 2) {
            uint32_t src_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
            unsigned char *b = (unsigned char *)&src_ip;
            event->details.details_buffer[0] = 0x04;
            event->details.details_buffer[1] = b[0];
            event->details.details_buffer[2] = b[1];
            event->details.details_buffer[3] = b[2];
            event->details.details_buffer[4] = b[3];
            event->details.details_buffer[5] = 0;
        } else if (family == 10) {
            event->details.details_buffer[0] = 0x06;
            bpf_probe_read_kernel(event->details.details_buffer + 1, 16, &sk->__sk_common.skc_v6_daddr);
            event->details.details_buffer[17] = 0;
        }
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(socket_sendmsg, struct socket *sock, struct msghdr *msg, int size) {
    if (!sock || !msg) return 0;
    // Fix: same class of bug as socket_accept above -- null-check sk itself,
    // not a second independent read of sock->sk.
    struct sock *sk = sock->sk;
    if (!sk) return 0;
    uint16_t family = BPF_CORE_READ(sk, __sk_common.skc_family);
    uint16_t type = BPF_CORE_READ(sock, type);
    if (type != 2) return 0; // SOCK_DGRAM = 2

    struct sockaddr *address = BPF_CORE_READ(msg, msg_name);
    if (!address) return 0;

    uint16_t dest_port = 0;
    if (family == 2) {
        struct sockaddr_in sin;
        bpf_probe_read_kernel(&sin, sizeof(sin), address);
        dest_port = bpf_ntohs(sin.sin_port);
    } else if (family == 10) {
        struct sockaddr_in6 sin6;
        bpf_probe_read_kernel(&sin6, sizeof(sin6), address);
        dest_port = bpf_ntohs(sin6.sin6_port);
    }

    if (dest_port != 53) return 0;

    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    // Group-leader-keyed: process_threshold_map is fork-propagated on the
    // leader's start_time - see get_current_group_leader_key()'s doc.
    struct process_key key = get_current_group_leader_key();
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (!threshold) return 0;

    // `struct iov_iter` is version-dependent in two ways at once, and getting
    // either wrong is worse than collecting nothing:
    //   * `ubuf`/ITER_UBUF only exist from 6.0. Naming `ubuf` on 5.15 makes
    //     CO-RE fail to resolve `struct msghdr.msg_iter.ubuf`, which poisons the
    //     instruction and stops this whole program loading.
    //   * the iovec member was renamed `iov` -> `__iov` in 6.4.
    //   * the iter_type CONSTANTS differ too: 4 is ITER_UBUF from 6.0 but
    //     ITER_BVEC on 5.15, so the `== 4` test does not even mean the same
    //     thing across kernels.
    // So each read is guarded by bpf_core_field_exists(), and on a kernel where
    // neither member is nameable this DNS-qname extraction degrades to a no-op
    // rather than reading some other member and reporting a fabricated query.
    // Losing qname telemetry on an old kernel is a known, bounded loss; a wrong
    // qname is a lie in an alert.
    // Shared with the tty capture path - see iov_iter_user_buf()'s comment for
    // why every read here is CO-RE guarded and why the iter_type constant must
    // be resolved from the running kernel rather than hardcoded.
    uint32_t user_len = 0;
    void *user_buf = iov_iter_user_buf(&msg->msg_iter, &user_len);
    if (!user_buf) return 0;

    char raw_qname[128];
    bpf_probe_read_user(raw_qname, sizeof(raw_qname), (char *)user_buf + 12);

    uint64_t qname_hash = 0;
    bpf_probe_read_kernel(&qname_hash, sizeof(qname_hash), raw_qname);
    if (qname_hash != 0) {
        uint64_t *cached = bpf_map_lookup_elem(&dns_cache_map, &qname_hash);
        if (cached) {
            return 0; // already seen, exit early!
        }
        uint64_t ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&dns_cache_map, &qname_hash, &ts, BPF_ANY);
    }

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, 21, SRC_BPF_LSM, pid); // EVT_DNS_QUERY = 21
        bpf_probe_read_kernel(event->details.details_buffer, 128, raw_qname);

        uint16_t dport_be = bpf_htons(dest_port);
        bpf_probe_read_kernel(event->details.details_buffer + 174, 2, &dport_be);

        if (family == 2) {
            struct sockaddr_in sin;
            bpf_probe_read_kernel(&sin, sizeof(sin), address);
            uint32_t src_ip = sin.sin_addr.s_addr;
            unsigned char *b = (unsigned char *)&src_ip;
            event->details.details_buffer[128] = 0x04;
            event->details.details_buffer[129] = b[0];
            event->details.details_buffer[130] = b[1];
            event->details.details_buffer[131] = b[2];
            event->details.details_buffer[132] = b[3];
            event->details.details_buffer[133] = 0;
        } else if (family == 10) {
            struct sockaddr_in6 sin6;
            bpf_probe_read_kernel(&sin6, sizeof(sin6), address);
            event->details.details_buffer[128] = 0x06;
            bpf_probe_read_kernel(event->details.details_buffer + 129, 16, &sin6.sin6_addr);
            event->details.details_buffer[145] = 0;
        }
        bpf_ringbuf_submit(event, 0);
    }

    if (is_install_session() || is_admin_session()) {
        uint32_t zero = 0;
        struct scratch_buf *buf = bpf_map_lookup_elem(&scratch_map, &zero);
        if (buf) {
            bpf_probe_read_user(buf->path, sizeof(buf->path), (char *)user_buf + 12);
            record_and_batch_event(8, NULL, 0, buf->path); // 8 = DNS_QUERY
        }
    }

    return 0;
}

// Supply-chain persistence deny at the point a NAME is created.
// file_open only sees an O_CREAT open after the inode already exists, so
// its deny left an empty file behind; and mkdir never reaches file_open at
// all (a drop-in dir under /etc/systemd/system/, then a file inside it whose
// parent was never registered). Both hooks are pre-operation, so a deny
// here means nothing was created. Signatures per lsm_hook_defs.h:
// (struct inode *dir, struct dentry *dentry, umode_t mode) for both.
SEC("lsm/inode_create")
int BPF_PROG(inode_create, struct inode *dir, struct dentry *dentry, umode_t mode) {
    return persistence_write_check(dir, dentry, bpf_get_current_pid_tgid() >> 32, KINN_PERSIST_OP_CREATE);
}

SEC("lsm/inode_mkdir")
int BPF_PROG(inode_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode) {
    return persistence_write_check(dir, dentry, bpf_get_current_pid_tgid() >> 32, KINN_PERSIST_OP_MKDIR);
}

// Residual-gap close #1: the raw-syscall half of self-defense
// that inode_unlink's core_pin_guard_map check below cannot reach - a
// privileged local attacker with CAP_BPF/CAP_SYS_ADMIN doesn't need `rm` or
// bpftool's path-based unlink at all. BPF_MAP_GET_FD_BY_ID lets them
// enumerate every live map by numeric ID (bpffs pin protection is
// filesystem-only, so this bypasses it entirely) and update it directly;
// BPF_LINK_DETACH tears down an attachment without ever touching the pin
// path inode_unlink guards. Both go through this single umbrella hook -
// `security_bpf` fires for every bpf(2) subcommand, before the kernel
// dispatches it - verified attachable via progload across the full LVH
// kernel matrix (5.10, 5.15, 6.1, 6.6, 6.18, rhel9.6, bpf-next)
// before writing this, per the "measure before designing"
// discipline this file's other hooks already follow.
//
// Deliberately coarse, not per-resource: denies these two subcommands for
// ANY pid other than the daemon's own (CONFIG_OWN_PID, same map and
// pattern as ptrace_access_check/task_kill's self-protection in
// kinnector_lsm_hooks_creds.h), not merely subcommands that would touch a
// map/link this object owns. Resolving a map_id/link_fd back to "is this
// specifically one of ours" from inside this hook is a harder problem
// (fd-to-object resolution, per-cmd union bpf_attr layout) not attempted in
// this pass - the tradeoff is that this also blocks unrelated BPF tooling
// (bpftool, other agents) from these two subcommands system-wide while this
// object is loaded, not just access to Kinnector's own resources. Same
// no-op-when-unset shape as every other CONFIG_OWN_PID check: a product
// that never sets it leaves this permanently inert.
//
// `void *attr`, not `union bpf_attr *` - never dereferenced (this only
// reads cmd), so no CO-RE/vmlinux.h struct dependency for it; `size` is
// kept only to preserve security_bpf(int, union bpf_attr *, unsigned int)'s
// real 3-argument arity, per this file's own "third gotcha" discipline
// (core/CLAUDE.md) against a BPF_PROG parameter list reading garbage.
SEC("lsm/bpf")
int BPF_PROG(bpf_syscall_guard, int cmd, void *attr, unsigned int size) {
    if (cmd != BPF_MAP_GET_FD_BY_ID && cmd != BPF_LINK_DETACH)
        return 0;

    uint32_t own_pid_idx = CONFIG_OWN_PID;
    uint32_t *own_pid = bpf_map_lookup_elem(&config_map, &own_pid_idx);
    if (!own_pid || *own_pid == 0)
        return 0; // no product has opted in - stay fully inert

    uint32_t bpf_caller_pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_caller_pid != *own_pid && blocking_enabled_now())
        return -EPERM;

    return 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(inode_unlink, struct inode *dir, struct dentry *dentry) {
    if (!dentry) return 0;
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    // Agent-core tamper resistance: deny removing anything
    // inside this object's own bpffs pin directory (/sys/fs/bpf/warden -
    // e.g. `rm /sys/fs/bpf/warden/task_kill`) unless the caller is the
    // daemon that loaded this object. The raw BPF_LINK_DETACH/
    // BPF_MAP_GET_FD_BY_ID syscall path is a separate attack surface this
    // hook cannot see - see the new `lsm/bpf` program (bpf_syscall_guard)
    // just above, which closes that half.
    // core_pin_guard_map is populated once, in C++, by
    // EbpfLoader::LoadAndAttachLsm - see its own doc comment in
    // kinnector_maps.h. Checked ahead of the persistence-deny logic below:
    // this is a distinct, higher-priority self-defense gate, not a
    // supply-chain policy decision.
    //
    // Audit-only mode: same CONFIG_BLOCKING_ENABLED gate as
    // the two own-pid self-defense blocks in kinnector_lsm_hooks_creds.h -
    // see ptrace_access_check's comment there for why this now honors the
    // global switch instead of being unconditional.
    if (dir) {
        uint32_t guard_idx = 0;
        struct core_pin_guard *guard = bpf_map_lookup_elem(&core_pin_guard_map, &guard_idx);
        if (guard && (guard->dir_id.dev || guard->dir_id.ino) && pid != guard->owner_pid) {
            struct resource_id parent_id = make_resource_id(dir);
            if (parent_id.dev == guard->dir_id.dev && parent_id.ino == guard->dir_id.ino) {
                uint32_t blocking_idx = CONFIG_BLOCKING_ENABLED;
                uint32_t *blocking = bpf_map_lookup_elem(&config_map, &blocking_idx);
                if (blocking && *blocking == 1) {
                    return -EPERM;
                }
            }
        }
    }

    // Supply-chain persistence deny: an install's descendant deleting a
    // registered append-file (`rm ~/.bashrc` before dropping its own) or
    // an entry in a drop dir. Ahead of the threshold gate below, which
    // antitheft never populates.
    {
        int refused = persistence_write_check(dir, dentry, pid, KINN_PERSIST_OP_UNLINK);
        if (refused) return refused;
    }

    // Group-leader-keyed: process_threshold_map is fork-propagated on the
    // leader's start_time - see get_current_group_leader_key()'s doc.
    struct process_key key = get_current_group_leader_key();
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    // antitheftd never writes process_threshold_map,
    // so the gate above made this hook - and the owner/resource-swap
    // "Unlink" trigger built on it - dead in every antitheft deployment.
    // Emit for antitheft too, but only when the file being unlinked is one
    // the agent tracks (a protected resource or an owner image), so this
    // never becomes a system-wide unlink flood.
    int antitheft_relevant = 0;
    if (!threshold && is_antitheft_mode()) {
        struct inode *victim = BPF_CORE_READ(dentry, d_inode);
        if (victim) {
            struct resource_id victim_id = make_resource_id(victim);
            if (bpf_map_lookup_elem(&sensitive_inodes_map, &victim_id) ||
                bpf_map_lookup_elem(&owner_images, &victim_id)) {
                antitheft_relevant = 1;
            }
        }
    }
    if (!threshold && !antitheft_relevant) return 0;

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, 22, SRC_BPF_LSM, pid); // EVT_FILE_DELETE = 22
        struct qstr d_name = BPF_CORE_READ(dentry, d_name);
        bpf_probe_read_kernel_str(event->details.details_buffer, 512, d_name.name);
        bpf_ringbuf_submit(event, 0);
    }

    if (is_install_session() || is_admin_session()) {
        uint32_t zero = 0;
        struct scratch_buf *buf = bpf_map_lookup_elem(&scratch_map, &zero);
        if (buf) {
            struct inode *inode = BPF_CORE_READ(dentry, d_inode);
            uint64_t ino = inode ? BPF_CORE_READ(inode, i_ino) : 0;
            struct qstr d_name = BPF_CORE_READ(dentry, d_name);
            bpf_probe_read_kernel_str(buf->path, sizeof(buf->path), d_name.name);
            record_and_batch_event(3, NULL, ino, buf->path); // 3 = DELETE
        }
    }

    return 0;
}

// Owner-swap defense follow-up: a rename(2) whose DESTINATION already has a
// file at it is exactly the shape a bind-mount/overwrite-style path swap
// takes without ever calling unlink() or open()+write() on that path at all
// - `inode_unlink` above and the fanotify write-notify path each miss this
// specific case. Telemetry-only, unconditional (no process_threshold_map
// gate, deliberately - unlike inode_unlink's pre-existing gate, this is a
// brand-new hook with no prior behavior to preserve, and gating it would
// just reproduce the exact blind spot this follow-up exists to close).
// Leaf names only (dentry->d_name), matching inode_unlink's own precision -
// the consumer only needs a basename to re-check a small, known set of
// owner paths, and a false-positive re-check on an unrelated same-named
// file elsewhere is cheap and harmless.
// Resource-swap-defense synchronous closure (antitheft-only, MODE_ANTITHEFT-
// gated per core/CLAUDE.md's shared-hook discipline): if `resource_id`
// currently holds a registered resource's protection, copies it verbatim
// onto `new_id` and (when a parent/name is supplied) refreshes
// protected_path_names_map so a LATER swap at the same path stays airtight
// too, without waiting on userspace's async round-trip either. Never denies
// the syscall - matches this product's established "don't block namespace/
// rename/symlink operations, just don't leave the result unprotected"
// philosophy. Returns 1 if protection was found and carried forward, 0 if
// there was nothing to carry (the common non-swap case - most renames/
// symlinks/links don't touch a currently-protected identity at all).
static __always_inline void apply_resource_protection(struct resource_id new_id, uint32_t category, uint64_t owner_mask,
                                                      struct resource_id origin_id) {
    // An identity that is not protected right now but still has an authoritative owner set is an
    // inode NUMBER that belonged to a protected file which has since been freed (inode_free_security
    // below drops the protection and keeps the set). The file that now has that number takes its
    // protection through the alias, never from its predecessor's set: that set may be a retired one
    // (only the daemon), which refused Chrome its own freshly saved `Local State`.
    if (!(origin_id.dev == new_id.dev && origin_id.ino == new_id.ino) && !bpf_map_lookup_elem(&sensitive_inodes_map, &new_id)) {
        bpf_map_delete_elem(&resource_exact_known, &new_id);
    }
    bpf_map_update_elem(&sensitive_inodes_map, &new_id, &category, BPF_ANY);
    bpf_map_update_elem(&resource_owner_map, &new_id, &owner_mask, BPF_ANY);
    // Record where the exact owner set for this protection lives. Copying
    // the mask alone would leave the swapped-in identity matchable by any
    // binary sharing an owner's 6-bit slot - see resource_owner_exact.
    if ((origin_id.dev || origin_id.ino) && !(origin_id.dev == new_id.dev && origin_id.ino == new_id.ino)) {
        bpf_map_update_elem(&resource_owner_alias, &new_id, &origin_id, BPF_ANY);
    }
}

static __always_inline int sync_carry_forward_protection(struct resource_id old_id, struct resource_id new_id, uint64_t parent_dev, uint64_t parent_ino, uint64_t name_hash) {
    uint32_t *category = bpf_map_lookup_elem(&sensitive_inodes_map, &old_id);
    uint64_t *owner_mask = bpf_map_lookup_elem(&resource_owner_map, &old_id);
    if (!category || !owner_mask) {
        return 0;
    }
    uint32_t cat = *category;
    uint64_t mask = *owner_mask;
    // The exact owner set stays where it is registered; the swapped-in
    // identity points at it. If old_id is itself an alias, is_resource_owner
    // walks the remaining hops.
    apply_resource_protection(new_id, cat, mask, old_id);
    if (parent_dev || parent_ino) {
        struct path_name_id name_id = { parent_dev, parent_ino, name_hash };
        struct path_protection prot = {0};
        prot.category = cat;
        prot.owner_mask = mask;
        prot.origin_dev = old_id.dev;
        prot.origin_ino = old_id.ino;
        bpf_map_update_elem(&protected_path_names_map, &name_id, &prot, BPF_ANY);
    }
    return 1;
}

// A protected identity is a (dev, inode NUMBER), and the number outlives the file. ext4 gives a
// freed number to the next file created nearby, and an atomic save frees one every time: Chrome's
// `Local State` alternates between exactly two numbers, each save's temp
// file getting the number the previous save freed. Whatever the maps still held for the freed number
// was inherited by that new file: a retired identity (only the daemon may open it) refused Chrome
// its own temp file, alerted as "Google Chrome tried to change its encryption key", and
// a program that owns nothing was refused ANY new file of its own that happened to get such a number.
//
// So when a protected inode is really gone, its number stops being protected: no sensitive entry,
// no mask. Its exact owner set and its alias stay, because a file swapped in over it is aliased to
// it and reads its owners through it until userspace registers the newcomer's own set;
// `apply_resource_protection` drops that leftover set if the number is later protected afresh.
//
// Also runs when an inode is merely dropped from the inode cache under memory pressure; that file
// still exists and must stay protected, and only a file with no name left (i_nlink 0) is gone.
// Runs after the filesystem has released the number, so a create on another CPU in the few
// instructions between the two can still see the old entry: narrowed, not closed.
//
// The daemon's own binary and .bpf.o (core_self_integrity_map) are numbers too. A rebuilt .bpf.o
// frees its number at once; the binary's is freed when the daemon exits, and pins left enforcing
// outlive it with nobody to update the map. Kept, the number refused a WRITE open of whichever new
// file got it next, from any program (EPERM after the agent binary was rebuilt).
// A zeroed slot matches nothing.
SEC("lsm/inode_free_security")
int BPF_PROG(inode_free_security, struct inode *inode) {
    if (!inode || !is_antitheft_mode()) return 0;
    if (BPF_CORE_READ(inode, i_nlink) != 0) return 0;
    struct resource_id id = make_resource_id(inode);
    {
        struct resource_id none = {0};
        uint32_t si0 = 0;
        struct resource_id *self0 = bpf_map_lookup_elem(&core_self_integrity_map, &si0);
        if (self0 && self0->dev == id.dev && self0->ino == id.ino) bpf_map_update_elem(&core_self_integrity_map, &si0, &none, BPF_ANY);
        uint32_t si1 = 1;
        struct resource_id *self1 = bpf_map_lookup_elem(&core_self_integrity_map, &si1);
        if (self1 && self1->dev == id.dev && self1->ino == id.ino) bpf_map_update_elem(&core_self_integrity_map, &si1, &none, BPF_ANY);
    }
    if (!bpf_map_lookup_elem(&sensitive_inodes_map, &id)) return 0;
    bpf_map_delete_elem(&sensitive_inodes_map, &id);
    bpf_map_delete_elem(&resource_owner_map, &id);
    return 0;
}

// Owner-swap defense follow-up: a rename(2) whose DESTINATION already has a
// file at it is exactly the shape a bind-mount/overwrite-style path swap
// takes without ever calling unlink() or open()+write() on that path at all
// - `inode_unlink` above and the fanotify write-notify path each miss this
// specific case. Telemetry-only, unconditional (no process_threshold_map
// gate, deliberately - unlike inode_unlink's pre-existing gate, this is a
// brand-new hook with no prior behavior to preserve, and gating it would
// just reproduce the exact blind spot this follow-up exists to close).
// Leaf names only (dentry->d_name), matching inode_unlink's own precision -
// the consumer only needs a basename to re-check a small, known set of
// owner paths, and a false-positive re-check on an unrelated same-named
// file elsewhere is cheap and harmless.
SEC("lsm/inode_rename")
int BPF_PROG(inode_rename, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry) {
    if (!new_dentry) return 0;
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    uint32_t config_idx = CONFIG_BLOCKING_ENABLED;
    uint32_t *mode = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode && *mode == 1);

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, 6, SRC_BPF_LSM, pid); // EVT_FILE_RENAME = 6
        struct qstr new_name = BPF_CORE_READ(new_dentry, d_name);
        bpf_probe_read_kernel_str(event->details.file_rename.destination_path, sizeof(event->details.file_rename.destination_path), new_name.name);
        if (old_dentry) {
            struct qstr old_name = BPF_CORE_READ(old_dentry, d_name);
            bpf_probe_read_kernel_str(event->details.file_rename.source_path, sizeof(event->details.file_rename.source_path), old_name.name);
        }
        bpf_ringbuf_submit(event, 0);
    }

    // Supply-chain persistence deny: rename INTO a persistence
    // location (`mv /tmp/evil.desktop ~/.config/autostart/`, or crontab(1)'s
    // own tmp-then-rename into the spool - the one bypass file_open's deny
    // could never see) and rename AWAY from one (`mv ~/.bashrc ~/.bashrc.bak`
    // before dropping a new one) are both refused for an install's
    // descendants. The package manager itself (depth 1) renames
    // `foo.service.dpkg-new` into place exactly this way, and stays allowed.
    {
        // Checked as two separate cases so the event reports the dentry
        // that actually matched: for `mv ~/.bashrc ~/.bashrc.bak` the
        // protected name is the SOURCE, and reporting the destination
        // would name a file no corpus location knows (the agent's
        // location_id lookup would then fall back to the wrong entry).
        // An atomic save (`unit.tmp` -> `unit` in the same unit dir, how
        // snapd and dpkg write) matches as the destination.
        if (is_antitheft_mode()) {
            struct resource_id dir_id = {0};
            int refused = 0;
            if (is_persistence_target(new_dir, new_dentry, &dir_id)) {
                refused = persistence_write_report(dir_id, new_dentry, pid, KINN_PERSIST_OP_RENAME_INTO);
            } else if (is_persistence_target(old_dir, old_dentry, &dir_id)) {
                refused = persistence_write_report(dir_id, old_dentry, pid, KINN_PERSIST_OP_RENAME_AWAY);
            }
            if (refused) return refused;
        }
    }

    // Destructive-ops gate (renaming is a real
    // bypass): is_resource_owner() is what file_open/file_permission use to
    // decide READ access, but nothing gated rename(2) itself - a same-user
    // non-owner process could `mv` a protected secret out from under its
    // owner (or over some other name) with no check at all, file_open's
    // owner-allowlist notwithstanding, because a rename that never opens the
    // source file never reaches it. Checked on old_dentry's CURRENT inode
    // (the resource exactly as it exists right now, before this rename would
    // touch it) against the exact same sensitive_inodes_map/is_resource_owner
    // gate file_open uses, so a rename is held to the same owner standard as
    // a read. Deliberately reuses EVT_FILE_OPEN/FileOpenDetails (verdict 7)
    // instead of a new event type - same (resource_dev, resource_ino)
    // identity shape file_open already emits, and the antitheft agent's
    // existing FileOpen decode path (handle_file_open_event) only needs one
    // more verdict arm, not a new decoder.
    if (is_antitheft_mode() && blocking_enabled && old_dentry) {
        struct inode *old_inode = BPF_CORE_READ(old_dentry, d_inode);
        if (old_inode) {
            struct resource_id old_id = make_resource_id(old_inode);
            uint32_t *category = bpf_map_lookup_elem(&sensitive_inodes_map, &old_id);
            if (category) {
                bool is_owner = is_resource_owner(old_id);
                struct process_key revoked_key = get_current_group_leader_key();
                uint32_t *revoked_flags = bpf_map_lookup_elem(&revoked_pid_map, &revoked_key);
                bool revoked = revoked_flags && *revoked_flags != 0;
                if (!is_owner || revoked) {
                    struct TelemetryEvent *deny_event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
                    if (deny_event) {
                        fill_header(deny_event, EVT_FILE_OPEN, SRC_BPF_LSM, pid);
                        kinn_file_open_actor(&deny_event->details.file_open);
                        deny_event->details.file_open.resource_dev = old_id.dev;
                        deny_event->details.file_open.resource_ino = old_id.ino;
                        deny_event->details.file_open.verdict = 7; // denied(rename of a protected resource, not an owner)
                        deny_event->details.file_open.access_mode = 0; // a rename, not an open
                        struct qstr old_name = BPF_CORE_READ(old_dentry, d_name);
                        bpf_probe_read_kernel_str(deny_event->details.file_open.file_path,
                                                  sizeof(deny_event->details.file_open.file_path), old_name.name);
                        bpf_ringbuf_submit(deny_event, 0);
                    }
                    return -EACCES;
                }
            }
        }
    }

    // Resource-swap-defense synchronous closure: the DESTINATION's CURRENT
    // (pre-rename) inode is exactly what's about to be replaced; the
    // SOURCE's inode is exactly what the destination path will resolve to
    // once this rename completes - both already available in-hook, no new
    // map lookup-by-name needed for this specific case.
    if (is_antitheft_mode() && old_dentry) {
        struct inode *old_dest_inode = BPF_CORE_READ(new_dentry, d_inode);
        struct inode *new_occupant_inode = BPF_CORE_READ(old_dentry, d_inode);
        if (old_dest_inode && new_occupant_inode) {
            struct resource_id old_dest_id = make_resource_id(old_dest_inode);
            struct resource_id new_occupant_id = make_resource_id(new_occupant_inode);
            struct qstr new_name = BPF_CORE_READ(new_dentry, d_name);
            uint64_t name_hash = fnv1a_hash_name(new_name.name);
            struct resource_id new_dir_id = new_dir ? make_resource_id(new_dir) : (struct resource_id){0};
            sync_carry_forward_protection(old_dest_id, new_occupant_id, new_dir_id.dev, new_dir_id.ino, name_hash);
        }
    }

    return 0;
}

// Owner-swap defense follow-up: symlink(2) creating a brand-new entry at a
// path (as opposed to rename(2) replacing an existing one) - the other half
// of "swap a path without unlink()+open()+write()". Same telemetry-only,
// unconditional, leaf-name-only discipline as inode_rename above.
// Remembers the dentry this thread's link(2)/symlink(2) is about to give an
// inode, for `lsm_d_instantiate` (see `pending_link_dentries`).
static __always_inline void note_pending_link(struct dentry *dentry) {
    if (!is_antitheft_mode()) return;
    uint64_t thread = bpf_get_current_pid_tgid();
    uint64_t addr = (uint64_t)(unsigned long)dentry;
    bpf_map_update_elem(&pending_link_dentries, &thread, &addr, BPF_ANY);
}

// Is `dentry` the one this thread's link(2)/symlink(2) is creating? Consumes it.
static __always_inline int take_pending_link(struct dentry *dentry) {
    uint64_t thread = bpf_get_current_pid_tgid();
    uint64_t *addr = bpf_map_lookup_elem(&pending_link_dentries, &thread);
    if (!addr || *addr != (uint64_t)(unsigned long)dentry) return 0;
    bpf_map_delete_elem(&pending_link_dentries, &thread);
    return 1;
}

SEC("lsm/inode_symlink")
int BPF_PROG(inode_symlink, struct inode *dir, struct dentry *dentry, const char *old_name) {
    if (!dentry) return 0;
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, 4, SRC_BPF_LSM, pid); // EVT_FILE_CREATE = 4
        event->details.file_create.zone_id = -1; // Windows ZoneId concept, not applicable on Linux
        struct qstr new_name = BPF_CORE_READ(dentry, d_name);
        bpf_probe_read_kernel_str(event->details.file_create.file_path, sizeof(event->details.file_create.file_path), new_name.name);
        bpf_ringbuf_submit(event, 0);
    }

    // Supply-chain persistence deny: a symlink dropped into a
    // persistence location by an install's descendant is persistence
    // (GNOME follows an autostart symlink like any .desktop file).
    {
        int refused = persistence_write_check(dir, dentry, pid, KINN_PERSIST_OP_SYMLINK);
        if (refused) return refused;
    }

    // Resource-swap-defense synchronous closure does NOT reach symlink(2)
    // FROM THIS HOOK - `security_inode_symlink` is a PRE-operation
    // permission check, so `dentry` is necessarily still a negative dentry
    // here (the whole reason symlink() would fail with EEXIST against an
    // existing destination) - `dentry->d_inode` is unconditionally NULL at
    // this exact point, no matter what. A first version of this hook tried
    // to read it anyway - live-root testing caught it as genuinely dead code
    // before it shipped (see git history/[[antitheft_synchronous_swap_closure]]
    // memory). The real fix lives in `lsm_d_instantiate` below instead,
    // which fires when a dentry is actually given its inode - same `dentry`
    // object, just observed at the point it's actually useful for this
    // purpose. See `apply_post_op_path_closure`'s own doc comment.
    note_pending_link(dentry);

    return 0;
}

// Resource-swap-defense synchronous closure, take two: `security_inode_symlink`
// above cannot do this (see its own doc comment - the destination dentry has
// no inode yet at that pre-operation point). `vfs_symlink()` is the function
// LSM's own hook fires from partway through - confirmed on this exact
// kernel via `bpftrace -lv kfunc:vfs_symlink` (real signature, not guessed):
// `vfs_symlink(struct mnt_idmap *idmap, struct inode *dir, struct dentry
// *dentry, const char *oldname)`, returns int. An `fexit` program gets BOTH
// the original arguments AND the return value in one BTF trampoline - no
// separate entry-probe-stashes-state dance needed (unlike, say, this
// codebase's own `kprobe_tty_read`/`kretprobe_tty_read` pair, which needs
// that because a plain kretprobe alone only gets the return value). On
// success (`ret == 0`), `dentry->d_inode` is now the real, newly-created
// inode - exactly the piece `inode_symlink` couldn't get. From there this
// is identical to `inode_rename`'s own carry-forward: consult
// `protected_path_names_map` by (parent dir identity, leaf name hash - see
// `path_name_id`'s declaration comment for why path-keyed, not inode-keyed,
// survives the unlink() that necessarily preceded this symlink) and apply
// whatever protection is on file there to the new inode, synchronously,
// before any userspace round-trip.
//
// **Known, confirmed (not assumed) limitation, unlike hardlink creation
// (`lsm/inode_link` below)**: `dentry->d_inode` for a SYMLINK is the symlink's OWN inode -
// distinct from whatever it points to. A plain `open()` transparently
// resolves through the symlink before `file_open`'s LSM hook ever runs, so
// that hook only ever sees the RESOLVED TARGET's inode, never the
// symlink's own - meaning this registration has no effect on the primary
// "open() follows the symlink to attacker content" threat model (it's
// still real and correct for `O_NOFOLLOW`/`lstat()`/unlinking-the-symlink-
// itself paths). Confirmed live in
// `agent/tests/test_ownership_swap_defense.rs`'s sixth scenario, part C -
// both a registered owner and a non-owner were allowed against a
// symlinked-in attacker target, since the target's own inode was never
// registered at all. Closing this for real would need resolving `oldname`
// (a plain string, same as a bind-mount's source) to its own inode
// synchronously in-kernel - the same "no safe arbitrary-path-resolution
// helper" difficulty already judged too fragile for `sb_mount`. Symlink
// swaps still get the same REACTIVE (async, telemetry-driven) protection
// as every trigger had before this session's synchronous-closure work -
// unaffected, not made worse.
// The post-operation closure `lsm_d_instantiate` below performs for a
// symlink/hardlink: the new dentry now HAS an inode, so a protected path
// name that was just re-created can be re-bound to the new resource.
//
// Was reached via a kprobe/kretprobe-stashed-state dance on `vfs_symlink`/
// `vfs_link` (a kretprobe alone only gets the return value, so the entry
// probe had to stash `dir`/`dentry` in a side map, `pending_path_ops`, for
// the return probe to pick up) or an `fexit` reading `bpf_get_func_ret()`
// on kernels new enough to have it - six separate program variants across
// two operations and two portability tiers, all just to observe "this
// dentry now has an inode" after the fact. `lsm_d_instantiate` already
// fires at exactly that moment, for every dentry-instantiation path,
// symlink/hardlink included (confirmed live: `ln -s`/`ln` both
// produce a hit with the correct new-dentry name, on both 6.18 and 7.2.5) -
// no stash, no return-value duality, no portability tiering needed.
//
// The new inode is the HOOK'S argument, never `dentry->d_inode`: d_instantiate()
// calls security_d_instantiate() before __d_instantiate() attaches the inode,
// so `d_inode` is still NULL here and this closure returned without
// protecting anything when it first moved onto this hook.
// A file hardlinked over a protected name was readable by anyone (antitheft
// test_ownership_swap_defense scenario 6, live on 6.18). The fexit_vfs_link
// it replaced ran after the link completed, when `d_inode` was set; the
// earlier check proved the hook fires, not that the closure applied.
static __always_inline void apply_post_op_path_closure(struct inode *dir,
                                                       struct dentry *dentry,
                                                       struct inode *new_inode) {
    if (!is_antitheft_mode() || !dir || !dentry || !new_inode) return;
    struct qstr new_name = BPF_CORE_READ(dentry, d_name);
    uint64_t name_hash = fnv1a_hash_name(new_name.name);
    struct resource_id dir_id = make_resource_id(dir);
    struct path_name_id name_id = { dir_id.dev, dir_id.ino, name_hash };
    struct path_protection *prot = bpf_map_lookup_elem(&protected_path_names_map, &name_id);
    if (prot) {
        struct resource_id new_id = make_resource_id(new_inode);
        struct resource_id origin = { prot->origin_dev, prot->origin_ino };
        apply_resource_protection(new_id, prot->category, prot->owner_mask, origin);
    }
}

// Directory-keyed synchronous carry-forward - see
// glob_owned_dirs_map's own declaration comment for what this protects and
// why it is deliberately distinct from apply_post_op_path_closure above
// (that one re-arms a NAME that was already protected before; this one
// covers a name that has never existed, inside a directory ownership.rs
// opted in via a wildcard corpus pattern).
//
// MEASURED, NOT GUESSED (live on 6.18 in an LVH VM): a first
// version of this hooked `vfs_create()`'s fexit, following the exact
// vfs_symlink/vfs_link precedent above. It attached and pinned cleanly with
// no error - and then never fired, not once, for a real `open(O_CREAT)` on
// tmpfs, confirmed with a bpf_printk in the closure plus one in
// fexit_vfs_create itself, both silent across the whole test run, while a
// matching printk in the PRE-EXISTING `lsm/inode_create` hook fired 52
// times in the same run. Root cause: modern local filesystems (tmpfs
// confirmed here; ext4 implements `->atomic_open` too) create a new file
// through their own `atomic_open` callback, which does not call the
// generic `vfs_create()` wrapper function at all - only some filesystems
// without atomic_open take that path. `vfs_create()` was therefore the
// wrong hook for "any new file, any filesystem" from the start; the
// vfs_symlink/vfs_link precedent worked only because symlink/link have no
// comparable atomic_open-style bypass.
//
// History of the hunt for a real "any new file, any filesystem" point,
// kept because the pattern has repeated twice now and will probably repeat
// again on some future kernel:
//   1. `vfs_create()`'s fexit - attached and pinned cleanly, never fired,
//      not once, for a real `open(O_CREAT)` on tmpfs. Modern
//      filesystems (tmpfs, ext4) create through their own `atomic_open`
//      callback, bypassing the generic `vfs_create()` wrapper entirely.
//   2. `d_instantiate`/`d_instantiate_new` kprobes - both PROVEN working
//      end to end (real deny, real allow, live kernel test) on 6.18, but
//      the identical test against real kernel 7.2.5 failed: neither kprobe
//      fires for a regular tmpfs file create on that kernel at all (kernel
//      7.2's tmpfs create path goes through a new `d_make_persistent()`
//      wrapper calling the internal `__d_instantiate()` helper, a
//      different symbol from the public `d_instantiate`/`d_instantiate_new`
//      functions kprobed here). (Not, as first suspected, `bpf_map_lookup_elem`
//      behaving differently per program type: `bpftool prog show`/`dump
//      xlated` showed identical map ids and logic.)
//
// Both attempts kprobed an internal VFS implementation detail that varies
// by kernel/filesystem. `security_d_instantiate(dentry, inode)` is the
// actual, durable answer: a real LSM hook (not a kprobe - `BPF_PROG_TYPE_LSM`,
// `SEC("lsm/d_instantiate")`), the same class as `file_open`/`mmap_file`
// already used here, which every dentry-instantiation path is contractually
// required to call so LSMs (SELinux included) can label the new dentry -
// that contract is exactly the "actually universal" property the two prior
// attempts were each hoping their kprobe target would have and didn't.
// Confirmed identical `(dentry, inode)` signature via `protodump
// security_d_instantiate` on both 6.18 and 7.2.5, confirmed loadable
// (`progload`, rc=0) on both, and confirmed to actually FIRE for a real
// `touch`ed tmpfs file on 7.2.5 via a name-filtered `bpf_printk` - the one
// thing neither kprobe ever did there. Also confirmed to fire
// identically for `symlink(2)`/`link(2)`, which is why this same hook also
// drives `apply_post_op_path_closure` above - see that function's own doc
// comment for what that replaced (the whole `vfs_symlink`/`vfs_link`
// kprobe/kretprobe/fexit apparatus).
static __always_inline void apply_glob_dir_closure(struct dentry *dentry, struct inode *new_inode) {
    if (!is_antitheft_mode() || !dentry || !new_inode) return;
    struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
    if (!parent) return;
    struct inode *dir = BPF_CORE_READ(parent, d_inode);
    if (!dir) return;
    struct resource_id dir_id = make_resource_id(dir);
    struct path_protection *prot = bpf_map_lookup_elem(&glob_owned_dirs_map, &dir_id);
    if (!prot) return;
    struct resource_id new_id = make_resource_id(new_inode);
    struct resource_id origin = { prot->origin_dev, prot->origin_ino };
    apply_resource_protection(new_id, prot->category, prot->owner_mask, origin);
}

SEC("lsm/d_instantiate")
int BPF_PROG(lsm_d_instantiate, struct dentry *dentry, struct inode *inode) {
    apply_glob_dir_closure(dentry, inode);
    // Same hook, same moment ("this dentry now has an inode"), covers the
    // symlink/hardlink re-bind case too - see apply_post_op_path_closure's
    // own doc comment for what this replaced. Only for the dentry a
    // link(2)/symlink(2) is creating: this hook also runs when a lookup
    // instantiates a file already on disk (see pending_link_dentries).
    if (dentry && take_pending_link(dentry)) {
        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
        struct inode *dir = parent ? BPF_CORE_READ(parent, d_inode) : NULL;
        apply_post_op_path_closure(dir, dentry, inode);
    }
    return 0;
}

// Antitheft resource-swap-defense follow-up (this session's third gap): no
// LSM hook anywhere in this codebase previously observed link(2) at all -
// hardlinking a new, attacker-controlled path onto an already-tracked
// resource/owner path (after unlinking whatever was there) was a completely
// unguarded swap vector, same class of gap as the rename/symlink cases
// above. Same telemetry-only-plus-synchronous-closure shape as
// inode_symlink: `old_dentry` is the EXISTING file being hardlinked
// (source, already has a real inode - not itself sensitive-relevant here),
// `new_dentry` is the new, necessarily-negative destination dentry link(2)
// is creating.
SEC("lsm/inode_link")
int BPF_PROG(inode_link, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry) {
    if (!new_dentry) return 0;
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, 41, SRC_BPF_LSM, pid); // EVT_FILE_LINK = 41
        struct qstr new_name = BPF_CORE_READ(new_dentry, d_name);
        bpf_probe_read_kernel_str(event->details.file_link.destination_path, sizeof(event->details.file_link.destination_path), new_name.name);
        if (old_dentry) {
            struct qstr old_name = BPF_CORE_READ(old_dentry, d_name);
            bpf_probe_read_kernel_str(event->details.file_link.source_path, sizeof(event->details.file_link.source_path), old_name.name);
        }
        bpf_ringbuf_submit(event, 0);
    }

    // Supply-chain persistence deny: same as inode_symlink.
    {
        int refused = persistence_write_check(dir, new_dentry, pid, KINN_PERSIST_OP_LINK);
        if (refused) return refused;
    }

    // Resource-swap-defense synchronous closure does NOT reach link(2) from
    // THIS HOOK either - identical reason as inode_symlink's own doc comment
    // above. `lsm_d_instantiate` above in this file is the real fix - see
    // `apply_post_op_path_closure`'s own doc comment.
    note_pending_link(new_dentry);

    return 0;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(task_fix_setuid, struct cred *new_cred, const struct cred *old_cred, int flags) {
    if (!new_cred || !old_cred) return 0;
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    // Group-leader-keyed: process_threshold_map is fork-propagated on the
    // leader's start_time - see get_current_group_leader_key()'s doc.
    struct process_key key = get_current_group_leader_key();
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    // emit for every process in antitheft mode
    // (rare event), not only Warden's threshold-tracked ones.
    int antitheft = is_antitheft_mode();
    if (!threshold && !antitheft) return 0;

    // widened from uid-only to all
    // four uid-family fields - a seteuid(0)-then-back pattern (the standard
    // setuid-root-daemon/sudo temporary-elevation shape) changes only euid,
    // so the old new_uid-only comparison never fired for the single most
    // common real privilege-elevation shape.
    uint32_t new_uid = BPF_CORE_READ(new_cred, uid.val);
    uint32_t old_uid = BPF_CORE_READ(old_cred, uid.val);
    uint32_t new_euid = BPF_CORE_READ(new_cred, euid.val);
    uint32_t old_euid = BPF_CORE_READ(old_cred, euid.val);
    uint32_t new_suid = BPF_CORE_READ(new_cred, suid.val);
    uint32_t old_suid = BPF_CORE_READ(old_cred, suid.val);
    uint32_t new_fsuid = BPF_CORE_READ(new_cred, fsuid.val);
    uint32_t old_fsuid = BPF_CORE_READ(old_cred, fsuid.val);

    if (new_uid != old_uid || new_euid != old_euid ||
        new_suid != old_suid || new_fsuid != old_fsuid) {
        // a credential change ends the exec
        // chain. sshd forking a login session, su, a daemon dropping
        // privileges: what runs after this is a different principal and
        // must not carry the previous one's owner identity.
        if (antitheft) {
            bpf_map_delete_elem(&exec_origin_map, &key);
            bpf_map_delete_elem(&protected_owner_pids, &key);
        }
        struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
        if (event) {
            fill_header(event, EVT_PRIVILEGE_CHANGE, SRC_BPF_LSM, pid);
            bpf_probe_read_kernel(event->details.details_buffer + 0,  4, &old_uid);
            bpf_probe_read_kernel(event->details.details_buffer + 4,  4, &new_uid);
            bpf_probe_read_kernel(event->details.details_buffer + 8,  4, &old_euid);
            bpf_probe_read_kernel(event->details.details_buffer + 12, 4, &new_euid);
            bpf_probe_read_kernel(event->details.details_buffer + 16, 4, &old_suid);
            bpf_probe_read_kernel(event->details.details_buffer + 20, 4, &new_suid);
            bpf_probe_read_kernel(event->details.details_buffer + 24, 4, &old_fsuid);
            bpf_probe_read_kernel(event->details.details_buffer + 28, 4, &new_fsuid);
            bpf_ringbuf_submit(event, 0);
        }
    }
    return 0;
}

// gid-family mirror of
// task_fix_setuid above - identical shape, same process_threshold_map gate,
// same "any of the four pairs differ" condition, new GroupChangeDetails/
// EVT_GROUP_CHANGE.
SEC("lsm/task_fix_setgid")
int BPF_PROG(task_fix_setgid, struct cred *new_cred, const struct cred *old_cred, int flags) {
    if (!new_cred || !old_cred) return 0;
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    // Group-leader-keyed: process_threshold_map is fork-propagated on the
    // leader's start_time - see get_current_group_leader_key()'s doc.
    struct process_key key = get_current_group_leader_key();
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    // see task_fix_setuid.
    int antitheft = is_antitheft_mode();
    if (!threshold && !antitheft) return 0;

    uint32_t new_gid = BPF_CORE_READ(new_cred, gid.val);
    uint32_t old_gid = BPF_CORE_READ(old_cred, gid.val);
    uint32_t new_egid = BPF_CORE_READ(new_cred, egid.val);
    uint32_t old_egid = BPF_CORE_READ(old_cred, egid.val);
    uint32_t new_sgid = BPF_CORE_READ(new_cred, sgid.val);
    uint32_t old_sgid = BPF_CORE_READ(old_cred, sgid.val);
    uint32_t new_fsgid = BPF_CORE_READ(new_cred, fsgid.val);
    uint32_t old_fsgid = BPF_CORE_READ(old_cred, fsgid.val);

    if (new_gid != old_gid || new_egid != old_egid ||
        new_sgid != old_sgid || new_fsgid != old_fsgid) {
        // same boundary as task_fix_setuid.
        if (antitheft) {
            bpf_map_delete_elem(&exec_origin_map, &key);
            bpf_map_delete_elem(&protected_owner_pids, &key);
        }
        struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
        if (event) {
            fill_header(event, EVT_GROUP_CHANGE, SRC_BPF_LSM, pid);
            bpf_probe_read_kernel(event->details.details_buffer + 0,  4, &old_gid);
            bpf_probe_read_kernel(event->details.details_buffer + 4,  4, &new_gid);
            bpf_probe_read_kernel(event->details.details_buffer + 8,  4, &old_egid);
            bpf_probe_read_kernel(event->details.details_buffer + 12, 4, &new_egid);
            bpf_probe_read_kernel(event->details.details_buffer + 16, 4, &old_sgid);
            bpf_probe_read_kernel(event->details.details_buffer + 20, 4, &new_sgid);
            bpf_probe_read_kernel(event->details.details_buffer + 24, 4, &old_fsgid);
            bpf_probe_read_kernel(event->details.details_buffer + 28, 4, &new_fsgid);
            bpf_ringbuf_submit(event, 0);
        }
    }
    return 0;
}

// belt-and-suspenders tracepoint -
// task_fix_setgid's cred-diff may not independently observe a bare
// setgroups() call (supplementary group list lives in cred->group_info,
// outside the gid-family fields read above), so this records "setgroups()
// was called with N entries" as a presence-only signal, no gid-array read.
struct sys_enter_setgroups_args {
    unsigned long long pad;
    long syscall_nr;
    int gidsetsize;
    gid_t *grouplist;
};

SEC("tracepoint/syscalls/sys_enter_setgroups")
int tracepoint_sys_enter_setgroups(struct sys_enter_setgroups_args *ctx) {
    // Group-leader-keyed: process_threshold_map is fork-propagated on the
    // leader's start_time - see get_current_group_leader_key()'s doc.
    struct process_key key = get_current_group_leader_key();
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (!threshold && !is_antitheft_mode()) return 0;

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_GROUP_SET, SRC_BPF_TRACEPOINT, key.pid);
        event->details.group_set.gidsetsize = ctx->gidsetsize;
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

// capset's cap_effective delta -
// deliberately only cap_effective ("what can I do right now"), not
// permitted/inheritable/ambient/bset. Confirmed real LSM hook signature
// (kernel_cap_t is a single-u64-field struct on this kernel's BTF).
SEC("lsm/capset")
int BPF_PROG(capset, struct cred *new_cred, const struct cred *old_cred,
             const kernel_cap_t *effective, const kernel_cap_t *inheritable,
             const kernel_cap_t *permitted) {
    if (!new_cred || !old_cred) return 0;

    // Group-leader-keyed: process_threshold_map is fork-propagated on the
    // leader's start_time - see get_current_group_leader_key()'s doc.
    struct process_key key = get_current_group_leader_key();
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (!threshold && !is_antitheft_mode()) return 0;

    uint64_t old_effective = 0, new_effective = 0;
    KINN_READ_CAP_U64(old_effective, old_cred, cap_effective);
    KINN_READ_CAP_U64(new_effective, new_cred, cap_effective);
    if (old_effective == new_effective) return 0;

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_CAPABILITY_CHANGE, SRC_BPF_LSM, key.pid);
        event->details.capability_change.old_effective = old_effective;
        event->details.capability_change.new_effective = new_effective;
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

#define PR_SET_KEEPCAPS 8
#define PR_SET_NAME 15
#define PR_SET_CHILD_SUBREAPER 36

// PR_SET_KEEPCAPS, PR_SET_NAME and PR_SET_CHILD_SUBREAPER branches - one hook, three
// presence-only branches, never returns non-zero for any of them or for any
// other prctl() option (every other option is completely unaffected).
SEC("lsm/task_prctl")
int BPF_PROG(task_prctl, int option, unsigned long arg2, unsigned long arg3,
             unsigned long arg4, unsigned long arg5) {
    // Group-leader-keyed: process_threshold_map is fork-propagated on the
    // leader's start_time - see get_current_group_leader_key()'s doc.
    struct process_key key = get_current_group_leader_key();
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    // KEEPCAPS and SUBREAPER are rare and emit
    // for everyone in antitheft mode; PR_SET_NAME fires for every named
    // thread on the box and stays threshold-gated.
    if (!threshold && !is_antitheft_mode()) return 0;

    if (option == PR_SET_KEEPCAPS) {
        struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
        if (event) {
            fill_header(event, EVT_PRCTL_KEEPCAPS, SRC_BPF_LSM, key.pid);
            event->details.prctl_keepcaps.keepcaps_enabled = (uint8_t)(arg2 != 0);
            bpf_ringbuf_submit(event, 0);
        }
    } else if (option == PR_SET_NAME && threshold) {
        struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
        if (event) {
            fill_header(event, EVT_COMM_RENAME, SRC_BPF_LSM, key.pid);
            bpf_probe_read_user_str(event->details.comm_rename.new_comm,
                                     sizeof(event->details.comm_rename.new_comm),
                                     (const char *)arg2);
            bpf_ringbuf_submit(event, 0);
        }
    } else if (option == PR_SET_CHILD_SUBREAPER) {
        struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
        if (event) {
            fill_header(event, EVT_SUBREAPER_SET, SRC_BPF_LSM, key.pid);
            event->details.subreaper_set.enabled = (uint8_t)(arg2 != 0);
            bpf_ringbuf_submit(event, 0);
        }
    }
    return 0;
}

SEC("lsm/shm_shmat")
int BPF_PROG(shm_shmat, struct shmid_kernel *shp, char *shmaddr, int shmflg) {
    if (!shp) return 0;
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    // SHM_EXEC: attach a SysV shared-memory segment as executable. The other
    // half of the fileless-code path closed in mmap_file - a segment another
    // process wrote can be executed here without a single byte touching
    // disk, and shmat(2) never goes through mmap_file's hook at all. Checked
    // before the process_threshold_map gate below, which exists for Warden's
    // telemetry scoping and would otherwise skip this entirely for an
    // unmonitored process. Antitheft-only via protected_selfexec_forbidden(),
    // so a MODE_WARDEN deployment is untouched.
    if ((shmflg & 0x8000) && protected_selfexec_forbidden()) { // SHM_EXEC
        emit_self_exec_denied(pid, 4); // 4 = shmat (SHM_EXEC)
        return -EACCES;
    }

    // Group-leader-keyed: process_threshold_map is fork-propagated on the
    // leader's start_time - see get_current_group_leader_key()'s doc.
    struct process_key key = get_current_group_leader_key();
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (!threshold) return 0;

    int32_t shmid = BPF_CORE_READ(shp, shm_perm.id);
    uint32_t creator_uid = BPF_CORE_READ(shp, shm_perm.cuid.val);

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, 25, SRC_BPF_LSM, pid); // EVT_IPC_ACCESS = 25
        bpf_probe_read_kernel(event->details.details_buffer, 4, &shmid);
        bpf_probe_read_kernel(event->details.details_buffer + 4, 4, &creator_uid);
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}


// Walks every task and records the group leader's start_time. Threads are
// skipped: every process-level key in this file is built from the LEADER's
// start_time (see get_current_group_leader_key), so a thread's own value
// would be a key nothing ever looks up - the exact mistake this map exists
// to stop userspace making.
//
// An iterator runs only while userspace reads its fd, so this costs nothing
// until something asks. bpf_iter__task's `task` is NULL on the final call
// that signals end-of-iteration.
SEC("iter/task")
int iter_task_start_times(struct bpf_iter__task *ctx) {
    struct task_struct *task = ctx->task;
    if (!task)
        return 0;
    pid_t pid = BPF_CORE_READ(task, pid);
    pid_t tgid = BPF_CORE_READ(task, tgid);
    if (pid != tgid)
        return 0; // a thread, not the process
    uint64_t start_time = BPF_CORE_READ(task, start_time);
    uint32_t key = (uint32_t)tgid;
    bpf_map_update_elem(&task_start_times, &key, &start_time, BPF_ANY);
    return 0;
}

#endif  // KINNECTOR_BPF_CONTAINER_LSM_HOOKS_H
