// SPDX-License-Identifier: GPL-2.0-only
#ifndef KINNECTOR_BPF_TRACEPOINTS_H
#define KINNECTOR_BPF_TRACEPOINTS_H

// eBPF tracepoint telemetry producers (fallback mode, for kernels without
// BPF LSM) plus the tty kprobes/kretprobe. Verbatim split out of
// kinnector.bpf.c - see that file's header comment. Corresponds to the
// original "eBPF Tracepoints (Fallback Mode)" section banner (the tty
// kprobes sit at the end of that same contiguous block in the source).

// ---------------------------------------------------------------------------
// eBPF Tracepoints (Fallback Mode — for kernels without BPF LSM)
// P2-1: sys_enter_execve — emit ProcessCreate events
// ---------------------------------------------------------------------------

struct sys_enter_execve_args {
    unsigned long long pad;
    long syscall_nr;
    char *filename;
    char **argv;
    char **envp;
};

// execveat(2) carries the same payload behind a different argument layout.
// Its own tracepoint context, so the shared body below can be handed plain
// pointers rather than being written twice.
struct sys_enter_execveat_args {
    unsigned long long pad;
    long syscall_nr;
    long dfd;
    char *filename;
    char **argv;
    char **envp;
    long flags;
};

// Shared body for both exec tracepoints. `filename`, `argv` and `envp` are
// USER pointers in both syscalls; every read below already goes through
// bpf_probe_read_user*, so nothing here depends on which one called it.
static __always_inline int handle_exec_tracepoint(char *tp_filename, char **tp_argv, char **tp_envp) {
    struct process_key key = get_current_process_key();
    // attached in LSM mode too now (it used to be
    // fallback-only, which left EnvironmentMarkers dead in every LSM
    // deployment). A Warden LSM deployment keeps bprm_check_security as its
    // sole ProcessCreate producer and gets nothing from here, exactly as
    // before; antitheft takes this program as its producer for the argv and
    // envp only a tracepoint can see, and bprm_check_security goes quiet.
    {
        uint32_t lsm_idx = CONFIG_LSM_ACTIVE;
        uint32_t *lsm_active = bpf_map_lookup_elem(&config_map, &lsm_idx);
        if (lsm_active && *lsm_active == 1 && !is_antitheft_mode())
            return 0;
    }
    uint32_t ppid = 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *real_parent;
        bpf_probe_read_kernel(&real_parent, sizeof(real_parent), &task->real_parent);
        if (real_parent) {
            bpf_probe_read_kernel(&ppid, sizeof(ppid), &real_parent->tgid);
        }
    }

    // Both events are built in a per-CPU scratch (3.2 KB, over the BPF stack)
    // and then either held for tracepoint_sched_process_exec, which emits them
    // only for an exec that succeeded, or emitted here (see
    // exec_stash_map). No ring-buffer reservation is held across the fill, so
    // the 5.15 "Unreleased reference" trap (bump_stat reading an _OR_NULL
    // reservation) cannot arise here any more.
    uint32_t scratch_idx = 0;
    struct exec_stash *st = bpf_map_lookup_elem(&exec_stash_scratch, &scratch_idx);
    if (!st) return 0;
    struct TelemetryEvent *event = &st->create;
    {
        fill_header(event, EVT_PROCESS_CREATE, SRC_BPF_TRACEPOINT, ppid);
        event->details.process_create.child_pid      = key.pid;
        event->details.process_create.real_parent_pid = ppid;
        if (tp_filename) {
            bpf_probe_read_user_str(&event->details.process_create.child_image_path,
                                    sizeof(event->details.process_create.child_image_path),
                                    tp_filename);
        } else {
            event->details.process_create.child_image_path[0] = '\0';
        }
        // in antitheft mode child_command_line
        // carries argv[0..7] as 8 fixed 128-byte NUL-terminated slots (same
        // 1024-byte field, no ABI change; the agent's telemetry::cmdline_args
        // splits them and stops at the first empty slot). Warden mode keeps
        // the filename it always got. A read failure zeroes the slot, so a
        // truncated argv never leaks ring-buffer garbage into a slot.
        if (is_antitheft_mode() && tp_argv) {
            #pragma unroll
            for (int i = 0; i < 8; i++) {
                char *arg = NULL;
                bpf_probe_read_user(&arg, sizeof(arg), &tp_argv[i]);
                if (!arg) {
                    event->details.process_create.child_command_line[i * 128] = '\0';
                    break;
                }
                bpf_probe_read_user_str(&event->details.process_create.child_command_line[i * 128], 128, arg);
            }
        } else if (tp_filename) {
            bpf_probe_read_user_str(&event->details.process_create.child_command_line,
                                    sizeof(event->details.process_create.child_command_line),
                                    tp_filename);
        } else {
            event->details.process_create.child_command_line[0] = '\0';
        }
        event->details.process_create.child_sequence_number = 0;
        event->details.process_create.parent_sequence_number = 0;
        event->details.process_create.mnt_ns_inum = get_current_mnt_ns_inum();
        event->details.process_create.pid_ns_inum = get_current_pid_ns_inum();
        event->details.process_create.child_start_time = key.start_time;
        event->details.process_create.pkg_lifecycle = 0;
        event->details.process_create.kernel_verdicts = 0;
    }

    // a SEPARATE, second event from this
    // same hook - does not touch the ProcessCreate emission above. envp is a
    // char** in *user* memory (bpf_probe_read_user, not _kernel). Bounded
    // unrolled scan (real environments rarely exceed 64 entries; missing an
    // LD_PRELOAD set beyond entry 64 is an accepted, documented gap) that
    // stops early on a NULL envp pointer (end of the real array).
    struct TelemetryEvent *env_event = &st->env;
    {
        fill_header(env_event, EVT_ENVIRONMENT_MARKERS, SRC_BPF_TRACEPOINT, key.pid);
        env_event->details.env_markers.ld_preload_present = 0;
        env_event->details.env_markers.ld_library_path_present = 0;
        env_event->details.env_markers.ld_audit_present = 0;
        env_event->details.env_markers.interp_injection_mask = 0;
        env_event->details.env_markers.ld_preload_value[0] = '\0';
        env_event->details.env_markers.node_options_value[0] = '\0';

        if (tp_envp) {
            // Tiered (see __SMALL_BPF_PROG at the top of this file): this is
            // pure EnvironmentMarkers telemetry, so scanning fewer entries
            // loses visibility into an env var declared late in a long
            // environment and nothing else - no verdict depends on it.
            #pragma unroll
            for (int i = 0; i < KINN_ENV_SCAN_ENTRIES; i++) {
                char *entry = NULL;
                bpf_probe_read_user(&entry, sizeof(entry), &tp_envp[i]);
                if (!entry) break;

                // Sized for the longest prefix scanned below
                // ("ELECTRON_RUN_AS_NODE=", 21 chars) plus a NUL terminator.
                char buf[24] = {0};
                bpf_probe_read_user_str(buf, sizeof(buf), entry);

                // Manual byte compare, not strcmp - this file's own
                // established BPF-verifier-safe string-match convention
                // (see bprm_check_security's newgidmap/newuidmap checks).
                bool is_preload = buf[0]=='L'&&buf[1]=='D'&&buf[2]=='_'&&buf[3]=='P'&&buf[4]=='R'&&
                                   buf[5]=='E'&&buf[6]=='L'&&buf[7]=='O'&&buf[8]=='A'&&buf[9]=='D'&&buf[10]=='=';
                bool is_libpath = buf[0]=='L'&&buf[1]=='D'&&buf[2]=='_'&&buf[3]=='L'&&buf[4]=='I'&&buf[5]=='B'&&
                                   buf[6]=='R'&&buf[7]=='A'&&buf[8]=='R'&&buf[9]=='Y'&&buf[10]=='_'&&buf[11]=='P'&&
                                   buf[12]=='A'&&buf[13]=='T'&&buf[14]=='H'&&buf[15]=='=';
                // LD_AUDIT is the
                // same-power sibling of LD_PRELOAD - a distinct dynamic-
                // linker auditing hook with equivalent injection power.
                bool is_ld_audit = buf[0]=='L'&&buf[1]=='D'&&buf[2]=='_'&&buf[3]=='A'&&buf[4]=='U'&&
                                    buf[5]=='D'&&buf[6]=='I'&&buf[7]=='T'&&buf[8]=='=';
                // interpreter-level
                // siblings of LD_PRELOAD/LD_AUDIT - each non-ELF-loader
                // runtime's own equivalent code-injection variable.
                bool is_node_options = buf[0]=='N'&&buf[1]=='O'&&buf[2]=='D'&&buf[3]=='E'&&buf[4]=='_'&&
                                        buf[5]=='O'&&buf[6]=='P'&&buf[7]=='T'&&buf[8]=='I'&&buf[9]=='O'&&
                                        buf[10]=='N'&&buf[11]=='S'&&buf[12]=='=';
                bool is_pythonpath = buf[0]=='P'&&buf[1]=='Y'&&buf[2]=='T'&&buf[3]=='H'&&buf[4]=='O'&&
                                      buf[5]=='N'&&buf[6]=='P'&&buf[7]=='A'&&buf[8]=='T'&&buf[9]=='H'&&buf[10]=='=';
                bool is_pythonstartup = buf[0]=='P'&&buf[1]=='Y'&&buf[2]=='T'&&buf[3]=='H'&&buf[4]=='O'&&
                                         buf[5]=='N'&&buf[6]=='S'&&buf[7]=='T'&&buf[8]=='A'&&buf[9]=='R'&&
                                         buf[10]=='T'&&buf[11]=='U'&&buf[12]=='P'&&buf[13]=='=';
                bool is_perl5lib = buf[0]=='P'&&buf[1]=='E'&&buf[2]=='R'&&buf[3]=='L'&&buf[4]=='5'&&
                                    buf[5]=='L'&&buf[6]=='I'&&buf[7]=='B'&&buf[8]=='=';
                bool is_rubylib = buf[0]=='R'&&buf[1]=='U'&&buf[2]=='B'&&buf[3]=='Y'&&buf[4]=='L'&&
                                   buf[5]=='I'&&buf[6]=='B'&&buf[7]=='=';
                bool is_classpath = buf[0]=='C'&&buf[1]=='L'&&buf[2]=='A'&&buf[3]=='S'&&buf[4]=='S'&&
                                     buf[5]=='P'&&buf[6]=='A'&&buf[7]=='T'&&buf[8]=='H'&&buf[9]=='=';
                // ELECTRON_RUN_AS_NODE turns any
                // Electron binary into a plain node interpreter - the exec'd
                // wallet then runs attacker JavaScript as itself, the owner.
                bool is_electron_node = buf[0]=='E'&&buf[1]=='L'&&buf[2]=='E'&&buf[3]=='C'&&buf[4]=='T'&&
                                        buf[5]=='R'&&buf[6]=='O'&&buf[7]=='N'&&buf[8]=='_'&&buf[9]=='R'&&
                                        buf[10]=='U'&&buf[11]=='N'&&buf[12]=='_'&&buf[13]=='A'&&buf[14]=='S'&&
                                        buf[15]=='_'&&buf[16]=='N'&&buf[17]=='O'&&buf[18]=='D'&&buf[19]=='E'&&
                                        buf[20]=='=';

                if (is_preload) {
                    env_event->details.env_markers.ld_preload_present = 1;
                    bpf_probe_read_user_str(env_event->details.env_markers.ld_preload_value,
                                             sizeof(env_event->details.env_markers.ld_preload_value),
                                             entry + 11);
                } else if (is_libpath) {
                    env_event->details.env_markers.ld_library_path_present = 1;
                } else if (is_ld_audit) {
                    env_event->details.env_markers.ld_audit_present = 1;
                } else if (is_node_options) {
                    env_event->details.env_markers.interp_injection_mask |= (1 << 0);
                    bpf_probe_read_user_str(env_event->details.env_markers.node_options_value,
                                             sizeof(env_event->details.env_markers.node_options_value),
                                             entry + 13);
                } else if (is_pythonstartup) {
                    // Checked before is_pythonpath - PYTHONSTARTUP is a
                    // prefix-distinct but longer match; order doesn't
                    // actually matter here since prefixes fully diverge by
                    // byte 6 ('S' vs 'P'), kept for readability only.
                    env_event->details.env_markers.interp_injection_mask |= (1 << 2);
                } else if (is_pythonpath) {
                    env_event->details.env_markers.interp_injection_mask |= (1 << 1);
                } else if (is_perl5lib) {
                    env_event->details.env_markers.interp_injection_mask |= (1 << 3);
                } else if (is_rubylib) {
                    env_event->details.env_markers.interp_injection_mask |= (1 << 4);
                } else if (is_classpath) {
                    env_event->details.env_markers.interp_injection_mask |= (1 << 5);
                } else if (is_electron_node) {
                    env_event->details.env_markers.interp_injection_mask |= (1 << 6);
                }
            }
        }
    }

    // antitheft with the success hook attached: hold them for it, by thread id.
    {
        uint32_t defer_idx = CONFIG_EXEC_AT_SUCCESS;
        uint32_t *defer = bpf_map_lookup_elem(&config_map, &defer_idx);
        if (defer && *defer == 1 && is_antitheft_mode()) {
            uint32_t tid = (uint32_t)bpf_get_current_pid_tgid();
            if (bpf_map_update_elem(&exec_stash_map, &tid, st, BPF_ANY) == 0) return 0;
        }
    }
    long out = bpf_ringbuf_output(&telemetry_ringbuf, &st->create, sizeof(struct TelemetryEvent), 0);
    bump_stat(out == 0 ? STAT_EXEC_EMITTED : STAT_EXEC_DROPPED);
    bpf_ringbuf_output(&telemetry_ringbuf, &st->env, sizeof(struct TelemetryEvent), 0);
    return 0;
}

// The exec succeeded: emit the events its execve tracepoint held
// (exec_stash_map), now that bprm_creds_for_exec has re-rooted or tainted the
// process, with that verdict in the event itself. `old_pid` is the thread id
// the syscall ran on: a non-leader thread's exec has made it the leader (pid =
// tgid) by now, which is also why the identity is read here, post de_thread,
// and not at the syscall. A failed exec never reaches here, so a `$PATH`
// search emits one pair instead of one per folder tried. Only fires after an
// exec that was itself an antitheft deferral, so Warden is untouched.
SEC("tracepoint/sched/sched_process_exec")
int tracepoint_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    uint32_t tid = (uint32_t)ctx->old_pid;
    struct exec_stash *st = bpf_map_lookup_elem(&exec_stash_map, &tid);
    if (!st) return 0;
    struct process_key key = get_current_group_leader_key();
    st->create.details.process_create.child_pid = key.pid;
    st->create.details.process_create.child_start_time = key.start_time;
    // The path as the caller passed it, from the kernel's own copy (bprm->filename): the syscall-time
    // read of the caller's string fails when its page is not resident (a forked child that has not
    // touched it yet: an empty image, seen in TestExecEventsOnlyForSuccessWithTheKernelsVerdict).
    {
        uint32_t loc = ctx->__data_loc_filename;
        bpf_probe_read_kernel_str(st->create.details.process_create.child_image_path,
                                  sizeof(st->create.details.process_create.child_image_path),
                                  (void *)((unsigned long)ctx + (loc & 0xFFFF)));
    }
    uint8_t *pkg = bpf_map_lookup_elem(&pkg_lifecycle_pids, &key);
    st->create.details.process_create.pkg_lifecycle = pkg ? *pkg : 0;
    st->create.details.process_create.kernel_verdicts = KINN_EXEC_VERDICT_PKG;
    st->env.header.pid = key.pid;
    long out = bpf_ringbuf_output(&telemetry_ringbuf, &st->create, sizeof(struct TelemetryEvent), 0);
    bump_stat(out == 0 ? STAT_EXEC_EMITTED : STAT_EXEC_DROPPED);
    bpf_ringbuf_output(&telemetry_ringbuf, &st->env, sizeof(struct TelemetryEvent), 0);
    bpf_map_delete_elem(&exec_stash_map, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_sys_enter_execve(struct sys_enter_execve_args *ctx) {
    return handle_exec_tracepoint(ctx->filename, ctx->argv, ctx->envp);
}

// execveat(2) had NO producer at all. In an antitheft LSM
// deployment bprm_creds_for_exec deliberately goes quiet (it would only
// duplicate the tracepoint, without argv/envp), and the only tracepoint
// attached was sys_enter_execve - so every fexecve()/memfd-backed exec,
// which is what execveat exists for, produced zero ProcessCreate. The
// kernel-side stamps in bprm_creds_for_exec still fired, so enforcement was
// unaffected; it was userspace that could not see the process, which is the
// half that builds the tree, classifies origin and decides install context.
// Note memfd exec is a vector this same file DENIES for protected non-JIT
// processes, so it was also the one exec the agent could not observe.
//
// With AT_EMPTY_PATH the filename is an empty string (the fd is the image),
// so such an event carries a pid and a parent but no path. That is still
// strictly more than the nothing it produced before, and the agent's own
// /proc read resolves the image where it needs one.
SEC("tracepoint/syscalls/sys_enter_execveat")
int tracepoint_sys_enter_execveat(struct sys_enter_execveat_args *ctx) {
    return handle_exec_tracepoint(ctx->filename, ctx->argv, ctx->envp);
}

// P2-10: sched/sched_process_exit — emit ProcessStop events
SEC("tracepoint/sched/sched_process_exit")
int tracepoint_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    struct process_key key = get_current_process_key();

    // Clean up all per-process BPF maps
    bpf_map_delete_elem(&category_flags_map,      &key);
    bpf_map_delete_elem(&pending_network_connect,  &key);
    bpf_map_delete_elem(&trusted_ancestor_roots,   &key);
    bpf_map_delete_elem(&process_threshold_map,    &key);
    bpf_map_delete_elem(&tainted_process_map,      &key);
    uint32_t pid = key.pid;
    bpf_map_delete_elem(&pid_tree_type_map,        &key);
    bpf_map_delete_elem(&jvm_exception_pids,       &pid);
    bpf_map_delete_elem(&admin_session_pids,       &pid);
    bpf_map_delete_elem(&protected_owner_pids,     &key); // Phase 5
    bpf_map_delete_elem(&revoked_pid_map,          &key); // Runtime-revocation plan
    bpf_map_delete_elem(&pkg_lifecycle_pids,       &key); // Supply-chain defense
    bpf_map_delete_elem(&exec_origin_map,          &key); // Chain identity
    {
        // A held exec of this THREAD that never succeeded (its last attempt failed).
        uint32_t tid = (uint32_t)bpf_get_current_pid_tgid();
        bpf_map_delete_elem(&exec_stash_map, &tid);
    }

    // ProcessStop only when the whole thread group ends. This tracepoint fires for
    // EVERY exiting thread, and the event carries only the tgid, so a worker thread's exit read as
    // the process's end: antitheft's tree dropped live multi-threaded processes.
    // do_exit decrements signal->live before this tracepoint, so 0
    // means this is the last thread, the same condition Tetragon's exit hook keys on
    // (acct_process, bpf/process/bpf_exit.c). Two threads racing to the end can both read 0: a
    // duplicate stop, which every consumer already treats as a no-op. The per-thread map cleanup
    // above is unchanged.
    struct task_struct *exiting = (struct task_struct *)bpf_get_current_task();
    if (exiting && BPF_CORE_READ(exiting, signal, live.counter) != 0)
        return 0;

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_PROCESS_STOP, SRC_BPF_TRACEPOINT, key.pid);
        event->details.process_stop.exit_code = 0;
        event->details.process_stop._pad = 0;
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

// DB-1: sched/sched_process_fork — propagate parent's threshold & trust to forked child.
// Critical for database worker processes (PostgreSQL bgworkers, Redis BGSAVE) that
// are created via fork() without execve, so exec-time hooks never fire for them.
// ATTACH-FAILURE BUGFIX: this was a raw
// SEC("tracepoint/sched/sched_process_fork") program reading a hand-written
// context struct with inline `char comm[16]` fields, which placed parent_pid
// at offset 24 and child_pid at offset 44. The kernel's real record uses
// __data_loc (4-byte) comm fields and is 24 bytes total, with parent_pid at
// offset 12 and child_pid at 20 - so the program read past the end of the
// record and the kernel refused to attach it at all ("failed to create BPF
// link for perf_event FD: -13 (Permission denied)"), on every boot, for both
// products. Everything this program propagates was therefore dead in
// production: trusted-ancestor and install-context inheritance, threshold
// inheritance, admin-session and JVM markers. It went unnoticed because the
// loader ignores this attach's result and nothing else fails when it is
// missing.
//
// Rewritten as tp_btf, which receives the real task_struct pointers and reads
// every field through CO-RE, so it can no longer drift from the kernel's
// record layout. That also fixes two correctness bugs the old version had
// even on the layout it expected: it keyed the child by the tracepoint's
// `pid` (a thread id) rather than the thread-group id every other map lookup
// uses, and it stamped the child's key with the PARENT's start_time as an
// admitted "best-effort", which never matches what the child's own later
// lookups compute. Both keys now come from each task's group leader -
// exactly what get_current_group_leader_key() derives at lookup time.
SEC("tp_btf/sched_process_fork")
int BPF_PROG(tracepoint_sched_process_fork, struct task_struct *parent, struct task_struct *child) {
    // Do not null-check `parent`/`child` directly: they are tracing context
    // pointers, which the verifier types as trusted and whose NULL branches it
    // prunes away as dead code (see mmap_file's VERIFIER GOTCHA comment). The
    // BPF_CORE_READ results below are ordinary scalars, so those checks are
    // real.
    struct task_struct *parent_leader = BPF_CORE_READ(parent, group_leader);
    struct task_struct *child_leader = BPF_CORE_READ(child, group_leader);
    if (!parent_leader || !child_leader)
        return 0;

    struct process_key parent_key = {0};
    parent_key.pid = BPF_CORE_READ(parent, tgid);
    parent_key.start_time = BPF_CORE_READ(parent_leader, start_time);

    // A new *thread* shares its parent's tgid and group leader, so both keys
    // come out identical and every update below is a harmless self-rewrite -
    // which is the correct behaviour, and better than the bogus per-thread
    // identity the old tracepoint-pid keying invented.
    struct process_key child_key = {0};
    child_key.pid = BPF_CORE_READ(child, tgid);
    child_key.start_time = BPF_CORE_READ(child_leader, start_time);

    // Propagate pid_tree_type_map
    uint32_t parent_pid = parent_key.pid;
    uint32_t child_pid = child_key.pid;
    uint32_t *parent_tree_type = bpf_map_lookup_elem(&pid_tree_type_map, &parent_key);
    if (parent_tree_type) {
        uint32_t val = *parent_tree_type;
        bpf_map_update_elem(&pid_tree_type_map, &child_key, &val, BPF_ANY);
    }

    // Propagate jvm_exception_pids
    uint8_t *parent_jvm_exc = bpf_map_lookup_elem(&jvm_exception_pids, &parent_pid);
    if (parent_jvm_exc) {
        uint8_t val = *parent_jvm_exc;
        bpf_map_update_elem(&jvm_exception_pids, &child_pid, &val, BPF_ANY);
    }

    // Propagate admin_session_pids
    uint8_t *parent_admin_pid = bpf_map_lookup_elem(&admin_session_pids, &parent_pid);
    if (parent_admin_pid) {
        uint8_t val = *parent_admin_pid;
        bpf_map_update_elem(&admin_session_pids, &child_pid, &val, BPF_ANY);
    }

    // Propagate protected_owner_pids - the "same process family" rule. A
    // protected app's helper processes are part of the same application and
    // must be covered with it: an Electron browser's crash handler
    // ptrace-attaches its own siblings as normal operation, and a
    // non-AppImage app's helpers exec a different binary than the one the
    // corpus matched, so without inheritance they would be strangers to
    // their own parent and their ordinary work would be denied. The whole
    // value is inherited, whatever bits it carries.
    if (is_antitheft_mode()) {
        uint8_t *parent_protected = bpf_map_lookup_elem(&protected_owner_pids, &parent_key);
        if (parent_protected) {
            uint8_t val = *parent_protected;
            bpf_map_update_elem(&protected_owner_pids, &child_key, &val, BPF_ANY);
        }
    }

    // Propagate the package-install mark, one generation deeper. This is the
    // whole mechanism behind supply-chain scoping: a lifecycle script is
    // several forks removed from the package manager (npm -> sh -> node ->
    // ...), and the mark has to survive every one of them - while the depth
    // is what lets file_open tell the package manager's own work (depth 1)
    // from the code it forked (depth 2+). Only a real fork deepens it: for a
    // new thread child_key == parent_key (see above), and incrementing there
    // would turn dpkg into its own descendant the moment it spawned a
    // worker thread.
    if (is_antitheft_mode()) {
        uint8_t *parent_pkg = bpf_map_lookup_elem(&pkg_lifecycle_pids, &parent_key);
        if (parent_pkg && child_key.pid != parent_key.pid) {
            uint8_t depth = *parent_pkg & PKG_LIFECYCLE_DEPTH_MASK;
            // The taint rides along: once arbitrary code has run above this
            // point in the tree, nothing below it can be a fetch helper
            // chain, so a child must not be able to shed it by forking.
            uint8_t val = (depth < PKG_LIFECYCLE_DEPTH_MASK ? depth + 1 : PKG_LIFECYCLE_DEPTH_MASK) |
                          (*parent_pkg & (PKG_LIFECYCLE_DISTRO | PKG_LIFECYCLE_RAN_OTHER_CODE));
            bpf_map_update_elem(&pkg_lifecycle_pids, &child_key, &val, BPF_ANY);
        }

        // a revoked owner must not get its
        // standing back by forking - the child has the same exe, so without
        // this it would be an owner again and not revoked.
        uint32_t *parent_revoked = bpf_map_lookup_elem(&revoked_pid_map, &parent_key);
        if (parent_revoked) {
            uint32_t val = *parent_revoked;
            bpf_map_update_elem(&revoked_pid_map, &child_key, &val, BPF_ANY);
        }

        // the chain's identity flows down to
        // children. This is the user's v1 call - a game launched by Steam may
        // read Steam's store - with the credential-change boundary in
        // task_fix_setuid/bprm_committing_creds as the only cut.
        struct exec_origin *parent_origin = bpf_map_lookup_elem(&exec_origin_map, &parent_key);
        if (parent_origin) {
            struct exec_origin val = *parent_origin;
            bpf_map_update_elem(&exec_origin_map, &child_key, &val, BPF_ANY);
        }
    }

    // Look up parent's threshold (contains ROLE_DATABASE flag)
    uint32_t *parent_threshold = bpf_map_lookup_elem(&process_threshold_map, &parent_key);
    uint8_t  *parent_trusted   = bpf_map_lookup_elem(&trusted_ancestor_roots, &parent_key);

    // Only propagate if parent has a meaningful entry
    if (!parent_threshold) {
        asm volatile("" : "+r"(parent_trusted));
        if (!parent_trusted) {
            return 0;
        }
    }

    if (parent_threshold) {
        uint32_t val = *parent_threshold;
        bpf_map_update_elem(&process_threshold_map, &child_key, &val, BPF_ANY);
    }
    if (parent_trusted) {
        uint8_t val = *parent_trusted;
        bpf_map_update_elem(&trusted_ancestor_roots, &child_key, &val, BPF_ANY);
    }

    return 0;
}

// P2-2: sys_enter_connect — emit NetworkConnect with real IP (fallback mode)
struct sys_enter_connect_args {
    unsigned long long pad;
    long syscall_nr;
    int fd;
    struct sockaddr *uservaddr;
    int addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint_sys_enter_connect(struct sys_enter_connect_args *ctx) {
    if (!ctx->uservaddr)
        return 0;

    unsigned short family = 0;
    bpf_probe_read_user(&family, sizeof(family), &ctx->uservaddr->sa_family);
    if (family != 2 && family != 10)
        return 0;

    struct process_key key = get_current_process_key();

    uint32_t conn_active = 1;
    bpf_map_update_elem(&pending_network_connect, &key, &conn_active, BPF_ANY);

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_NETWORK_CONNECT, SRC_BPF_TRACEPOINT, key.pid);

        if (family == 2) {
            uint16_t port_be = 0;
            uint32_t addr_be = 0;
            bpf_probe_read_user(&port_be, sizeof(port_be), (char *)ctx->uservaddr + 2);
            bpf_probe_read_user(&addr_be, sizeof(addr_be), (char *)ctx->uservaddr + 4);
            event->details.network_connect.destination_port =
                ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
            uint8_t ip_buf[4];
            bpf_probe_read_user(ip_buf, sizeof(ip_buf), &addr_be);
            event->details.network_connect.destination_ip[0] = 0x04;
            event->details.network_connect.destination_ip[1] = ip_buf[0];
            event->details.network_connect.destination_ip[2] = ip_buf[1];
            event->details.network_connect.destination_ip[3] = ip_buf[2];
            event->details.network_connect.destination_ip[4] = ip_buf[3];
            event->details.network_connect.destination_ip[5] = 0;
        } else {
            uint16_t port_be = 0;
            bpf_probe_read_user(&port_be, sizeof(port_be), (char *)ctx->uservaddr + 2);
            event->details.network_connect.destination_port =
                ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
            event->details.network_connect.destination_ip[0] = 0x06;
            bpf_probe_read_user(event->details.network_connect.destination_ip + 1,
                                16, (char *)ctx->uservaddr + 8);
            event->details.network_connect.destination_ip[17] = 0;
        }

        event->details.network_connect.protocol[0] = 'T';
        event->details.network_connect.protocol[1] = 'C';
        event->details.network_connect.protocol[2] = 'P';
        event->details.network_connect.protocol[3] = 0;

        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

// P2-4: sys_enter_openat — emit FileOpen events in fallback mode
struct sys_enter_openat_args {
    unsigned long long pad;
    long syscall_nr;
    int dfd;
    char *filename;
    int flags;
    int mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_sys_enter_openat(struct sys_enter_openat_args *ctx) {
    struct process_key key = get_current_process_key();

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_FILE_READ, SRC_BPF_TRACEPOINT, key.pid);
        event->details.file_read.bytes_requested = 0;
        event->details.file_read.zone_id = 0;
        if (ctx->filename) {
            bpf_probe_read_user_str(&event->details.file_read.file_path,
                                    sizeof(event->details.file_read.file_path),
                                    ctx->filename);
        } else {
            event->details.file_read.file_path[0] = '\0';
        }
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

// P2-5/P2-6: sys_enter_mmap + sys_enter_mprotect — MemoryMap events for anonymous exec detection
struct sys_enter_mmap_args {
    unsigned long long pad;
    long syscall_nr;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long off;
};

SEC("tracepoint/syscalls/sys_enter_mmap")
int tracepoint_sys_enter_mmap(struct sys_enter_mmap_args *ctx) {
    // Only interested in anonymous PROT_EXEC mappings (RCE / shellcode indicator)
    if (!(ctx->prot & 0x4)) // PROT_EXEC
        return 0;
    if (!(ctx->flags & 0x20)) // MAP_ANONYMOUS
        return 0;

    struct process_key key = get_current_process_key();

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_MEMORY_MAP, SRC_BPF_TRACEPOINT, key.pid);
        event->details.memory_map.addr   = ctx->addr;
        event->details.memory_map.length = ctx->len;
        event->details.memory_map.prot   = (uint32_t)ctx->prot;
        event->details.memory_map.flags  = (uint32_t)ctx->flags;
        event->details.memory_map.fd     = (int32_t)ctx->fd;
        // Group-leader start_time - see the REVOCATION IDENTITY note in
        // file_mprotect. This is the tracepoint antitheft's runtime-tamper
        // revocation actually consumes, so it had the same silent-no-op bug.
        event->details.memory_map.target_start_time = get_current_group_leader_key().start_time;
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

struct sys_enter_mprotect_args {
    unsigned long long pad;
    long syscall_nr;
    unsigned long start;
    size_t len;
    unsigned long prot;
};

SEC("tracepoint/syscalls/sys_enter_mprotect")
int tracepoint_sys_enter_mprotect(struct sys_enter_mprotect_args *ctx) {
    // Only interested in adding PROT_EXEC to an existing mapping
    if (!(ctx->prot & 0x4)) // PROT_EXEC
        return 0;

    struct process_key key = get_current_process_key();

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_MEMORY_MAP, SRC_BPF_TRACEPOINT, key.pid);
        event->details.memory_map.addr   = ctx->start;
        event->details.memory_map.length = ctx->len;
        event->details.memory_map.prot   = (uint32_t)ctx->prot;
        event->details.memory_map.flags  = 0;
        event->details.memory_map.fd     = -1;
        event->details.memory_map.file_inode = 0;
        // Was never set at all here, so consumers read whatever the previous
        // occupant of this ringbuf slot left behind - a garbage identity, not
        // merely a wrong one. Same group-leader rule as every other producer.
        event->details.memory_map.target_start_time = get_current_group_leader_key().start_time;
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

// P2-7: sys_enter_dup2 + sys_enter_dup3 — emit Dup2 events for reverse shell detection (M-02 fix)
// A process redirecting stdin/stdout/stderr (fd 0/1/2) to a socket is a classic reverse shell indicator.

// Every syscall argument is an 8-byte slot in the tracepoint record (see
// /sys/kernel/tracing/events/syscalls/sys_enter_dup2/format: oldfd at 16,
// newfd at 24). Declared as `unsigned int`, newfd was read at offset 20 - the
// zero upper half of oldfd's slot - so every Dup2 event said newfd 0 and any
// socket dup'd onto any fd looked like stdin.
struct sys_enter_dup2_args {
    unsigned long long pad;
    long syscall_nr;
    unsigned long oldfd;
    unsigned long newfd;
};

SEC("tracepoint/syscalls/sys_enter_dup2")
int tracepoint_sys_enter_dup2(struct sys_enter_dup2_args *ctx) {
    // Attached in LSM mode for antitheft only: warden acts on Dup2 (a kill in
    // heuristics.rs) and never received it in LSM mode, so it still doesn't.
    if (is_lsm_non_antitheft_deployment())
        return 0;
    struct process_key key = get_current_process_key();

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_DUP2, SRC_BPF_TRACEPOINT, key.pid);
        event->details.dup2.oldfd = ctx->oldfd;
        event->details.dup2.newfd = ctx->newfd;
        // resolved at syscall *entry*,
        // so oldfd is still open/valid here - fixes warden's reverse-shell
        // check, which has been reading this field uninitialized.
        uint16_t family;
        event->details.dup2.old_fd_type = resolve_fd_kind(ctx->oldfd, &family);
        event->details.dup2.old_fd_family = family;
        bpf_ringbuf_submit(event, 0);
    }

    if (is_install_session() || is_admin_session()) {
        record_and_batch_event(6, NULL, 0, "[dup2]"); // 6 = SYSCALL
    }

    return 0;
}

struct sys_enter_dup3_args {
    unsigned long long pad;
    long syscall_nr;
    unsigned long oldfd;
    unsigned long newfd;
    long flags;
};

SEC("tracepoint/syscalls/sys_enter_dup3")
int tracepoint_sys_enter_dup3(struct sys_enter_dup3_args *ctx) {
    if (is_lsm_non_antitheft_deployment())
        return 0;
    struct process_key key = get_current_process_key();

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_DUP2, SRC_BPF_TRACEPOINT, key.pid);
        event->details.dup2.oldfd = ctx->oldfd;
        event->details.dup2.newfd = ctx->newfd;
        uint16_t family;
        event->details.dup2.old_fd_type = resolve_fd_kind(ctx->oldfd, &family);
        event->details.dup2.old_fd_family = family;
        bpf_ringbuf_submit(event, 0);
    }

    if (is_install_session() || is_admin_session()) {
        record_and_batch_event(6, NULL, 0, "[dup3]"); // 6 = SYSCALL
    }

    return 0;
}

struct sys_enter_listen_args {
    unsigned long long pad;
    long syscall_nr;
    int fd;
    int backlog;
};

SEC("tracepoint/syscalls/sys_enter_listen")
int tracepoint_sys_enter_listen(struct sys_enter_listen_args *ctx) {
    struct process_key key = get_current_process_key();

    // resolve the listening socket's
    // local port via the same fd-table walk + __sk_common.skc_num pattern
    // lsm/socket_accept already proves works elsewhere in this file.
    uint16_t port = 0;
    struct file *listen_file = resolve_fd_to_file((unsigned int)ctx->fd);
    if (listen_file) {
        struct socket *sock = BPF_CORE_READ(listen_file, private_data); // a socket fd's file->private_data is its struct socket*
        if (sock) {
            struct sock *sk = BPF_CORE_READ(sock, sk);
            if (sk) port = BPF_CORE_READ(sk, __sk_common.skc_num);
        }
    }

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_LISTEN, SRC_BPF_TRACEPOINT, key.pid);
        event->details.listen.port = port;
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

// process_vm_readv/writev - the
// primary non-ptrace cross-process memory read/write primitive on modern
// Linux (credential/token theft, code injection without ever touching
// mmap/mprotect in the victim). Confirmed real tracepoint format (both IDs
// 684/682, byte-identical shape).
struct sys_enter_process_vm_readv_args {
    unsigned long long pad;
    long syscall_nr;
    pid_t pid;
    const struct iovec *lvec;
    unsigned long liovcnt;
    const struct iovec *rvec;
    unsigned long riovcnt;
    unsigned long flags;
};

SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int tracepoint_sys_enter_process_vm_readv(struct sys_enter_process_vm_readv_args *ctx) {
    // Group-leader-keyed: process_threshold_map is fork-propagated on the
    // leader's start_time - see get_current_group_leader_key()'s doc.
    struct process_key key = get_current_group_leader_key();
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (!threshold) return 0;

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_CROSS_MEMORY_ACCESS, SRC_BPF_TRACEPOINT, key.pid);
        event->details.cross_memory_access.target_pid = (uint32_t)ctx->pid;
        event->details.cross_memory_access.direction = 0; // read
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

// sys_enter_process_vm_writev_args: byte-identical shape to readv's (same
// syscall ABI) - reuse the same typed struct rather than declaring a twin.
SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int tracepoint_sys_enter_process_vm_writev(struct sys_enter_process_vm_readv_args *ctx) {
    // Group-leader-keyed: process_threshold_map is fork-propagated on the
    // leader's start_time - see get_current_group_leader_key()'s doc.
    struct process_key key = get_current_group_leader_key();
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (!threshold) return 0;

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_CROSS_MEMORY_ACCESS, SRC_BPF_TRACEPOINT, key.pid);
        event->details.cross_memory_access.target_pid = (uint32_t)ctx->pid;
        event->details.cross_memory_access.direction = 1; // write
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

#define UNIX98_PTY_SLAVE_MAJOR 136

static __always_inline bool is_pty_file(struct file *file) {
    if (!file) return false;
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode) return false;
    unsigned int rdev = BPF_CORE_READ(inode, i_rdev);
    // The kernel's internal dev_t packs MAJOR in the high 12 bits and MINOR in
    // the low 20 (MINORBITS = 20), so MAJOR(dev) is `dev >> 20`. This used to
    // compute `(rdev >> 8) & 0xfff`, the old 16-bit kdev_t encoding, which for
    // a pts device (major 136 -> rdev 0x8800000|minor) yields 0 rather than
    // 136. That made this function return false for EVERY pty, so PTY capture
    // matched nothing even once its kprobes were reading the right struct.
    // Same encoding trap that once silently disabled all (dev, ino) resource
    // attribution - see ToKernelDevEncoding() in ebpf_loader.cpp.
    unsigned int major = rdev >> 20;
    return major == UNIX98_PTY_SLAVE_MAJOR;
}

// tty_write(struct kiocb *iocb, struct iov_iter *from).
//
// This used to declare `(struct file *file, const char *buf, size_t count)`,
// the pre-iter signature. A kprobe has NO verifier-enforced signature - it just
// receives pt_regs - so that loaded and verified cleanly on every kernel while
// is_pty_file() dereferenced a `kiocb` as a `file`. It therefore matched
// nothing, and PTY capture silently captured NOTHING, with no error anywhere.
// Found only when BTF validation was first pointed at these programs.
//
// Every kernel we support (5.15+) uses the iter form; the old one predates our
// floor. The policy table asserts arg0 is a kiocb against the running kernel's
// BTF, so a kernel that disagrees disables this program rather than letting it
// misread memory again.
SEC("kprobe/tty_write")
int BPF_KPROBE(kprobe_tty_write, struct kiocb *iocb, struct iov_iter *from) {
#ifdef __KINN_TEST_BREAK_OPTIONAL
    KINN_TEST_VERIFIER_FAULT();
#endif
    struct file *file = BPF_CORE_READ(iocb, ki_filp);
    if (!is_pty_file(file))
        return 0;

    uint32_t to_copy = 0;
    void *buf = iov_iter_user_buf(from, &to_copy);
    if (!buf || !to_copy)
        return 0;

    struct tty_event *ev = bpf_ringbuf_reserve(&tty_ringbuf, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->is_write = 1;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    ev->len = to_copy;

    bpf_probe_read_user(&ev->data, to_copy & 1023, buf);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// tty_read(struct kiocb *iocb, struct iov_iter *to) - same correction as
// tty_write above. The destination buffer is resolved here, on entry, because
// the kretprobe only gets the return value and cannot reach the iov_iter.
SEC("kprobe/tty_read")
int BPF_KPROBE(kprobe_tty_read, struct kiocb *iocb, struct iov_iter *to) {
    struct file *file = BPF_CORE_READ(iocb, ki_filp);
    if (!is_pty_file(file))
        return 0;

    uint32_t unused_len = 0;
    void *buf = iov_iter_user_buf(to, &unused_len);
    if (!buf)
        return 0;

    uint32_t tid = bpf_get_current_pid_tgid();
    struct tty_read_req req = {
        .file = file,
        .buf = buf
    };
    bpf_map_update_elem(&pending_tty_reads, &tid, &req, BPF_ANY);
    return 0;
}

SEC("kretprobe/tty_read")
int BPF_KRETPROBE(kretprobe_tty_read, int ret) {
    uint32_t tid = bpf_get_current_pid_tgid();
    struct tty_read_req *req = bpf_map_lookup_elem(&pending_tty_reads, &tid);
    if (!req)
        return 0;

    struct file *file = req->file;
    void *buf = req->buf;
    bpf_map_delete_elem(&pending_tty_reads, &tid);

    if (ret <= 0)
        return 0;

    struct tty_event *ev = bpf_ringbuf_reserve(&tty_ringbuf, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->is_write = 0;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    unsigned int uret = (unsigned int)ret;
    uint32_t to_copy = uret > 1023 ? 1023 : uret;
    ev->len = to_copy;

    bpf_probe_read_user(&ev->data, to_copy & 1023, buf);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}


#endif  // KINNECTOR_BPF_TRACEPOINTS_H
