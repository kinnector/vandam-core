// SPDX-License-Identifier: GPL-2.0-only
#ifndef KINNECTOR_BPF_LSM_HOOKS_CREDS_H
#define KINNECTOR_BPF_LSM_HOOKS_CREDS_H

// BPF LSM hooks, part 2: credential/exec-commit hooks (bprm_committing_creds,
// bprm_check_security), ptrace/kill (ptrace_access_check, task_kill), the
// self-exec and W^X owner-protection helpers, and file_mprotect/mmap_file/
// socket_listen/path_chmod. Verbatim split out of kinnector.bpf.c - see that
// file's header comment. This and kinnector_lsm_hooks_exec.h together are
// the original "BPF LSM Hooks" section banner, split in two purely for
// file size.

SEC("lsm/bprm_committing_creds")
int BPF_PROG(bprm_committing_creds, const struct linux_binprm *bprm) {
    if (!bprm) return 0;
    struct process_key key = get_current_process_key();

    uint32_t pre_exec_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    uint32_t post_exec_euid = BPF_CORE_READ(bprm, cred, euid.val);
    uint64_t pre_exec_cap_effective = 0;
    struct task_struct *cur_task = (struct task_struct *)bpf_get_current_task();
    if (cur_task) {
        const struct cred *cur_cred = BPF_CORE_READ(cur_task, cred);
        if (cur_cred) {
            KINN_READ_CAP_U64(pre_exec_cap_effective, cur_cred, cap_effective);
        }
    }
    uint64_t post_exec_cap_effective = 0;
    KINN_READ_CAP_U64(post_exec_cap_effective, bprm, cred, cap_effective);

    // Chain identity (B4): an exec that changes the
    // effective uid (a setuid binary) ends the chain. chrome-sandbox, sudo,
    // pkexec: whatever comes out the other side must earn its own identity
    // by exec'ing an owner image, which the zygote does a moment later.
    if (is_antitheft_mode() && cur_task) {
        const struct cred *cur_cred2 = BPF_CORE_READ(cur_task, cred);
        uint32_t cur_euid = cur_cred2 ? BPF_CORE_READ(cur_cred2, euid.val) : pre_exec_uid;
        if (post_exec_euid != cur_euid) {
            struct process_key leader_key = get_current_group_leader_key();
            bpf_map_delete_elem(&exec_origin_map, &leader_key);
            bpf_map_delete_elem(&protected_owner_pids, &leader_key);
        }
    }

    if (post_exec_euid != pre_exec_uid ||
        (post_exec_cap_effective & ~pre_exec_cap_effective) != 0) {
        struct TelemetryEvent *delta_event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
        if (delta_event) {
            fill_header(delta_event, EVT_EXEC_CREDENTIAL_DELTA, SRC_BPF_LSM, key.pid);
            delta_event->details.exec_credential_delta.pre_exec_uid = pre_exec_uid;
            delta_event->details.exec_credential_delta.post_exec_euid = post_exec_euid;
            delta_event->details.exec_credential_delta.pre_exec_cap_effective = pre_exec_cap_effective;
            delta_event->details.exec_credential_delta.post_exec_cap_effective = post_exec_cap_effective;
            bpf_ringbuf_submit(delta_event, 0);
        }
    }
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm) {
    if (!bprm)
        return 0;

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode && *mode == 1);
    if (!blocking_enabled)
        return 0;

    // Bypass for admin sessions (unless it is install context)
    if (is_admin_session() && !is_install_session()) {
        return 0;
    }

    // Group-leader-keyed: process_threshold_map is fork-propagated on the
    // leader's start_time (get_current_group_leader_key()'s doc) - a plain
    // thread key silently misses a worker thread's own process entry.
    struct process_key key = get_current_group_leader_key();
    uint32_t *active_threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (!active_threshold) {
        return 0;
    }

    uint32_t thresh_val = *active_threshold;

    struct file *bprm_file = BPF_CORE_READ(bprm, file);
    if (bprm_file) {
        // Block memfd execution for monitored processes / install contexts
        struct dentry *dentry = BPF_CORE_READ(bprm_file, f_path.dentry);
        if (dentry) {
            struct qstr d_name = BPF_CORE_READ(dentry, d_name);
            char name[16] = {0};
            bpf_probe_read_kernel_str(name, sizeof(name), d_name.name);
            if (name[0] == 'm' && name[1] == 'e' && name[2] == 'm' && name[3] == 'f' && name[4] == 'd' && name[5] == ':') {
                if (thresh_val > 0 || is_install_session()) {
                    return -EACCES;
                }
            }
        }

        struct inode *inode = BPF_CORE_READ(bprm_file, f_inode);
        if (inode) {
            uint64_t ino = BPF_CORE_READ(inode, i_ino);
            struct resource_id exec_id = make_resource_id(inode); // Phase 6

            // Re-validate against newly_created_inodes (untrusted/tampered)
            uint8_t *is_newly_created = bpf_map_lookup_elem(&newly_created_inodes, &exec_id);
            if (is_newly_created && *is_newly_created == 1) {
                if (thresh_val > 0) {
                    if (!is_install_session()) {
                        return -EACCES;
                    }
                }
            }

            // PROFILE_ZERO_EXECUTION: unconditionally deny execution
            if (thresh_val & PROFILE_ZERO_EXECUTION) {
                return -EACCES;
            }

            // PROFILE_RESTRICTED_EXEC: check exec_allowlist_map
            if (thresh_val & PROFILE_RESTRICTED_EXEC) {
                uint8_t *allowed = bpf_map_lookup_elem(&exec_allowlist_map, &ino);
                if (!allowed || *allowed != 1) {
                    return -EACCES; // Deny execution of unapproved binary
                }
            }
        }
    }

    if (is_install_session() || is_admin_session()) {
        struct file *bprm_file = BPF_CORE_READ(bprm, file);
        if (bprm_file) {
            struct inode *inode = BPF_CORE_READ(bprm_file, f_inode);
            uint64_t ino = inode ? BPF_CORE_READ(inode, i_ino) : 0;
            record_and_batch_event(5, bprm_file, ino, NULL); // 5 = EXEC
        }
    }

    return 0;
}

// True only for antitheftd itself, only while its own switch is on, and only
// for an access that is not a real attach: (tgid, start_time) of the caller
// must equal (CONFIG_OWN_PID, CONFIG_OWN_START_TIME_LO/HI). 0x2 is
// PTRACE_MODE_ATTACH; READ (0x1) and the FSCREDS/REALCREDS/NOAUDIT nuance bits
// never carry it, so a real ptrace attach/seize, process_vm_*, and
// /proc/<pid>/mem (all ATTACH modes) are never exempted. Scalars in, scalar
// out: no pointer crosses the call, so no null-check has to be carried.
static __always_inline int daemon_may_read_protected_identity(uint32_t caller_pid, uint64_t caller_start_time, unsigned int mode) {
    if (mode & 0x2) return 0;
    uint32_t idx = CONFIG_DAEMON_READS_PROTECTED_IDENTITY;
    uint32_t *on = bpf_map_lookup_elem(&config_map, &idx);
    if (!on || *on != 1) return 0;
    idx = CONFIG_OWN_PID;
    uint32_t *own_pid = bpf_map_lookup_elem(&config_map, &idx);
    if (!own_pid || *own_pid == 0 || *own_pid != caller_pid) return 0;
    idx = CONFIG_OWN_START_TIME_LO;
    uint32_t *lo = bpf_map_lookup_elem(&config_map, &idx);
    idx = CONFIG_OWN_START_TIME_HI;
    uint32_t *hi = bpf_map_lookup_elem(&config_map, &idx);
    if (!lo || !hi) return 0;
    uint64_t own_start = ((uint64_t)(*hi) << 32) | (uint64_t)(*lo);
    return own_start != 0 && own_start == caller_start_time;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_access_check, struct task_struct *child, unsigned int mode) {
    if (!child) return 0;

    // The TRACER's key at group-leader level: every map looked
    // up with it below - pid_tree_type_map, protected_owner_pids,
    // trusted_ancestor_roots, process_threshold_map - is written by the
    // fork handler and by userspace keyed on the leader's start_time, so a
    // thread-level key (get_current_process_key()) matched only when the
    // main thread was the one asking. A worker thread of an admin-session
    // or protected process reading /proc/<own child>/exe was denied as an
    // outsider to its own family. See get_current_group_leader_key()'s doc.
    struct process_key key = get_current_group_leader_key();
    uint32_t tracee_pid = BPF_CORE_READ(child, tgid);
    uint32_t tracer_pid = key.pid;

    // Agent-core tamper resistance: nobody, including root and
    // including another attached LSM (a deny from THIS hook wins regardless
    // of what any other stacked LSM decides), gets to ptrace the daemon's
    // own process. CONFIG_OWN_PID is only set by a product that opts in
    // (antitheft's lib.rs today - see its own doc comment); a product that
    // never sets it leaves this at 0, which no real tgid ever is, so the
    // check is a no-op there.
    //
    // Audit-only mode: gated on CONFIG_BLOCKING_ENABLED, the
    // same global switch every other deny site in this object honors, so
    // an operator's `POST /api/v1/enforcement/pause` really does mean
    // "nothing enforces" rather than "nothing enforces except the daemon's
    // own self-defense" - deliberate, at the explicit request of whoever is
    // running this in a test/audit deployment. This trades away the
    // original guarantee that the daemon can't be tampered with while an
    // attacker has flipped this same switch; it is still unconditional
    // against every OTHER process's blocking-enabled state, since the
    // config map is global, not per-process.
    {
        uint32_t own_pid_idx = CONFIG_OWN_PID;
        uint32_t *own_pid = bpf_map_lookup_elem(&config_map, &own_pid_idx);
        if (own_pid && *own_pid != 0 && tracee_pid == *own_pid) {
            uint32_t blocking_idx = CONFIG_BLOCKING_ENABLED;
            uint32_t *blocking = bpf_map_lookup_elem(&config_map, &blocking_idx);
            if (blocking && *blocking == 1) {
                return -EACCES;
            }
        }
    }
    // {0} first, then field-assign -- a positional {a, b} initializer with
    // every member filled is not guaranteed to zero the padding between
    // `pid` (4 bytes) and the 8-byte-aligned `start_time`, and BPF hash-map
    // keys compare the full byte-for-byte struct including that padding.
    // Garbage padding here made this key never match the one written by
    // get_current_process_key() (which does start from {0}), so this lookup
    // silently missed every time regardless of pid/start_time being correct.
    struct process_key tracee_key = {0};
    tracee_key.pid = tracee_pid;
    // Group leader's start_time, to match tracee_key.pid being the tgid: a
    // ptrace target resolved to a specific thread would otherwise build a
    // (tgid, thread start_time) key that matches nothing ever registered.
    // Also what this event reports as target_start_time, so a userspace
    // revocation driven by a ptrace attach writes a key the kernel's own
    // file_open/file_permission lookups will actually find.
    struct task_struct *tracee_leader = BPF_CORE_READ(child, group_leader);
    tracee_key.start_time = tracee_leader ? BPF_CORE_READ(tracee_leader, start_time)
                                          : BPF_CORE_READ(child, start_time);

    // Protect admin session from ptrace attempts by non-admin processes.
    // MODE AUDIT: Warden-only, and one of only TWO rules in this
    // file that were LIVE in an antitheft deployment - TREE_ADMIN_SESSION is
    // stamped by this file itself (a TTY-attached process with an untracked
    // parent), not from any userspace map, so it fired with no antitheft opt-in
    // anywhere. Antitheft's own ptrace policy is the branch below.
    uint32_t *tracee_tree = bpf_map_lookup_elem(&pid_tree_type_map, &tracee_key);
    if (!is_antitheft_mode() && tracee_tree && (*tracee_tree & TREE_ADMIN_SESSION)) {
        uint32_t *tracer_tree = bpf_map_lookup_elem(&pid_tree_type_map, &key);
        if (!tracer_tree || !(*tracer_tree & TREE_ADMIN_SESSION)) {
            return -EACCES; // Block non-admin tracing admin process!
        }
    }

    // Antitheft-only, generalizes the
    // TREE_ADMIN_SESSION protection above to any configured owner process (e.g.
    // a password manager), via protected_owner_pids -- appended after Warden's
    // existing admin-session check, never interleaved with it, so a MODE_WARDEN
    // deployment's ptrace_access_check behavior is byte-for-byte unchanged.
    //
    // ATTACH-only: the kernel calls this hook
    // with a READ-class mode (no PTRACE_MODE_ATTACH bit 0x2: 0x9 =
    // READ|FSCREDS, 0xd = READ|FSCREDS|NOAUDIT) for ANY access under
    // /proc/<pid>/ - cmdline, status, exe, cwd, stat, environ, maps - so
    // denying it made `ps`, `pgrep`, `htop` and `cat /proc/PID/cmdline` fail
    // and alert on every refresh. Real memory access (ptrace attach/seize,
    // process_vm_readv/writev, /proc/<pid>/mem) always carries the ATTACH bit,
    // so only that is denied and reported here. A non-ATTACH access falls
    // through to the ordinary verdict-1 "observed" emit below and is allowed.
    // Accepted trade-off: /proc/<pid>/{environ,maps,exe,cwd} of a protected
    // process are readable by other processes.
    // `mode` is a hook scalar (not a checked pointer), so no null-check is
    // carried or re-read here.
    if (is_antitheft_mode() && (mode & 0x2)) {
        uint8_t *tracee_protected = bpf_map_lookup_elem(&protected_owner_pids, &tracee_key);
        if (tracee_protected && (*tracee_protected & OWNER_PROTECTED)) {
            // Daemon-identity-read exemption
            // (CONFIG_DAEMON_READS_PROTECTED_IDENTITY): the daemon may READ
            // (mode has no PTRACE_MODE_ATTACH bit: /proc/<pid>/{exe,cwd,root})
            // the identity of a protected process, so it can tell WHICH
            // process a revocation is for before it kills it. Returns early
            // and never adds a deny; every other caller, every ATTACH-mode
            // access, and the switch being off all fall through to the deny
            // below unchanged. `key` is the caller's group-leader key.
            if (daemon_may_read_protected_identity(key.pid, key.start_time, mode)) {
                return 0;
            }
            // A protected process may be traced only by another protected
            // process, i.e. by its own family (protection is inherited
            // across fork, so an app's helpers/crash handler are covered).
            // Anything outside that set - which is what real memory-
            // scraping malware is - is denied.
            uint8_t *tracer_protected = bpf_map_lookup_elem(&protected_owner_pids, &key);
            if (!tracer_protected || !(*tracer_protected & OWNER_PROTECTED)) {
                // alert-visibility audit: this used to return
                // -EACCES here, before the unconditional "observed" emit
                // below was ever reached - a real attacker being blocked
                // was completely invisible to userspace. verdict=2 (denied).
                struct TelemetryEvent *deny_evt = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
                if (deny_evt) {
                    fill_header(deny_evt, EVT_PTRACE_ATTACH, SRC_BPF_LSM, key.pid);
                    deny_evt->details.ptrace_attach.target_pid = tracee_pid;
                    deny_evt->details.ptrace_attach.target_start_time = tracee_key.start_time;
                    format_ptrace_mode(mode, deny_evt->details.ptrace_attach.mode);
                    deny_evt->details.ptrace_attach.verdict = 2;
                    bpf_ringbuf_submit(deny_evt, 0);
                }
                // Paused: the verdict-2 event above still reports the policy
                // decision (the agent only alerts on it), nothing is refused.
                if (!blocking_enabled_now())
                    return 0;
                return -EACCES; // Block unprivileged process from ptrace'ing a protected owner process!
            }
        }
    }

    // Fix 8/11: Emit EVT_PTRACE_ATTACH telemetry on EVERY ptrace attempt,
    // regardless of trust level. This allows the agent to correlate injection
    // attempts on high-value targets (browser, ssh-agent, gpg-agent) even when
    // both processes appear trusted.
    struct TelemetryEvent *ptrace_evt = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (ptrace_evt) {
        fill_header(ptrace_evt, EVT_PTRACE_ATTACH, SRC_BPF_LSM, key.pid);
        ptrace_evt->details.ptrace_attach.target_pid = tracee_pid;
        ptrace_evt->details.ptrace_attach.target_start_time = tracee_key.start_time;
        format_ptrace_mode(mode, ptrace_evt->details.ptrace_attach.mode);
        ptrace_evt->details.ptrace_attach.verdict = 1; // observed, not itself a block decision
        bpf_ringbuf_submit(ptrace_evt, 0);
    }

    uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
    if (trusted && *trusted == 1)
        return 0;

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode_val = bpf_map_lookup_elem(&config_map, &config_idx);
    if (mode_val && *mode_val == 1) {
        uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
        if (threshold && *threshold > 0) {
            if (tracee_pid != tracer_pid) {
                return -EACCES; // Block monitored processes from tracing/reading other processes' memory!
            }
        }
        if (threshold && *threshold == 1) {
            return -EACCES; // Block untrusted process from ptrace attachments!
        }
    }

    return 0;
}

SEC("lsm/task_kill")
int BPF_PROG(task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred) {
    if (!p) return 0;

    uint32_t target_pid = BPF_CORE_READ(p, tgid);
    uint32_t current_pid = bpf_get_current_pid_tgid() >> 32;
    // See the identical fix/comment on tracee_key in ptrace_access_check --
    // same uninitialized-padding hash-key-mismatch bug.
    struct process_key target_key = {0};
    target_key.pid = target_pid;
    // Group leader's start_time, as ptrace_access_check's tracee_key: `p`
    // is the specific task being signalled, which for tgkill(2) is a worker
    // thread whose own start_time matches no registered (tgid, leader
    // start_time) entry - so the admin/protected target checks below quietly
    // did not apply to a signal aimed at a thread.
    struct task_struct *target_leader = BPF_CORE_READ(p, group_leader);
    target_key.start_time = target_leader ? BPF_CORE_READ(target_leader, start_time)
                                          : BPF_CORE_READ(p, start_time);
    // The SENDER at group-leader level too, for the same reason
    // as ptrace_access_check's tracer key: pid_tree_type_map and
    // process_threshold_map are leader-keyed, so a worker thread of an
    // admin-session process killing its own child was refused with EPERM as
    // a non-admin sender.
    struct process_key current_key = get_current_group_leader_key();

    // Ignore self-signals
    if (target_pid == current_pid) return 0;

    // Agent-core tamper resistance: deny ANY signal to the
    // daemon's own process from anyone else - kill -9, kill -STOP, a
    // competing/rogue LSM's own signal path, all of it, from any sender
    // including root. Self-signals already returned above, which is what
    // lets an authenticated userspace shutdown path work: the daemon calls
    // kill(getpid(), ...) or just exit()s itself in response to an
    // authenticated control-plane request (see antitheft/agent's shutdown
    // endpoint), and that is still the ONLY way to stop it - a bare
    // `kill`/`systemctl kill` from outside no longer does anything.
    // CONFIG_OWN_PID is a no-op (stays 0) for a product that never opts in.
    //
    // Audit-only mode: same CONFIG_BLOCKING_ENABLED gate as
    // ptrace_access_check's own-pid block above - see its comment for why
    // this now honors the global switch instead of being unconditional.
    // When blocking is off, fall through to the rest of this hook instead
    // of denying, so a paused deployment can still have the daemon's own
    // process signalled (and, via the sig==9/19 branch further down,
    // observed rather than silently allowed with no trace).
    {
        uint32_t own_pid_idx = CONFIG_OWN_PID;
        uint32_t *own_pid = bpf_map_lookup_elem(&config_map, &own_pid_idx);
        uint32_t blocking_idx = CONFIG_BLOCKING_ENABLED;
        uint32_t *blocking = bpf_map_lookup_elem(&config_map, &blocking_idx);
        if (own_pid && *own_pid != 0 && target_pid == *own_pid && blocking && *blocking == 1) {
            struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
            if (event) {
                fill_header(event, 23, SRC_BPF_LSM, current_pid); // EVT_SIGNAL_DELIVERY = 23
                bpf_probe_read_kernel(event->details.details_buffer, 4, &target_pid);
                bpf_probe_read_kernel(event->details.details_buffer + 4, 4, &sig);
                uint8_t verdict = 2; // denied
                bpf_probe_read_kernel(event->details.details_buffer + 8, 1, &verdict);
                bpf_ringbuf_submit(event, 0);
            }
            return -EPERM;
        }
    }

    // Check if target is Warden
    char target_comm[16] = {0};
    bpf_probe_read_kernel_str(target_comm, sizeof(target_comm), &p->comm);
    int is_target_warden = (target_comm[0] == 'w' && target_comm[1] == 'a' && target_comm[2] == 'r' && target_comm[3] == 'd' && target_comm[4] == 'e' && target_comm[5] == 'n');

    // Check if target is admin session
    uint32_t *target_tree = bpf_map_lookup_elem(&pid_tree_type_map, &target_key);
    int is_target_admin = (target_tree && (*target_tree & TREE_ADMIN_SESSION));

    // MODE AUDIT: the second of the two live leaks. This
    // returned -EPERM in antitheft deployments, directly contradicting the
    // antitheft branch a few dozen lines below, which states "Deliberately no
    // deny here ... it does not make a process unkillable". Found live: one
    // Claude Code instance's kill(pid, 0) liveness probe of another was
    // refused, because a terminal-launched process had been stamped
    // TREE_ADMIN_SESSION by this file itself.
    if (!is_antitheft_mode() && (is_target_warden || is_target_admin)) {
        // Allow if sender is Warden
        char current_comm[16] = {0};
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        if (task) {
            bpf_probe_read_kernel_str(current_comm, sizeof(current_comm), &task->comm);
        }
        int is_sender_warden = (current_comm[0] == 'w' && current_comm[1] == 'a' && current_comm[2] == 'r' && current_comm[3] == 'd' && current_comm[4] == 'e' && current_comm[5] == 'n');

        // Allow if sender is admin session
        uint32_t *sender_tree = bpf_map_lookup_elem(&pid_tree_type_map, &current_key);
        int is_sender_admin = (sender_tree && (*sender_tree & TREE_ADMIN_SESSION));

        if (!is_sender_warden && !is_sender_admin) {
            struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
            if (event) {
                fill_header(event, 23, SRC_BPF_LSM, current_pid); // EVT_SIGNAL_DELIVERY = 23
                bpf_probe_read_kernel(event->details.details_buffer, 4, &target_pid);
                bpf_probe_read_kernel(event->details.details_buffer + 4, 4, &sig);
                uint8_t verdict = 2; // denied (blocked)
                bpf_probe_read_kernel(event->details.details_buffer + 8, 1, &verdict);
                bpf_ringbuf_submit(event, 0);
            }
            return -EPERM; // Deny signal delivery!
        }
    }

    // Antitheft-only, same generalization as
    // ptrace_access_check above -- appended after Warden's existing Warden-comm/
    // admin-session check, never interleaved with it.
    if (is_antitheft_mode()) {
        // Deliberately no deny here. Antitheft protects what executes inside
        // a process and what it can reach on disk; it does not make a
        // process unkillable, because that denies the user's own force-quit
        // of their own application and defends availability rather than
        // secrets. Signals to a protected process are still reported below.
        uint8_t *target_protected = bpf_map_lookup_elem(&protected_owner_pids, &target_key);
        if (target_protected && (*target_protected & OWNER_PROTECTED)) {
            struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
            if (event) {
                fill_header(event, 23, SRC_BPF_LSM, current_pid); // EVT_SIGNAL_DELIVERY = 23
                bpf_probe_read_kernel(event->details.details_buffer, 4, &target_pid);
                bpf_probe_read_kernel(event->details.details_buffer + 4, 4, &sig);
                uint8_t verdict = 1; // delivered (observed, not blocked - see antitheft policy note above)
                bpf_probe_read_kernel(event->details.details_buffer + 8, 1, &verdict);
                bpf_ringbuf_submit(event, 0);
            }
        }
    }

    if (sig == 9 || sig == 19) {
        uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &current_key);
        if (threshold) {
            struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
            if (event) {
                fill_header(event, 23, SRC_BPF_LSM, current_pid); // EVT_SIGNAL_DELIVERY = 23
                bpf_probe_read_kernel(event->details.details_buffer, 4, &target_pid);
                bpf_probe_read_kernel(event->details.details_buffer + 4, 4, &sig);
                uint8_t verdict = 1; // delivered (observed, not blocked - SIGKILL/SIGSTOP monitoring only)
                bpf_probe_read_kernel(event->details.details_buffer + 8, 1, &verdict);
                bpf_ringbuf_submit(event, 0);
            }
        }
    }

    return 0;
}

// Shared anonymous-executable-memory policy for the two LSM hooks that can
// see one being created: file_mprotect (two-step: mmap(RW) then
// mprotect(RX)) and mmap_file (one-step: mmap(PROT_EXEC, MAP_ANONYMOUS)).
// One function so the two hooks can't drift - until this existed the
// one-step form was silently uncovered (see mmap_file's comment for the
// verifier-level reason). `key` is the caller's ambient
// get_current_process_key() (thread-level, fork-propagated - what
// trusted_ancestor_roots/process_threshold_map are keyed by); the
// protected_owner_pids self-check derives its own group-leader key. The
// order is deliberate:
//   1. Antitheft protected-owner self-check, BEFORE the trust bypass - a
//      protected_owner_pids-registered process must not escape by having
//      been forked from a trusted lineage (same ordering discipline as
//      ptrace_access_check/task_kill). Independent of blocking mode - a
//      protected process can be fully dpkg/corpus-trusted and still
//      shouldn't do this. Antitheft-only, can't regress MODE_WARDEN.
//      Off unless the user switched self-injection protection on
//      (CONFIG_SELF_INJECTION_PROTECTION) - see
//      protected_selfexec_forbidden(), which is where that whole decision
//      lives, and runtime_integrity.rs's decide_self_mem_exec for the
//      userspace half that reads the same setting.
//   2. trusted_ancestor_roots bypass - reported as ANON_EXEC_ALLOW_TRUSTED
//      so a caller can keep skipping its telemetry for trusted processes.
//   3. W^X (writable+executable) deny in blocking mode, jvm_exception_pids
//      exempt.
//   4. Warden's threshold-based shellcode-injection deny in blocking mode.
#define ANON_EXEC_ALLOW 0
#define ANON_EXEC_ALLOW_TRUSTED 1
#define ANON_EXEC_DENY (-EACCES)

// Is the current process one that must not manufacture executable code for
// itself? True for a protected process while the user has self-injection
// protection switched on, and false for everything else - including every
// protected process while it is off, which is the default. Split out
// because the same question decides three different syscalls: anonymous
// mmap/mprotect below, a memfd/tmpfs-backed executable mapping in
// mmap_file, and SHM_EXEC in shm_shmat. Answering it in one place keeps
// them from drifting apart, which is how the one-step mmap gap survived as
// long as it did, and it is what makes one switch cover all of them.
// Pure predicate, no side effects - deliberately separate from
// emit_self_exec_denied() below. A caller may test this to decide whether to
// even LOOK at further exec-vector-specific conditions (mmap_file's tmpfs
// branch does: being "forbidden" in general doesn't mean every mapping this
// process makes is denied, only the specific vectors checked after this
// gate) - emitting telemetry here unconditionally on true would have logged
// a false "denied" for a request this function's own caller went on to
// allow. Only call emit_self_exec_denied() at an actual `return -EACCES`.
static __always_inline int protected_selfexec_forbidden(void) {
    if (!is_antitheft_mode() || !blocking_enabled_now())
        return 0;
    // The switch, read fresh on every call so a live toggle applies to
    // processes that are already running (the alternative - encoding it in
    // each protected_owner_pids entry - would only reach processes that
    // exec after the flip). Default 0: an unset config_map slot, an older
    // userspace that never writes this index, and an explicit "off" are all
    // the same answer, and that answer is "allowed".
    //
    // There is no per-process or per-application exemption left below. The
    // JIT allowance that used to live here needed a per-app JIT answer from
    // the corpus, which was wrong often enough to kill real applications;
    // retired with OWNER_JIT_SELFEXEC. On now means every
    // protected process is denied, a JIT engine included - which is why it
    // is off by default and why it belongs to the user, not to a data file.
    uint32_t protection_idx = CONFIG_SELF_INJECTION_PROTECTION;
    uint32_t *protection_on = bpf_map_lookup_elem(&config_map, &protection_idx);
    if (!protection_on || *protection_on != 1)
        return 0;
    // Group-leader-keyed lookup, not plain key - see
    // get_current_group_leader_key()'s doc for why (a real protected app is
    // essentially always multi-threaded, and the syscall can be issued from
    // any worker thread, not just the one that originally exec'd and got
    // registered).
    struct process_key self_key = get_current_group_leader_key();
    uint8_t *self_protected = bpf_map_lookup_elem(&protected_owner_pids, &self_key);
    if (!self_protected || !(*self_protected & OWNER_PROTECTED))
        return 0;
    // Revocation deliberately does not change this answer either way (it
    // used to withdraw the JIT allowance). revoke() already SIGKILLs the
    // process it names (runtime_integrity.rs's kill_revoked_process), and a
    // revocation is inherited by every child while the kill targets one
    // pid, so denying memory to the survivors only ever produced a
    // half-dead process tree. Revocation's other half still applies:
    // file_open/file_permission below refuse a revoked process its owner
    // standing, so a survivor keeps running but cannot reach what it used
    // to own.
    return 1;
}

// alert-visibility audit: antitheft's whole fileless-exec
// defense (shm_shmat direct, mmap_file's two branches, file_mprotect via
// anon_exec_policy) denied real attempts with zero telemetry at all before
// this - call this exactly once per real `return -EACCES`/ANON_EXEC_DENY
// this policy causes, never at protected_selfexec_forbidden()'s bare
// truthiness (see its own comment on why). `via` distinguishes the vector
// since nothing else here is caller-agnostic. See SelfExecDeniedDetails.
static __always_inline void emit_self_exec_denied(uint32_t pid, uint8_t via) {
    struct TelemetryEvent *deny_event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (deny_event) {
        fill_header(deny_event, EVT_SELF_EXEC_DENIED, SRC_BPF_LSM, pid);
        deny_event->details.details_buffer[0] = via;
        bpf_ringbuf_submit(deny_event, 0);
    }
}

static __always_inline int anon_exec_policy(const struct process_key *key, unsigned long prot, uint8_t via) {
    if (protected_selfexec_forbidden()) {
        emit_self_exec_denied(key->pid, via);
        return ANON_EXEC_DENY;
    }

    uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, key);
    if (trusted && *trusted == 1)
        return ANON_EXEC_ALLOW_TRUSTED;

    uint32_t config_idx = 0;
    uint32_t *mode_val = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode_val && *mode_val == 1);
    if (!blocking_enabled)
        return ANON_EXEC_ALLOW;

    // Block RWX mappings (W^X violation) unless in jvm_exception_pids.
    // Warden-only (A2): this applies to every process
    // on the machine, and the only exemption map has no antitheft populator.
    // HotSpot, Mono, PyPy and Windows apps under Wine use RWX memory, so a
    // consumer desktop cannot carry this server rule. Antitheft's own
    // per-process check ran above in protected_selfexec_forbidden().
    if ((prot & 0x2) && (prot & 0x4) && !is_antitheft_mode()) { // PROT_WRITE=2, PROT_EXEC=4
        uint32_t pid = key->pid;
        uint8_t *exc = bpf_map_lookup_elem(&jvm_exception_pids, &pid);
        if (!exc)
            return ANON_EXEC_DENY;
    }

    // Anonymous executable region in a threshold-flagged process ->
    // shellcode injection prevention
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, key);
    if (threshold && *threshold == 1)
        return ANON_EXEC_DENY;

    return ANON_EXEC_ALLOW;
}

SEC("lsm/file_mprotect")
// AppImage protection plan bugfix: the real security_file_mprotect hook
// (include/linux/lsm_hook_defs.h) takes exactly 3 args - (vma, reqprot,
// prot) - not 4. The pre-existing signature here declared a phantom 4th
// param ("newprot"), which read undefined trampoline context data instead
// of the real requested protection bits; "start"/"end" were bound to
// reqprot/prot themselves (not real address range values, despite their
// names) - both mistaken names, inherited from an unrelated mmap-style
// hook's parameter convention that doesn't apply here. Net effect: the
// top-level `newprot & PROT_EXEC` gate this whole function's logic sits
// behind was checking garbage, so the pre-existing W^X and anon-exec
// shellcode-prevention checks below have likely never reliably fired -
// found while live-testing this plan's own new check, which sits behind
// the same gate. Real address-range values for telemetry now come from
// vma->vm_start/vm_end directly (the correct source - never real
// parameters of this hook), read once below.
int BPF_PROG(file_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot) {
    // Only care about PROT_EXEC changes
    if (!(prot & 0x4)) // PROT_EXEC = 4
        return 0;

    // Group-leader-keyed: anon_exec_policy() and the trusted_ancestor_roots
    // lookup below both read fork-propagated maps (see
    // get_current_group_leader_key()'s doc) - a plain thread key silently
    // misses a worker thread's own process entry. key.pid stays identical.
    struct process_key key = get_current_group_leader_key();
    struct file *vm_file = BPF_CORE_READ(vma, vm_file);
    unsigned long vma_start = BPF_CORE_READ(vma, vm_start);
    unsigned long vma_end = BPF_CORE_READ(vma, vm_end);

    if (!vm_file) {
        // Anonymous region gaining PROT_EXEC via mprotect(2) - the two-step
        // half of the shared policy; see anon_exec_policy()'s doc for the
        // ordering rationale (protected-owner self-check ahead of the trust
        // bypass, then W^X, then Warden's threshold deny). `vm_file` here is
        // a BPF_CORE_READ result (a plain scalar to the verifier), so this
        // NULL test is real - unlike a NULL test on an LSM hook's own
        // pointer argument, which the verifier deletes (see mmap_file).
        int verdict = anon_exec_policy(&key, prot, 3); // 3 = mprotect (anonymous)
        if (verdict == ANON_EXEC_DENY)
            return -EACCES;
        if (verdict == ANON_EXEC_ALLOW_TRUSTED)
            return 0;
    } else {
        uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
        if (trusted && *trusted == 1)
            return 0;

        // Check config/blocking mode
        uint32_t config_idx = 0;
        uint32_t *mode_val = bpf_map_lookup_elem(&config_map, &config_idx);
        uint32_t blocking_enabled = (mode_val && *mode_val == 1);

        // Block RWX mappings (W^X violation) unless in jvm_exception_pids.
        // Warden-only - see anon_exec_policy's comment (A2).
        if ((prot & 0x2) && (prot & 0x4) && !is_antitheft_mode()) { // PROT_WRITE=2, PROT_EXEC=4
            uint32_t pid = key.pid;
            uint8_t *exc = bpf_map_lookup_elem(&jvm_exception_pids, &pid);
            if (!exc && blocking_enabled) {
                return -EACCES;
            }
        }
    }

    // Emit telemetry for both anonymous and file-backed PROT_EXEC changes.
    // ABI FIX: file-backed VMAs (vm_file != NULL) now populate
    // the real MemoryProtectDetails shape (see its struct def's doc) instead
    // of writing the memory_map (MemoryMapDetails) shape under the
    // EVT_MEMORY_PROTECT tag - every consumer's
    // null_terminated_str(prot_flags)/(old_prot_flags) was reading garbage
    // before this fix, breaking e.g. warden's anonymous-mprotect-shellcode
    // detection's PROT_EXEC-transition check. The old Fix-6 file_inode
    // population is dropped along with it - MemoryProtectDetails has no
    // field for it, and no consumer's struct ever had one either, so it was
    // never actually reachable through this event regardless. Anonymous
    // changes keep using EVT_MEMORY_MAP/MemoryMapDetails exactly as before -
    // unaffected by this fix, since that shape already matched on both sides.
    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        if (vm_file) {
            fill_header(event, EVT_MEMORY_PROTECT, SRC_BPF_LSM, key.pid);
            event->details.memory_protect.target_pid = key.pid;
            // Group-leader start_time, not this thread's - see the
            // REVOCATION IDENTITY note on EVT_MEMORY_MAP below.
            event->details.memory_protect.target_start_time = get_current_group_leader_key().start_time;
            event->details.memory_protect.address    = vma_start;
            event->details.memory_protect.length     = vma_end - vma_start;
            format_prot_flags((uint32_t)prot, event->details.memory_protect.prot_flags);
            // This LSM hook fires BEFORE the protection change is applied,
            // so vma's current vm_flags still reflects the OLD protection.
            // VM_READ/VM_WRITE/VM_EXEC share PROT_READ/PROT_WRITE/PROT_EXEC's
            // bit values in the low 3 bits on Linux (calc_vm_prot_bits'
            // mapping), so format_prot_flags's PROT_* switch applies as-is.
            uint64_t vm_flags = BPF_CORE_READ(vma, vm_flags);
            format_prot_flags((uint32_t)(vm_flags & 0x7), event->details.memory_protect.old_prot_flags);
        } else {
            fill_header(event, EVT_MEMORY_MAP, SRC_BPF_LSM, key.pid);
            event->details.memory_map.addr       = vma_start;
            event->details.memory_map.length     = vma_end - vma_start;
            event->details.memory_map.prot       = (uint32_t)prot;
            event->details.memory_map.flags      = 0;
            event->details.memory_map.fd         = -1;
            event->details.memory_map.file_inode = 0;
            // REVOCATION IDENTITY (fix): target_start_time exists
            // so userspace can revoke the process this event came from, by
            // writing (pid, start_time) into revoked_pid_map. file_open and
            // file_permission look that map up with
            // get_current_group_leader_key(), so this must be the group
            // leader's start_time too. It used to be get_current_process_key()'s
            // - the CURRENT THREAD's - so for any multi-threaded process that
            // triggered from a worker thread (i.e. essentially every real
            // browser, wallet or JIT runtime, which is exactly what this
            // event is for) userspace wrote a key the kernel would never look
            // up, and the revocation silently did nothing. Same landmine as
            // the protected_owner_pids one get_current_group_leader_key() was
            // introduced for; this is the producer side of it.
            event->details.memory_map.target_start_time = get_current_group_leader_key().start_time;
        }
        bpf_ringbuf_submit(event, 0);
    }

    if (is_install_session() || is_admin_session()) {
        struct file *vm_file = BPF_CORE_READ(vma, vm_file);
        if (vm_file) {
            struct inode *inode = BPF_CORE_READ(vm_file, f_inode);
            uint64_t ino = inode ? BPF_CORE_READ(inode, i_ino) : 0;
            record_and_batch_event(4, vm_file, ino, NULL); // 4 = MMAP_EXEC (file-backed)
        } else {
            record_and_batch_event(4, NULL, 0, "[anonymous]"); // 4 = MMAP_EXEC (anonymous)
        }
    }

    return 0;
}

// Fix 10: lsm/mmap_file hook — SO/shared-library load telemetry, plus the
// one-step anonymous-executable-mapping half of anon_exec_policy().
// Fires for every mmap(2) (security_mmap_file(file, prot, flags); file is
// NULL for anonymous mappings): a file-backed executable mapping (the
// dynamic linker mapping a .so) produces EVT_IMAGE_LOAD so the agent can
// detect unsigned/unexpected module loads (SO side-loading, LOLBin module
// loads); an anonymous PROT_EXEC mapping goes through the shared anon-exec
// policy and is otherwise silent here (its telemetry comes from
// tracepoint_sys_enter_mmap).
//
// VERIFIER GOTCHA - never write the anonymous branch below as `if (!file)`.
// `file` is an LSM context pointer, which the verifier types as a trusted,
// non-NULL PTR_TO_BTF_ID; a `file == NULL` comparison is therefore proven
// never-taken and hard-wired out of the loaded program as dead code
// (opt_hard_wire_dead_code_branches), together with everything behind it.
// The runtime value IS NULL for anonymous mappings - the kernel really does
// call this hook for them (confirmed on 6.17: kprobes on security_mmap_file
// and bpf_lsm_mmap_file both fire with file=0/prot=5/flags=0x22 for a
// one-step mmap(PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS), and a
// standalone lsm/mmap_file program's xlated dump showed its `!file` branch
// and the -EACCES behind it simply absent) - but no branch on it survives
// verification. The previous `if (!file) return 0;` here was dead for the
// same reason, which is why anonymous PROT_EXEC mappings used to fall
// through into the file-backed path below and emit EVT_IMAGE_LOAD with a
// failed bpf_d_path (uninitialized module_path), and why an earlier attempt
// to add the anon-exec deny under `if (!file)` was "built, loaded, never
// reached" and got misdiagnosed as "the hook never fires for anonymous
// mmap". Anonymity is derived from the mmap flags instead - MAP_ANONYMOUS
// is a scalar the verifier can't reason away, and it is also the
// semantically right test: MAP_ANONYMOUS|MAP_HUGETLB mappings carry a
// hugetlbfs pseudo-file yet are still anonymous memory. Every non-anonymous
// caller of security_mmap_file (ksys_mmap_pgoff, vm_mmap, do_shmat,
// remap_file_pages) passes a real file, and bpf_d_path/BPF_CORE_READ are
// fault-safe on a bad pointer regardless.
SEC("lsm/mmap_file")
int BPF_PROG(mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags) {
    // `file` is NULL for an anonymous mapping - that is the ordinary case
    // here, not an edge case, since the anon-exec policy below exists
    // precisely for anonymous PROT_EXEC. Every dereference in this program is
    // therefore guarded on `file` explicitly.
    //
    // Older verifiers tolerated the unguarded reads; the 7.2 verifier rejects
    // the program outright with -EACCES and says so plainly: "Make sure that a
    // NULL check precedes any arithmetic performed on the pointer" (BPF_CORE_READ
    // is pointer arithmetic). The whole object then fails to load, so a single
    // missing check here cost ALL enforcement on that kernel - the same
    // all-or-nothing blast radius as the complexity limit.
    // Only executable mappings matter to either branch. `prot` is the
    // effective protection (security_mmap_file's mmap_prot() adjustment,
    // e.g. READ_IMPLIES_EXEC personalities) - the protection the mapping
    // actually gets, and the same value file_mprotect checks.
    if (!(prot & 0x4)) return 0; // PROT_EXEC = 4

    // Fileless code: a memfd or a SysV/POSIX shared-memory segment is
    // file-BACKED, so it never reaches the MAP_ANONYMOUS branch below - yet
    // mapping one executable is the same act as anonymous shellcode, only
    // staged through a descriptor that leaves nothing on disk. `memfd_create`
    // + write + mmap(PROT_EXEC) is the standard fileless loader, and it also
    // slipped past the userspace library check, whose stat() of
    // "/memfd:x (deleted)" fails and returns silently.
    //
    // Scoped by FILELESSNESS, not by filesystem. This used to deny any file
    // whose superblock magic was TMPFS_MAGIC, which meant that on a host where
    // /tmp is a tmpfs (systemd's default, and both LVH test VMs) a protected
    // app could not exec anything out of /tmp at all - and died by
    // SIGSEGV rather than a clean EACCES, because this fires past execve's
    // point of no return. See is_fileless_tmpfs_mapping() for the full
    // reasoning and the measurements.
    //
    // Scoped to processes that must not manufacture their own executable
    // code, i.e. only when the user has switched self-injection protection
    // on. Some JIT engines genuinely do stage generated code through a
    // memfd, so this vector cannot be left armed by default any more than
    // the anonymous one can - both are the same decision, taken once in
    // protected_selfexec_forbidden().
    if (file && protected_selfexec_forbidden()) {
        struct inode *mapped_inode = BPF_CORE_READ(file, f_inode);
        struct super_block *mapped_sb = mapped_inode ? BPF_CORE_READ(mapped_inode, i_sb) : NULL;
        unsigned long mapped_magic = mapped_sb ? BPF_CORE_READ(mapped_sb, s_magic) : 0;
        if (mapped_magic == TMPFS_MAGIC &&
            is_fileless_tmpfs_mapping(file, mapped_inode)) {
            emit_self_exec_denied(bpf_get_current_pid_tgid() >> 32, 2); // 2 = mmap (fileless tmpfs mapping)
            return -EACCES;
        }
        // The real-file (non-tmpfs) case used to be checked right here,
        // narrowly scoped to protected_selfexec_forbidden(). Replaced below
        // by a broader check that stands on its own: see that block's own
        // doc for why "may this process build its own code" never should
        // have governed loading a FOREIGN file in the first place. That
        // check is unaffected by the self-injection switch.
    }

    // Untrusted-.so synchronous kernel deny (widened):
    // a root-installed protected app mapping a foreign,
    // untrusted library file executable is refused here, synchronously,
    // BEFORE the mapping succeeds - the userspace reactive classify-then-
    // revoke path this used to rely on (protection.rs::handle_image_load's
    // REASON_UNSAFE_LIBRARY_ON_APPIMAGE) only ever ran AFTER the library's
    // constructor had already executed. Deliberately independent of
    // protected_selfexec_forbidden()/OWNER_JIT_SELFEXEC: that exemption
    // answers "may this process build ITS OWN executable memory" (a JIT
    // compiler generating code at runtime is normal and has nothing to do
    // with this), not "may this process load an arbitrary file it doesn't
    // own as a shared library" - a JIT-capable browser has exactly as
    // little business dlopen()-ing an untrusted foreign .so as a non-JIT
    // wallet does, which is the real gap this closes (a protected browser
    // used to be completely exempt from this whole deny).
    //
    // A mapping is trusted (allowed to proceed) if ANY of:
    //   1. The file is root-owned (mapped_uid == 0) - the ordinary shape of
    //      a package-manager-installed system library.
    //   2. This app's own exec-origin file is itself user-owned (an
    //      AppImage/pipx-style install under $HOME) - exempt by its own
    //      uid, since such an app legitimately ships user-owned libraries
    //      (browsers load user-owned Widevine this way too).
    //   3. The file lives in a directory ownership.rs has registered as
    //      this app's OWN storage dir, and this process is a recognized
    //      owner of it - trustworthy because file_permission's storage-dir
    //      write gate (see its own comment) already denies anyone else from
    //      writing a `.so` there in the first place. This is what makes a
    //      self-installed component like Chrome's Widevine CDM - living
    //      user-owned inside Chrome's own profile directory - load
    //      correctly under this otherwise-strict deny, with no per-app
    //      corpus data naming it specifically.
    // A MODIFIED SYSTEM LIBRARY overrides all three:
    // rule 1 trusts a root-owned file by its
    // owner alone, so a trojaned package-installed library used to pass. The
    // agent fills modified_system_libraries with the (dev, ino) of every
    // package-owned library whose content no longer matches its package
    // manager's recorded hash; a hit is refused through the very same deny
    // below, whatever the three rules say. Empty by default and only ever
    // filled behind a default-off switch, so this is a no-op until the owner
    // turns it on.
    //
    // Excludes only genuinely FILELESS mappings (memfd, SysV shm, unlinked):
    // those are self-generated-code territory, governed by the switchable
    // check just above, and a legitimate engine's memfd staging must never
    // be caught by this broader gate, which is always on.
    //
    // An ordinary NAMED file that merely lives on a tmpfs mount is not
    // excluded, and deliberately so: when the check above was narrowed from
    // "any tmpfs file" to "fileless", such a file would otherwise have been
    // judged by neither gate - trading a false positive for a hole. It is now
    // evaluated on ownership and origin here, exactly as the same file would be
    // on ext4.
    // `!(flags & MAP_ANONYMOUS)` already implies a real file, but the verifier
    // cannot infer that from a flag bit - it needs the pointer itself checked.
    if (file && !(flags & 0x20) && is_protected_owner_process()) { // real (non-anonymous) mapping only
        struct inode *mapped_inode = BPF_CORE_READ(file, f_inode);
        if (mapped_inode) {
            struct super_block *mapped_sb = BPF_CORE_READ(mapped_inode, i_sb);
            unsigned long mapped_magic = mapped_sb ? BPF_CORE_READ(mapped_sb, s_magic) : 0;
            if (!(mapped_magic == TMPFS_MAGIC &&
                  is_fileless_tmpfs_mapping(file, mapped_inode))) {
                uint32_t mapped_uid = BPF_CORE_READ(mapped_inode, i_uid.val);
                int trusted = (mapped_uid == 0);
                if (!trusted) {
                    struct process_key origin_key = get_current_group_leader_key();
                    struct exec_origin *chain = bpf_map_lookup_elem(&exec_origin_map, &origin_key);
                    trusted = chain && chain->uid != 0;
                }
                if (!trusted) {
                    struct dentry *file_dentry = BPF_CORE_READ(file, f_path.dentry);
                    int dir_verdict = file_dentry ? storage_dir_verdict(file_dentry) : -1;
                    trusted = (dir_verdict == 1);
                }
                // One lookup, applied AFTER the three trust rules so it also
                // covers the files they would have trusted. `mapped_inode` is
                // the pointer checked at the top of this branch; the re-read
                // inside make_resource_id() is a probe read on a scalar, so no
                // null-check has to be carried across it.
                struct resource_id lib_id = make_resource_id(mapped_inode);
                uint8_t *modified_lib = bpf_map_lookup_elem(&modified_system_libraries, &lib_id);
                if (modified_lib && *modified_lib == 1) {
                    trusted = 0;
                }
                if (!trusted) {
                    struct TelemetryEvent *deny_event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
                    if (deny_event) {
                        fill_header(deny_event, EVT_IMAGE_LOAD, SRC_BPF_LSM, bpf_get_current_pid_tgid() >> 32);
                        deny_event->details.image_load.is_signed = 0;
                        deny_event->details.image_load.signer_subject[0] = 0;
                        deny_event->details.image_load.verdict = 1; // 1 = denied
                        // `file` is non-NULL for this whole branch, but the
                        // check is far above and the verifier stops carrying
                        // it across the inlined fill_header - on bpf-next
                        // (7.2) it treats `file` as scalar 0 here and rejects
                        // `&file->f_path` as "not an accepted pointer type"
                        // for bpf_d_path. Re-asserting it immediately before
                        // the use is the same discipline this file already
                        // documents for re-read null checks; it costs one
                        // branch and makes the program loadable.
                        if (file) {
                            KINN_D_PATH(&file->f_path, deny_event->details.image_load.module_path,
                                       sizeof(deny_event->details.image_load.module_path));
                        }
                        bpf_ringbuf_submit(deny_event, 0);
                    }
                    if (!blocking_enabled_now())
                        return 0;
                    return -EACCES;
                }
            }
        }
    }

    if (flags & 0x20) { // MAP_ANONYMOUS
        // Group-leader-keyed: anon_exec_policy() reads fork-propagated maps
        // (trusted_ancestor_roots, process_threshold_map) - see
        // get_current_group_leader_key()'s doc.
        struct process_key anon_key = get_current_group_leader_key();
        int verdict = anon_exec_policy(&anon_key, prot, 1); // 1 = mmap (anonymous)
        if (verdict == ANON_EXEC_DENY)
            return -EACCES;
        // No EVT_MEMORY_MAP from here: tracepoint_sys_enter_mmap already
        // emits one for every anonymous PROT_EXEC mmap (attached in both
        // the LSM and fallback loader paths), and file_mprotect's
        // equivalent path emits nothing on a deny either.
        if (verdict == ANON_EXEC_ALLOW && (is_install_session() || is_admin_session())) {
            record_and_batch_event(4, NULL, 0, "[anonymous]"); // 4 = MMAP_EXEC (anonymous)
        }
        return 0;
    }

    // Group-leader-keyed: trusted_ancestor_roots below is fork-propagated on
    // the leader's start_time (get_current_group_leader_key()'s doc);
    // key.pid (jvm_exception_pids/telemetry) is identical either way.
    struct process_key key = get_current_group_leader_key();

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode_val = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode_val && *mode_val == 1);

    // Block RWX mappings (W^X violation) unless in jvm_exception_pids.
    // Warden-only - see anon_exec_policy's comment (A2).
    if ((prot & 0x2) && !is_antitheft_mode()) { // PROT_WRITE=2 (PROT_EXEC=4 already checked)
        uint32_t pid = key.pid;
        uint8_t *exc = bpf_map_lookup_elem(&jvm_exception_pids, &pid);
        if (!exc && blocking_enabled) {
            return -EACCES;
        }
    }

    // Skip absolutely-trusted processes (e.g., kinnector itself)
    uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
    if (trusted && *trusted == 1)
        return 0;

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (!event) return 0;

    fill_header(event, EVT_IMAGE_LOAD, SRC_BPF_LSM, key.pid);

    // ABI FIX: ImageLoadDetails no longer has a file_inode
    // field (it was never actually reachable through this event by any
    // consumer - see the struct's own doc comment) - is_signed/
    // signer_subject are the real fields now, set to the honest "not
    // implemented" default.
    event->details.image_load.is_signed = 0;
    event->details.image_load.signer_subject[0] = 0;
    event->details.image_load.verdict = 0; // 0 = allowed - this mapping is about to succeed

    // AppImage protection plan: this used to be the dentry LEAF name only
    // (d_name.name) - no directory component, so a consumer could never
    // resolve it back to a specific file (ambiguous against any other file
    // sharing that basename elsewhere on the system, e.g. inside an
    // AppImage's own squashfs vs. the real system copy). Never actually
    // consumed by anything (see antitheft-agent's lib.rs, which explicitly
    // left EVT_IMAGE_LOAD unwired for exactly this reason) until this plan
    // needed a real resolvable path to check a loaded library's device
    // against a protected process's own AppImage device. bpf_d_path is the
    // same technique already used for file_open/file_read's full-path
    // telemetry elsewhere in this file.
    // The last unguarded `file` use in this program, and the one bpf-next
    // actually rejected: `&file->f_path` is pointer arithmetic on a pointer
    // the verifier knows can be NULL (anonymous mappings), so it arrives at
    // bpf_d_path as a scalar and the whole object fails to load.
    //
    // An anonymous mapping has no path to resolve, so the field is simply left
    // empty rather than the event being dropped - the consumer already treats
    // an empty module_path as "no file", and the event carries the rest.
    if (file) {
        KINN_D_PATH(&file->f_path, event->details.image_load.module_path,
                   sizeof(event->details.image_load.module_path));
    } else {
        event->details.image_load.module_path[0] = '\0';
    }

    bpf_ringbuf_submit(event, 0);

    if (file && (is_install_session() || is_admin_session())) {
        struct inode *inode = BPF_CORE_READ(file, f_inode);
        uint64_t ino = inode ? BPF_CORE_READ(inode, i_ino) : 0;
        record_and_batch_event(4, file, ino, NULL); // 4 = MMAP_EXEC
    }

    return 0;
}

// Deliberate no-op: this hook only fires when a local socket starts
// listening (bind/listen), not per-remote-peer, so it can't express "deny
// inbound connections from CIDR X" the way fw_check_egress does for
// outbound. Real inbound eBPF enforcement needs a hook that sees each
// remote peer (XDP or an ingress LSM socket hook this program doesn't
// attach today) — a separate, larger project. Inbound firewall rules are
// enforced by IptablesBackend/NftablesBackend's INPUT chain instead (see
// warden/src/firewall/backend.rs) — that's a complete, working enforcement
// path already, just not this one.
SEC("lsm/socket_listen")
int BPF_PROG(socket_listen, struct socket *sock, int backlog) {
    return 0;
}

SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, const struct path *path, umode_t mode) {
    if (!path) return 0;

    uint32_t config_idx = 0;
    uint32_t *mode_val = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode_val && *mode_val == 1);
    if (!blocking_enabled) return 0;

    // If setting any executable permission bits (S_IXUSR, S_IXGRP, S_IXOTH)
    if (mode & (0100 | 0010 | 0001)) {
        // Group-leader-keyed: both maps below are fork-propagated on the
        // leader's start_time - see get_current_group_leader_key()'s doc.
        struct process_key key = get_current_group_leader_key();
        uint32_t *active_threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
        if (!active_threshold || *active_threshold == 0) {
            return 0; // Not a monitored process, allow chmod
        }

        if (is_admin_session() && !is_install_session()) {
            return 0; // Allow active admin operators (SSH shell, PTY)
        }
        if (is_install_session()) {
            return 0; // Allow package managers to set executable bits during install
        }

        uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
        if (trusted && *trusted == 1) {
            return 0; // Allow system installers, updates, and trusted tools
        }

        return -EACCES; // Strictly block any other process from making files executable!
    }
    return 0;
}


#endif  // KINNECTOR_BPF_LSM_HOOKS_CREDS_H
