// SPDX-License-Identifier: GPL-2.0-only
#ifndef KINNECTOR_BPF_LSM_HOOKS_EXEC_H
#define KINNECTOR_BPF_LSM_HOOKS_EXEC_H

// BPF LSM hooks, part 1: file_open, file_permission, socket_connect and
// bprm_creds_for_exec - the exec-time and open/connect enforcement path.
// Verbatim split out of kinnector.bpf.c - see that file's header comment.
// This and kinnector_lsm_hooks_creds.h together are the original
// "BPF LSM Hooks" section banner, split in two purely for file size.

// -------------------------------------------------------------------------------------------
// BPF LSM Hooks
// ---------------------------------------------------------------------------

// Shared by both call sites in file_open below (Warden's blanket admin-
// session check and antitheft's protected-owner-scoped one) so the
// unrolled dentry walk exists once, not twice - see each call site for
// which processes/paths actually reach it.
//
// Ancestor directory names are looked up in untrusted_dir_names_map
// (config-driven from protect-community/configs/warden/exec_control_lists.json's
// untrusted_library_directories, via kinnector-config - see core/CLAUDE.md's
// former "Known debt" entry, now fixed, for why this used to be a hardcoded
// tmp/dev/mnt character-comparison chain here). Do NOT add "home" or "user" back in:
// that made every .so under any user's $HOME - real toolchains, venvs,
// node_modules native addons, Cargo build output - look like an
// injection, found live via an ordinary `cargo build` under an admin-
// session shell getting silently EACCES'd reading its own toolchain's
// librustc_driver*.so.
static __always_inline bool is_library_open_from_untrusted_dir(struct dentry *dentry) {
    if (!dentry)
        return false;

    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    char filename[64] = {0};
    bpf_probe_read_kernel_str(filename, sizeof(filename), d_name.name);

    bool is_library = false;
    #pragma unroll
    for (int i = 0; i < 58; i++) {
        if (filename[i] == '.' && filename[i+1] == 's' && filename[i+2] == 'o') {
            is_library = true;
            break;
        }
        if (filename[i] == '\0') {
            break;
        }
    }
    if (!is_library)
        return false;

    struct dentry *curr = dentry;
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        curr = BPF_CORE_READ(curr, d_parent);
        if (!curr) break;
        struct qstr p_name = BPF_CORE_READ(curr, d_name);
        struct exe_name_key key = {0};
        bpf_probe_read_kernel_str(key.name, sizeof(key.name), p_name.name);
        if (bpf_map_lookup_elem(&untrusted_dir_names_map, &key)) {
            return true;
        }
    }
    return false;
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file) {
#ifdef __KINN_TEST_BREAK_REQUIRED
    KINN_TEST_VERIFIER_FAULT();
#endif
    if (!file)
        return 0;

    struct process_key key = get_current_process_key();
    // Group-leader-keyed for every process_threshold_map/trusted_ancestor_roots
    // lookup below - both are fork-propagated on the leader's start_time (see
    // get_current_group_leader_key()'s doc), so a plain `key` read from a
    // worker thread of a monitored process would silently miss its own
    // process's entry. `key` itself stays in use for category_flags_map
    // (genuinely per-thread, not fork-propagated) and telemetry pid fields.
    struct process_key leader_key = get_current_group_leader_key();

    // PHANTOM-PARAMETER BUGFIX: this hook used to declare a
    // second context parameter, `int mask`, and test write intent with
    // `mask & MAY_WRITE`. The real hook is `security_file_open(struct file *)`
    // and takes ONE argument (include/linux/lsm_hook_defs.h) - the extra
    // parameter read undefined trampoline data, so every "is this a write?"
    // decision below was made on garbage. Same bug class as the four-argument
    // file_mprotect fixed earlier today, found the same way: a rule that
    // should have denied a write did not.
    //
    // Write intent comes from the file itself instead. FMODE_WRITE is set by
    // the time this hook runs, for O_WRONLY, O_RDWR and O_CREAT alike.
    uint32_t f_mode = BPF_CORE_READ(file, f_mode);
    bool opening_for_write = (f_mode & 0x2) != 0; // FMODE_WRITE

    // Block cross-process /proc/<PID>/fd/ access (pidfd_getfd / LFI attack path)
    {
        struct path f_path = BPF_CORE_READ(file, f_path);
        struct dentry *dentry = f_path.dentry;
        if (dentry) {
            struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
            if (parent) {
                struct qstr p_name = BPF_CORE_READ(parent, d_name);
                char p_str[8] = {0};
                bpf_probe_read_kernel_str(p_str, sizeof(p_str), p_name.name);
                if (p_str[0] == 'f' && p_str[1] == 'd' && p_str[2] == '\0') {
                    struct dentry *grandparent = BPF_CORE_READ(parent, d_parent);
                    if (grandparent) {
                        struct qstr gp_name = BPF_CORE_READ(grandparent, d_name);
                        char gp_str[16] = {0};
                        bpf_probe_read_kernel_str(gp_str, sizeof(gp_str), gp_name.name);
                        
                        uint32_t gp_pid = 0;
                        bool is_numeric = true;
                        #pragma unroll
                        for (int i = 0; i < 10; i++) {
                            char c = gp_str[i];
                            if (c == '\0') break;
                            if (c >= '0' && c <= '9') {
                                gp_pid = gp_pid * 10 + (c - '0');
                            } else {
                                is_numeric = false;
                                break;
                            }
                        }

                        if (is_numeric && gp_pid > 0 && gp_pid != key.pid) {
                            uint32_t *active_threshold = bpf_map_lookup_elem(&process_threshold_map, &leader_key);
                            if (active_threshold && *active_threshold > 0) {
                                if (!is_admin_session() || is_install_session()) {
                                    return -EACCES;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // SSHD Pre-Auth Zero-Trust Lockdown:
    // If the process is running under the unprivileged sshd user's UID,
    // deny reading files in sensitive folders (home, root, www, opt, srv, etc.).
    uint32_t current_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    uint32_t sshd_uid_key = CONFIG_SSHD_UID;
    uint32_t *sshd_uid = bpf_map_lookup_elem(&config_map, &sshd_uid_key);
    if (sshd_uid && *sshd_uid > 0 && current_uid == *sshd_uid) {
        struct path f_path = BPF_CORE_READ(file, f_path);
        struct dentry *dentry = f_path.dentry;
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            if (!dentry) break;
            struct qstr d_name = BPF_CORE_READ(dentry, d_name);
            char name[16] = {0};
            bpf_probe_read_kernel_str(name, sizeof(name), d_name.name);
            if (name[0] == 'h' && name[1] == 'o' && name[2] == 'm' && name[3] == 'e' && name[4] == '\0') {
                return -EACCES;
            }
            if (name[0] == 'r' && name[1] == 'o' && name[2] == 'o' && name[3] == 't' && name[4] == '\0') {
                return -EACCES;
            }
            if (name[0] == 'w' && name[1] == 'w' && name[2] == 'w' && name[3] == '\0') {
                return -EACCES;
            }
            if (name[0] == 'o' && name[1] == 'p' && name[2] == 't' && name[3] == '\0') {
                return -EACCES;
            }
            if (name[0] == 's' && name[1] == 'r' && name[2] == 'v' && name[3] == '\0') {
                return -EACCES;
            }
            dentry = BPF_CORE_READ(dentry, d_parent);
        }
    }

    // Admin Session Hook (Warden only): Allow everything EXCEPT dynamic
    // library injection attempts (.so from writable dirs).
    //
    // ANTITHEFT SCOPING FIX: this used to also run for
    // antitheft, unscoped - ANY process merely for being inside an
    // admin-session tree (e.g. a shell that had run `sudo` earlier) got its
    // .so opens blanket-checked, nothing to do with antitheft's actual job
    // of protecting specific money-categorized apps (browsers, wallets).
    // That's a Warden-shaped defense (Warden protects a whole
    // server/container, no notion of "which app matters"), not an
    // antitheft one, so it is Warden-only now (gated on
    // `!is_antitheft_mode()` below, same as the rest of this hook's
    // deployment-mode split).
    //
    // Antitheft's real equivalent already exists, is better, and needed no
    // new code here: `mmap_file`'s EVT_IMAGE_LOAD fires when a `.so` maps
    // into a process `protection::handle_image_load` (agent/src/
    // protection.rs) is already tracking as a protected owner (browsers/
    // wallets only, via ProtectedProcessTracker - so already scoped
    // correctly). It allows same-device loads outright (an AppImage's own
    // squashfs/FUSE mount - the "inside the appimage" case), then checks
    // real dpkg/rpm/pacman/apk ownership plus immutable stores (nix/snap/
    // flatpak) via `package_ownership::classify` (the "provisioned/
    // installed with system pkm" case) - config-driven and multi-distro,
    // not hardcoded ancestor-directory names. Anything left over is
    // Alert'd or Revoke'd (into `revoked_pid_map`, which section 2's
    // owner-allowlist check below, and file_permission, already consult).
    // Do not re-add a second, cruder synchronous check here for antitheft.
    if (is_admin_session() && !is_install_session() && !is_antitheft_mode()) {
        struct path f_path = BPF_CORE_READ(file, f_path);
        if (is_library_open_from_untrusted_dir(f_path.dentry)) {
            return -EACCES; // Block library injection!
        }
        // Deployment-mode-gated per core/CLAUDE.md's discipline (appended,
        // never interleaved with Warden's existing behavior): a Warden
        // deployment keeps this exact pre-existing bypass unchanged.
        return 0; // Admin session is completely bypassed for non-injected files (Warden only)!
    }

    // Check if the process is absolutely trusted
    uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &leader_key);
    if (trusted && *trusted == 1)
        return 0;

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode && *mode == 1);

    if (blocking_enabled) {
        struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
        if (dentry) {
            struct qstr d_name = BPF_CORE_READ(dentry, d_name);
            char filename[64] = {0};
            bpf_probe_read_kernel_str(filename, sizeof(filename), d_name.name);

            // Rule 2: UNIX Socket Protection (Warden's docker.sock/containerd.sock
            // mount-escape defense - see core/CLAUDE.md's shared-hook discipline
            // and the MODE AUDIT precedent on is_container_restricted() in
            // kinnector_helpers.h, which this rule predates and was missed by).
            // Antitheft is a single-user consumer product with no notion of
            // "restricted container namespace" - this whole rule is Warden-only.
            //
            // Bug fixed alongside the gate: both checks compared only the first
            // 11/15 characters with no terminator check, so "docker.socket" (a
            // systemd unit's cgroup directory name, unrelated to the real
            // /var/run/docker.sock) and anything else merely PREFIXED by
            // "docker.sock"/"containerd.sock" matched too. Found live: a real
            // `snap run` denied snap-update-ns's cgroup walk with EACCES on
            // /sys/fs/cgroup/system.slice/docker.socket, 100% reproducible
            // immediately after a fresh `snap install`, under antitheft mode -
            // this rule should never have been reachable there at all.
            if (!is_antitheft_mode()) {
                if ((filename[0] == 'd' && filename[1] == 'o' && filename[2] == 'c' && filename[3] == 'k' && filename[4] == 'e' && filename[5] == 'r' && filename[6] == '.' && filename[7] == 's' && filename[8] == 'o' && filename[9] == 'c' && filename[10] == 'k' && filename[11] == '\0') ||
                    (filename[0] == 'c' && filename[1] == 'o' && filename[2] == 'n' && filename[3] == 't' && filename[4] == 'a' && filename[5] == 'i' && filename[6] == 'n' && filename[7] == 'e' && filename[8] == 'r' && filename[9] == 'd' && filename[10] == '.' && filename[11] == 's' && filename[12] == 'o' && filename[13] == 'c' && filename[14] == 'k' && filename[15] == '\0')) {
                    return -EACCES;
                }
            }

            // Rule 3: Container Escape Block
            uint32_t host_mnt_ns_idx = CONFIG_HOST_MNT_NS;
            uint32_t *host_mnt_ns = bpf_map_lookup_elem(&config_map, &host_mnt_ns_idx);
            if (host_mnt_ns && *host_mnt_ns > 0) {
                uint32_t current_mnt_ns = get_current_mnt_ns_inum();
                if (current_mnt_ns != *host_mnt_ns) {
                    if (opening_for_write) {
                        if ((filename[0] == 'r' && filename[1] == 'u' && filename[2] == 'n' && filename[3] == 'c' && filename[4] == '\0') ||
                            (filename[0] == 'c' && filename[1] == 'o' && filename[2] == 'n' && filename[3] == 't' && filename[4] == 'a' && filename[5] == 'i' && filename[6] == 'n' && filename[7] == 'e' && filename[8] == 'r' && filename[9] == 'd' && filename[10] == '-' && filename[11] == 's' && filename[12] == 'h' && filename[13] == 'i' && filename[14] == 'm' && filename[15] == '\0')) {
                            return -EACCES; // Block escape write!
                        }
                    }
                }
            }

            uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &leader_key);
            bool is_install = is_install_session();
            if ((threshold && *threshold > 0) || is_install) {
                // 1. Block .git reads unconditionally for all monitored processes (including daemon and forks)
                if (is_git_file(filename)) {
                    return -EACCES;
                }

                // 2. Block spawned subprocesses (untrusted) or install context from reading .env*
                if ((threshold && *threshold == 1) || is_install) {
                    if (is_env_file(filename)) {
                        return -EACCES;
                    }
                }

                // 2. Persistent Boot-Read Rule: allow reading .env exactly once during bootstrap
                if (is_env_file(filename)) {
                    uint32_t pid = key.pid;
                    uint8_t *count = bpf_map_lookup_elem(&env_read_count_map, &pid);
                    if (count) {
                        if (*count >= 1) {
                            return -EACCES;
                        }
                    } else {
                        uint8_t one = 1;
                        bpf_map_update_elem(&env_read_count_map, &pid, &one, BPF_ANY);
                    }
                }
            }
        }
    }

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    uint64_t ino = BPF_CORE_READ(inode, i_ino);
    struct resource_id res_id = make_resource_id(inode); // Phase 6: canonical (dev, ino) identity

    // 1. Procfs, input device and uinput protection (synchronous vetoes)
    if (blocking_enabled) {
        struct path f_path = BPF_CORE_READ(file, f_path);
        struct dentry *dentry = f_path.dentry;
        if (dentry) {
            struct qstr d_name = BPF_CORE_READ(dentry, d_name);
            char filename[32] = {0};
            bpf_probe_read_kernel_str(filename, sizeof(filename), d_name.name);

            struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
            char parent_name[32] = {0};
            if (parent) {
                struct qstr p_name = BPF_CORE_READ(parent, d_name);
                bpf_probe_read_kernel_str(parent_name, sizeof(parent_name), p_name.name);
            }

            bool is_blocked_dev = false;
            // Check for /dev/input/event*
            if (parent_name[0] == 'i' && parent_name[1] == 'n' && parent_name[2] == 'p' && parent_name[3] == 'u' && parent_name[4] == 't' && parent_name[5] == '\0') {
                if (filename[0] == 'e' && filename[1] == 'v' && filename[2] == 'e' && filename[3] == 'n' && filename[4] == 't') {
                    is_blocked_dev = true;
                }
            }
            // Check for /dev/uinput
            else if (filename[0] == 'u' && filename[1] == 'i' && filename[2] == 'n' && filename[3] == 'p' && filename[4] == 'u' && filename[5] == 't' && filename[6] == '\0') {
                is_blocked_dev = true;
            }
            // Check for /proc/<pid>/mem (writes and reads)
            else if (filename[0] == 'm' && filename[1] == 'e' && filename[2] == 'm' && filename[3] == '\0') {
                if (parent_name[0] >= '0' && parent_name[0] <= '9') {
                    // this branch
                    // already blocked monitored processes from opening
                    // /proc/<pid>/mem but never resolved which pid was the
                    // target and emitted no telemetry at all - blunt
                    // enforcement, zero data. Parse parent_name's ASCII
                    // digits into a real target pid (bounded 10-digit
                    // accumulation, same style as this file's other
                    // digit-parsing loops) and emit unconditionally,
                    // regardless of whether the -EACCES below fires - the
                    // existing block condition is untouched.
                    uint32_t target_pid = 0;
                    #pragma unroll
                    for (int i = 0; i < 10; i++) {
                        char c = parent_name[i];
                        if (c == '\0') break;
                        if (c >= '0' && c <= '9') {
                            target_pid = target_pid * 10 + (c - '0');
                        } else {
                            break;
                        }
                    }

                    struct TelemetryEvent *mem_event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
                    if (mem_event) {
                        fill_header(mem_event, EVT_CROSS_MEMORY_ACCESS, SRC_BPF_LSM, key.pid);
                        mem_event->details.cross_memory_access.target_pid = target_pid;
                        // 2=/proc/<pid>/mem read, 3=/proc/<pid>/mem write
                        mem_event->details.cross_memory_access.direction = opening_for_write ? 3 : 2;
                        bpf_ringbuf_submit(mem_event, 0);
                    }

                    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &leader_key);
                    bool is_install_proc = is_install_session();
                    if ((threshold && *threshold > 0) || is_install_proc) {
                        return -EACCES; // Block monitored processes from accessing procfs memory files!
                    }
                }
            }

            if (is_blocked_dev) {
                uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &leader_key);
                bool is_install_proc = is_install_session();
                if ((threshold && *threshold == 1) || is_install_proc) {
                    return -EACCES; // Block synchronously!
                }
            }
        }
    }

    // Supply-chain defense: anything a package manager FORKED during an
    // install (depth >= PKG_LIFECYCLE_DESCENDANT). The package manager
    // itself, depth 1, is exempt on purpose - see pkg_lifecycle_pids' own
    // doc: it has to write the unit files it unpacks and read its own
    // registry credentials, and the ordinary owner rules below still apply
    // to it. Checked before the sensitive-resource early-return below,
    // because a persistence directory is not a protected secret and would
    // otherwise never be reached.
    //
    // Group-leader keyed for the same reason every other per-process lookup
    // is - see get_current_group_leader_key().
    if (is_antitheft_mode() && blocking_enabled) {
        // Residual-gap close #2: deny writing the daemon's own
        // binary or .bpf.o (core_self_integrity_map, see its doc in
        // kinnector_maps.h) unless the writer IS the package manager itself
        // (pkg_lifecycle depth == PKG_LIFECYCLE_ROOT) - a lifecycle script
        // it forked (depth >= PKG_LIFECYCLE_DESCENDANT) does not qualify,
        // matching the file's own "package manager itself is exempt on
        // purpose" reasoning just below, not a new legitimacy rule. Checked
        // ahead of the persistence/credential logic below since it's a
        // separate protected identity, not a persistence directory or a
        // sensitive_inodes_map entry. leader_key is reused, not recomputed -
        // this hook already derived it above via
        // get_current_group_leader_key() for the fork-propagated lookups.
        if (opening_for_write) {
            // Manually unrolled, not a loop - only 2 slots exist
            // (core_self_integrity_map's max_entries), and clang's
            // #pragma unroll declined to unroll a bpf_map_lookup_elem-
            // bearing loop here anyway (benign warning, but this hook lives
            // inside an already-large file_open, and this codebase has a
            // documented history of a single extra insn tipping a program
            // into -E2BIG on some kernels - see bprm_verifier_complexity_
            // limit in project history - so straight-line code beats
            // relying on the verifier's bounded-loop support here).
            bool self_write_denied = false;
            {
                uint32_t si0 = 0;
                struct resource_id *pid0 = bpf_map_lookup_elem(&core_self_integrity_map, &si0);
                uint32_t si1 = 1;
                struct resource_id *pid1 = bpf_map_lookup_elem(&core_self_integrity_map, &si1);
                bool matched = (pid0 && pid0->dev && pid0->ino && pid0->dev == res_id.dev && pid0->ino == res_id.ino) ||
                               (pid1 && pid1->dev && pid1->ino && pid1->dev == res_id.dev && pid1->ino == res_id.ino);
                if (matched) {
                    uint8_t *pm_v = bpf_map_lookup_elem(&pkg_lifecycle_pids, &leader_key);
                    bool is_pkg_manager_root = pm_v && ((*pm_v & PKG_LIFECYCLE_DEPTH_MASK) == PKG_LIFECYCLE_ROOT);
                    self_write_denied = !is_pkg_manager_root;
                }
            }
            if (self_write_denied) {
                return -EPERM;
            }
        }

        struct process_key pkg_key = get_current_group_leader_key();
        uint8_t *in_install = bpf_map_lookup_elem(&pkg_lifecycle_pids, &pkg_key);
        if (in_install && (*in_install & PKG_LIFECYCLE_DEPTH_MASK) >= PKG_LIFECYCLE_DESCENDANT) {
            // Persistence write: opening for write a file that sits in a
            // registered drop dir (autostart, unit dirs, cron.d) or IS a
            // registered append-file (~/.bashrc, /etc/crontab). An install
            // script has no legitimate reason to touch either. Every other
            // way of putting a name there - create, mkdir, rename, link,
            // symlink, unlink - is refused by the sibling hooks below on
            // the same is_persistence_target() predicate.
            if (opening_for_write) {
                struct dentry *pd = BPF_CORE_READ(file, f_path.dentry);
                struct dentry *parent_d = pd ? BPF_CORE_READ(pd, d_parent) : NULL;
                struct inode *parent_i = parent_d ? BPF_CORE_READ(parent_d, d_inode) : NULL;
                struct resource_id parent_id = {0};
                if (is_persistence_target(parent_i, pd, &parent_id)) {
                    int distro = (*in_install & PKG_LIFECYCLE_DISTRO) != 0;
                    emit_persistence_deny(parent_id, pd, key.pid, distro ? 6 : 5, *in_install, KINN_PERSIST_OP_WRITE);
                    if (!distro) return -EACCES;
                }
            }
            // Credential access: any LOCKED store, not merely one this
            // process could claim to own. Ownership of the store is
            // irrelevant here - the package manager may well be a registered
            // owner of something, and that is exactly the standing a
            // malicious lifecycle script would otherwise inherit.
            //
            // LOCKED means the agent registered an owner set for it
            // (resource_owner_map has an entry: its corpus policy is
            // effectively deny), the same "is a store" test
            // protected_store_dir_of uses. An OBSERVED store (audit policy, or
            // a deny store with no owner on this machine) is in
            // sensitive_inodes_map for visibility only, with no owner set, and
            // is NOT refused here: legitimate
            // installs read SSH keys (git+ssh deps, private submodules), cloud
            // CLI credentials (private registries, credential providers run
            // from hooks), .npmrc/.netrc and .env files. Such an open falls
            // through to the ordinary path below, whose verdict=1
            // EVT_FILE_OPEN records it (the agent attributes it to the
            // install). Before this, every sensitive_inodes_map entry was
            // refused, audit-only included.
            uint32_t *pkg_category = bpf_map_lookup_elem(&sensitive_inodes_map, &res_id);
            if (pkg_category && !bpf_map_lookup_elem(&resource_owner_map, &res_id))
                pkg_category = NULL; // observed, not locked: allowed and recorded below
            // Credential-helper exemption, gated on an UNBROKEN CHAIN of
            // helpers from the package manager rather than on fork depth.
            //
            // The old rule was "depth exactly 2", which was wrong in both
            // directions. Too permissive: `exec` keeps the process, so a
            // lifecycle script at depth 2 running `exec gh` presented gh as
            // its current image and was allowed - measured. Too strict: a
            // real private HTTPS fetch is `git`(2) -> `git-remote-https`(3)
            // -> `git-credential-*`(4), and depths 3 and 4 were refused the
            // credential the fetch exists to use.
            //
            // PKG_LIFECYCLE_RAN_OTHER_CODE is set at exec the moment anything
            // that is not a helper or a manager runs in the process, and is
            // inherited across fork, so it is exactly "arbitrary code has run
            // somewhere between the package manager and here". Requiring it
            // clear AND the current image to be a helper allows the whole
            // legitimate fetch chain at any depth and denies the script.
            if (pkg_category && !(*in_install & PKG_LIFECYCLE_RAN_OTHER_CODE)) {
                struct task_struct *ct = (struct task_struct *)bpf_get_current_task();
                struct mm_struct *cmm = ct ? BPF_CORE_READ(ct, mm) : NULL;
                struct file *cexe = cmm ? BPF_CORE_READ(cmm, exe_file) : NULL;
                struct inode *cino = cexe ? BPF_CORE_READ(cexe, f_inode) : NULL;
                if (cino) {
                    struct resource_id helper_id = make_resource_id(cino);
                    uint8_t *is_helper = bpf_map_lookup_elem(&credential_helper_images, &helper_id);
                    if (is_helper && *is_helper == 1)
                        pkg_category = NULL; // authenticating the fetch, not reading secrets
                }
            }
            if (pkg_category) {
                // A real deny - see the EVT_FILE_READ wire contract at the
                // success-path emission near the end of this function: in
                // antitheft mode this event type means DENIED and nothing
                // else, so it must stay paired with the -EACCES below.
                struct TelemetryEvent *ev = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
                if (ev) {
                    fill_header(ev, EVT_FILE_READ, SRC_BPF_LSM, key.pid);
                    ev->details.file_read.bytes_requested = 0;
                    ev->details.file_read.zone_id = 0;
                    KINN_D_PATH(&file->f_path, ev->details.file_read.file_path,
                               sizeof(ev->details.file_read.file_path));
                    bpf_ringbuf_submit(ev, 0);
                }
                return -EACCES;
            }
        }
    }

    // 2. Sensitive files protection
    uint32_t *category = bpf_map_lookup_elem(&sensitive_inodes_map, &res_id);
    if (!category && is_antitheft_mode()) {
        // A file inside a folder-shaped store is judged as that folder, and reported as it (the
        // event's path stays the file's): see protected_store_dir_of.
        struct resource_id store_id = {0};
        if (protected_store_dir_of(file, &store_id)) {
            res_id = store_id;
            category = bpf_map_lookup_elem(&sensitive_inodes_map, &res_id);
        }
    }
    if (!category)
        return 0;

    // Check if the process threshold is 1 (Untrusted) or in install context
    if (blocking_enabled) {
        uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &leader_key);
        bool is_install_proc = is_install_session();
        if ((threshold && *threshold == 1) || is_install_proc) {
            // Emit blocked event first. A real deny - see the EVT_FILE_READ
            // wire contract at the success-path emission near the end of
            // this function: in antitheft mode this event type means DENIED
            // and nothing else, so it must stay paired with the -EACCES
            // below.
            struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
            if (event) {
                fill_header(event, EVT_FILE_READ, SRC_BPF_LSM, key.pid);
                event->details.file_read.bytes_requested = 0;
                event->details.file_read.zone_id = 0;
                // full path via
                // bpf_d_path instead of the dentry leaf name - producer-side
                // only, zero ABI change (file_path already has 512 bytes).
                KINN_D_PATH(&file->f_path, event->details.file_read.file_path,
                           sizeof(event->details.file_read.file_path));
                bpf_ringbuf_submit(event, 0);
            }
            return -EACCES; // Block synchronously!
        }
    }

    // Antitheft-only owner-allowlist enforcement,
    // appended after Warden's existing threshold-based deny above, never interleaved
    // with it. A MODE_WARDEN deployment never calls is_antitheft_mode() true, so its
    // file_open behavior for sensitive-category files is byte-for-byte unchanged.
    //
    // Runtime-revocation plan: combined into a single is_owner/revoked evaluation
    // (was two separate is_resource_owner() calls, one per branch) so a userspace-
    // pushed revocation - a registered owner whose runtime integrity failed (see
    // revoked_pid_map's declaration comment) - denies even though the static
    // owner-allowlist check alone would still allow. Known, accepted, out-of-scope
    // gap: the admin-session block above (is_admin_session() && !is_install_session())
    // returns before this point is ever reached for most opens, so an admin-session
    // process bypasses both the static owner-allowlist and this revocation check
    // today - unchanged pre-existing behavior, not something this plan fixes.
    bool is_owner = is_resource_owner(res_id);
    // Group-leader-keyed lookup, not plain key - see
    // get_current_group_leader_key()'s doc. revoked_pid_map entries are
    // written from ProcessCreateDetails::child_start_time (a process-level,
    // exec-time fact) or a telemetry event's own target_start_time (also
    // resolved via the kernel's own group-leader-equivalent lookup for
    // whichever hook captured it) - a plain get_current_process_key() read
    // here would use whichever THREAD of the process happens to be issuing
    // this specific open(), which silently never matches for any
    // multi-threaded process. Found live: a genuinely revoked test process
    // kept reading successfully because of exactly this mismatch.
    struct process_key revoked_key = get_current_group_leader_key();
    uint32_t *revoked_flags = bpf_map_lookup_elem(&revoked_pid_map, &revoked_key);
    bool revoked = is_antitheft_mode() && revoked_flags && *revoked_flags != 0;
    // Telemetry: this used to gate the deny
    // EVENT on `blocking_enabled` together with the deny ACTION below, so a
    // paused agent emitted no EVT_FILE_OPEN at all, denied or
    // allowed: the cloud's whole StorageAccess pipeline (`secrets.read`
    // included) saw zero access events, ever, while paused. Telemetry must be
    // unconditional in antitheft mode; only the -EACCES return (the actual
    // enforcement) may depend on `blocking_enabled`. `is_owner`/`revoked`
    // themselves never depend on it either (resource_owner_map is populated
    // at agent startup/reconcile regardless of pause), so this event is
    // exactly as accurate paused as armed.
    if (is_antitheft_mode() && (!is_owner || revoked)) {
        struct TelemetryEvent *deny_event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
        if (deny_event) {
            fill_header(deny_event, EVT_FILE_OPEN, SRC_BPF_LSM, key.pid);
            kinn_file_open_actor(&deny_event->details.file_open);
            deny_event->details.file_open.resource_dev = res_id.dev;
            deny_event->details.file_open.resource_ino = res_id.ino;
            deny_event->details.file_open.verdict = revoked ? 3 : 2; // 3=denied(revoked), 2=denied(not an owner)
            deny_event->details.file_open.access_mode = kinn_open_access(file);
            KINN_D_PATH(&file->f_path, deny_event->details.file_open.file_path,
                       sizeof(deny_event->details.file_open.file_path));
            bpf_ringbuf_submit(deny_event, 0);
        }
        if (blocking_enabled) {
            return -EACCES; // Refused before it completes: not a configured owner, or a revoked one.
        }
    }

    // Symmetric antitheft-only signal for the allowed case (recognized
    // owner, not revoked) - same resource identity, verdict=1, so userspace
    // can build a full picture of storage access, not just denials. Appended
    // after the deny branch above, same gating discipline, never interleaved
    // with Warden's shared block below. Unconditional on `blocking_enabled`
    // for the same telemetry-vs-action reason as the deny branch above: this
    // emission was never an enforcement action (it has no -EACCES return to
    // begin with), so it never needed the pause gate it was wrongly sharing.
    //
    // Self-noise exemption (see CONFIG_OWN_PID's own comment):
    // antitheftd reading a resource it protects (fanotify's internal
    // dentry_open re-read after a write, chiefly) is never itself a
    // security-relevant event - the actor and the protector are the same
    // process - but was consuming real ring-buffer bandwidth on every
    // occurrence, live-confirmed to starve the DENY branch above under real
    // load. Skips ONLY this ALLOWED emission; the deny branch is untouched.
    uint32_t own_pid_idx = CONFIG_OWN_PID;
    uint32_t *own_pid = bpf_map_lookup_elem(&config_map, &own_pid_idx);
    bool is_self = own_pid && *own_pid == key.pid;
    if (is_antitheft_mode() && is_owner && !revoked && !is_self) {
        struct TelemetryEvent *allow_event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
        if (allow_event) {
            fill_header(allow_event, EVT_FILE_OPEN, SRC_BPF_LSM, key.pid);
            kinn_file_open_actor(&allow_event->details.file_open);
            allow_event->details.file_open.resource_dev = res_id.dev;
            allow_event->details.file_open.resource_ino = res_id.ino;
            allow_event->details.file_open.verdict = 1; // allowed
            // Read or write (antitheft-cloud contract v12): an audit-only
            // locator reaches the agent through THIS branch for any actor,
            // so without the mode `aws configure` writing its own
            // credentials read as a credential read.
            allow_event->details.file_open.access_mode = kinn_open_access(file);
            KINN_D_PATH(&file->f_path, allow_event->details.file_open.file_path,
                       sizeof(allow_event->details.file_open.file_path));
            bpf_ringbuf_submit(allow_event, 0);
        }
    }

    uint32_t *flags = bpf_map_lookup_elem(&category_flags_map, &key);
    if (flags) {
        uint32_t new_flags = *flags | *category;
        bpf_map_update_elem(&category_flags_map, &key, &new_flags, BPF_ANY);
    } else {
        uint32_t new_flags = *category;
        bpf_map_update_elem(&category_flags_map, &key, &new_flags, BPF_ANY);
    }

    // Emit event to ring buffer for user-space heuristics state tracking.
    //
    // WIRE CONTRACT (found live): in antitheft mode an
    // EVT_FILE_READ from SRC_BPF_LSM means DENIED, and nothing else.
    // FileReadDetails has no verdict field - it carries only a path - so a
    // consumer cannot tell this success-path emission apart from the two
    // real deny sites above (the pkg-lifecycle credential deny and the
    // process-threshold/install-session deny), both of which return -EACCES
    // right after emitting the identical event shape. antitheftd's
    // handle_file_read_event therefore labels every one of them Denied,
    // which was correct for the deny sites and wrong for this one: a
    // legitimate owner's ALLOWED open emitted verdict=1 EVT_FILE_OPEN here
    // and then this event microseconds later, so the agent logged one
    // phantom "denied" alert per successful read of every protected
    // resource. Measured on one real session's alerts.log: 988 of 1080
    // "denied" records were this phantom, including essentially all of the
    // wallet-extension-storage denials that a previous session
    // mis-diagnosed as a Chrome sandbox identity failure. Verified live:
    // `gh auth status` exits 0 - the read succeeded - while logging
    // allowed+denied 3us apart on the same file.
    //
    // So this is gated off for antitheft, which has no other consumer of
    // EVT_FILE_READ: the allowed case is already reported, with resolved
    // resource identity, by the verdict=1 EVT_FILE_OPEN emission a few
    // dozen lines above. Warden's own heuristics feed is untouched -
    // is_antitheft_mode() is false for every Warden deployment - the same
    // gating discipline the rest of this file's antitheft work follows.
    // Removing it here also drops one ring-buffer emission per open of
    // every sensitive inode in antitheft mode, which is the same
    // starvation class the alert-visibility audit fought.
    if (!is_antitheft_mode()) {
        struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
        if (event) {
            fill_header(event, EVT_FILE_READ, SRC_BPF_LSM, key.pid);
            event->details.file_read.bytes_requested = 0;
            event->details.file_read.zone_id = 0;
            KINN_D_PATH(&file->f_path, event->details.file_read.file_path,
                       sizeof(event->details.file_read.file_path));
            bpf_ringbuf_submit(event, 0);
        }
    }

    if (is_install_session() || is_admin_session()) {
        struct inode *inode = BPF_CORE_READ(file, f_inode);
        if (inode) {
            uint64_t ino = BPF_CORE_READ(inode, i_ino);
            record_and_batch_event(1, file, ino, NULL); // 1 = READ
        }
    }

    return 0;
}

// P2-8: lsm/file_permission — emit FileWrite events for web-root write detection (M-13 fix)
SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask) {
#define MAY_WRITE 0x2
    if (!(mask & MAY_WRITE))
        return 0;

    if (!file)
        return 0;

    // Group-leader-keyed: trusted_ancestor_roots/process_threshold_map are
    // fork-propagated on the leader's start_time (get_current_group_leader_key()'s
    // doc) - a plain thread key silently misses a worker thread's own process
    // entry. key.pid (used below for telemetry only) is identical either way.
    struct process_key key = get_current_group_leader_key();

    uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
    if (trusted && *trusted == 1)
        return 0;

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode && *mode == 1);

    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);

    if (blocking_enabled) {
        struct inode *inode = BPF_CORE_READ(file, f_inode);
        if (inode) {
            struct resource_id res_id = make_resource_id(inode); // Phase 6
            uint8_t *is_protected = bpf_map_lookup_elem(&protected_static_inodes, &res_id);
            if (is_protected && *is_protected == 1) {
                if (threshold && *threshold > 0) {
                    return -EACCES; // Block writing to pre-existing static web-root/config files!
                }
            }

            // Antitheft-only owner-allowlist
            // enforcement, appended after Warden's existing protected_static_inodes
            // deny above, never interleaved with it — a MODE_WARDEN deployment never
            // calls is_antitheft_mode() true, so its file_permission behavior is
            // byte-for-byte unchanged. Independent of protected_static_inodes: a
            // resource can be owner-tracked (e.g. a wallet file) without being one
            // of Warden's web-root files.
            //
            // Runtime-revocation plan: same combined is_owner/revoked evaluation
            // as file_open's antitheft branch - kept in sync deliberately, see
            // that branch's comment for the full rationale and the accepted
            // admin-session-bypass gap.
            //
            // REAL BUG FOUND AND FIXED via live-root testing (two iterations
            // to get the fix's scope right - see
            // [[antitheft_runtime_revocation_design_feedback]] for the full
            // live-root investigation). `revoked_pid_map`, unlike
            // resource_owner_map, is keyed ONLY by process identity
            // (pid, start_time) - not by (resource, process). The
            // pre-existing `!perm_is_owner`-only check was safe with no
            // extra gate purely by luck: is_resource_owner() already
            // defaults to "allow" (returns 1) for any res_id with no
            // resource_owner_map entry, so an unregistered file never denied
            // on that condition alone - so that check is left exactly as it
            // was (an earlier fix attempt that gated it behind
            // sensitive_inodes_map too was a real regression: it broke the
            // pre-existing write-deny path for resources that are
            // resource_owner_map-tracked but were never separately
            // registered via add_sensitive_inode, which e2e's own write-deny
            // test case exercises). `perm_revoked`, being PID-only-scoped,
            // has no equivalent built-in safety - gated it explicitly behind
            // "is this resource actually tracked in resource_owner_map at
            // all" (a real map lookup, not is_resource_owner()'s bool
            // return, which can't distinguish "untracked, defaulted true"
            // from "tracked and this process satisfies it"). Without this,
            // a revoked pid got EACCES on every write to every file it
            // touched - stdout/stderr included, not just owned resources -
            // confirmed live: a revoked test process's own `println!` calls
            // started failing, cascading into a permanent process-level hang
            // well outside file I/O.
            bool perm_is_owner = is_resource_owner(res_id);
            uint64_t *perm_owner_mask = bpf_map_lookup_elem(&resource_owner_map, &res_id);
            // Group-leader-keyed, not plain key - same reasoning as
            // file_open's revoked_key above (kept in sync deliberately).
            struct process_key perm_revoked_key = get_current_group_leader_key();
            uint32_t *perm_revoked_flags = perm_owner_mask ? bpf_map_lookup_elem(&revoked_pid_map, &perm_revoked_key) : NULL;
            bool perm_revoked = perm_owner_mask && is_antitheft_mode() && perm_revoked_flags && *perm_revoked_flags != 0;
            if (is_antitheft_mode() && (!perm_is_owner || perm_revoked)) {
                // Same resource-identity signal as file_open's deny branch -
                // an unauthorized *write* attempt (tamper/"hijack" of a
                // protected resource, not just a read) deserves the same
                // attribution, and today this path emitted nothing at all.
                struct TelemetryEvent *deny_event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
                if (deny_event) {
                    fill_header(deny_event, EVT_FILE_OPEN, SRC_BPF_LSM, key.pid);
                    kinn_file_open_actor(&deny_event->details.file_open);
                    deny_event->details.file_open.resource_dev = res_id.dev;
                    deny_event->details.file_open.resource_ino = res_id.ino;
                    deny_event->details.file_open.verdict = perm_revoked ? 3 : 2; // 3=denied(revoked), 2=denied(not an owner)
                    deny_event->details.file_open.access_mode = KINN_OPEN_KNOWN | KINN_OPEN_WRITE; // only MAY_WRITE reaches here
                    // Phase 10's bpf_d_path fix does NOT apply in
                    // file_permission - real verifier rejection ("helper
                    // call is not allowed in probe"), see
                    // record_and_batch_event's comment for the full story.
                    struct qstr d_name;
                    bpf_probe_read_kernel(&d_name, sizeof(d_name), &BPF_CORE_READ(file, f_path.dentry)->d_name);
                    bpf_probe_read_kernel_str(&deny_event->details.file_open.file_path,
                                              sizeof(deny_event->details.file_open.file_path), d_name.name);
                    bpf_ringbuf_submit(deny_event, 0);
                }
                return -EACCES; // Refused before it completes: not a configured owner of this resource.
            }
        }

        // Storage-dir write protection (universal - no corpus
        // data): a `.so`-named write into a directory ownership.rs has
        // registered as a protected storage dir is denied unless the
        // writer is a recognized owner of that directory - independent of
        // whether the FILE ITSELF is individually tracked as a resource
        // (most `.so` files never are, only the handful of files a corpus
        // locator names directly). Deliberately narrow to `.so`-shaped
        // names, so ordinary writes inside a storage dir (cookies, login
        // data, cache files) are completely unaffected. See
        // storage_dir_verdict()'s own doc for the nearest-ancestor-wins
        // rule that keeps this from leaking across sibling apps' dirs.
        if (is_antitheft_mode()) {
            struct dentry *file_dentry = BPF_CORE_READ(file, f_path.dentry);
            if (file_dentry && dentry_name_has_so_extension(file_dentry)) {
                int dir_verdict = storage_dir_verdict(file_dentry);
                if (dir_verdict == 0) {
                    struct TelemetryEvent *dir_deny = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
                    if (dir_deny) {
                        fill_header(dir_deny, EVT_FILE_OPEN, SRC_BPF_LSM, key.pid);
                        kinn_file_open_actor(&dir_deny->details.file_open);
                        dir_deny->details.file_open.resource_dev = 0;
                        dir_deny->details.file_open.resource_ino = 0;
                        dir_deny->details.file_open.verdict = 4; // 4=denied(storage-dir .so write, not an owner)
                        dir_deny->details.file_open.access_mode = KINN_OPEN_KNOWN | KINN_OPEN_WRITE;
                        struct qstr d_name;
                        bpf_probe_read_kernel(&d_name, sizeof(d_name), &BPF_CORE_READ(file, f_path.dentry)->d_name);
                        bpf_probe_read_kernel_str(&dir_deny->details.file_open.file_path,
                                                  sizeof(dir_deny->details.file_open.file_path), d_name.name);
                        bpf_ringbuf_submit(dir_deny, 0);
                    }
                    return -EACCES; // Refused before it completes: not a recognized owner of this storage dir.
                }
            }
        }
    }

    // Alert-visibility audit, root-caused via direct Rust-side
    // throughput measurement after every other ring-buffer-pressure
    // hypothesis (capacity, self-noise, orphaned programs, leaks) was tested
    // and ruled out: this whole tail - general write telemetry plus its
    // DB-bypass/newly-created-inode bookkeeping - is Warden's own feature
    // ("P2-8: emit FileWrite events for web-root write detection"),
    // unconditional for every write(2) syscall on the entire machine
    // (nothing below gated it on deployment_mode), yet none of it is
    // antitheft-owned: `lib.rs`'s FileWrite handler explicitly processes
    // only the FANOTIFY-sourced copy of this event for its own resource-
    // swap-defense triggers (see that handler's own comment on why -
    // this SRC_BPF_LSM copy carries only a leaf filename), so every one of
    // these emissions was decoded, discarded, and gone. Measured live: on
    // this one real, ordinarily-busy desktop (browser + IDE + containers +
    // a VM), this single site alone produced this event type at ~200,000/s
    // - sustained, not bursty - which at 1606 bytes/event is roughly
    // 320 MB/s of production against ANY ring buffer capacity, permanently
    // starving the antitheft owner-check's own rare, high-value deny
    // emission a few dozen lines above (which DOES stay active - this gate
    // sits strictly after that block closes) of the reservation space it
    // needed. A MODE_WARDEN deployment (a server protecting a web root,
    // where write volume is the exception, not the norm this hook was
    // silently assuming) is completely unaffected by this gate.
    if (!is_antitheft_mode()) {
        // DB bypass: suppress write telemetry for DB processes writing to
        // their own data directories. Guard: only skip if this process
        // carries ROLE_DATABASE.
        if (threshold && (*threshold & ROLE_DATABASE)) {
            struct path f_path = BPF_CORE_READ(file, f_path);
            struct dentry *dentry = f_path.dentry;
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                if (!dentry) break;
                struct inode *dir_inode = BPF_CORE_READ(dentry, d_inode);
                if (dir_inode) {
                    struct resource_id dir_id = make_resource_id(dir_inode); // Phase 6
                    uint8_t *bypass = bpf_map_lookup_elem(&bypassed_directories, &dir_id);
                    if (bypass && *bypass == 1)
                        return 0;
                }
                dentry = BPF_CORE_READ(dentry, d_parent);
            }
        }

        if (threshold && *threshold > 0) {
            struct inode *inode = BPF_CORE_READ(file, f_inode);
            if (inode) {
                struct resource_id new_id = make_resource_id(inode); // Phase 6
                uint8_t val = 1;
                bpf_map_update_elem(&newly_created_inodes, &new_id, &val, BPF_ANY);
            }
        }

        struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
        if (event) {
            fill_header(event, EVT_FILE_WRITE, SRC_BPF_LSM, key.pid);
            event->details.file_write.bytes_written = 0;
            // Phase 10's bpf_d_path fix does NOT apply in file_permission - real
            // verifier rejection ("helper call is not allowed in probe"), see
            // record_and_batch_event's comment for the full story.
            struct qstr d_name;
            bpf_probe_read_kernel(&d_name, sizeof(d_name), &BPF_CORE_READ(file, f_path.dentry)->d_name);
            bpf_probe_read_kernel_str(&event->details.file_write.file_path,
                                      sizeof(event->details.file_write.file_path), d_name.name);
            bpf_ringbuf_submit(event, 0);
        }

        if (is_install_session() || is_admin_session()) {
            struct inode *inode = BPF_CORE_READ(file, f_inode);
            if (inode) {
                uint64_t ino = BPF_CORE_READ(inode, i_ino);
                record_and_batch_event(2, file, ino, NULL); // 2 = WRITE
            }
        }
    }

    return 0;
}

// B-07 fix: lsm/socket_connect — extract actual IP from sockaddr_in/in6 (not hardcoded)
SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    unsigned short family = 0;
    if (address) {
        bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
    }
    if (family != 1 && family != 2 && family != 10) {
        return 0; // Only intercept Unix (AF_UNIX=1), IPv4 (AF_INET=2) and IPv6 (AF_INET6=10)
    }

    // Group-leader-keyed: trusted_ancestor_roots/process_threshold_map below
    // are fork-propagated on the leader's start_time (see
    // get_current_group_leader_key()'s doc); key.pid (telemetry/allowlist
    // keys only) is identical either way.
    struct process_key key = get_current_group_leader_key();

    // SSHD Pre-Auth Zero-Trust Lockdown:
    // If the process is running under the unprivileged sshd user's UID,
    // deny outbound network connection immediately.
    uint32_t current_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    uint32_t sshd_uid_key = CONFIG_SSHD_UID;
    uint32_t *sshd_uid = bpf_map_lookup_elem(&config_map, &sshd_uid_key);
    if (sshd_uid && *sshd_uid > 0 && current_uid == *sshd_uid) {
        return -EACCES;
    }

    // Bypass network blocking for admin sessions (unless it is an install context)
    if (is_admin_session() && !is_install_session()) {
        return 0;
    }

    uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
    if (trusted && *trusted == 1)
        return 0;

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode && *mode == 1);

    if (blocking_enabled) {
        uint16_t dest_port = 0;
        uint32_t dest_ip = 0;
        uint8_t dest_ip6[16] = {};
        if (family == 2) {
            struct sockaddr_in *sin = (struct sockaddr_in *)address;
            uint16_t port_be = 0;
            bpf_probe_read_kernel(&port_be, sizeof(port_be), &sin->sin_port);
            dest_port = ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
            bpf_probe_read_kernel(&dest_ip, sizeof(dest_ip), &sin->sin_addr.s_addr);
        } else if (family == 10) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
            uint16_t port_be = 0;
            bpf_probe_read_kernel(&port_be, sizeof(port_be), &sin6->sin6_port);
            dest_port = ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
            bpf_probe_read_kernel(dest_ip6, sizeof(dest_ip6), &sin6->sin6_addr.in6_u.u6_addr8);
        }

        // Rule 1: API Port Protection - Block external/public connections to Docker/Kubelet APIs
        if (dest_port == 2375 || dest_port == 2376 || dest_port == 10250 || dest_port == 10255) {
            if (family == 2 && !is_private_ip(dest_ip)) {
                return -EACCES;
            }
        }

        // Firewall rule store (warden/src/firewall) — explicit IP/CIDR DENY
        // rules and, budget-capped, resolved GeoIP country rules. Placed
        // before role-based sandboxing below so an explicit firewall DENY
        // is authoritative over a role ALLOW, matching every other check
        // in this function sitting downstream of the trust/admin bypasses
        // above but upstream of role logic.
        int fw_result = fw_check_egress(family, dest_ip, dest_ip6);
        if (fw_result != 0) {
            return fw_result;
        }
    }

    // Egress Port and Role Sandboxing:
    uint32_t *active_threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (active_threshold && blocking_enabled) {
        uint32_t thresh_val = *active_threshold;

        // Extract destination port & address for role-based/allowlist checks
        uint16_t dest_port = 0;
        uint32_t dest_ip = 0;
        if (family == 2) {
            struct sockaddr_in *sin = (struct sockaddr_in *)address;
            uint16_t port_be = 0;
            bpf_probe_read_kernel(&port_be, sizeof(port_be), &sin->sin_port);
            dest_port = ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
            bpf_probe_read_kernel(&dest_ip, sizeof(dest_ip), &sin->sin_addr.s_addr);
        } else if (family == 10) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
            uint16_t port_be = 0;
            bpf_probe_read_kernel(&port_be, sizeof(port_be), &sin6->sin6_port);
            dest_port = ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
        }

        // 1. PROFILE_ZERO_NETWORK: only allow loopback connect attempts (or DNS/NTP for ROLE_NTP_CLIENT)
        if (thresh_val & PROFILE_ZERO_NETWORK) {
            bool is_ntp_bypass = false;
            if ((thresh_val & ROLE_NTP_CLIENT) && (dest_port == 53 || dest_port == 123)) {
                is_ntp_bypass = true;
            }
            if (!is_ntp_bypass) {
                if (family == 2) { // AF_INET
                    struct sockaddr_in *sin = (struct sockaddr_in *)address;
                    uint32_t daddr = 0;
                    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sin->sin_addr.s_addr);
                    if (daddr != 0x0100007f) { // 127.0.0.1 in network byte order
                        return -EACCES;
                    }
                } else if (family == 10) { // AF_INET6
                    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
                    uint8_t addr6[16];
                    bpf_probe_read_kernel(addr6, sizeof(addr6), &sin6->sin6_addr.in6_u.u6_addr8);
                    bool is_loopback6 = true;
                    #pragma unroll
                    for (int i = 0; i < 15; i++) {
                        if (addr6[i] != 0) is_loopback6 = false;
                    }
                    if (addr6[15] != 1) is_loopback6 = false;
                    if (!is_loopback6) {
                        return -EACCES;
                    }
                }
            }
        }

        // 2. ROLE_MAIL_GATEWAY: Only allow DNS (53) and SMTP/S (25, 465, 587)
        if (thresh_val & ROLE_MAIL_GATEWAY) {
            if (family == 2 || family == 10) {
                if (dest_port != 53 && dest_port != 25 && dest_port != 465 && dest_port != 587) {
                    return -EACCES;
                }
            }
        }

        // 3. ROLE_QUEUE_MANAGER: Only allow cluster, management, and DNS ports
        if (thresh_val & ROLE_QUEUE_MANAGER) {
            if (family == 2 || family == 10) {
                if (dest_port != 53 && dest_port != 5672 && dest_port != 5671 && 
                    dest_port != 15672 && dest_port != 4369 && dest_port != 9092 && 
                    dest_port != 9093 && dest_port != 2181) {
                    return -EACCES;
                }
            }
        }

        // 4. ROLE_DATABASE: Only allow DNS (53) and approved replication/cluster peer IPs
        if (thresh_val & ROLE_DATABASE) {
            if (family == 2 || family == 10) {
                if (dest_port != 53) {
                    // Check db_outbound_allowlist
                    struct db_allowlist_key db_key = { key.pid, dest_ip };
                    uint8_t *allowed = bpf_map_lookup_elem(&db_outbound_allowlist, &db_key);
                    if (!allowed || *allowed != 1) {
                        return -EACCES; // Block replication / DB connection unless allowlisted!
                    }
                }
            }
        }

        // 5. General Infrastructure Egress check against infra_outbound_allowlist
        if (family == 2) {
            struct infra_allowlist_key infra_key = { key.pid, dest_ip };
            uint8_t *allowed_infra = bpf_map_lookup_elem(&infra_outbound_allowlist, &infra_key);
            if (allowed_infra && *allowed_infra != 1) {
                return -EACCES;
            }
        }
    }



    // Set PendingNetworkConnect flag in maps (for IPv4/IPv6 connections)
    if (family == 2 || family == 10) {
        uint32_t conn_active = 1;
        bpf_map_update_elem(&pending_network_connect, &key, &conn_active, BPF_ANY);
    }

    // 2. Synchronous network blocking for untrusted processes
    if ((family == 2 || family == 10) && blocking_enabled) {
        uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
        if (threshold && *threshold == 1) {
            if (!is_install_session()) {
                // Emit blocked event first
                struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
                if (event) {
                    fill_header(event, EVT_NETWORK_CONNECT, SRC_BPF_LSM, key.pid);
                    event->details.network_connect.destination_port = 0;
                    event->details.network_connect.destination_ip[0] = '\0';
                    event->details.network_connect.protocol[0] = '\0';
                    bpf_ringbuf_submit(event, 0);
                }
                return -EACCES; // Block connection synchronously!
            }
        }
    }

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_NETWORK_CONNECT, SRC_BPF_LSM, key.pid);

        if (family == 2) {
            // IPv4 — struct sockaddr_in: sa_family(2) + sin_port(2) + sin_addr(4)
            uint16_t port_be = 0;
            uint32_t addr_be = 0;
            bpf_probe_read_kernel(&port_be, sizeof(port_be), (char *)address + 2);
            bpf_probe_read_kernel(&addr_be, sizeof(addr_be), (char *)address + 4);

            // Convert port from big-endian
            event->details.network_connect.destination_port =
                ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);

            // ABI FIX: write a real dotted-decimal string here -
            // this field used to carry a marker-byte (0x04) + raw-address
            // binary encoding that no consumer actually parsed for THIS
            // event type (unlike NetworkAccept/DNSQuery below, whose
            // consumers already knew about and correctly decoded that
            // scheme - see format_ipv4_string's doc and this file's other
            // ABI FIX comments for the fuller story). Both
            // warden's and antitheft's NetworkConnect handlers already read
            // this field as a plain null-terminated string, matching
            // telemetry.h's own "support IPv6" comment - this fix makes the
            // producer actually honor that contract instead of the reader.
            uint8_t ip_buf[4];
            bpf_probe_read_kernel(ip_buf, sizeof(ip_buf), &addr_be);
            format_ipv4_string(event->details.network_connect.destination_ip, ip_buf);
        } else if (family == 10) {
            // IPv6 — struct sockaddr_in6: family(2) + port(2) + flowinfo(4) + addr(16)
            uint16_t port_be = 0;
            bpf_probe_read_kernel(&port_be, sizeof(port_be), (char *)address + 2);
            event->details.network_connect.destination_port =
                ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);

            uint8_t ip6_buf[16];
            bpf_probe_read_kernel(ip6_buf, sizeof(ip6_buf), (char *)address + 8);
            format_ipv6_string(event->details.network_connect.destination_ip, ip6_buf);
        } else {
            // Unix Domain Socket (AF_UNIX) - local/IPC. Already a real path
            // string before this fix; only the leading 0x01 marker byte
            // (unnecessary now that IPv4/IPv6 no longer use markers either,
            // and previously left a stray non-printable byte at the front
            // of every Unix-socket destination_ip a consumer read) is
            // dropped, using the full 46-byte budget for the path itself.
            event->details.network_connect.destination_port = 0;
            bpf_probe_read_kernel_str(event->details.network_connect.destination_ip,
                                      46, (char *)address + 2);
        }

        event->details.network_connect.protocol[0] = 'T';
        event->details.network_connect.protocol[1] = 'C';
        event->details.network_connect.protocol[2] = 'P';
        event->details.network_connect.protocol[3] = 0;

        bpf_ringbuf_submit(event, 0);
    }

    if (is_install_session() || is_admin_session()) {
        uint32_t zero = 0;
        struct scratch_buf *buf = bpf_map_lookup_elem(&scratch_map, &zero);
        if (buf) {
            uint16_t dest_port = 0;
            uint32_t dest_ip = 0;
            if (family == 2) {
                struct sockaddr_in *sin = (struct sockaddr_in *)address;
                uint16_t port_be = 0;
                bpf_probe_read_kernel(&port_be, sizeof(port_be), &sin->sin_port);
                dest_port = ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
                bpf_probe_read_kernel(&dest_ip, sizeof(dest_ip), &sin->sin_addr.s_addr);

                unsigned char *b = (unsigned char *)&dest_ip;
                format_ip_port(buf->path, b, dest_port);
                record_and_batch_event(7, NULL, dest_port, buf->path); // 7 = NETWORK_CONNECT
            } else if (family == 10) {
                record_and_batch_event(7, NULL, 0, "[IPv6 connection]");
            } else {
                record_and_batch_event(7, NULL, 0, "[Unix socket connection]");
            }
        }
    }

    return 0;
}

// Same-user secret brokers with no owner check (Unix-socket agents):
// ssh-agent, gpg-agent, the 1Password agent and the
// gnome-keyring control socket answer any same-user process today with zero
// visibility. This is AUDIT ONLY - confirmed product decision, mirrors the
// ssh_material file policy split (see ownership.rs::locator_denies): ssh,
// scp, ansible, CI runners and VS Code Remote all legitimately connect to
// these sockets constantly, so the goal is recording WHO connected, never
// blocking. Never add a deny path here, even off-by-default - see this
// file's own module doc and the comment on secret_broker_sockets_map.
//
// `unix_sk()` is `container_of(sock, struct unix_sock, sk)`; `sk` is
// unix_sock's first member (verified against this repo's own vmlinux.h), so
// the cast is a same-address reinterpretation, not real pointer arithmetic -
// BPF_CORE_READ then relocates `path.dentry` against the target kernel's own
// BTF for struct unix_sock, tolerant of fields inserted/reordered around it.
SEC("lsm/unix_stream_connect")
int BPF_PROG(unix_stream_connect, struct sock *sock, struct sock *other, struct sock *newsk) {
    if (!is_antitheft_mode())
        return 0;
    if (!other)
        return 0;

    struct unix_sock *uother = (struct unix_sock *)other;
    struct dentry *dentry = BPF_CORE_READ(uother, path.dentry);
    if (!dentry)
        return 0; // abstract-namespace or otherwise unbound socket - no file identity to match

    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode)
        return 0;

    struct resource_id res_id = make_resource_id(inode);
    uint8_t *is_broker = bpf_map_lookup_elem(&secret_broker_sockets_map, &res_id);
    if (!is_broker)
        return 0;

    struct process_key key = get_current_process_key();
    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_SECRET_BROKER_CONNECT, SRC_BPF_LSM, key.pid);
        event->details.secret_broker_connect.resource_dev = res_id.dev;
        event->details.secret_broker_connect.resource_ino = res_id.ino;
        struct qstr d_name = BPF_CORE_READ(dentry, d_name);
        bpf_probe_read_kernel_str(event->details.secret_broker_connect.socket_path,
                                   sizeof(event->details.secret_broker_connect.socket_path), d_name.name);
        bpf_ringbuf_submit(event, 0);
    }

    return 0; // AUDIT ONLY - never deny, by design (see this hook's module doc)
}

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(bprm_creds_for_exec, struct linux_binprm *bprm) {
    if (!bprm)
        return 0;

    struct process_key key = get_current_process_key();
    // Thread-key bug (see kinnector_helpers.h's get_current_group_leader_key
    // doc): every map this hook stamps here (pid_tree_type_map,
    // trusted_ancestor_roots, process_threshold_map) is read back elsewhere
    // via the group-leader key, and pre-de_thread the exec-calling thread
    // need not be the leader. Use this for every one of those maps, and for
    // the ProcessCreate telemetry's child_start_time (which userspace's own
    // subsequent lookups also key on) - `key` stays only for key.pid, which
    // is identical either way.
    struct process_key leader_key = get_current_group_leader_key();

    // package-manager/install-binary detection is
    // now inode-based against install_binary_map (userspace-populated from
    // package_manager_signatures.json via kinnector_config), not a hardcoded filename
    // substring scan -- adding a new ecosystem is a config change, not a rebuild.
    struct inode *bin_inode = BPF_CORE_READ(bprm, file, f_inode);
    uint64_t bin_ino = bin_inode ? BPF_CORE_READ(bin_inode, i_ino) : 0;
    if (bin_inode) {
        uint8_t *is_install_bin = bpf_map_lookup_elem(&install_binary_map, &bin_ino);
        if (is_install_bin && *is_install_bin == 1) {
            uint32_t *tree_type = bpf_map_lookup_elem(&pid_tree_type_map, &leader_key);
            if (tree_type) {
                *tree_type &= ~TREE_ADMIN_SESSION;
                *tree_type |= TREE_INSTALL_CONTEXT;
            } else {
                uint32_t val = TREE_INSTALL_CONTEXT;
                bpf_map_update_elem(&pid_tree_type_map, &leader_key, &val, BPF_ANY);
            }
        }

        // Antitheft-only, appended after Warden's
        // install-binary marking above, never interleaved with it. Stamps
        // protected_owner_pids when the exec'd binary matches a configured owner
        // binary (e.g. a password manager) -- ptrace_access_check/task_kill below
        // consult this to extend the same protection TREE_ADMIN_SESSION processes
        // already get. A MODE_WARDEN deployment never calls is_antitheft_mode()
        // true, so protected_owner_binaries/protected_owner_pids stay untouched
        // for it regardless of what's compiled in.
        if (is_antitheft_mode()) {
            uint8_t *is_owner_bin = bpf_map_lookup_elem(&protected_owner_binaries, &bin_ino);
            if (is_owner_bin && *is_owner_bin == 1) {
                // Injection defense only.
                // Fork-propagated map -- leader_key, not the thread-level
                // `key` this used to carry (same class of bug as this file's
                // other get_current_group_leader_key() call sites; this one
                // site wasn't caught by that earlier sweep).
                uint8_t val = OWNER_PROTECTED;
                bpf_map_update_elem(&protected_owner_pids, &leader_key, &val, BPF_ANY);

                // Also seed exec_origin_map, exactly like the owner_images
                // branch below does for its own owners. Without this, a
                // process stamped OWNER_PROTECTED here has no chain entry to
                // vouch for its OWN binary, and mmap_file's untrusted-image
                // deny then refuses the ELF loader's own PROT_EXEC mapping
                // of a user-owned (non-root) protected binary the moment it
                // starts -- past execve's point of no return, so it surfaces
                // as a bare SIGSEGV at startup rather than a denied exec.
                // Dormant today (userspace never populates
                // protected_owner_binaries, only owner_images), but this map
                // is still compiled in and documented as kernel-config-driven,
                // so fix it before anything wires it up for real.
                struct exec_origin origin = {0};
                struct resource_id bin_id = make_resource_id(bin_inode);
                origin.dev = bin_id.dev;
                origin.ino = bin_id.ino;
                origin.flags = OWNER_PROTECTED;
                origin.uid = BPF_CORE_READ(bin_inode, i_uid.val);
                struct dentry *pob_dentry = BPF_CORE_READ(bprm, file, f_path.dentry);
                struct dentry *pob_parent = pob_dentry ? BPF_CORE_READ(pob_dentry, d_parent) : NULL;
                struct inode *pob_dir = pob_parent ? BPF_CORE_READ(pob_parent, d_inode) : NULL;
                if (pob_dir) {
                    struct resource_id pob_dir_id = make_resource_id(pob_dir);
                    origin.dir_dev = pob_dir_id.dev;
                    origin.dir_ino = pob_dir_id.ino;
                }
                bpf_map_update_elem(&exec_origin_map, &leader_key, &origin, BPF_ANY);
            }
        }

        // Supply-chain scoping, kernel half of the re-root rule (see
        // pkg_lifecycle_pids' doc and origin_classifier.rs::
        // stamps_package_manager_root): exec of a registered package-manager
        // image makes this process the install's ROOT (depth 1) when it is
        // either untagged (fresh `bash -> apt`) or exactly depth 2 (a
        // package manager's direct child: `apt -> dpkg`). Anything deeper -
        // a lifecycle script launching npm - keeps its inherited depth.
        // Synchronous at exec, so dpkg never spends its first milliseconds
        // as a "descendant" waiting for the agent to process its exec
        // event; userspace still stamps too, as the fallback for an image
        // this map does not know (a package manager installed after
        // startup, or one found outside PATH).
        if (is_antitheft_mode()) {
            struct resource_id pm_img_id = make_resource_id(bin_inode);
            uint8_t *pm_image = bpf_map_lookup_elem(&pkg_manager_images, &pm_img_id);
            struct process_key pm_leader_key = get_current_group_leader_key();
            uint8_t *cur = bpf_map_lookup_elem(&pkg_lifecycle_pids, &pm_leader_key);
            // Chain bookkeeping, and it must run before the re-root below.
            // A process already inside an install that execs something which
            // is neither a credential helper nor a package-manager image has
            // just run arbitrary code, and can never regain either standing
            // by exec'ing one later. This single bit closes both halves of
            // the `exec` escape: the credential rule above stops trusting
            // `sh -c 'exec gh'`, and the re-root below stops handing a
            // lifecycle script a clean install root via `exec mvn`.
            if (cur && (*cur & PKG_LIFECYCLE_DEPTH_MASK) >= PKG_LIFECYCLE_DESCENDANT &&
                !(*cur & PKG_LIFECYCLE_RAN_OTHER_CODE) && !pm_image) {
                struct resource_id helper_id = make_resource_id(bin_inode);
                uint8_t *is_helper = bpf_map_lookup_elem(&credential_helper_images, &helper_id);
                // A helper is allowed to interpose a SHELL, because git's own
                // configuration format asks for one: a credential.helper
                // value beginning with `!` is run via `sh -c`, and that is
                // what `gh auth setup-git` writes
                // (`helper = !/usr/bin/gh auth git-credential`). So the real
                // chain for a GitHub CLI user is git -> sh -> gh, and
                // tainting on that shell would refuse the single most common
                // private-fetch setup there is - measured, it hung the fetch
                // on git's interactive password prompt.
                //
                // What separates that from the attack is the PARENT, not the
                // image: git's shell is forked by a credential helper, while
                // a lifecycle script's shell is forked by the package manager
                // itself. So an image we do not recognise is forgiven exactly
                // once, when the process that forked it is a helper mid-chain.
                // `npm -> sh -> exec gh` still taints, because npm is not a
                // helper.
                bool parent_is_helper = false;
                if (!is_helper || *is_helper != 1) {
                    struct task_struct *cur_task = (struct task_struct *)bpf_get_current_task();
                    struct inode *pino = cur_task ? BPF_CORE_READ(cur_task, real_parent, mm, exe_file, f_inode) : NULL;
                    if (pino) {
                        struct resource_id pid_id = make_resource_id(pino);
                        uint8_t *phelper = bpf_map_lookup_elem(&credential_helper_images, &pid_id);
                        parent_is_helper = phelper && *phelper == 1;
                    }
                }
                if ((!is_helper || *is_helper != 1) && !parent_is_helper) {
                    uint8_t tainted = *cur | PKG_LIFECYCLE_RAN_OTHER_CODE;
                    bpf_map_update_elem(&pkg_lifecycle_pids, &pm_leader_key, &tainted, BPF_ANY);
                    cur = bpf_map_lookup_elem(&pkg_lifecycle_pids, &pm_leader_key);
                }
            }
            if (pm_image && (*pm_image & PKG_LIFECYCLE_DEPTH_MASK) == 1) {
                // Re-root only from an UNTAINTED depth-2 process. `apt` ->
                // `dpkg` is the case this exists for and stays allowed: the
                // forked child's first exec IS dpkg, so nothing else ran in
                // it. `npm` -> `sh postinst` -> `exec mvn` is refused,
                // because the shell already tainted that process.
                if (!cur || ((*cur & PKG_LIFECYCLE_DEPTH_MASK) == PKG_LIFECYCLE_DESCENDANT &&
                             !(*cur & PKG_LIFECYCLE_RAN_OTHER_CODE))) {
                    // The flag comes from the IMAGE being exec'd (dpkg is a
                    // distro manager whoever launched it), not the parent.
                    uint8_t root = PKG_LIFECYCLE_ROOT | (*pm_image & PKG_LIFECYCLE_DISTRO);
                    bpf_map_update_elem(&pkg_lifecycle_pids, &pm_leader_key, &root, BPF_ANY);
                }
            }
        }

        // Chain identity (B3). bprm->file
        // here is the ORIGINAL file the caller asked to exec - the .AppImage,
        // the #! script - because security_bprm_creds_for_exec runs once,
        // before exec_binprm's binfmt loop swaps an interpreter in. Keyed on
        // the group leader: a non-leader thread may exec, and de_thread later
        // copies the leader's start_time onto it, so the leader key is the
        // post-exec key every later lookup computes.
        if (is_antitheft_mode()) {
            // leader_key computed once at function top now - reused here.
            struct resource_id img_id = make_resource_id(bin_inode);
            uint32_t *img_flags = bpf_map_lookup_elem(&owner_images, &img_id);
            if (img_flags) {
                // An owner image starts (or restarts) a chain: this process
                // IS the app from here on.
                struct exec_origin origin = {0};
                origin.dev = img_id.dev;
                origin.ino = img_id.ino;
                origin.flags = *img_flags;
                origin.uid = BPF_CORE_READ(bin_inode, i_uid.val);
                // The image's own directory, so OWNER_NO_EXTERNAL_INHERIT can
                // later tell this app's own helpers from a foreign binary it
                // merely launched. Recorded for every chain, costing two
                // reads, because the flag is a property of the corpus entry
                // and may be added to one without the kernel changing.
                struct dentry *img_dentry = BPF_CORE_READ(bprm, file, f_path.dentry);
                struct dentry *img_parent = img_dentry ? BPF_CORE_READ(img_dentry, d_parent) : NULL;
                // OWNER_ORIGIN_ROOT_UP1 (userspace sets it only for an owner
                // resolved to a Flatpak <bundle>/files/bin/<name> layout):
                // climb one extra level so origin_dir lands on the bundle's
                // files/ root, an ancestor of every subtree in it (bin, lib,
                // share, ...), instead of just files/bin. See the flag's own
                // doc comment in kinnector_maps.h for why files/bin alone
                // makes a same-install sibling under files/lib/ unreachable
                // by image_is_internal_to_origin()'s ancestor walk.
                if (img_parent && (*img_flags & OWNER_ORIGIN_ROOT_UP1)) {
                    struct dentry *img_grandparent = BPF_CORE_READ(img_parent, d_parent);
                    if (img_grandparent) {
                        img_parent = img_grandparent;
                    }
                }
                struct inode *img_dir = img_parent ? BPF_CORE_READ(img_parent, d_inode) : NULL;
                if (img_dir) {
                    struct resource_id dir_id = make_resource_id(img_dir);
                    origin.dir_dev = dir_id.dev;
                    origin.dir_ino = dir_id.ino;
                }
                bpf_map_update_elem(&exec_origin_map, &leader_key, &origin, BPF_ANY);
                if (*img_flags & OWNER_BASIC_ONLY) {
                    // basic_protection: the chain identity above is kept (it
                    // is what makes the owner allowlist recognise this app's
                    // own helpers on its own files), but the process gets no
                    // protected_owner_pids entry at all. Delete rather than
                    // skip: this exec may be replacing a protected identity
                    // this pid inherited or previously earned, and leaving
                    // that behind would grant exactly the powers this tier
                    // says we cannot justify.
                    bpf_map_delete_elem(&protected_owner_pids, &leader_key);
                } else {
                    uint8_t prot = OWNER_PROTECTED;
                    bpf_map_update_elem(&protected_owner_pids, &leader_key, &prot, BPF_ANY);
                }
            } else {
                // A non-owner image exec'd inside an owner's chain (an
                // interpreter, a helper, a game under Steam) keeps the
                // chain's identity and its injection defense. It used to be
                // granted the JIT allowance unconditionally here as well, so
                // that a non-JIT wallet could not crash a JIT app it
                // launched; with the allowance retired (kinnector_maps.h)
                // there is nothing left to differ about - the
                // helper is protected exactly like the owner it descends
                // from, and self-injection protection, when the user turns
                // it on, applies to both alike.
                struct exec_origin *inherited = bpf_map_lookup_elem(&exec_origin_map, &leader_key);
                if (inherited) {
                    // OWNER_NO_EXTERNAL_INHERIT: for an app that spawns
                    // external helpers by design, an image from outside its
                    // install stops being the app entirely. Drop BOTH halves
                    // - the chain identity (so is_resource_owner() no longer
                    // recognises it as an owner of the app's vaults) and the
                    // protection entry - rather than re-granting them. It
                    // keeps the restriction lift by having no entry at all,
                    // so protected_selfexec_forbidden() never fires on it and
                    // a legitimate helper still runs; it simply lives on its
                    // own from here. Ordered BEFORE load_elf_binary maps
                    // anything, so the mmap_file foreign-file gate below also
                    // sees the corrected identity and stops refusing a
                    // browser's own native messaging host.
                    struct dentry *new_dentry = BPF_CORE_READ(bprm, file, f_path.dentry);
                    if ((inherited->flags & OWNER_NO_EXTERNAL_INHERIT) &&
                        !image_is_internal_to_origin(new_dentry, inherited->dir_dev, inherited->dir_ino)) {
                        bpf_map_delete_elem(&exec_origin_map, &leader_key);
                        bpf_map_delete_elem(&protected_owner_pids, &leader_key);
                    } else if (!(inherited->flags & OWNER_BASIC_ONLY)) {
                        uint8_t prot = OWNER_PROTECTED;
                        bpf_map_update_elem(&protected_owner_pids, &leader_key, &prot, BPF_ANY);
                    }
                }
            }
        }
    }

    // SSHD Pre-Auth Zero-Trust Lockdown:
    // If the process is running under the unprivileged sshd user's UID,
    // deny execution of any binary (e.g. shells, tools) immediately.
    uint32_t current_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    uint32_t sshd_uid_key = CONFIG_SSHD_UID;
    uint32_t *sshd_uid = bpf_map_lookup_elem(&config_map, &sshd_uid_key);
    if (sshd_uid && *sshd_uid > 0 && current_uid == *sshd_uid) {
        return -EACCES;
    }
    // 1. If executing a trusted admin binary (like logrotate), mark the process tree as TRUSTED_ADMIN
    if (bin_inode) {
        uint64_t ino = bin_ino;
        uint8_t *is_admin_bin = bpf_map_lookup_elem(&trusted_admin_binaries, &ino);
        if (is_admin_bin && *is_admin_bin == 1) {
            uint32_t val = TREE_TRUSTED_ADMIN;
            bpf_map_update_elem(&pid_tree_type_map, &leader_key, &val, BPF_ANY);
        }
    }

    // 2. Enforce execution restrictions on TREE_TRUSTED_ADMIN processes
    uint32_t *tree_type = bpf_map_lookup_elem(&pid_tree_type_map, &leader_key);
    if (tree_type && (*tree_type & TREE_TRUSTED_ADMIN)) {
        struct dentry *dentry = BPF_CORE_READ(bprm, file, f_path.dentry);
        if (dentry) {
            char exe_name[32] = {0};
            bpf_probe_read_kernel_str(exe_name, sizeof(exe_name), BPF_CORE_READ(dentry, d_name.name));
            
            // One lookup replaces 13 name chains (up to 14 `&&` each). See
            // exe_name_class_map: those chains were the dominant source of
            // verifier states in this program.
            //
            // Skipped entirely until the table is populated, because this is
            // an ALLOWLIST - an empty table would deny every exec in an admin
            // tree rather than allowing the safe ones.
            bool is_allowed_admin_cmd = !exe_classes_ready()
                || (exe_name_classes(exe_name) & EXE_CLASS_ADMIN_ALLOWED) != 0;
            if (!is_allowed_admin_cmd) {
                return -EACCES; // Block non-safe commands from logrotate tree!
            }
        }
    }
    // Rule 4: Privileged Container Detection
    // MODE AUDIT: Warden-only, same family as
    // is_container_restricted() above - see its comment for why this is
    // gated even though it is dormant in antitheft today.
    if (!is_antitheft_mode()) {
    uint32_t host_mnt_ns_idx = CONFIG_HOST_MNT_NS;
    uint32_t *host_mnt_ns = bpf_map_lookup_elem(&config_map, &host_mnt_ns_idx);
    if (host_mnt_ns && *host_mnt_ns > 0) {
        uint32_t current_mnt_ns = get_current_mnt_ns_inum();
        if (current_mnt_ns != *host_mnt_ns) {
            uint32_t host_pid_ns_idx = CONFIG_HOST_PID_NS;
            uint32_t *host_pid_ns = bpf_map_lookup_elem(&config_map, &host_pid_ns_idx);
            uint32_t host_net_ns_idx = CONFIG_HOST_NET_NS;
            uint32_t *host_net_ns = bpf_map_lookup_elem(&config_map, &host_net_ns_idx);

            bool is_privileged = false;
            if (host_pid_ns && *host_pid_ns > 0) {
                if (get_current_pid_ns_inum() == *host_pid_ns) {
                    is_privileged = true;
                }
            }
            if (host_net_ns && *host_net_ns > 0) {
                if (get_current_net_ns_inum() == *host_net_ns) {
                    is_privileged = true;
                }
            }
            
            struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
            if (current_task) {
                const struct cred *cred = BPF_CORE_READ(current_task, cred);
                if (cred) {
                    uint64_t cap_effective = 0;
                    KINN_READ_CAP_U64(cap_effective, cred, cap_effective);
                    if (cap_effective & (1ULL << 21)) { // CAP_SYS_ADMIN is bit 21
                        is_privileged = true;
                    }
                }
            }

            if (is_privileged) {
                uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &leader_key);
                if (!trusted || *trusted != 1) {
                    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
                    if (event) {
                        fill_header(event, EVT_IMAGE_LOAD, SRC_BPF_LSM, key.pid);
                        // ABI FIX: is_signed/signer_subject are
                        // real fields in the corrected ImageLoadDetails
                        // layout (see its struct def) - explicitly set to
                        // the honest "not implemented" default rather than
                        // left as whatever the ring-buffer-reserved memory
                        // happened to contain.
                        event->details.image_load.is_signed = 0;
                        event->details.image_load.signer_subject[0] = 0;
                        event->details.image_load.verdict = 1; // 1 = denied (blocked privileged-container exec, not a .so-specific deny, but "denied" either way)
                        struct dentry *dentry = BPF_CORE_READ(bprm, file, f_path.dentry);
                        if (dentry) {
                            bpf_probe_read_kernel_str(event->details.image_load.module_path,
                                                      sizeof(event->details.image_load.module_path),
                                                      BPF_CORE_READ(dentry, d_name.name));
                        } else {
                            event->details.image_load.module_path[0] = 0;
                        }
                        bpf_ringbuf_submit(event, 0);
                    }
                    return -EACCES; // Block execution of untrusted privileged containers!
                }
            }
        }
    }
    } // !is_antitheft_mode() - Warden-only container hardening

    // Detect an interactive login session. loginuid is stamped once by
    // pam_loginuid.so at authentication time -- sshd, console login/getty, and
    // GDM/LightDM/SDDM's PAM stacks all call it (confirmed on this build: see
    // /etc/pam.d/login, gdm-password, gdm-autologin) -- and stays fixed for the
    // life of the session across su/sudo/setuid, unlike sniffing the direct
    // parent process's name (the old approach here only matched "sshd" or
    // "login" as an immediate parent, so a GUI terminal's shell -- parented by
    // a window manager/terminal emulator, never sshd/login -- was never
    // recognized as an admin session at all).
    //
    // Critical difference from the old check: loginuid+tty stays true for
    // EVERY exec for the entire lifetime of the session, not just once at
    // login. The old "direct parent is sshd/login" condition was structurally
    // one-shot -- only the login shell itself has sshd/login as its immediate
    // parent, so only it ever got stamped directly; everything it later ran
    // inherited the flag exclusively via sched_process_fork's tree_type
    // propagation. Naively swapping the condition for loginuid+tty broke that
    // structure: it re-qualifies on every subsequent exec too, so ANY binary
    // run from an authenticated terminal -- including this test's own
    // deliberately-untrusted probe processes, and in production literally
    // anything a user executes -- independently re-earns the bypass. Confirmed
    // live: without the guard below, 7 of this test's "should be denied"
    // assertions silently started passing as "allowed" instead.
    //
    // Fix: only stamp here when the process's real_parent is itself untracked
    // (no pid_tree_type_map entry) -- true for a fresh login shell (parent is
    // sshd/login, or a GUI terminal emulator, neither ever tracked) but false
    // for anything that shell subsequently runs (parent is the
    // already-tracked shell itself). This restores the original "stamp once
    // at the session's entry point, propagate via fork from there" shape
    // while generalizing the entry-point condition to cover GUI/console
    // sessions, not just SSH.
    // task_struct.loginuid lives inside #ifdef CONFIG_AUDIT in the kernel
    // source, so its CO-RE relocation is only safe when guarded -
    // bprm_creds_for_exec is a kRequired program (core_linux_open_items),
    // and an unguarded read that fails to resolve poisons this instruction,
    // which fails this program's load and - since it's Required - the
    // daemon comes up enforcing NOTHING. Same pattern Tetragon uses for the
    // same field (bpf/process/bpf_process_event.h's __get_auid) - see
    // check_tetragon_first. Not porting their task->audit->loginuid
    // fallback: that's for their 3.10/4.19 tiers, both below BPF LSM's own
    // floor, and any kernel that actually has BPF LSM has loginuid directly
    // (no shipped distro pairs CONFIG_BPF_LSM=y with CONFIG_AUDIT=n).
    //
    // Fails closed on the (currently unobserved) kernel where the field is
    // genuinely absent: has_valid_loginuid stays 0, so this exec never
    // earns the TREE_ADMIN_SESSION bypass via this path - consistent with
    // every other fail-closed default in this codebase (owner+resource,
    // revoked_pid_map). The alternative (fail open) would silently grant an
    // unearned bypass on a kernel this code has never even been run on.
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int has_valid_loginuid = 0;
    if (task && bpf_core_field_exists(task->loginuid)) {
        uint32_t loginuid = BPF_CORE_READ(task, loginuid.val);
        if (loginuid != (uint32_t)-1) {
            has_valid_loginuid = 1;
        }
    }

    if (has_valid_loginuid) {
        struct task_struct *real_parent = NULL;
        bpf_probe_read_kernel(&real_parent, sizeof(real_parent), &task->real_parent);
        int parent_already_tracked = 0;
        if (real_parent) {
            struct process_key parent_key = {0};
            bpf_probe_read_kernel(&parent_key.pid, sizeof(parent_key.pid), &real_parent->tgid);
            bpf_probe_read_kernel(&parent_key.start_time, sizeof(parent_key.start_time), &real_parent->start_time);
            if (bpf_map_lookup_elem(&pid_tree_type_map, &parent_key)) {
                parent_already_tracked = 1;
            }
        }

        if (!parent_already_tracked) {
            struct signal_struct *signal = NULL;
            bpf_probe_read_kernel(&signal, sizeof(signal), &task->signal);
            if (signal) {
                struct tty_struct *tty = NULL;
                bpf_probe_read_kernel(&tty, sizeof(tty), &signal->tty);
                if (tty) {
                    // Yes! This is a fresh session's entry point: real login,
                    // TTY/PTY attached, untracked parent. Stamp it as TREE_ADMIN_SESSION!
                    uint32_t pid = key.pid;
                    uint32_t flag = TREE_ADMIN_SESSION;
                    bpf_map_update_elem(&pid_tree_type_map, &leader_key, &flag, BPF_ANY);
                    uint8_t allowed = 1;
                    bpf_map_update_elem(&admin_session_pids, &pid, &allowed, BPF_ANY);
                }
            }
        }
    }

    // Warden's trust/threshold execution-control system, including the
    // Universal Dangerous-Exec Filter below - none of this was ever gated by
    // deployment_mode, so an antitheft deployment (which never populates
    // trusted_exec_inodes) turned every exec on the machine "Untrusted" the
    // moment it armed CONFIG_BLOCKING_ENABLED (shared with Warden), and then
    // this filter denied sudo/su/pkexec machine-wide as a side effect - not
    // an antitheft feature, just an unintended leak.
    if (!is_antitheft_mode()) {
    // Bypass execution blocking for admin sessions (unless it is an install context)
    if (is_admin_session() && !is_install_session()) {
        return 0;
    }

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode && *mode == 1);

    // Look up executable file inode to check trust level
    struct file *bprm_file = BPF_CORE_READ(bprm, file);
    if (bprm_file) {
        struct inode *inode = BPF_CORE_READ(bprm_file, f_inode);
        if (inode) {
            uint64_t ino = BPF_CORE_READ(inode, i_ino);
            uint32_t *trust_val = bpf_map_lookup_elem(&trusted_exec_inodes, &ino);
            if (trust_val) {
                uint32_t threshold = *trust_val;
                if (threshold == 0) {
                    return -EACCES;
                }
                bpf_map_update_elem(&process_threshold_map, &leader_key, &threshold, BPF_ANY);
            } else if (blocking_enabled) {
                // If blocking is enabled, untrusted files default to Threshold = 1 (Untrusted)
                uint32_t threshold = 1;
                bpf_map_update_elem(&process_threshold_map, &leader_key, &threshold, BPF_ANY);
            }
        }
    }

    uint32_t *active_threshold = bpf_map_lookup_elem(&process_threshold_map, &leader_key);
    if (active_threshold && blocking_enabled) {
        // Block execution of any newly created/written files
        if (bprm_file) {
            struct inode *inode = BPF_CORE_READ(bprm_file, f_inode);
            if (inode) {
                struct resource_id exec_id = make_resource_id(inode); // Phase 6
                uint8_t *is_newly_created = bpf_map_lookup_elem(&newly_created_inodes, &exec_id);
                if (is_newly_created && *is_newly_created == 1) {
                    if (active_threshold && *active_threshold > 0) {
                        if (!is_install_session()) {
                            return -EACCES;
                        }
                    }
                }
            }
        }

        uint32_t thresh_val = *active_threshold;

        // PROFILE_ZERO_EXECUTION: unconditionally deny execution
        if (thresh_val & PROFILE_ZERO_EXECUTION) {
            return -EACCES;
        }

        // PROFILE_RESTRICTED_EXEC: check exec_allowlist_map
        if (thresh_val & PROFILE_RESTRICTED_EXEC) {
            if (bprm_file) {
                struct inode *inode = BPF_CORE_READ(bprm_file, f_inode);
                if (inode) {
                    uint64_t ino = BPF_CORE_READ(inode, i_ino);
                    uint8_t *allowed = bpf_map_lookup_elem(&exec_allowlist_map, &ino);
                    if (!allowed || *allowed != 1) {
                        return -EACCES; // Deny execution of unapproved binary
                    }
                }
            }
        }
    }

    // Universal Dangerous-Exec Filter: L1 / L2 blocks for known dangerous tools in monitored contexts
    if (bprm_file) {
        struct inode *inode = BPF_CORE_READ(bprm_file, f_inode);
        if (inode) {
            char exe_name[32] = {0};
            struct dentry *dentry = BPF_CORE_READ(bprm_file, f_path.dentry);
            if (dentry) {
                bpf_probe_read_kernel_str(exe_name, sizeof(exe_name), BPF_CORE_READ(dentry, d_name.name));
            }

            // Check for dangerous binaries: nc, ncat, netcat, socat, tftp
            // Same single lookup for both classes - these were 10 more
            // name chains. An unknown name yields 0, so neither flag is set,
            // which is the same answer the chains gave.
            uint32_t exe_classes = exe_name_classes(exe_name);
            bool is_dangerous_tool = (exe_classes & EXE_CLASS_DANGEROUS_TOOL) != 0;
            bool is_priv_esc = (exe_classes & EXE_CLASS_PRIV_ESC) != 0;

            if ((is_dangerous_tool || is_priv_esc) && blocking_enabled) {
                // If it is in a monitored context (threshold exists and is > 0), block!
                if (active_threshold && *active_threshold > 0) {
                    return -EACCES; // Block dangerous/priv-esc execution in monitored contexts!
                }
            }
        }
    }
    } // !is_antitheft_mode() - Warden-only trust/threshold execution control

    // in an antitheft LSM deployment the execve
    // tracepoint is the ProcessCreate producer (argv + envp); this hook
    // would only duplicate it without the arguments.
    int antitheft_tracepoint_producer = 0;
    if (is_antitheft_mode()) {
        uint32_t lsm_idx = CONFIG_LSM_ACTIVE;
        uint32_t *lsm_active = bpf_map_lookup_elem(&config_map, &lsm_idx);
        antitheft_tracepoint_producer = (lsm_active && *lsm_active == 1);
    }
    struct TelemetryEvent *event = antitheft_tracepoint_producer
        ? NULL
        : bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    // Only counted when this hook is the actual producer - in antitheft LSM
    // mode it is deliberately silent, and counting that as a drop would
    // report a loss rate of 100% for a design decision.
    //
    // Deliberately AFTER the reservation is consumed, not between the reserve
    // and its null check. 5.15's verifier rejected the earlier ordering with
    // "Unreleased reference id=39": reading the _OR_NULL reference inside
    // bump_stat's argument forks the state while the reference is live, and on
    // that verifier one of the resulting paths reaches the exit still holding
    // it. Newer verifiers prune those states and never complain, which is
    // exactly why this stayed invisible until a 5.15 VM existed.
    const int emitted = (event != NULL);
    if (event) {
        event->details.process_create.child_pid = key.pid;

        uint32_t ppid = 0;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        if (task) {
            struct task_struct *real_parent;
            bpf_probe_read_kernel(&real_parent, sizeof(real_parent), &task->real_parent);
            if (real_parent) {
                bpf_probe_read_kernel(&ppid, sizeof(ppid), &real_parent->tgid);
            }
        }

        fill_header(event, EVT_PROCESS_CREATE, SRC_BPF_LSM, ppid);
        event->details.process_create.real_parent_pid = ppid;

        const char *filename = 0;
        bpf_probe_read_kernel(&filename, sizeof(filename), &bprm->filename);
        if (filename) {
            bpf_probe_read_kernel_str(&event->details.process_create.child_image_path,
                                      sizeof(event->details.process_create.child_image_path), filename);
            bpf_probe_read_kernel_str(&event->details.process_create.child_command_line,
                                      sizeof(event->details.process_create.child_command_line), filename);
        } else {
            event->details.process_create.child_image_path[0] = '\0';
            event->details.process_create.child_command_line[0] = '\0';
        }
        event->details.process_create.child_sequence_number = 0;
        event->details.process_create.parent_sequence_number = 0;
        event->details.process_create.mnt_ns_inum = get_current_mnt_ns_inum();
        event->details.process_create.pid_ns_inum = get_current_pid_ns_inum();
        event->details.process_create.child_start_time = leader_key.start_time;
        event->details.process_create.pkg_lifecycle = 0;
        event->details.process_create.kernel_verdicts = 0;

        bpf_ringbuf_submit(event, 0);
    }
    if (!antitheft_tracepoint_producer) {
        bump_stat(emitted ? STAT_EXEC_EMITTED : STAT_EXEC_DROPPED);
    }

    return 0;
}

// exec-time credential-delta.
//
// CORRECTED (real-kernel testing during this plan's own Phase 9):
// the plan's original design appended this to bprm_creds_for_exec, reasoning
// that "bprm->cred already reflects the POST-exec identity" there because
// capability precedes bpf in this machine's LSM order. That reasoning is
// right for FILE CAPABILITIES (security.capability xattr - cap_bprm_creds_for_exec
// computes those into bprm->cred->cap_effective very early, essentially
// right after bprm->cred is allocated as a plain copy of the caller's own
// cred) but WRONG for the setuid/setgid BIT - empirically verified live
// (bpf_trace_printk against a real setuid-root exec after a real setuid(1000)
// drop): bprm_creds_for_exec saw euid still 1000 (unelevated), while the
// process's real post-exec /proc/<pid>/status Uid line showed euid=0 - proof
// the setuid-bit elevation (bprm_fill_uid(), deep inside the ELF loader) runs
// LATER than bprm_creds_for_exec, not earlier. Moved to bprm_committing_creds -
// a void-returning LSM hook (confirmed real via vmlinux.h) that fires right
// before the new creds are installed onto the task, i.e. after bprm_fill_uid()
// has already run - bprm->cred here is the real, final post-exec identity for
// both mechanisms. Void return means this hook structurally cannot become an
// enforcement point by accident (there is no non-zero to return that the
// kernel would act on).

#endif  // KINNECTOR_BPF_LSM_HOOKS_EXEC_H
