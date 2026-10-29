#ifndef KINNECTOR_FFI_H
#define KINNECTOR_FFI_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "kinnector/telemetry.h"
#include "kinnector/cloud_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#  ifdef kinnector_core_EXPORTS
#    define KINNECTOR_API __declspec(dllexport)
#  else
#    define KINNECTOR_API __declspec(dllimport)
#  endif
#else
#  define KINNECTOR_API
#endif

// Initialize the telemetry engine configuration
KINNECTOR_API bool initialize_telemetry_engine(const char* bpf_obj_path, const char* socket_path, const char* auth_token);

// Start the telemetry engine (loading eBPF/LSM programs and starting IPC connection)
KINNECTOR_API bool start_telemetry_engine();

// Stop the telemetry engine (unloading hooks and disconnecting IPC)
KINNECTOR_API void stop_telemetry_engine();

// Populate sensitive inode category mappings.
// `dev` (st_dev/dev_t, widened) makes the identity canonical across
// bind-mounts/multiple filesystems with overlapping inode ranges — a bare
// inode number alone is ambiguous. See kinnector.bpf.c's resource_id
// declaration comment for which maps this applies to and why.
KINNECTOR_API bool add_sensitive_inode(uint64_t dev, uint64_t inode, uint32_t category);

// register a same-user secret-broker socket
// (ssh-agent/gpg-agent/1Password-agent/gnome-keyring-control) for
// `unix_stream_connect`'s AUDIT-ONLY connect tracing. Never a deny path -
// see that hook's own doc comment in kinnector.bpf.c.
KINNECTOR_API bool add_secret_broker_socket(uint64_t dev, uint64_t inode);

// Supply-chain defense: register a DIRECTORY (by its own dev/inode) as a
// place where a persistence entry would be planted - autostart, user systemd
// units, cron. A process running inside a package manager's install is denied
// creating or writing any file whose parent is one of these.
KINNECTOR_API bool add_persistence_dir(uint64_t dev, uint64_t inode);
// The append-file half of the same corpus (~/.bashrc, /etc/crontab): keyed by
// (parent dir identity, leaf name) exactly like add_protected_path_name, so
// the entry exists whether or not the file does and survives a replace.
// An install's descendant is denied opening, creating, renaming, linking or
// unlinking that name. Registering the PARENT DIRECTORY for these instead
// (the old behaviour) turned /etc and $HOME into persistence
// dirs and denied ldconfig/useradd their /etc writes mid-install.
KINNECTOR_API bool add_persistence_name(uint64_t parent_dev, uint64_t parent_inode, const char* name);
// Package-manager image identities (dev, ino), from the package_managers
// corpus's binary names resolved on PATH. bprm_creds_for_exec re-roots the
// install depth to 1 synchronously when one is exec'd fresh or by another
// package manager - see kinnector.bpf.c's pkg_manager_images.
// `flags`: PKG_IMAGE_DISTRO (0x80) marks an OS package manager whose
// maintainer scripts legitimately manage persistence (persistence rule
// becomes visibility-only for its descendants; the credential rule stays).
#define KINNECTOR_PKG_IMAGE_DISTRO 0x80u
KINNECTOR_API bool add_package_manager_image(uint64_t dev, uint64_t inode, uint32_t flags);
KINNECTOR_API bool remove_package_manager_image(uint64_t dev, uint64_t inode);

// re-read /proc/self/mountinfo
// and add the notify-only fanotify mark to every real filesystem mount that
// does not have one yet. The agent calls this on mount telemetry so a
// freshly mounted data partition or USB stick gets write-notify coverage.
// Returns the number of marks added (0 when nothing changed or fanotify is
// unavailable).
KINNECTOR_API uint64_t fanotify_rescan_mounts(void);
KINNECTOR_API bool add_protected_static_inode(uint64_t dev, uint64_t inode);
KINNECTOR_API bool remove_protected_static_inode(uint64_t dev, uint64_t inode);

// Register a directory inode as a DB data-dir bypass (suppresses telemetry for DB processes)
KINNECTOR_API bool add_bypassed_directory_inode(uint64_t dev, uint64_t inode);

// Remove a directory inode from the DB bypass map (called on DB process stop / upgrade)
KINNECTOR_API bool remove_bypassed_directory_inode(uint64_t dev, uint64_t inode);

// register/unregister a legitimate owner process
// (identified by its executable's bare inode — Phase 6's dev+inode compositing
// applies to the protected *resource* side only, not this lossy owner-hash
// bucket input) for a protected resource identified by (resource_dev,
// resource_inode). Antitheft-only — the kernel side only ever consults this
// once CONFIG_DEPLOYMENT_MODE == MODE_ANTITHEFT has been set via set_config_value.
KINNECTOR_API bool add_resource_owner(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode);

// Registers one executable basename in exe_name_class_map (EXE_CLASS_ADMIN_ALLOWED
// / EXE_CLASS_DANGEROUS_TOOL / EXE_CLASS_PRIV_ESC bits, OR'd with any existing
// entry for the same name). Warden-only - config-driven from protect-community's
// exec_control_lists.json, replacing what used to be a hardcoded table populated
// automatically at Start(). Caller MUST call set_config_value(8 /* CONFIG_EXE_CLASSES_READY */, 1)
// once every name has been added - the admin-command rule this table feeds is an
// ALLOWLIST, so consulting it before it's fully seeded would deny every exec in a
// TREE_TRUSTED_ADMIN tree instead of allowing the safe ones.
KINNECTOR_API bool add_exe_name_class(const char* name, uint32_t classes);

// Registers one ancestor-directory basename (e.g. "tmp") in untrusted_dir_names_map,
// consulted by is_library_open_from_untrusted_dir() for Warden's admin-session
// .so-injection block. Config-driven from exec_control_lists.json's
// untrusted_library_directories. A denylist - unlike add_exe_name_class there is
// no "ready" flag to set afterward.
KINNECTOR_API bool add_untrusted_dir_name(const char* name);
// Resource-swap-defense fail-closed follow-up: a genuine RESET (exactly one
// owner bit, everything else cleared), NOT an OR like add_resource_owner
// above. Needed because the synchronous carry-forward mechanism
// (`lsm_d_instantiate`'s `apply_post_op_path_closure` call, `inode_rename`'s
// in-kernel copy)
// can leave a swapped identity's mask pointing at the OLD owner - an
// OR-only "deny everyone" call could never clear that bit, silently
// defeating the fail-closed guarantee. See EbpfLoader::ResetResourceOwnerToSingle's
// doc comment for the live bug this closes.
KINNECTOR_API bool reset_resource_owner_to_single(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode);
KINNECTOR_API bool remove_resource_owner(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode);

// Chain identity (B1/B2), Linux-only,
// Antitheft-only. The `*_exact` trio is the composite-identity form of the
// three owner-set calls above: `owner_dev` is the owner file's POSIX st_dev,
// so a user-mountable FUSE filesystem presenting a chosen inode number can
// no longer impersonate an owner. The three bare-inode calls above keep
// working and register a device wildcard (owner_dev == 0) - core's own e2e
// test and the agent's older live tests rely on that.
KINNECTOR_API bool add_resource_owner_exact(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_dev, uint64_t owner_exec_inode);
KINNECTOR_API bool reset_resource_owner_to_single_exact(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_dev, uint64_t owner_exec_inode);
KINNECTOR_API bool remove_resource_owner_exact(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_dev, uint64_t owner_exec_inode);
// A resource's whole owner set in one call: `count` owners as parallel arrays
// of POSIX st_dev and inode. The set becomes authoritative in the kernel only
// once the last one is written, so an identity a rename just swapped in never
// has a partial set in force (adding owners one call at a time does: the
// owner missing so far is refused its own file until its call lands).
KINNECTOR_API bool add_resource_owners_exact_batch(uint64_t resource_dev, uint64_t resource_inode, const uint64_t* owner_devs, const uint64_t* owner_inodes, uint32_t count);

// Storage-dir write/mmap protection, Linux-only, Antitheft-only.
// Registers/removes one (directory, owner) pair against
// kinnector.bpf.c's protected_dir_map/protected_dir_owner_exact - same
// 64-slot-mask-plus-exact-membership scheme as the resource-owner calls
// above, but deliberately separate maps: registering a directory here never
// affects file_open's general read-gate (see those maps' declaration
// comment). `dir_dev`/`dir_inode` are the directory's own (dev, ino);
// `owner_dev`/`owner_exec_inode` are the same owner identity a resource
// under that directory was registered with.
KINNECTOR_API bool add_dir_owner(uint64_t dir_dev, uint64_t dir_inode, uint64_t owner_dev, uint64_t owner_exec_inode);
KINNECTOR_API bool remove_dir_owner(uint64_t dir_dev, uint64_t dir_inode, uint64_t owner_dev, uint64_t owner_exec_inode);
// owner_images: every resolved owner file (binary, script, AppImage) with the
// OWNER_* flags the exec hook stamps onto any process that execs it. This is
// what makes an interpreter or an AppImage's inner process carry the app's
// identity: bprm_creds_for_exec sees the original file and records it as the
// chain's origin.
KINNECTOR_API bool add_owner_image(uint64_t dev, uint64_t inode, uint32_t flags);
// credential_helper_images: binaries a package manager launches DIRECTLY to
// authenticate a fetch (git, gh, ssh, git-credential-*). Exempt from the
// supply-chain credential deny at fork depth 2 only.
KINNECTOR_API bool add_credential_helper_image(uint64_t dev, uint64_t inode);
KINNECTOR_API bool remove_credential_helper_image(uint64_t dev, uint64_t inode);
// modified_system_libraries (Antitheft, Linux): package-owned libraries whose
// content no longer matches their package manager's record. mmap_file refuses
// a protected-owner process a PROT_EXEC mapping of one, through the same deny
// as the untrusted-.so rule. `dev` is
// the POSIX st_dev; core converts it. Fail open: false (no engine, no map)
// simply means the deny does not apply. clear empties the whole set.
KINNECTOR_API bool add_modified_library(uint64_t dev, uint64_t inode);
KINNECTOR_API bool remove_modified_library(uint64_t dev, uint64_t inode);
KINNECTOR_API bool clear_modified_libraries(void);
KINNECTOR_API bool remove_owner_image(uint64_t dev, uint64_t inode);
// exec_origin_map: userspace fallback for a chain the kernel could not stamp
// itself (an AppImage first seen at ProcessCreate, after its exec already
// happened). `start_time` must be the real kernel task->start_time from a
// ProcessCreate event's child_start_time; `uid` is the origin file's st_uid.
KINNECTOR_API bool set_exec_origin(uint32_t pid, uint64_t start_time, uint64_t dev, uint64_t inode, uint32_t flags, uint32_t uid);

// Resource-swap-defense synchronous-closure follow-up (Linux only - see
// kinnector.bpf.c's path_name_id/protected_path_names_map declaration
// comments for the full rationale): `name` is hashed identically on both
// sides (FNV-1a over exactly the string's bytes, see fnv1a_hash_name in
// kinnector.bpf.c and ownership.rs's matching Rust implementation) so a
// later rename(2)/symlink(2)/link(2) targeting the same (parent, name) can
// carry this resource's protection forward onto whatever new inode occupies
// it, synchronously, before that syscall returns - no userspace round-trip
// needed for the protection itself. `get_resource_owner_mask` exists so
// antitheft-agent (which never computes the raw bitmask itself - only
// `add_resource_owner`'s OR logic does) can read back the CURRENT mask after
// registering owners, to keep this map's value in sync.
// `origin_dev`/`origin_inode` name the resource identity this protection was
// derived from, so a swapped-in inode can be linked back to the identity
// whose exact owner set is registered (see resource_owner_exact in
// kinnector.bpf.c). Pass the resource's own (dev, inode).
KINNECTOR_API bool add_protected_path_name(uint64_t parent_dev, uint64_t parent_inode, const char* name, uint32_t category, uint64_t owner_mask,
                                           uint64_t origin_dev, uint64_t origin_inode);
// Directory-keyed synchronous protection (closes the gap where new secret
// files in a protected directory were unprotected for up to 60s). Keyed on
// the directory's own (dev, inode) - call this for a resource's immediate
// parent directory ONLY when that resource came from a corpus locator whose
// pattern is a wildcard directly inside that directory (see
// kinnector.bpf.c's glob_owned_dirs_map declaration for the full rationale
// and what deliberately does NOT get this treatment). `owner_mask`/
// `origin_dev`/`origin_inode` mean the same thing as add_protected_path_name's
// - the resource's own owner mask and (dev, inode), so a brand-new sibling
// file inherits identical protection instantly, at creation time.
KINNECTOR_API bool add_glob_owned_dir(uint64_t dir_dev, uint64_t dir_inode, uint32_t category, uint64_t owner_mask,
                                      uint64_t origin_dev, uint64_t origin_inode);
KINNECTOR_API uint64_t get_resource_owner_mask(uint64_t resource_dev, uint64_t resource_inode);

// Populate trusted executable inodes mappings
KINNECTOR_API bool add_trusted_exec_inode(uint64_t inode, uint32_t trust_level);
KINNECTOR_API bool is_trusted_exec_inode(uint64_t inode);

// Set configuration variables (e.g. blocking mode enabled)
KINNECTOR_API bool set_config_value(uint32_t index, uint32_t value);

// Update process threshold dynamically (1 = Untrusted, 2 = Verified, 3 = Naked TTY)
KINNECTOR_API bool update_process_threshold(uint32_t pid, uint64_t start_time, uint32_t threshold);

// Update/Delete BPF map entries dynamically from userspace
KINNECTOR_API bool update_map_entry(int map_type, uint32_t pid, uint64_t start_time, uint32_t value);

// pkg_lifecycle_pids value for one process, or -1 when it is not inside an
// install. Lets the agent see PKG_LIFECYCLE_RAN_OTHER_CODE, which only the
// kernel can set (at exec, before the agent sees the exec event).
KINNECTOR_API int lookup_pkg_lifecycle(uint32_t pid, uint64_t start_time);

// Fills the kernel's task_start_times snapshot from a live iter/task walk and
// returns how many processes it recorded (-1 on failure). Pair with
// get_task_start_time() to address a (pid, start_time) map for a process that
// predates this daemon: /proc's starttime is USER_HZ-quantized, so a key built
// from it never matches what the kernel wrote.
KINNECTOR_API int refresh_task_start_times(void);

// One pid's real task_struct::start_time from that snapshot, 0 if absent.
KINNECTOR_API uint64_t get_task_start_time(uint32_t pid);

// Exec-telemetry accounting. `dropped` counts execs whose ProcessCreate could
// not be reserved on a full ring buffer - a loss that was previously invisible
// everywhere (the kernel handles a failed reserve with a bare `if (event)`,
// and libbpf's ringbuf consumer has no lost-event notion at all).
KINNECTOR_API void get_exec_telemetry_stats(uint64_t* emitted, uint64_t* dropped);
KINNECTOR_API bool delete_map_entry(int map_type, uint32_t pid, uint64_t start_time);

// Send a telemetry event through the active IPC sender (for verification/testing)
KINNECTOR_API bool send_telemetry_event(const TelemetryEvent* event);

// Check if LSM mode is actively loaded in the kernel
KINNECTOR_API bool is_lsm_active();

// DANGEROUS, test-only (Linux): see EbpfLoader::ForceUnpinAllLinks's doc
// comment in ebpf_loader.h. Unconditionally unpins and destroys every
// LSM/kprobe hook this loader can attach, so a root test run that flips
// blocking_enabled=1 against real inodes cannot outlive its own process and
// leave live system-wide enforcement behind (the exact mechanism behind the
// sudo/su/pkexec/chmod lockout documented in linux_coverage_plan_phasing).
// Call this from a test harness's shutdown path and its crash/signal
// handler ONLY - never from warden/antitheft-agent's own Stop() path, which
// deliberately leaves pins in place so enforcement survives a daemon
// restart. No-op (returns false) on non-Linux builds or if the engine was
// never initialized.
KINNECTOR_API bool force_unpin_all_links_test_only();

// DANGEROUS, test-only (Linux), async-signal-safe variant of the above: does
// ONLY unlink() on the same kWardenPinnedLinkPaths (see ebpf_loader.h), no
// mutex, no libbpf calls (bpf_link__destroy is not signal-safe) - safe to
// call from a signal handler installed for SIGSEGV/SIGABRT/SIGBUS/SIGILL/
// SIGFPE/SIGTERM/SIGINT in a root test harness, so a crash mid-test still
// drops every pin's last reference before the process dies. Mirrors
// core's own test_enforcement_e2e.cpp ForceUnpinOnCrash handler exactly -
// callers outside Linux get a no-op. Void return: nothing about calling
// this from within a signal handler may safely report success/failure.
KINNECTOR_API void raw_unpin_all_links_signal_safe();

// Firewall (warden/src/firewall) — see ebpf_loader.h's AddFirewallCidr doc
// comment for the addr/prefixlen contract.
KINNECTOR_API bool add_firewall_cidr(bool is_v6, const uint8_t* addr, uint32_t prefixlen,
                                      uint32_t rule_id, uint16_t port, uint8_t proto,
                                      uint8_t direction, uint8_t action);
KINNECTOR_API bool remove_firewall_cidr(bool is_v6, const uint8_t* addr, uint32_t prefixlen);
KINNECTOR_API int64_t count_firewall_entries();

// Kill-on-access for one resource: while CONFIG_BLOCKING_ENABLED is 1, a non-owner open of
// (dev, inode) kills the opener. Off per resource by default. Returns false where the engine has
// no such response (it is a no-op on Linux, where the BPF LSM deny already refuses the open).
KINNECTOR_API bool set_resource_kill_on_access(uint64_t dev, uint64_t inode, bool enabled);

// ---------------------------------------------------------------------------
// Observe-only collectors.
//
// Independent of start_telemetry_engine(): a separate BPF object with nothing pinned, so the
// programs vanish with the calling process. Call cloud_collectors_start, register the file scope,
// then poll the drains from one thread (each drain removes what it returns). Layouts are in
// cloud_abi.h.
//
// `features`: bit 0 network (TCP in/out, UDP peers and bytes, DNS names; IPv4 and IPv6), bit 1
// ordinary-file opens, bit 2 process lifecycle (fork, exec, exit), bit 3 move/rename/link/symlink
// rows (needs bit 1's dir_rows_on policy also on - see cloud_drain_moves).
// Returns true when at least one source attached;
// cloud_collectors_program_status reports which, so a kernel that rejects a
// program (or a provider that does not enable) yields reduced coverage instead
// of failure.
// ---------------------------------------------------------------------------
KINNECTOR_API bool cloud_collectors_start(const char* bpf_object_path, uint32_t features, int32_t scan_secs);
KINNECTOR_API void cloud_collectors_stop(void);
KINNECTOR_API bool cloud_collectors_running(void);
// Writes "name loaded attached\n" lines for every program into `buf`, NUL
// terminated and truncated to `cap`. Returns the bytes needed.
KINNECTOR_API size_t cloud_collectors_program_status(char* buf, size_t cap);

// `dev` is stat()'s st_dev. kind is CLOUD_ROOT_*. The maps change at once and the commit drops the
// verdict cache: change the scope, then commit once.
KINNECTOR_API bool cloud_scope_add_root(uint64_t dev, uint64_t inode, uint32_t kind);
KINNECTOR_API bool cloud_scope_remove_root(uint64_t dev, uint64_t inode);
KINNECTOR_API bool cloud_scope_add_skip(uint64_t dev, uint64_t inode);
KINNECTOR_API bool cloud_scope_remove_skip(uint64_t dev, uint64_t inode);
KINNECTOR_API void cloud_scope_clear(void);
// Call after a batch of scope changes: drops the per-directory verdict cache.
KINNECTOR_API void cloud_scope_commit(void);

KINNECTOR_API size_t cloud_drain_net(struct cloud_net_rec* out, size_t cap);
KINNECTOR_API size_t cloud_drain_dns(struct cloud_dns_name* out, size_t cap);
KINNECTOR_API size_t cloud_drain_udp(struct cloud_udp_row* out, size_t cap);
KINNECTOR_API size_t cloud_drain_files(struct cloud_file_row* out, size_t cap);
KINNECTOR_API size_t cloud_drain_projects(struct cloud_proj_row* out, size_t cap);
// out[0..CLOUD_STAT_MAX) are the kernel counters (enum cloud_stat), out[CLOUD_STAT_MAX]
// is the number of records the loader dropped because they were not drained in time.
KINNECTOR_API void cloud_collectors_stats(uint64_t* out, size_t n);

// Process lifecycle (feature bit 2 of cloud_collectors_start): fork, exec with the
// full argument block and resolved executable path, and exit, from one kernel ring
// buffer in the order the kernel saw them. cloud_drain_life copies WHOLE records into
// `out` (each is a struct cloud_life_rec followed by exe_len + argv_len bytes, padded
// to 8 bytes; see cloud_abi.h) while they fit in cap_bytes, oldest first, and returns
// the bytes written. Give it at least CLOUD_LIFE_REC_MAX bytes or a large record never
// fits. `nrecs` may be null. A drain removes what it returns.
KINNECTOR_API size_t cloud_drain_life(uint8_t* out, size_t cap_bytes, size_t* nrecs);
// out[0..CLOUD_LIFE_STAT_MAX) are the kernel counters (enum cloud_life_stat), out[CLOUD_LIFE_STAT_MAX]
// is the number of lifecycle records the loader dropped (queue full or malformed).
KINNECTOR_API void cloud_life_stats(uint64_t* out, size_t n);

// Directory rows v2 (part of feature bit 1). The
// key is (process, exact parent directory, operation); only ELIGIBLE opens create or feed one - an
// allowed extension, else a matching name mask, else the separate dir-eligibility prefix policy;
// every open when no policy is loaded (see cloud_abi.h).
// cloud_drain_dirs copies up to `cap` directory keys with their eligible-open counter and
// timestamps (struct cloud_dir_row) and removes them; it also starts a new epoch for the
// per-process bound of new keys, whose refusals cloud_drain_dir_drops then returns, one row per
// process (opens exact, dirs an upper bound). cloud_drain_names copies up to `cap` name records
// (oldest first: a directory key, the open's number and the file's FULL path, struct
// cloud_name_rec) and removes them - a name is sent ONLY for an exact-name mask match, unconditionally,
// never for an ordinary eligible open (the old reservoir sample is gone). cloud_drain_dir_ext_fold
// and cloud_drain_dir_prefix_fold copy up to `cap` extension/prefix breakdown rows (a count and the
// summed i_size of their opens, struct cloud_dir_ext_row / cloud_dir_prefix_row) and remove them.
// cloud_drain_dir_hll copies up to `cap` distinct-file HLL sketch rows (struct cloud_dir_hll_row,
// the raw registers - the cardinality estimate is computed by the caller, not here) and removes
// them. cloud_set_dir_rows_on is the LOAD-TIME switch for the whole mechanism (dir_state, both
// breakdown maps, the sketch and mask names): call it BEFORE cloud_collectors_start (a running
// collector keeps what it started with); off (the default) means no ring, no state.
// cloud_set_name_policy limits which opens are eligible via the extension/mask routes (extension
// values as in cloud_file_key.ext; for a file whose extension is not listed, exact file names and
// prefix masks of at most 8 bytes matched against the basename - a mask match sends a NAME).
// cloud_set_dir_prefix_policy is the separate, broader eligibility-only prefix list:
// a match grants a directory record the same way the mask does, but sends no name, and
// is its own list end to end, not shared with cloud_set_name_policy's prefixes. All policies empty
// (the default) = every open is eligible via the extension route. Also before start.
// cloud_set_dir_limits sets the kernel safety bound of new directory keys per process per drain
// epoch (0 = the default, CLOUD_DIR_PROC_DEFAULT: 16384), also before start.
// out[0..CLOUD_NAME_STAT_MAX) of cloud_name_stats are the kernel counters (enum cloud_name_stat),
// out[CLOUD_NAME_STAT_MAX] is the number of name records the loader dropped.
KINNECTOR_API void cloud_set_dir_rows_on(bool on);
KINNECTOR_API void cloud_set_name_policy(const uint64_t* exts, size_t n_exts, const char* const* names, size_t n_names,
                                         const char* const* prefixes, size_t n_prefixes);
KINNECTOR_API void cloud_set_dir_prefix_policy(const char* const* prefixes, size_t n_prefixes);
KINNECTOR_API void cloud_set_dir_limits(uint32_t proc_max);
KINNECTOR_API size_t cloud_drain_dirs(struct cloud_dir_row* out, size_t cap);
KINNECTOR_API size_t cloud_drain_dir_drops(struct cloud_dir_drop_row* out, size_t cap);
KINNECTOR_API size_t cloud_drain_names(struct cloud_name_rec* out, size_t cap);
KINNECTOR_API size_t cloud_drain_dir_ext_fold(struct cloud_dir_ext_row* out, size_t cap);
KINNECTOR_API size_t cloud_drain_dir_prefix_fold(struct cloud_dir_prefix_row* out, size_t cap);
KINNECTOR_API size_t cloud_drain_dir_hll(struct cloud_dir_hll_row* out, size_t cap);
KINNECTOR_API void cloud_name_stats(uint64_t* out, size_t n);
// Entries of the name policy (cloud_set_name_policy, cloud_set_dir_prefix_policy) the RUNNING
// collectors could not hold: out[0] extension values, out[1] exact names, out[2] prefixes. A level
// for the current load (reset by every cloud_collectors_start), not a delta. The policy maps are
// sized to the policy before the load, so this is 0 unless an entry is malformed or the kernel
// refused an insert; it is counted so the cloud can see a device that watches less than it was told.
KINNECTOR_API void cloud_policy_stats(uint64_t* out, size_t n);

// v7: move/rename/link/symlink rows (feature bit 3). One
// record per ELIGIBLE rename(2)/link(2)/symlink(2), eligibility and scope decided on the
// DESTINATION exactly as cloud_drain_dirs decides them for an opened file, reusing the same
// dir_rows_on/name-policy/dir-prefix-policy configuration (cloud_set_dir_rows_on etc., above -
// there is no separate policy surface for moves). cloud_drain_moves copies up to `cap` records
// (struct cloud_move_rec: process key, old/new parent directory (dev, ino) - old is zeroed with
// CLOUD_MOVE_F_NO_SOURCE set for a symlink's target, which the kernel cannot resolve to an
// inode - and the destination's basename) oldest first and removes them. out[0..CLOUD_MOVE_STAT_MAX)
// of cloud_move_stats are the kernel counters (enum cloud_move_stat), out[CLOUD_MOVE_STAT_MAX] is
// the number of records the loader dropped (queue full or malformed).
KINNECTOR_API size_t cloud_drain_moves(struct cloud_move_rec* out, size_t cap);
KINNECTOR_API void cloud_move_stats(uint64_t* out, size_t n);

#ifdef __cplusplus
}
#endif

#endif // KINNECTOR_FFI_H
