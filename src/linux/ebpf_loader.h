#ifndef KINNECTOR_EBPF_LOADER_H
#define KINNECTOR_EBPF_LOADER_H

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <functional>
#include <thread>
#include <atomic>
#include <cstddef>
#include <map>
#include <set>
#include <utility>
#include "kinnector/telemetry.h"

// Forward declarations for libbpf types to avoid exposing headers globally
struct bpf_object;
struct bpf_link;
struct ring_buffer;

struct resource_id;

namespace kinnector::lnx {

// Map types for core-agent communication
enum class BpfMapType {
    CategoryFlags,
    PendingNetwork,
    TrustedRoots,
    SensitiveInodes,
    TaintedProcess,
    TrustedExecInodes,
    ProcessThreshold,
    ConfigMap,
    BypassedDirectories,
    PidTreeType,
    JvmExceptionPids,
    DbOutboundAllowlist,
    InfraOutboundAllowlist,
    ExecAllowlistMap,
    AdminSessionPids,
    TrustedAdminBinaries,
    // resolved package-manager binary inode -> 1.
    // Populated via UpdateMapEntry(InstallBinaryMap, /*pid unused*/0, inode, 1), same
    // start_time-as-key convention already used for ExecAllowlistMap/TrustedAdminBinaries.
    InstallBinaryMap,
    // Phase 5: configured owner-protection binary inode -> 1 (e.g. a password
    // manager). Same start_time-as-key convention as InstallBinaryMap.
    ProtectedOwnerBinaries,
    // Phase 5: (pid, start_time) -> 1, stamped by the kernel at exec time when a
    // process matches ProtectedOwnerBinaries -- read-only from userspace's
    // perspective in the common case, but exposed via the normal
    // UpdateMapEntry/DeleteMapEntry process_key path for test/debug use.
    ProtectedOwnerPids,
    // Runtime-revocation plan: (pid, start_time) -> reason bitflags, entirely
    // userspace-populated (unlike ProtectedOwnerPids above, nothing in the
    // kernel ever writes this on its own) via UpdateMapEntry/DeleteMapEntry --
    // this is its only population path, there's no dedicated Add/Remove pair.
    RevokedPidMap,
    // Supply-chain defense: processes running inside a package manager's
    // install, propagated across fork by the kernel side.
    PkgLifecyclePids,
    // Chain identity (B2). Not
    // addressable through UpdateMapEntry/DeleteMapEntry (owner_images is
    // keyed by resource_id, exec_origin's value is a struct) - use
    // AddOwnerImage/RemoveOwnerImage/SetExecOrigin. Listed so the ordinal
    // space stays documented in one place.
    OwnerImages,
    ExecOrigin
};

class EbpfLoader {
public:
    EbpfLoader();
    ~EbpfLoader();

    // Initializes loader, checks capabilities, and sets up fallback status
    bool Initialize(const std::string& bpf_obj_path, bool force_fallback = false);

    // Starts loading and attaching eBPF programs (or sets up mock mode)
    bool Start();

    // Detaches and unloads eBPF programs
    void Stop();

    // Programs the running kernel refused, mapped to why. Empty on a clean
    // load. See bpf_portability.h: a non-empty result means enforcement is
    // degraded but running, which callers should surface rather than swallow.
    std::map<std::string, std::string> SkippedPrograms() const;

    // DANGEROUS, test-only: Stop() deliberately *disconnects* (rather than
    // destroys) every pinned LSM/kprobe link so real wardend/antitheft-agent
    // enforcement survives a daemon restart. That's correct for production,
    // but it means a root test run (e.g. test_enforcement_e2e) that pins its
    // own test-fixture policy state to these same system-wide paths leaves
    // that state enforcing against the *entire live machine* forever, even
    // after the test process exits -- see linux_coverage_plan_phasing memory
    // for the sudo/su/pkexec lockout this caused. ForceUnpinAllLinks() fully
    // unpins and destroys every hook this loader can attach, unconditionally,
    // so nothing outlives the calling process. Call this ONLY from test
    // harnesses that just ran with blocking_enabled=1 against real inodes --
    // never from warden/antitheft-agent's own shutdown path.
    void ForceUnpinAllLinks();

    // Test-only: core_self_integrity_map's slot (0 = the daemon binary, 1 = its .bpf.o), read and
    // written with a userspace st_dev, so test_enforcement_e2e can stand a file of its own in for
    // the daemon binary. An empty slot reads (0, 0). Never from a product's code path.
    bool SelfIntegrityIdentityTestOnly(uint32_t slot, uint64_t& kernel_dev, uint64_t& inode);
    bool SetSelfIntegrityIdentityTestOnly(uint32_t slot, uint64_t dev, uint64_t inode);

    // Map modification interfaces
    bool UpdateMapEntry(BpfMapType map_type, uint32_t pid, uint64_t start_time, uint32_t value);
    // pkg_lifecycle_pids value for this process, or -1 if absent. See the
    // implementation for why the agent needs to read this map back.
    int LookupPkgLifecycle(uint32_t pid, uint64_t start_time);

    // Returns the kernel's own start_time for `pid`'s protected_owner_pids
    // entry, or 0 if it has none. Tests need this because revoked_pid_map is
    // keyed by (pid, start_time) where start_time is task_struct::start_time
    // in nanoseconds, and userspace cannot reconstruct that value: /proc's
    // starttime is USER_HZ-quantized and is not guaranteed to bit-match (the
    // gap antitheft's proc_sweep::kernel_start_time_ns documents). The real
    // agent sidesteps this by taking start_time from a telemetry event; a
    // test that has no event for the process it just spawned reads the key
    // the kernel already wrote at exec instead.
    uint64_t LookupOwnerStartTime(uint32_t pid);

    // Exec-telemetry accounting, summed across CPUs from telemetry_stats.
    // `dropped` counts execs whose ProcessCreate could not be reserved on a
    // full ring buffer - previously untracked anywhere, see that map's own
    // comment in kinnector.bpf.c.
    void GetExecTelemetryStats(uint64_t& emitted, uint64_t& dropped);

    // Fills `task_start_times` with the kernel's own task_struct::start_time
    // for every running process, so userspace can key the (pid, start_time)
    // maps correctly for a process that predates this daemon. Returns the
    // number of processes recorded, or -1 on failure.
    int RefreshTaskStartTimes();

    // Reads back one pid's real start_time from the map RefreshTaskStartTimes
    // filled. 0 if absent.
    uint64_t GetTaskStartTime(uint32_t pid);
    bool DeleteMapEntry(BpfMapType map_type, uint32_t pid, uint64_t start_time);
    // sensitive/protected-*file*-identity maps
    // (sensitive, protected-static, resource-owner, bypassed-directory) take a
    // `dev` (st_dev/dev_t, widened) alongside `inode` -- a bare inode number is
    // ambiguous across bind-mounts/multiple filesystems with overlapping inode
    // ranges. Deliberately NOT applied to the exec-trust/binary-identity
    // functions below (AddTrustedExecInode etc.) -- see kinnector.bpf.c's
    // resource_id declaration comment for the scoping rationale.
    bool AddSensitiveInode(uint64_t dev, uint64_t inode, uint32_t category);
    // registers a same-user secret-broker socket
    // (ssh-agent/gpg-agent/1Password-agent/gnome-keyring-control) for
    // `unix_stream_connect`'s AUDIT-ONLY tracing - never denies, see that
    // hook's own doc comment.
    bool AddSecretBrokerSocket(uint64_t dev, uint64_t inode);
    bool AddProtectedStaticInode(uint64_t dev, uint64_t inode);
    bool RemoveProtectedStaticInode(uint64_t dev, uint64_t inode);
    bool AddTrustedExecInode(uint64_t inode, uint32_t trust_level);
    // Fix 10: query whether an inode is present in the trusted_exec_inodes BPF map
    bool LookupTrustedExecInode(uint64_t inode);
    bool SetConfigValue(uint32_t index, uint32_t value);

    /// Registers one executable name in `exe_name_class_map` (ADMIN_ALLOWED/
    /// DANGEROUS_TOOL/PRIV_ESC bits, ORed if the name is added more than
    /// once). This used to be a hardcoded table populated automatically from
    /// `Start()` (`PopulateExeNameClasses`, now removed) - the list is
    /// config-driven now (protect-community's `exec_control_lists.json` via
    /// `kinnector-config`), so the caller (warden's Rust startup code) owns
    /// the loop and must call `SetConfigValue(CONFIG_EXE_CLASSES_READY, 1)`
    /// (index 8) once every name is added - the admin-command rule is an
    /// ALLOWLIST, so a rule that consults the table before it is fully
    /// seeded would deny every exec in a TREE_TRUSTED_ADMIN tree instead of
    /// allowing the safe ones.
    bool AddExeNameClass(const char* name, uint32_t classes);

    /// Registers one directory basename in untrusted_dir_names_map (see that
    /// map's doc in kinnector_maps.h) - a denylist, so unlike AddExeNameClass
    /// there is no "ready" flag to set afterward.
    bool AddUntrustedDirName(const char* name);
    // DB: register a directory inode in the bypassed_directories bypass map
    bool AddBypassedDirectoryInode(uint64_t dev, uint64_t inode);
    // DB: remove a directory inode from bypassed_directories (on DB process stop)
    bool RemoveBypassedDirectoryInode(uint64_t dev, uint64_t inode);

    // register/unregister `owner_exec_inode` as a
    // legitimate owner process for the protected resource `(resource_dev,
    // resource_inode)`, via the same 64-slot hash-bitmask representation
    // kinnector.bpf.c's resource_owner_hash() uses -- this is Antitheft-only;
    // callers must have already set CONFIG_DEPLOYMENT_MODE == MODE_ANTITHEFT via
    // SetConfigValue for the kernel side to ever consult this map.
    // `owner_exec_inode` itself stays a bare inode (Phase 6 scope is the
    // protected *resource*'s identity, not the lossy owner-hash bucket input).
    bool AddResourceOwner(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode);
    bool ResetResourceOwnerToSingle(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode);
    bool RemoveResourceOwner(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode);
    // Chain identity (B1): the same
    // three operations with the owner's own POSIX st_dev, so the exact owner
    // set is a composite (dev, ino) identity a FUSE mount cannot forge. The
    // three legacy functions above register with owner_dev == 0, which the
    // kernel treats as "any device" - kept for core's own e2e test and the
    // agent's older live tests; production registration uses these.
    bool AddResourceOwnerExact(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_dev, uint64_t owner_exec_inode);
    bool ResetResourceOwnerToSingleExact(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_dev, uint64_t owner_exec_inode);
    bool RemoveResourceOwnerExact(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_dev, uint64_t owner_exec_inode);
    // A resource's WHOLE owner set in one step, for an identity the kernel
    // has only aliased so far (a rename swapped it in): the exact set is
    // written entry by entry but the identity is marked authoritative
    // (resource_exact_known) only with the last one. Adding owners one call
    // at a time marks it authoritative on the first, and until the last
    // arrives the kernel checks the partial set instead of following the
    // alias to the complete one - the owner itself is refused its own file
    // for that long. Each owner is (POSIX st_dev, inode).
    bool AddResourceOwnersExactBatch(uint64_t resource_dev, uint64_t resource_inode, const std::vector<std::pair<uint64_t, uint64_t>>& owners);
    // Chain identity (B2): owner_images and exec_origin_map population.
    // `flags` are kinnector.bpf.c's OWNER_* bits; `uid` for SetExecOrigin is
    // the origin image's st_uid.
    bool AddOwnerImage(uint64_t dev, uint64_t inode, uint32_t flags);
    // Credential helpers exempt from the supply-chain credential deny at
    // fork depth 2 only - see credential_helper_images in kinnector.bpf.c.
    bool AddCredentialHelperImage(uint64_t dev, uint64_t inode);
    bool RemoveCredentialHelperImage(uint64_t dev, uint64_t inode);
    // modified_system_libraries: package-owned libraries whose content no
    // longer matches their package manager's record; mmap_file refuses a
    // protected-owner mapping of one. `dev` is
    // the POSIX st_dev, converted here like every other (dev, ino) map. Fail
    // open: an absent map is a false return and denies nothing.
    // ClearModifiedLibraries empties the whole set (walks the keys).
    bool AddModifiedLibrary(uint64_t dev, uint64_t inode);
    bool RemoveModifiedLibrary(uint64_t dev, uint64_t inode);
    bool ClearModifiedLibraries();
    bool RemoveOwnerImage(uint64_t dev, uint64_t inode);
    bool SetExecOrigin(uint32_t pid, uint64_t start_time, uint64_t dev, uint64_t inode, uint32_t flags, uint32_t uid);
    bool AddPersistenceDir(uint64_t dev, uint64_t inode);
    // Supply-chain scoping: the append-file half of the
    // persistence corpus, keyed like AddProtectedPathName (parent identity +
    // FNV-1a of the leaf name); and the package-manager image identities
    // bprm_creds_for_exec re-roots the install depth on.
    bool AddPersistenceName(uint64_t parent_dev, uint64_t parent_inode, const std::string& name);
    bool AddPackageManagerImage(uint64_t dev, uint64_t inode, uint32_t flags);
    bool RemovePackageManagerImage(uint64_t dev, uint64_t inode);
    // Storage-dir write/mmap protection: mirrors
    // AddResourceOwnerExact/RemoveResourceOwnerExact's mask+exact-membership
    // scheme against kinnector.bpf.c's protected_dir_map/
    // protected_dir_owner_exact instead of resource_owner_map/
    // resource_owner_exact - a separate pair of maps and a separate
    // dir_owners_ bookkeeping cache, so registering a directory here can
    // never affect file_open's general read-gate for it.
    bool AddDirOwner(uint64_t dir_dev, uint64_t dir_inode, uint64_t owner_dev, uint64_t owner_exec_inode);
    bool RemoveDirOwner(uint64_t dir_dev, uint64_t dir_inode, uint64_t owner_dev, uint64_t owner_exec_inode);
    bool AddProtectedPathName(uint64_t parent_dev, uint64_t parent_inode, const std::string& name, uint32_t category, uint64_t owner_mask,
                              uint64_t origin_dev, uint64_t origin_inode);
    // Directory-keyed synchronous protection - see
    // glob_owned_dirs_map's declaration comment in kinnector_maps.h.
    bool AddGlobOwnedDir(uint64_t dir_dev, uint64_t dir_inode, uint32_t category, uint64_t owner_mask,
                          uint64_t origin_dev, uint64_t origin_inode);
    uint64_t GetResourceOwnerMask(uint64_t resource_dev, uint64_t resource_inode);

    // Firewall (warden/src/firewall) — one CIDR at a time; the caller
    // (warden's EbpfBackend) owns the desired-state diff and issues a call
    // per added/removed CIDR, so no bulk/array variant is needed here — see
    // fw_key4/fw_key6/fw_value in kinnector.bpf.c for the wire shape.
    // `addr` must point to 4 bytes (is_v6=false) or 16 bytes (is_v6=true),
    // network byte order. `prefixlen` is in bits.
    bool AddFirewallCidr(bool is_v6, const uint8_t* addr, uint32_t prefixlen,
                          uint32_t rule_id, uint16_t port, uint8_t proto,
                          uint8_t direction, uint8_t action);
    bool RemoveFirewallCidr(bool is_v6, const uint8_t* addr, uint32_t prefixlen);
    // Anti-tamper: total live entry count across both firewall tries, for
    // ebpf_health.rs to compare against warden's own expected count.
    // Returns -1 if the maps aren't reachable (mock mode / not loaded).
    int64_t CountFirewallEntries();

    // Checks if the active mode is BPF LSM or Fallback (Tracepoints)
    bool IsLsmActive() const { return lsm_active_; }
    bool IsMockMode() const { return mock_mode_; }

    struct TtyEvent {
        uint64_t timestamp_ns;
        uint32_t pid;
        uint32_t len;
        uint8_t  is_write;
        char     comm[16];
        char     data[1024];
    } __attribute__((packed));

    // Read events from the BPF ring buffer (non-blocking)
    using EventCallback = std::function<void(const TelemetryEvent&)>;
    void SetEventCallback(EventCallback cb);

    using TtyEventCallback = std::function<void(const TtyEvent&)>;
    void SetTtyEventCallback(TtyEventCallback cb);

private:
    // Authoritative per-resource owner set, mirroring resource_owner_exact so
    // owners can be removed precisely - BPF maps are not enumerable from a
    // program. Keyed by the kernel-encoded (dev, ino). Guarded by map_mutex_.
    // Each owner is (kernel-encoded owner_dev, owner_ino); owner_dev 0 is the
    // legacy wildcard.
    std::map<std::pair<uint64_t, uint64_t>, std::set<std::pair<uint64_t, uint64_t>>> resource_owners_;
    // `mark_known` false writes the entry but leaves the identity's exact set
    // non-authoritative (see AddResourceOwnersExactBatch); every other caller
    // wants the default.
    bool WriteExactOwnerLocked(const struct resource_id& key, uint64_t owner_dev, uint64_t owner_exec_inode, bool present, bool mark_known = true);
    void ClearExactOwnersLocked(const struct resource_id& key);
    // Forgets the owner set this loader recorded for `key` when the kernel says it belongs to a
    // file that no longer exists (see the definition), so a new file with the same inode number
    // is registered from nothing rather than on top of its predecessor's owners.
    void DiscardPreviousLifeLocked(const struct resource_id& key, bool sensitive_absent);
    bool OtherOwnerSharesSlotLocked(const struct resource_id& key, uint64_t owner_dev, uint64_t owner_exec_inode);
    bool AddResourceOwnerLocked(const struct resource_id& key, uint64_t owner_dev, uint64_t owner_exec_inode);
    bool ResetResourceOwnerToSingleLocked(const struct resource_id& key, uint64_t owner_dev, uint64_t owner_exec_inode);
    bool RemoveResourceOwnerLocked(const struct resource_id& key, uint64_t owner_dev, uint64_t owner_exec_inode);

    // Storage-dir write/mmap protection: AddDirOwner/RemoveDirOwner's own
    // bookkeeping, mirroring resource_owners_ above but against
    // protected_dir_map/protected_dir_owner_exact - deliberately a separate
    // cache/map pair (see this class's AddDirOwner declaration comment).
    std::map<std::pair<uint64_t, uint64_t>, std::set<std::pair<uint64_t, uint64_t>>> dir_owners_;

    bool CheckLsmSupport();
    // Opens, configures and loads the object with per-program tolerance (see
    // bpf_portability.h). false only when a Required program was rejected.
    bool LoadObjectTolerantly(bool lsm_mode);
    bool LoadAndAttachLsm();
    bool LoadAndAttachFallback();
    void RingBufferPollLoop();
    static int HandleRingBufferEvent(void *ctx, void *data, size_t data_sz);
    static int HandleTtyRingBufferEvent(void *ctx, void *data, size_t data_sz);

    std::string bpf_obj_path_;
    // Programs this kernel would not take, and why. Non-empty means the daemon
    // is running degraded: everything else loaded, but these hooks are absent.
    // Exposed via SkippedPrograms() so health reporting can say so out loud
    // rather than leaving "started successfully" to imply full coverage.
    mutable std::mutex skipped_programs_mu_;
    std::map<std::string, std::string> skipped_programs_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
    std::atomic<bool> lsm_active_{false};
    std::atomic<bool> mock_mode_{false};
    
    struct bpf_object* bpf_obj_{nullptr};
    struct bpf_link* file_open_link_{nullptr};
    struct bpf_link* socket_connect_link_{nullptr};
    struct bpf_link* unix_stream_connect_link_{nullptr};
    struct bpf_link* socket_listen_link_{nullptr};
    struct bpf_link* exec_link_{nullptr};
    struct bpf_link* bprm_check_security_link_{nullptr};
    struct bpf_link* ptrace_link_{nullptr};
    struct bpf_link* mprotect_link_{nullptr};
    struct bpf_link* task_kill_link_{nullptr};
    struct bpf_link* path_chmod_link_{nullptr};
    struct bpf_link* mmap_file_link_{nullptr};   // image-load telemetry + W^X block (LSM-mode only)
    struct bpf_link* fork_link_{nullptr};        // sched_process_fork, pinned LSM-mode attach — lineage propagation

    // new LSM hooks, all
    // zero-enforcement (never return non-zero) - pinned the same way as
    // task_fix_setuid/shm_shmat above.
    struct bpf_link* task_fix_setgid_link_{nullptr};
    struct bpf_link* capset_link_{nullptr};
    struct bpf_link* task_prctl_link_{nullptr};
    struct bpf_link* sb_pivotroot_link_{nullptr};
    struct bpf_link* bprm_committing_creds_link_{nullptr};
    // Antitheft container/namespace tracking fix: sb_mount/path_chroot were
    // real LSM hooks with working is_container_restricted() deny logic that
    // had never been attached anywhere (not even the fallback path), and
    // sys_enter_setns/sys_enter_unshare (below, unpinned) were attached only
    // in LoadAndAttachFallback - meaning mount/chroot/setns/unshare produced
    // zero NamespaceChange telemetry in any real production deployment,
    // silently starving antitheft's own already-written re-classification
    // consumer (agent/src/lib.rs's NamespaceChange handler) of the events it
    // needs. Confirmed safe to attach: is_container_restricted() requires
    // is_container_process(), which itself requires CONFIG_HOST_MNT_NS to be
    // explicitly configured (a Warden-only container-restriction opt-in) -
    // for any deployment that hasn't set it, these hooks are pure telemetry,
    // same discipline as sb_pivotroot above. Pinned the same way as
    // task_fix_setuid/shm_shmat.
    struct bpf_link* sb_mount_link_{nullptr};
    struct bpf_link* path_chroot_link_{nullptr};
    // Owner-swap defense follow-up: telemetry-only, unconditional (no
    // process_threshold_map gate - brand-new hooks, no prior behavior to
    // preserve, and gating them would reproduce inode_unlink's own known
    // blind spot). Pinned the same way as sb_mount/path_chroot above.
    struct bpf_link* inode_create_link_ = nullptr;
    struct bpf_link* inode_mkdir_link_ = nullptr;
    struct bpf_link* inode_rename_link_{nullptr};
    struct bpf_link* inode_symlink_link_{nullptr};
    struct bpf_link* inode_link_link_{nullptr};
    struct bpf_link* lsm_d_instantiate_link_{nullptr};
    struct bpf_link* inode_free_security_link_{nullptr};
    // New tracepoints, unpinned (telemetry-only, no enforcement value in
    // surviving a hot-reload the way an LSM deny hook's pin does) - same
    // discipline as the pre-existing tp_dup2_link_/tp_listen_link_ etc.
    struct bpf_link* tp_setns_link_{nullptr};
    struct bpf_link* tp_unshare_link_{nullptr};
    struct bpf_link* tp_setgroups_link_{nullptr};
    struct bpf_link* tp_process_vm_readv_link_{nullptr};
    struct bpf_link* tp_process_vm_writev_link_{nullptr};
    struct bpf_link* tp_clone_link_{nullptr};
    struct bpf_link* tp_clone3_link_{nullptr};

    // Fallback tracepoint links
    struct bpf_link* tp_exec_link_{nullptr};
    struct bpf_link* tp_execat_link_{nullptr};
    struct bpf_link* tp_sched_exec_link_{nullptr};
    struct bpf_link* tp_connect_link_{nullptr};
    struct bpf_link* tp_exit_link_{nullptr};     // sched_process_exit → ProcessStop
    struct bpf_link* tp_openat_link_{nullptr};   // sys_enter_openat → FileOpen
    struct bpf_link* tp_mmap_link_{nullptr};     // sys_enter_mmap → MemoryMap
    struct bpf_link* tp_mprotect_link_{nullptr}; // sys_enter_mprotect → MemoryMap
    struct bpf_link* tp_dup2_link_{nullptr};     // sys_enter_dup2 → Dup2
    struct bpf_link* tp_dup3_link_{nullptr};     // sys_enter_dup3 → Dup2
    struct bpf_link* tp_listen_link_{nullptr};   // sys_enter_listen → Listen
    struct bpf_link* tp_fork_link_{nullptr};     // sched_process_fork, fallback-mode attach — lineage propagation


    // TTY hooks
    struct bpf_link* kprobe_tty_write_link_{nullptr};
    struct bpf_link* kprobe_tty_read_link_{nullptr};
    struct bpf_link* kretprobe_tty_read_link_{nullptr};

    // Ring buffer manager
    struct ring_buffer* ring_buf_{nullptr};
    std::thread ring_buffer_thread_;
    std::mutex map_mutex_;
    EventCallback event_callback_;
    TtyEventCallback tty_event_callback_;
};

// Every path EbpfLoader can pin an LSM/kprobe link to under /sys/fs/bpf/warden.
// Shared with test harnesses (e.g. test_enforcement_e2e's crash signal handler)
// so an emergency unlink-everything cleanup can't drift out of sync with what
// ForceUnpinAllLinks() actually unpins -- see that method's doc comment.
extern const char* const kWardenPinnedLinkPaths[];
extern const size_t kWardenPinnedLinkPathsCount;

} // namespace kinnector::lnx

#endif // KINNECTOR_EBPF_LOADER_H
