// SPDX-License-Identifier: GPL-2.0-only
#ifndef KINNECTOR_BPF_TYPES_H
#define KINNECTOR_BPF_TYPES_H

// Data structures and EventType constants.
// Verbatim split out of kinnector.bpf.c (see that file's header comment for
// the why). This holds the wire structs shared with C++ TelemetryEvent and
// Rust TelemetryEventRaw, plus the EVT_* constants shared with the Rust
// EventType enum. No logic here, only layout - see kinnector.bpf.c's
// original section banners ("Data structures", "EventType constants") for
// the exact provenance of each block below.

// ---------------------------------------------------------------------------
// Data structures — must match C++ TelemetryEvent and Rust TelemetryEventRaw
// ---------------------------------------------------------------------------

struct process_key {
    uint32_t pid;
    uint64_t start_time;
};

// canonical resource identity. A raw i_ino
// alone is ambiguous across bind-mounts/multiple filesystems with overlapping
// inode ranges -- (dev, ino) is unique system-wide. Scoped to the
// sensitive/protected-*file*-identity maps (sensitive_inodes_map,
// protected_static_inodes, resource_owner_map, bypassed_directories,
// newly_created_inodes) -- deliberately NOT applied to the exec-trust/binary-
// identity maps (trusted_exec_inodes, exec_allowlist_map,
// trusted_admin_binaries, install_binary_map, protected_owner_binaries),
// which identify known system binaries at fixed, effectively single-filesystem
// canonical paths (/usr/bin, /usr/sbin) where bind-mount collision is not a
// realistic risk -- see this file's own header/[[linux_coverage_plan_phasing]]
// memory for the scoping rationale. `dev` is dev_t (32-bit on Linux) widened
// to uint64_t for a stable BPF map key layout.
struct resource_id {
    uint64_t dev;
    uint64_t ino;
};

// Antitheft resource-swap-defense follow-up: closes the reactive-model race
// window between "an untrusted rename(2)/symlink(2)/link(2) swaps a
// protected resource path" and "userspace's async reverify_resource_path
// processes the resulting telemetry and updates kernel state." inode_rename
// can carry a resource's protection forward synchronously using only data
// already in its own LSM hook (the destination dentry's pre-rename inode).
// symlink(2)/link(2) cannot do this from their LSM hooks (`inode_symlink`/
// `inode_link` below) - both always operate on a NEGATIVE destination
// dentry at that pre-operation point (link()/symlink() fail with EEXIST
// otherwise), so there is no existing inode yet to read a "was this
// sensitive" answer from. This map is what makes that answer available
// anyway: keyed by (parent dir identity, leaf name hash), not by any
// specific inode, so it survives the unlink() that necessarily precedes a
// symlink/link swap - consulted by `lsm_d_instantiate`'s
// `apply_post_op_path_closure` call (kinnector_container_lsm_hooks.h),
// which fires AFTER the operation completes and the new inode actually
// exists. Antitheft-side (Rust) keeps it in sync with
// resource_owner_map/sensitive_inodes_map from the one existing choke point
// (`register_link`) every registration already goes through - see
// ownership.rs.
struct path_name_id {
    uint64_t parent_dev;
    uint64_t parent_ino;
    uint64_t name_hash;
};

struct path_protection {
    uint32_t category;
    uint64_t owner_mask;
    // The resource identity this protection was derived from, so applying it
    // to a newly swapped-in inode can record an alias back to the identity
    // whose exact owner set is registered - see resource_owner_exact.
    uint64_t origin_dev;
    uint64_t origin_ino;
};

// Exact owner-set membership: (resource dev, resource ino, owner exec ino).
// See resource_owner_exact's declaration for why the 64-slot mask below is
// no longer sufficient on its own. All members are 8 bytes, so there is no
// padding for a userspace writer to leave uninitialised - the bug class that
// has already bitten process_key twice in this codebase.
struct owner_link {
    uint64_t dev;
    uint64_t ino;
    // Chain identity (B1): the
    // owner's own device, so an attacker cannot forge a bare inode number on
    // a filesystem they control (a user-mountable FUSE fs hands out whatever
    // i_ino it likes). 0 means "any device" - the legacy registration shape
    // still used by core's own e2e test and the agent's older live tests.
    uint64_t owner_dev;
    uint64_t owner_ino;
};

// Chain identity: the owner image a
// process's exec chain started from. Stamped in bprm_creds_for_exec when the
// exec'd file (bprm->file - the ORIGINAL file the caller named, before
// binfmt_script/binfmt_misc swap an interpreter in) is in owner_images;
// copied to children on fork; kept across later execs of non-owner images;
// dropped on a credential change. `uid` is the origin image's i_uid, which
// mmap_file uses to tell a root-installed app from a user-installed one.
// 40 bytes, no padding.
struct exec_origin {
    uint64_t dev;
    uint64_t ino;
    uint32_t flags;
    uint32_t uid;
    // The origin image's own PARENT DIRECTORY, used only by
    // OWNER_NO_EXTERNAL_INHERIT to answer "is this new image part of the
    // same install?". Zero when unknown - a chain stamped from userspace via
    // set_exec_origin() cannot supply it - and zero is treated as "don't
    // know, fall through to the pre-existing behaviour", never as "outside".
    uint64_t dir_dev;
    uint64_t dir_ino;
};

// FNV-1a, matched byte-for-byte by antitheft-agent's own Rust implementation
// (ownership.rs) - both sides hash exactly the basename's bytes up to (and
// excluding) its natural NUL/end, so padding scheme on either side doesn't
// matter as long as neither hashes past the real string. 128-byte cap: a
// bounded, unrollable read, comfortably longer than any real corpus
// filename (e.g. "Login Data", "logins.json") - NAME_MAX (255) would double
// the unrolled iteration count in the verifier for no practical benefit here.
static __always_inline uint64_t fnv1a_hash_name(const unsigned char *name) {
    char buf[128] = {0};
    bpf_probe_read_kernel_str(buf, sizeof(buf), name);
    uint64_t hash = 0xcbf29ce484222325ULL; // FNV-1a 64-bit offset basis
    #pragma unroll
    for (int i = 0; i < 128; i++) {
        if (buf[i] == '\0') break;
        hash ^= (uint8_t)buf[i];
        hash *= 0x100000001b3ULL; // FNV-1a 64-bit prime
    }
    return hash;
}

struct TelemetryHeader {
    uint64_t sequence_number;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint8_t  event_type;
    uint8_t  source;
    // Must match kinnector/telemetry.h's TelemetryHeader exactly - this
    // struct is reinterpreted directly from the raw ringbuf bytes by
    // ebpf_loader.cpp (no translation step), so any size drift from the
    // canonical C++ header means the data_sz == sizeof(TelemetryEvent) guard
    // there never passes and every BPF-sourced event is silently dropped
    // before it reaches userspace. Always 0 on Linux (see telemetry.h's own
    // comment - only Windows populates a real value).
    uint64_t actor_sequence_number;
} __attribute__((packed));

struct ProcessCreateDetails {
    uint32_t child_pid;
    uint32_t real_parent_pid;
    char child_image_path[512];
    char child_command_line[1024];
    // Same ABI-parity requirement as actor_sequence_number above - matches
    // telemetry.h's ProcessCreateDetails. Always 0 on Linux today (Rust's
    // process_tree.rs already documents and tolerates this).
    uint64_t child_sequence_number;
    uint64_t parent_sequence_number;
    // Container support: current process's own mnt/pid namespace inode
    // numbers at exec time, via the same get_current_*_ns_inum() helpers
    // is_container_restricted() already uses. Must match telemetry.h's
    // ProcessCreateDetails exactly (same ABI-parity requirement as every
    // other field in this file).
    uint32_t mnt_ns_inum;
    uint32_t pid_ns_inum;
    // AppImage protection plan: the exec'ing task's real task->start_time,
    // read synchronously off get_current_process_key() at emission time
    // below - NOT the same quantity as process_tree.rs's start_time_ns
    // proxy (TelemetryHeader.timestamp_ns). Userspace needs this exact
    // value to build a process_key that matches what protected_owner_pids/
    // ptrace_access_check will look up later for the same task - a
    // dispatch-time-proxy key would silently never match. Must match
    // telemetry.h's ProcessCreateDetails exactly (same ABI-parity
    // requirement as every other field in this file).
    uint64_t child_start_time;
    // the kernel's own verdicts for THIS exec, read when it has
    // succeeded (tracepoint_sched_process_exec), after bprm_creds_for_exec
    // re-rooted or tainted the process: its pkg_lifecycle_pids value (0 = in
    // no install). Only meaningful with KINN_EXEC_VERDICT_PKG in
    // kernel_verdicts; a producer that does not know it leaves both 0, and the
    // agent falls back to looking the map up (which loses to a process that
    // has already exited by the time its event is handled).
    uint8_t  pkg_lifecycle;
    uint8_t  kernel_verdicts;
} __attribute__((packed));

#define KINN_EXEC_VERDICT_PKG 0x01

struct FileReadDetails {
    uint32_t bytes_requested;
    int32_t  zone_id;
    char file_path[512];
} __attribute__((packed));

// ABI FIX: this struct carried an extra `zone_id` field
// telemetry.h's declared `FileWriteDetails` (and both warden's and
// antitheft's Rust mirrors) never had - FileReadDetails legitimately has
// zone_id on every side, but FileWriteDetails apparently dropped it from the
// contract at some point without this local copy following. The extra field
// shifted `file_path` 4 bytes later than every consumer expected, so
// `null_terminated_str(&d.file_path)`/`cstr(&file_path)` read starting at
// what was actually the (always-zero) zone_id's second half - a leading NUL,
// so every real FileWrite event decoded to an EMPTY path. Concretely, this
// silently broke warden's "unrestricted upload / RFI-staging" web-file-write
// detector (heuristics.rs's `EventType::FileWrite | EventType::FileCreate`
// arm) for every real write, not just some. See the EVT_FILE_WRITE/
// EVT_MEMORY_MAP renumbering below for a second, compounding bug in the same
// area (wrong event-type discriminants, not just this struct's layout).
struct FileWriteDetails {
    uint32_t bytes_written;
    char file_path[512];
} __attribute__((packed));

// Owner-swap defense follow-up: telemetry.h/telemetry.rs have
// carried EVT_FILE_CREATE=4/FileCreateDetails and EVT_FILE_RENAME=6/
// FileRenameDetails on both userspace sides for a long time, but neither
// was ever mirrored into THIS local union or actually emitted by any hook -
// dormant, fully ABI-matching infrastructure, now activated by
// inode_symlink/inode_rename below. Field layout matches telemetry.h
// exactly (packed, no implicit padding to drift out of sync).
struct FileCreateDetails {
    int32_t zone_id; // Windows ZoneId concept, always -1 on Linux
    char file_path[512];
} __attribute__((packed));

struct FileRenameDetails {
    char source_path[512];
    char destination_path[512];
} __attribute__((packed));

// Resource-swap-defense follow-up: mirrors telemetry.h's FileLinkDetails
// exactly - see this local union's own doc comment above for why this file
// hand-maintains a separate mirror instead of #include-ing the shared header.
struct FileLinkDetails {
    char source_path[512];
    char destination_path[512];
} __attribute__((packed));

struct NetworkConnectDetails {
    char     destination_ip[46];
    uint16_t destination_port;
    char     protocol[8];
} __attribute__((packed));

struct MemoryMapDetails {
    uint64_t addr;
    uint64_t length;
    uint32_t prot;          // PROT_READ | PROT_WRITE | PROT_EXEC
    uint32_t flags;         // MAP_ANONYMOUS | MAP_PRIVATE etc.
    int32_t  fd;            // -1 for anonymous
    uint64_t file_inode;    // Fix 6: inode of backing file (0 for anonymous regions)
    // Runtime-revocation plan: target's real task->start_time, needed
    // bit-for-bit to key revoked_pid_map's process_key correctly. This
    // struct was BPF-local only until this plan added its twin to the
    // shared telemetry.h header, so no userspace consumer could decode it
    // before now.
    uint64_t target_start_time;
} __attribute__((packed));

// old_fd_type added so warden's
// `is_reverse_shell = old_fd_type==2(socket) && new_fd in {0,1,2}` check
// (already declared on the Rust side since before this fix) has something
// real to read instead of uninitialized ring-buffer memory. Populated via
// resolve_fd_kind() at tracepoint entry, before oldfd is closed/replaced.
struct Dup2Details {
    uint32_t oldfd;
    uint32_t newfd;         // 0=stdin, 1=stdout, 2=stderr (reverse shell indicator)
    uint8_t  old_fd_type;   // 0=unknown, 1=file, 2=socket, 3=pipe - see FdKind
    // For a socket: its address family (1 AF_UNIX, 2 AF_INET, 10 AF_INET6), 0 unknown or not a
    // socket. Appended, so a consumer that reads only the first 9 bytes (warden) is unchanged.
    uint16_t old_fd_family;
} __attribute__((packed));

// EVT_LISTEN's payload has always been
// a meaningless zeroed reuse of ProcessCreateDetails (see
// tracepoint_sys_enter_listen below) - this is the first real payload for
// it, giving ProcessTree.mark_listening a port to attribute NET_SPAWNED's
// "spawned by a listening service" half against.
struct ListenDetails {
    uint16_t port; // 0 if resolution failed (Unix socket, or a real failure) -
                    // an honest ambiguity, not fabricated.
} __attribute__((packed));

// presence-plus-short-value only,
// deliberately never a stronger claim than "this key was present with this
// value at exec time" - matches origin_probe.rs's ENV_MARKER_ALLOWLIST
// spoofability philosophy. Captured from the real envp the kernel used at
// exec, materially stronger than a later /proc/<pid>/environ read (which can
// race a short-lived or self-overwriting process).
// ld_audit_present / interp_injection_mask: extends the original two-field struct in place -
// must match include/kinnector/telemetry.h's EnvironmentMarkersDetails
// exactly (same ABI-parity requirement as every other struct in this file).
struct EnvironmentMarkersDetails {
    uint8_t ld_preload_present;
    uint8_t ld_library_path_present;
    uint8_t ld_audit_present;
    uint8_t interp_injection_mask; // bit0=NODE_OPTIONS bit1=PYTHONPATH
                                     // bit2=PYTHONSTARTUP bit3=PERL5LIB
                                     // bit4=RUBYLIB bit5=CLASSPATH
    char    ld_preload_value[128]; // truncated, presence + short value only
    // NODE_OPTIONS'
    // value, same truncation rule. Presence alone is too common to act on;
    // `--require`/`--import`/`--loader` inside the value is not.
    char    node_options_value[128];
} __attribute__((packed));

// presence-only setgroups() companion.
struct GroupSetDetails {
    int32_t gidsetsize;
} __attribute__((packed));

// see telemetry.h's
// CrossMemoryAccessDetails for the full comment - direction is extended
// (Phase 3) to also cover /proc/<pid>/mem access via file_permission/
// file_open, not just process_vm_readv/writev.
struct CrossMemoryAccessDetails {
    uint32_t target_pid;
    uint8_t  direction;
} __attribute__((packed));

struct CapabilityChangeDetails {
    uint64_t old_effective;
    uint64_t new_effective;
} __attribute__((packed));

struct PrctlKeepcapsDetails {
    uint8_t keepcaps_enabled;
} __attribute__((packed));

struct CommRenameDetails {
    char new_comm[16];
} __attribute__((packed));

struct SubreaperSetDetails {
    uint8_t enabled;
} __attribute__((packed));

// See telemetry.h's
// ExecCredentialDeltaDetails for the full comment on LSM-ordering reasoning.
struct ExecCredentialDeltaDetails {
    uint32_t pre_exec_uid;
    uint32_t post_exec_euid;
    uint64_t pre_exec_cap_effective;
    uint64_t post_exec_cap_effective;
} __attribute__((packed));

struct NamespaceChangeDetails {
    uint8_t  operation;
    uint64_t flags;
} __attribute__((packed));

// ABI FIX: this struct did not exist in this file at all before
// this fix, even though include/kinnector/telemetry.h has always declared
// `MemoryProtectDetails` (and both warden's and antitheft's Rust mirrors
// already decode it as this exact shape) for EVT_MEMORY_PROTECT. Without a
// matching local struct/union member, `lsm/file_mprotect` below was instead
// filling `event->details.memory_map` (the *numeric* MemoryMapDetails shape)
// for EVT_MEMORY_PROTECT events - so every consumer's
// `null_terminated_str(details.prot_flags)` was reading raw binary
// (an addr/length/prot/flags/fd/file_inode tuple) as if it were an ASCII
// string. Concretely, this broke warden's "S-A anonymous mprotect(PROT_EXEC)
// shellcode (SIGKILL)" detection (heuristics.rs's `EventType::MemoryProtect`
// arm) - `new_flags.contains("PROT_EXEC")` was being evaluated against
// garbage, so that detection could not reliably fire. See
// `format_prot_flags` below for how `prot_flags`/`old_prot_flags` are now
// built as real strings, and `lsm/file_mprotect`'s file-backed branch for
// where this is populated.
struct MemoryProtectDetails {
    uint32_t target_pid;
    uint64_t address;
    uint64_t length;
    char     prot_flags[64];
    char     old_prot_flags[64];
    // Runtime-revocation plan: target's real task->start_time, needed
    // bit-for-bit to key revoked_pid_map's process_key correctly.
    uint64_t target_start_time;
} __attribute__((packed));

// Fix 8/11: PtraceAttach telemetry struct.
// Emitted on every lsm/ptrace_access_check regardless of trust level,
// so the agent can correlate injection attempts on high-value targets.
//
// ABI FIX: this struct's field layout had drifted from
// include/kinnector/telemetry.h's declared `PtraceAttachDetails` - `mode`
// was a raw uint32_t here but a char[32] string on the userspace/consumer
// side (both warden's and antitheft's Rust mirrors already declare it as a
// string, since they were written against telemetry.h, not this file) -
// `ebpf_loader.cpp` reinterpret-casts these bytes with zero translation, so
// every consumer's `mode` string was reading raw binary as text. Fixed by
// matching telemetry.h's layout here instead of drifting further from it;
// `target_pid` (first field, always a plain uint32_t on both sides) was
// never actually affected by this - see `format_ptrace_mode` below for how
// `mode` is now populated.
struct PtraceAttachDetails {
    uint32_t target_pid;    // PID of the process being attached to
    char     mode[32];      // human-readable ptrace mode, e.g. "PTRACE_MODE_ATTACH"
    uint64_t target_start_time; // see MemoryProtectDetails' comment above
    // `verdict` (alert-visibility audit): the antitheft
    // protected-owner-family ptrace block (ptrace_access_check, "Block
    // unprivileged process from ptrace'ing a protected owner process!")
    // used to return -EACCES before ever reaching this hook's unconditional
    // telemetry emit below it - a real attacker being blocked was
    // completely invisible to userspace. 1 = observed (the pre-existing
    // unconditional emit - not itself a verdict, just "this ptrace attempt
    // happened, decide for yourself"), 2 = denied (the kernel already made
    // a definitive block decision - always alert-worthy, no further
    // heuristics needed).
    uint8_t  verdict;
} __attribute__((packed));

// Fix 10: ImageLoadDetails for lsm/mmap_file SO load telemetry.
//
// ABI FIX: same class of drift as PtraceAttachDetails above -
// this struct was `{file_inode, module_path[256]}` here but
// include/kinnector/telemetry.h (and both consumers' Rust mirrors) declare
// `{is_signed: u8, module_path[512], signer_subject[256]}`. Every consumer
// reading `is_signed` was actually reading the low byte of `file_inode`, and
// `module_path` was misaligned entirely. Fixed by matching telemetry.h's
// layout; `file_inode` is dropped (neither consumer's mirror struct had a
// field for it either - it was never actually reachable through this event
// despite the comment below, only ever through the different-shaped
// `memory_map`/`FileOpenDetails` events). `is_signed`/`signer_subject` are
// populated as an honest "not implemented" (0 / empty) rather than reading
// garbage as if it meant something - Linux has no directly-equivalent cheap
// per-mmap signature check the way Windows Authenticode does; wiring a real
// one (IMA appraisal / fs-verity) is a separate, larger follow-up.
struct ImageLoadDetails {
    uint8_t  is_signed;         // always 0 today - see comment above
    char     module_path[512];  // dentry name of the loaded module
    char     signer_subject[256]; // always empty today - see comment above
    uint8_t  verdict;           // antitheft-only: 0 = allowed, 1 = denied - see mmap_file's untrusted-.so deny
} __attribute__((packed));

struct ProcessStopDetails {
    uint32_t exit_code;
    uint32_t _pad;
} __attribute__((packed));

// Antitheft-only (deployment_mode == MODE_ANTITHEFT): mirrors telemetry.h's
// FileOpenDetails exactly - carries the storage-ownership decision's own
// resource_id (dev, ino) so userspace can reverse-map straight to which
// ProtectedResource this was (a bare basename is ambiguous - e.g. "Login
// Data" exists identically under every Chrome profile). Emitted from the
// file_open LSM hook's antitheft owner-check branch, not by any Warden path.
struct FileOpenDetails {
    uint64_t resource_dev;
    uint64_t resource_ino;
    uint8_t  verdict; // 1 = allowed (recognized owner), 2 = denied, 3 = denied(revoked), 4 = denied(storage-dir .so write, not an owner), 5 = denied(supply-chain persistence), 6 = observed(supply-chain persistence by a distro maintainer script, not denied), 7 = denied(rename of a protected resource, not an owner), 8 = observed(a persistence write by a process no install rule applies to, or any writer while blocking is off); for 5/6/8 resource_dev/ino = the persistence DIRECTORY, file_path = leaf name
    char     file_path[512]; // leaf name only (d_name.name), kept for logs
    // Appended (antitheft-cloud contract v12): how the file was
    // opened, so a consumer can tell a read of a secret from a create or an
    // overwrite of it. A bit set of KINN_OPEN_*; 0 = unknown (an emission
    // site that has no open mode, or a producer from before this field).
    // file_open sets it from f_mode (FMODE_READ/FMODE_WRITE, stable values
    // on every kernel) and f_flags (O_TRUNC is still set when the LSM hook
    // runs: do_dentry_open strips it only after security_file_open);
    // file_permission's write deny sets KNOWN|WRITE. Appended after
    // file_path so every existing offset is unchanged.
    uint8_t  access_mode;
    // telemetry.h's macOS-only open response; never set by a BPF producer, here so the fields after
    // it sit at telemetry.h's offsets.
    uint8_t  response;
    // Persistence events only (verdict 5, 6, 8): the writer's pkg_lifecycle_pids value at
    // the moment of the write (0 = in no install; depth, PKG_LIFECYCLE_DISTRO, RAN_OTHER_CODE), read
    // synchronously so the agent never has to look it up after the writer may have exited, and which
    // operation it was (KINN_PERSIST_OP_*). Appended; FileOpenDetails is far from the union's size.
    uint8_t  pkg_lifecycle;
    uint8_t  persist_op;
    // Appended (telemetry.h): the opener's parent tgid and its group leader's start_time,
    // set at every FileOpen emission (kinn_file_open_actor), so a forked child that writes before it
    // execs can be placed in the agent's tree. The ring buffer is not zeroed: every site sets both.
    uint32_t parent_pid;
    uint64_t process_start_time;
} __attribute__((packed));

#define KINN_PERSIST_OP_CREATE      1
#define KINN_PERSIST_OP_MKDIR       2
#define KINN_PERSIST_OP_RENAME_INTO 3
#define KINN_PERSIST_OP_RENAME_AWAY 4
#define KINN_PERSIST_OP_LINK        5
#define KINN_PERSIST_OP_SYMLINK     6
#define KINN_PERSIST_OP_UNLINK      7
#define KINN_PERSIST_OP_WRITE       8

#define KINN_OPEN_READ  0x01 // FMODE_READ
#define KINN_OPEN_WRITE 0x02 // FMODE_WRITE
#define KINN_OPEN_TRUNC 0x04 // O_TRUNC requested (an existing file's content is discarded)
#define KINN_OPEN_KNOWN 0x80 // the producer filled access_mode; without it the mode is unknown

// Same-user secret-broker socket connect (Unix-
// socket agents): AUDIT ONLY, never a deny - emitted from `unix_stream_connect`
// when the target socket's (dev, ino) matches an entry userspace registered
// in `secret_broker_sockets_map` (ssh-agent/gpg-agent/1Password-agent/
// gnome-keyring-control style sockets whose path resolves to a fixed
// location - see `support/`'s corpus entries for which ones qualify).
// resource_dev/resource_ino identify WHICH registered socket was hit, the
// same identity space as FileOpenDetails, so userspace's existing (dev,ino)
// reverse-index machinery applies unchanged; connecting_pid is redundant
// with the header's own pid field and intentionally omitted.
struct SecretBrokerConnectDetails {
    uint64_t resource_dev;
    uint64_t resource_ino;
    char     socket_path[128]; // dentry leaf name of the socket file, for logs
} __attribute__((packed));

struct TelemetryEvent {
    struct TelemetryHeader header;
    union {
        struct ProcessCreateDetails  process_create;
        struct FileReadDetails       file_read;
        struct FileWriteDetails      file_write;
        struct NetworkConnectDetails network_connect;
        struct MemoryMapDetails      memory_map;
        struct MemoryProtectDetails  memory_protect; // ABI FIX, see struct def above
        struct Dup2Details           dup2;
        struct ProcessStopDetails    process_stop;
        struct PtraceAttachDetails   ptrace_attach;  // Fix 8/11
        struct ImageLoadDetails      image_load;     // Fix 10
        struct FileOpenDetails       file_open;
        struct ListenDetails         listen;
        struct EnvironmentMarkersDetails env_markers;
        struct GroupSetDetails          group_set;
        struct CrossMemoryAccessDetails cross_memory_access;
        struct CapabilityChangeDetails  capability_change;
        struct PrctlKeepcapsDetails     prctl_keepcaps;
        struct CommRenameDetails        comm_rename;
        struct SubreaperSetDetails      subreaper_set;
        struct ExecCredentialDeltaDetails exec_credential_delta;
        struct NamespaceChangeDetails   namespace_change;
        struct FileCreateDetails        file_create;          // Owner-swap defense follow-up
        struct FileRenameDetails        file_rename;          // Owner-swap defense follow-up
        struct FileLinkDetails          file_link;            // Resource-swap-defense follow-up
        struct SecretBrokerConnectDetails secret_broker_connect; // audit-only
        char   details_buffer[1544];
    } details;
} __attribute__((packed));

_Static_assert(sizeof(struct TelemetryEvent) == 1608, "kinnector.bpf.c's own local TelemetryEvent mirror must match telemetry.h's ABI-locked size - see that header's own static_assert");

// An exec's two events, filled at the syscall and held until the exec has succeeded
// (exec_stash_map, tracepoint_sched_process_exec).
struct exec_stash {
    struct TelemetryEvent create;
    struct TelemetryEvent env;
};

// ---------------------------------------------------------------------------
// EventType constants (must match Rust EventType enum)
// ---------------------------------------------------------------------------
#define EVT_PROCESS_CREATE  1
#define EVT_PROCESS_STOP    2
#define EVT_FILE_READ       3
// ABI FIX (found auditing for): this
// was `4`, colliding with Rust's `EventType::FileCreate = 4` (telemetry.h
// never declares an EVT_FILE_CREATE - nothing emits it - but the numeric
// value was still squatting on FileCreate's discriminant). Every real write
// this hook emits was decoded on the consumer side as FileCreate, not
// FileWrite - see the FileWriteDetails struct-layout fix above for the
// compounding bug this created. `5` matches telemetry.h's real
// `EventType::FileWrite = 5`.
#define EVT_FILE_WRITE      5
// Antitheft-only resource-scoped file_open signal (dev/ino + verdict) -
// matches Rust EventType::FileOpen = 16. Never emitted by any Warden path.
#define EVT_FILE_OPEN       16
// ABI FIX: this was `5`, which is Rust's `EventType::FileWrite`
// discriminant (see above) - every real anonymous-mmap/mprotect(PROT_EXEC)
// shellcode event this file emits was being decoded by consumers as
// FileWrite (misreading MemoryMapDetails' raw addr/length/prot/flags/fd
// bytes as a FileWriteDetails string), while warden's real
// `EventType::MemoryMap` arm (heuristics.rs's anon-exec SIGKILL detector)
// was permanently dead code, since nothing was ever tagged with its actual
// Rust discriminant. `17` matches telemetry.h's real `EventType::MemoryMap = 17`.
#define EVT_MEMORY_MAP      17
#define EVT_NETWORK_CONNECT 7
// Fix 8/11: PtraceAttach matches Rust EventType::PtraceAttach = 13
#define EVT_PTRACE_ATTACH   13
// Fix 10: ImageLoad matches Rust EventType::ImageLoad = 8
#define EVT_IMAGE_LOAD      8
// Fix 6: MemoryProtect matches Rust EventType::MemoryProtect = 12
#define EVT_MEMORY_PROTECT  12
#define EVT_DUP2            18
#define EVT_LISTEN          19
#define EVT_FILE_BATCH      42  // was 26, which collides with TaskRegistered - see telemetry.h
// matches Rust EventType::EnvironmentMarkers = 31
#define EVT_ENVIRONMENT_MARKERS 31
#define EVT_PRIVILEGE_CHANGE 24
#define EVT_IPC_ACCESS       25
#define EVT_SIGNAL_DELIVERY  23
// matches Rust EventType 32-40
#define EVT_CROSS_MEMORY_ACCESS   32
#define EVT_CAPABILITY_CHANGE     33
#define EVT_PRCTL_KEEPCAPS        34
#define EVT_COMM_RENAME           35
#define EVT_SUBREAPER_SET         36
#define EVT_EXEC_CREDENTIAL_DELTA 37
#define EVT_GROUP_CHANGE          38
#define EVT_GROUP_SET             39
#define EVT_NAMESPACE_CHANGE      40
// alert-visibility audit: matches Rust EventType::SelfExecDenied = 43
#define EVT_SELF_EXEC_DENIED      43
// matches Rust EventType::SecretBrokerConnect = 44
#define EVT_SECRET_BROKER_CONNECT 44


// TelemetrySource constants
#define SRC_BPF_LSM         6
#define SRC_BPF_TRACEPOINT  7

#ifndef EACCES
#define EACCES 13
// shmem/tmpfs superblock magic (include/uapi/linux/magic.h) - memfd_create,
// SysV shm segments, /dev/shm and a tmpfs /tmp all live on it.
#define TMPFS_MAGIC 0x01021994
#endif

#ifndef EPERM
#define EPERM 1
#endif

// Role flag: set in process_threshold_map value for known database processes
#define ROLE_DATABASE 0x80000000u

#define PROFILE_ZERO_EXECUTION     0x10000000u
#define PROFILE_RESTRICTED_EXEC    0x20000000u
#define PROFILE_SHELL_ENABLED      0x40000000u
#define PROFILE_ZERO_NETWORK       0x80000000u
#define PROFILE_PATH_CONSTRAINED   0x01000000u

#define ROLE_MAIL_GATEWAY          0x02000000u
#define ROLE_QUEUE_MANAGER         0x04000000u
#define ROLE_NTP_CLIENT            0x08000000u

#define TREE_ADMIN_SESSION         0x00010000u
#define TREE_TRUSTED_ADMIN         0x00020000u
#define TREE_AUTOMATION            0x00040000u
#define TREE_INSTALL_CONTEXT       0x00080000u


#endif  // KINNECTOR_BPF_TYPES_H
