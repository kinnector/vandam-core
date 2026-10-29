// SPDX-License-Identifier: GPL-2.0-only
#ifndef KINNECTOR_BPF_MAPS_H
#define KINNECTOR_BPF_MAPS_H

// BPF map definitions, including the egress firewall's LPM_TRIE tables.
// Verbatim split out of kinnector.bpf.c - see that file's header comment.
// Corresponds to the original "BPF Maps" and "Firewall" section banners.

// ---------------------------------------------------------------------------
// BPF Maps
// ---------------------------------------------------------------------------

// Map: (pid, start_time) -> category bitmask (sensitive file categories opened)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct process_key);
    __type(value, uint32_t);
} category_flags_map SEC(".maps");

// Map: (pid, start_time) -> pending network connect flags (non-zero = active outbound)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct process_key);
    __type(value, uint32_t);
} pending_network_connect SEC(".maps");

// Map: (pid, start_time) -> trusted state (1 = absolutely trusted)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);  // per-process maps sized for a busy dev machine
    __type(key, struct process_key);
    __type(value, uint8_t);
} trusted_ancestor_roots SEC(".maps");

// Map: (dev, Inode) -> Category ID. Phase 6: composite key, see resource_id's
// declaration comment for the scoping rationale.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct resource_id);
    __type(value, uint32_t);
} sensitive_inodes_map SEC(".maps");

// Map: (dev, Inode) of a same-user secret-broker socket (ssh-agent,
// gpg-agent, 1Password agent, gnome-keyring control
// section 1) -> 1. AUDIT ONLY: `unix_stream_connect` reads this to decide
// whether to emit a SecretBrokerConnect event, never to deny - unlike every
// other *_map above, no code path may ever return -EACCES off a lookup in
// this map. Small on purpose: a handful of well-known broker sockets per
// user, not a general resource table.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct resource_id);
    __type(value, uint8_t);
} secret_broker_sockets_map SEC(".maps");

// Map: Inode -> TrustLevel (2 = Verified, 3 = Naked TTY)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, uint64_t);
    __type(value, uint32_t);
} trusted_exec_inodes SEC(".maps");

// Map: (pid, start_time) -> threshold (1 = Untrusted, 2 = Verified, 3 = Naked TTY)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct process_key);
    __type(value, uint32_t);
} process_threshold_map SEC(".maps");

// Map: Config Key (0 = blocking_enabled, 1 = sshd_uid) -> Value
/// Executable basename -> class bitmask, replacing what used to be 141
/// hand-written byte-by-byte character comparisons inside
/// bprm_creds_for_exec.
///
/// Those chains were the single largest source of verifier complexity in this
/// file. Every `&&` is a branch and every alternative in a chain is a separate
/// path the verifier must walk with its own register state, which is how one
/// program reached 40442 states and 1000001 processed instructions - one over
/// the million-instruction limit. It loaded on 6.17 and was rejected with
/// -E2BIG on 6.18.46, because newer verifiers prune fewer states: the program
/// had not changed, the ceiling moved under it.
///
/// A single hash lookup replaces all of them, so the cost no longer grows with
/// the number of names, and adding a name costs nothing in the verifier.
///
/// Key is the full 32-byte buffer the callers already read into, zero-padded
/// by its own initialiser, so a name and its key are the same bytes and there
/// is no truncation question. Populated from userspace (ebpf_loader.cpp) -
/// keeping the list out of the BPF source is also what this project's own rule
/// about not hardcoding match lists asks for.
#define EXE_CLASS_ADMIN_ALLOWED  0x1u
#define EXE_CLASS_DANGEROUS_TOOL 0x2u
#define EXE_CLASS_PRIV_ESC       0x4u

struct exe_name_key {
    char name[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct exe_name_key);
    __type(value, uint32_t);
} exe_name_class_map SEC(".maps");

/// Ancestor directory basenames is_library_open_from_untrusted_dir() treats
/// as world-writable/mount-point-shaped (tmp/dev/mnt) - config-driven
/// (protect-community's exec_control_lists.json, untrusted_library_directories),
/// replacing the hardcoded character-comparison chain that check used to be.
/// A DENYLIST, unlike exe_name_class_map: an empty/unpopulated table just
/// means nothing extra is flagged yet (a narrower detection window at
/// startup), never "deny everything" the way an empty allowlist would - so
/// this has no CONFIG_*_READY gate, matching sensitive_inodes_map and every
/// other denylist-shaped map in this file.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, struct exe_name_key);
    __type(value, uint8_t);
} untrusted_dir_names_map SEC(".maps");

#define CONFIG_BLOCKING_ENABLED 0
#define CONFIG_SSHD_UID          1
#define CONFIG_HOST_MNT_NS       2
#define CONFIG_HOST_PID_NS       3
#define CONFIG_HOST_NET_NS       4
// Critical constraint: this file is shared production
// code between vandamd and antitheft-agent. CONFIG_DEPLOYMENT_MODE lets Antitheft-only
// branches (Phase 3's resource_owner_map, Phase 5's protected_owner_pids) be gated
// behind mode == MODE_ANTITHEFT, appended after Warden's existing checks and never
// interleaved with them, so a MODE_WARDEN deployment (or one that never sets this key
// at all, e.g. an unrelated old build) takes the exact same code path it does today.
#define CONFIG_DEPLOYMENT_MODE   5
#define MODE_WARDEN              1
#define MODE_ANTITHEFT           2
// 1 when the loader attached the BPF LSM hook
// set (set by EbpfLoader::LoadAndAttachLsm, read by
// tracepoint_sys_enter_execve). In LSM mode bprm_check_security is Warden's
// ProcessCreate producer and the execve tracepoint stays silent for it; an
// antitheft deployment takes the tracepoint as its producer instead, since
// only the tracepoint sees argv and envp.
#define CONFIG_LSM_ACTIVE        6
// Alert-visibility audit: antitheftd's own pid, set once at
// startup via set_own_pid() FFI. Lets file_open's "symmetric ALLOWED"
// telemetry (see its own comment) skip emission specifically for the
// daemon's OWN opens - found live, via bpf_printk ground-truth tracing on a
// real desktop under real load, that fanotify's internal dentry_open
// re-read of a frequently-written resource (Chrome's Cookies SQLite file,
// which Chrome rewrites continuously during active browsing) was emitting
// this ALLOWED signal dozens of times within microseconds, on antitheftd's
// own thread - self-verification noise with zero security value (the actor
// and the resource's protector are the same process), but real ring-buffer
// bandwidth, chronically starving the DENY branch's rare, high-value
// bpf_ringbuf_reserve() of space (confirmed failing, live, via this same
// tracing - a quadrupled 16MB->64MB buffer made no measurable difference,
// ruling out capacity as the driver). The DENY branch is never skipped here
// - only this specific ALLOWED-and-it-was-me case.
#define CONFIG_OWN_PID           7
/// Set to 1 by the loader AFTER exe_name_class_map is populated.
///
/// Load-bearing for safety, not just tidiness: the admin-command check is an
/// ALLOWLIST, so an empty name table would mean "nothing is allowed" and
/// bprm_creds_for_exec would deny every exec in a TREE_TRUSTED_ADMIN tree.
/// The rules that consult the table are skipped until this says the table is
/// real.
#define CONFIG_EXE_CLASSES_READY 8
// Antitheft's self-injection protection, off (0) unless userspace says
// otherwise. When 0, protected_selfexec_forbidden() answers "not forbidden"
// for every process and all four self-exec vectors it gates - anonymous
// mmap, mprotect W->X, a memfd/tmpfs-backed executable mapping, and
// SHM_EXEC shmat - are allowed. Set from antitheft's persisted
// `self_injection_protection_enabled` setting (agent/src/settings.rs), at
// startup and again on every toggle, so flipping it takes effect live for
// already-running processes with no re-registration.
//
// Off is the default on purpose. Telling a JIT engine apart from a wallet
// used to be corpus data (`runtime_hint.jit_capable`, retired)
// and getting it wrong killed real applications - Chrome losing tabs was a
// real, shipped instance of it. Without that distinction the deny cannot be
// selective, so it is opt-in and blunt instead: on means NO protected
// process may manufacture its own executable code, JIT engine or not.
//
// Warden never reads this index (protected_selfexec_forbidden() returns
// early unless is_antitheft_mode()), so a MODE_WARDEN deployment is
// unaffected whatever it holds.
#define CONFIG_SELF_INJECTION_PROTECTION 9
// Antitheft's daemon-identity-read exemption.
// ptrace_access_check denies every tracer that
// is not itself protected access to a protected-owner process, and a plain
// readlink of /proc/<pid>/{exe,cwd,root} goes through that hook as a READ
// access, so antitheftd could not identify a process it had itself revoked
// (its exe-identity check read "denied" and the kill was silently skipped).
// With CONFIG_DAEMON_READS_PROTECTED_IDENTITY == 1, the ONE process whose
// (tgid, start_time) equals (CONFIG_OWN_PID, CONFIG_OWN_START_TIME_LO/HI)
// is let through for non-ATTACH access modes on OWNER_PROTECTED targets, and
// nothing else changes: real attach/seize, process_vm_*, /proc/<pid>/mem stay
// denied, and every other caller is decided exactly as before. Off (0) is the
// default and the untouched-map value; the agent writes the three slots at
// startup and the switch bit on every toggle of its
// `kill_revoked_protected_processes_enabled` setting.
//
// The start time is a u64 split over two u32 config slots (config_map values
// are u32). Written LO, HI, then the switch, so a reader that sees the switch
// on has both halves; a torn read only ever fails to match (= denied, the old
// behaviour). The pid alone is not enough: the pinned map outlives the daemon,
// and a later process could be handed the same pid.
#define CONFIG_DAEMON_READS_PROTECTED_IDENTITY 10
#define CONFIG_OWN_START_TIME_LO 11
#define CONFIG_OWN_START_TIME_HI 12

// Set to 1 by EbpfLoader once tracepoint_sched_process_exec is attached: the
// execve tracepoints then HOLD an antitheft exec's events (exec_stash_map)
// and only a successful exec emits them, with the kernel's verdict for it.
// 0 (not attached, or Warden) = emitted at the syscall, as before.
#define CONFIG_EXEC_AT_SUCCESS 13

// protected_owner_pids value bits. The map's value used to be a plain 1
// ("this process is protected"), which conflated three separate decisions
// and made the anon-exec deny unconditional - fatal for a JIT app, which
// builds its own executable memory as normal startup work (see
// anon_exec_policy()). Callers now say which protections apply; a value
// with no OWNER_PROTECTED bit is treated as absent everywhere.
//
// 0x2 (OWNER_JIT_SELFEXEC) is RETIRED and deliberately not
// recycled, so an older userspace that still sets it cannot silently turn
// on some unrelated future flag. It used to carry "this process is a JIT
// engine, let it build its own executable memory", sourced from the
// corpus's `runtime_hint.jit_capable`. Maintaining a per-application JIT
// answer proved unsustainable - the corpus omitted Chromium-family browsers
// by design and the resulting misclassification killed them - so the
// distinction is gone: self-injection is allowed for everyone by default,
// and CONFIG_SELF_INJECTION_PROTECTION turns the deny on for everyone at
// once. See protected_selfexec_forbidden().
//
// There is deliberately no "cannot be killed" bit. Denying signals to a
// protected process also denies the *user's own* kill/force-quit of their
// own wallet or browser, and it defends availability rather than secrets -
// killing a wallet steals nothing from it. What this product protects is
// what executes inside a process and what it can reach on disk.
#define OWNER_PROTECTED       0x1u
// 0x2 retired - see the paragraph above. Nothing reads or writes it.
// "A descendant that execs outside this app's own install directory stops
// being this app." Set from the corpus's per-resource
// `no_external_inheritance` (config.rs), opt-in, off for every entry that
// does not ask for it. Carried on the owner image, so it rides the
// exec_origin chain into every descendant.
//
// Why it exists: browsers, Electron and CEF/webview apps spawn arbitrary
// EXTERNAL helpers by design (Chrome native messaging hosts, a password
// manager's browser bridge, a game launched by Steam). bprm_creds_for_exec's
// non-owner-image branch below re-grants OWNER_PROTECTED on every exec
// inside the chain, and is_resource_owner() matches on that same inherited
// exec_origin - so such a helper, running a completely unrelated binary, is
// recognised as an owner of the app's vaults. This bit stops that: an
// external helper gets no entry at all, so it inherits neither protection
// nor owner standing, and protected_selfexec_forbidden() never fires on it
// even with self-injection protection switched on.
#define OWNER_NO_EXTERNAL_INHERIT 0x4u

// The corpus's `basic_protection` tier (config.rs). Enforce this app's owner
// allowlist on its own corpus-listed files, and make NO claim about its
// process: it is never entered into protected_owner_pids, so it gets no
// ptrace/kill immunity, no foreign-library mmap gate, no anon-exec or JIT
// policing. Chain identity is still stamped, so the app's own interpreters
// and helpers still resolve to it for the file check.
//
// For apps whose runtime cannot be judged honestly - there is no Linux
// signature story, and a self-updating binary installed by a curl script
// into $HOME gives us nothing to validate against. "Is the opener the binary
// the corpus names" is answerable from inode alone; "is this process's
// memory safe" is not, and guessing it wrong kills a running app.
#define OWNER_BASIC_ONLY          0x8u

// Set only for an owner userspace resolved to a Flatpak sandbox layout
// (<bundle>/files/bin/<name>). bprm_creds_for_exec normally records
// exec_origin.dir_dev/dir_ino as the owner binary's own immediate parent
// directory (here, files/bin) - a same-install sibling under files/lib/...
// is never an ancestor of files/bin (they're siblings under files), so
// image_is_internal_to_origin()'s ancestor walk (run from the sibling's own
// dentry) can never reach it, and a legitimate same-bundle helper reads as
// external. This bit climbs one extra parent level when stamping the origin
// directory so it lands on files itself - an ancestor of every subtree in
// the bundle - instead of files/bin.
#define OWNER_ORIGIN_ROOT_UP1     0x10u

// Sized above the highest CONFIG_* index in use, with headroom: an ARRAY
// map rejects an out-of-range index, and a config write that fails is
// silent on the kernel side (userspace sees a false return it mostly only
// logs), so a new index added past the end reads as "the setting had no
// effect" rather than as an error. Every unset slot is zero, which every
// CONFIG_* here treats as its off/default state.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, uint32_t);
    __type(value, uint32_t);
} config_map SEC(".maps");

// Agent-core tamper resistance: the (dev,ino) of the bpffs
// directory this object pins its own LSM/kprobe links under
// (/sys/fs/bpf/warden - shared by both products, see core/CLAUDE.md's
// "kinnector.bpf.c is shared" section) plus the pid of whichever process
// loaded it. Populated ONCE, entirely in C++, by EbpfLoader::LoadAndAttachLsm
// right after it creates/confirms that directory - no Rust/FFI wiring needed
// on either product's side, so this activates for Warden and Antitheft
// identically. `inode_unlink` (below/see kinnector_container_lsm_hooks.h)
// denies removing anything under this directory unless the caller IS
// `owner_pid` - i.e. the daemon's own normal unpin-at-shutdown/hot-reload
// path keeps working, but `rm`/`bpftool` from any other process, including
// root, does not. Single entry, zeroed until the loader runs - a zeroed
// dir_id matches nothing real, so an unpopulated agent denies nothing extra,
// same "no gate needed" shape as untrusted_dir_names_map above.
struct core_pin_guard {
    struct resource_id dir_id;
    uint32_t owner_pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct core_pin_guard);
} core_pin_guard_map SEC(".maps");

// Residual-gap close #2: the (dev,ino) of the daemon's own
// binary (slot 0) and the .bpf.o it actually loaded (slot 1), so file_open
// can deny a write to either unless the writer is the package manager
// itself. This is the kernel-level deny the antitheft-agent's
// check_self_integrity() doc names as missing ("a real kernel-level deny
// here needs a corpus/owner-allowlist entry naming dpkg as the sole
// legitimate writer") - dpkg-legitimacy already exists as
// pkg_lifecycle_pids' depth mechanism (see that map's doc just below), so
// this needs no new legitimacy concept, only two new protected identities.
// Same "populate last, in C++, no Rust/FFI wiring" shape as
// core_pin_guard_map above: EbpfLoader::LoadAndAttachLsm stat()s
// /proc/self/exe and whichever bpf_obj_path_ tier actually loaded, after
// every pin is up. No owner_pid exemption here (unlike core_pin_guard_map) -
// legitimacy for these two files is "package-manager depth 1", not "the pid
// that loaded us", since it's dpkg on upgrade, not the running daemon
// itself, that is expected to rewrite them. Antitheft-only: gated on
// is_antitheft_mode() at the check site in kinnector_lsm_hooks_exec.h -
// Warden ships its own binary through a different channel and is out of
// scope for this gap, so populating this map is harmless-but-inert under
// Warden even though population itself is unconditional.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, uint32_t);
    __type(value, struct resource_id);
} core_self_integrity_map SEC(".maps");

/// One hash lookup in place of a chain of character comparisons. Returns 0 for
/// an unknown name, which every caller must read as "no class" - never as
/// "allowed".
static __always_inline uint32_t exe_name_classes(const void *name32) {
    uint32_t *cls = bpf_map_lookup_elem(&exe_name_class_map, name32);
    return cls ? *cls : 0;
}

/// Whether the loader has populated the name table yet. See
/// CONFIG_EXE_CLASSES_READY: the admin check is an allowlist, so running it
/// against an empty table would deny every exec in an admin tree.
static __always_inline int exe_classes_ready(void) {
    uint32_t idx = CONFIG_EXE_CLASSES_READY;
    uint32_t *v = bpf_map_lookup_elem(&config_map, &idx);
    return v && *v == 1;
}

// Antitheft-only, MODE_ANTITHEFT-gated.
// Key: a protected resource's (dev, inode) identity (Phase 6 composite key;
// same identity space as sensitive_inodes_map/protected_static_inodes). Value:
// a 64-slot bitmask; each legitimate owner process is represented by hashing
// its executable's inode into one of 64 slots (see resource_owner_hash()
// below) and setting that bit. This trades a small, bounded
// false-negative-owner rate under hash collision (undercounts as "not an
// owner" only when two configured owners collide into the same slot, which then
// both still match) for a fixed-size BPF map value — a full inode set isn't
// representable as a single BPF hash-map value.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct resource_id);
    __type(value, uint64_t);
} resource_owner_map SEC(".maps");

// SECURITY FIX: the 64-slot mask above cannot be the whole
// answer. Folding an owner's executable inode into 6 bits means one in 64
// unrelated binaries is accepted as that owner - and an attacker does not
// have to wait for the coincidence. The owner binary is world-readable, so
// its inode (and therefore its slot) can simply be stat'd, and inode numbers
// are handed out predictably enough that creating copies of an attacker
// binary until one lands in the target slot takes a couple of hundred
// attempts. Confirmed live against this kernel before the fix: a binary that
// owned nothing, sharing the owner's slot, read a protected resource.
//
// The mask is kept, but demoted to what it is actually sound for: a cheap
// negative pre-filter, and the record of whether a resource is tracked at
// all. Membership is decided by this exact map. Population is entirely from
// userspace (EbpfLoader keeps the authoritative per-resource owner set so it
// can delete precisely, which BPF cannot do - maps are not enumerable from a
// program), alongside resource_exact_known below.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct owner_link);
    __type(value, uint8_t);
} resource_owner_exact SEC(".maps");

// 1 when `resource_owner_exact` holds the complete owner set for this
// resource, i.e. userspace has registered it. Absent means no exact
// information exists for that identity and the mask alone still decides -
// which is the case for an identity the kernel itself just carried
// protection onto during a swap, before userspace has caught up. Those
// identities are covered by resource_owner_alias instead, so the mask-only
// path is a genuine last resort rather than the normal case.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct resource_id);
    __type(value, uint8_t);
} resource_exact_known SEC(".maps");

// Swapped-in identity -> the identity whose protection was carried onto it.
// `sync_carry_forward_protection` runs inside the rename/link/symlink hooks
// and has both identities, but it cannot copy the exact owner set (it would
// have to enumerate a map), so it records where that set lives instead and
// `is_resource_owner` follows the link. Without this, every synchronous
// carry-forward would fall back to mask-only matching and reopen exactly the
// hole this change closes, for as long as userspace took to catch up.
//
// LRU rather than a plain hash: entries are written by kernel hooks on a
// path any unprivileged process can drive (rename/link in its own
// directory), with no natural cleanup point, so this must not be allowed to
// grow without bound. Eviction fails closed - a lost alias degrades that
// identity to the mask-only path, never to "allow".
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct resource_id);
    __type(value, struct resource_id);
} resource_owner_alias SEC(".maps");

// The new dentry a link(2)/symlink(2) is creating, per calling thread
// (bpf_get_current_pid_tgid), written by `inode_link`/`inode_symlink` and
// taken by `lsm_d_instantiate`, which applies the path-name closure only to
// that dentry. d_instantiate also runs for a plain lookup of a file already on
// disk, and protected_path_names_map is never pruned, so applying it on every
// instantiation would re-protect a name the daemon has since released. LRU:
// any process can drive link(2), and a link that fails before instantiating
// leaves its entry behind (the next link by that thread overwrites it, and a
// mismatching dentry is ignored).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, uint64_t);
    __type(value, uint64_t);
} pending_link_dentries SEC(".maps");

// Resource-swap-defense synchronous-closure follow-up: see path_name_id's
// own declaration comment above for why this exists and what it's keyed by.
// Same 4096-entry sizing precedent as resource_owner_map (one entry per
// enforced resource path, not per inode - swaps don't grow this map).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct path_name_id);
    __type(value, struct path_protection);
} protected_path_names_map SEC(".maps");

// Directory-keyed synchronous protection (closes the gap where new secret
// files in a protected directory were unprotected for up to 60s, the
// periodic discovery timer). Keyed on a DIRECTORY's own (dev, ino) -
// ownership.rs populates this ONLY for a resource's immediate parent
// directory when that resource came from a corpus locator whose pattern is
// a wildcard directly inside that directory (e.g. `~/.electrum/wallets/*`)
// - i.e. the corpus author already declared "everything matching this glob
// here is equally sensitive". A brand-new file created inside such a
// directory - a name never seen before, so sensitive_inodes_map/
// resource_owner_map have no entry for it yet - inherits the SAME
// protection synchronously, at creation time (kprobe on d_instantiate - see
// that hook's own comment for why, not a vfs_create() fexit as first
// attempted), rather than waiting for the next periodic discovery pass to
// notice and register it.
//
// Deliberately NOT the same thing as protected_dir_map/storage_dir_verdict
// just below: that one is an intentionally BROAD, multi-level ancestor walk
// used only for `.so`-named writes (anti-injection), and explicitly must
// never affect file_open's general read gate (see that map's own comment).
// This map does the opposite: ONE level only (the exact parent directory,
// no ancestor walk), and IS meant to gate a normal file_open read - but only
// inside directories ownership.rs explicitly opted in via a wildcard
// pattern, never a directory registered by an exact filename (a browser
// profile's `Login Data`, say, never causes its containing folder to gain
// this).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct resource_id);
    __type(value, struct path_protection);
} glob_owned_dirs_map SEC(".maps");

// Storage-dir write/mmap protection (universal - no corpus
// data). ownership.rs's register_link registers not just a resource's own
// (dev, ino) but a bounded walk of its ancestor directories too (see its
// storage_dir_ancestors() doc), with the SAME owner set as the resource
// itself. These two maps are that directory registration's kernel-side
// storage - deliberately separate from resource_owner_map/
// resource_owner_exact/sensitive_inodes_map: a directory registered here
// must never affect file_open's general read-gate (listing/reading an
// ordinary file inside a protected storage dir stays completely
// unrestricted) - it only feeds storage_dir_verdict(), which file_permission
// consults for `.so`-named WRITES and mmap_file consults to decide whether
// a `.so` living in an app's own storage dir should be trusted to LOAD.
// Same 64-slot mask + exact-membership scheme as resource_owner_map/
// resource_owner_exact (see those maps' own declaration comments for the
// collision tradeoff) - deliberately no alias-following/swap-defense
// counterpart to resource_owner_alias/resource_exact_known: directories
// aren't yet subject to the rename/hardlink carry-forward file resources
// are, so dir_owner_verdict() only ever consults these two maps directly.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct resource_id);   // the directory's own (dev, ino)
    __type(value, uint64_t);           // 64-slot owner-hash mask
} protected_dir_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct owner_link);    // directory id + owner id
    __type(value, uint8_t);
} protected_dir_owner_exact SEC(".maps");

// Map: (pid, start_time) -> exfiltration taint hops
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct process_key);
    __type(value, uint32_t);
} tainted_process_map SEC(".maps");

// Map: (dev, directory inode) -> 1 (bypass telemetry for DB data dirs). Phase 6:
// composite key. Only honoured for processes with ROLE_DATABASE set in
// process_threshold_map.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct resource_id);
    __type(value, uint8_t);  // 1 = bypass
} bypassed_directories SEC(".maps");

// keyed on (pid, start_time), not raw pid —
// a raw-pid key let a since-exited npm-descended process's TREE_INSTALL_CONTEXT
// stamp be inherited by an unrelated new process that reuses the same PID.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct process_key);
    __type(value, uint32_t);
} pid_tree_type_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint32_t);
    __type(value, uint8_t);
} jvm_exception_pids SEC(".maps");

struct db_allowlist_key {
    uint32_t pid;
    uint32_t ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct db_allowlist_key);
    __type(value, uint8_t);
} db_outbound_allowlist SEC(".maps");

struct infra_allowlist_key {
    uint32_t pid;
    uint32_t ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct infra_allowlist_key);
    __type(value, uint8_t);
} infra_outbound_allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint64_t);
    __type(value, uint8_t);
} exec_allowlist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, uint64_t);
    __type(value, uint8_t);
} trusted_admin_binaries SEC(".maps");

// userspace-populated, sourced from
// protect-community/configs/warden/package_manager_signatures.json via
// kinnector_config's package_manager_signatures() — replaces is_install_binary()'s
// old hardcoded string scan so adding a new ecosystem is a config change, not a
// kernel-object rebuild. Key: the resolved package-manager binary's inode.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, uint64_t);
    __type(value, uint8_t);
} install_binary_map SEC(".maps");

// Antitheft-only, config-driven list of binaries
// that should get the same ptrace/signal owner-process protection Warden's own
// binary and TREE_ADMIN_SESSION processes already get -- e.g. a password manager.
// Same shape/population convention as install_binary_map (Phase 4): key = the
// configured owner binary's inode.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, uint64_t);
    __type(value, uint8_t);
} protected_owner_binaries SEC(".maps");

// Phase 5: (pid, start_time) -> OWNER_* bit set (see their definitions),
// stamped at exec time in bprm_creds_for_exec when the exec'd binary's inode
// matches protected_owner_binaries, and from userspace (antitheft-agent's
// ProcessCreate handler) for corpus-classified apps, which is also the only
// populator that can set OWNER_JIT_SELFEXEC - JIT-capability comes from the
// support corpus, not from anything the kernel can see. Mirrors
// admin_session_pids' own "detect a pattern at exec/login time, stamp the
// process" population shape, but correctly keyed on process_key from the start
// (admin_session_pids predates the Phase 2 fix and is intentionally left alone,
// out of that phase's scope -- no reason to inherit its raw-pid key here too).
//
// Propagated across fork by tracepoint_sched_process_fork so a protected app's
// helper processes are covered as one family: an Electron browser's crash
// handler ptrace-attaches its siblings as normal operation, and a
// non-AppImage app's helpers exec a different binary than the one the corpus
// matched, so without inheritance they would be strangers to their own parent.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct process_key);
    __type(value, uint8_t);
} protected_owner_pids SEC(".maps");

// Supply-chain defense (antitheft.md section 4): (pid, start_time) -> install
// DEPTH for a process running inside a package manager's install. Written by
// userspace as PKG_LIFECYCLE_ROOT (1) when it sees a package-manager binary
// exec, and propagated across fork by tracepoint_sched_process_fork with the
// depth incremented at every real fork (never for a new thread) - ancestry
// recorded at birth, never asked for afterwards, so a lifecycle script cannot
// escape it by detaching or by re-parenting itself.
//
// The depth is what separates the package manager's OWN work from the
// arbitrary code it runs on the package's behalf, and both halves matter:
//
//   1  the package manager itself (apt, dpkg, npm, cargo, pip ...). It has to
//      write a unit file into /usr/lib/systemd/user while unpacking a
//      package, and read its own registry credentials (~/.npmrc,
//      ~/.cargo/credentials.toml). Denying those killed a real `apt upgrade`
//      mid-transaction (dpkg refused its own
//      keyboxd.service.dpkg-new write, leaving gnupg half-configured) and
//      breaks every private-registry install. The ordinary ownership rules
//      still apply to it, so it reads only what it is a registered owner of.
//   2+ anything the package manager forked: a Debian maintainer script, an
//      npm postinstall hook, a build.rs binary. That is the arbitrary-code
//      surface this rule exists to contain - it runs automatically, with
//      your privileges, and reading a wallet is the single most common way
//      developers actually lose keys. Nothing there has a legitimate reason
//      to read a LOCKED store (one with an owner set in resource_owner_map:
//      a wallet, a browser's saved passwords) or to write an autostart
//      entry, so both are denied outright, regardless of whether the
//      process would otherwise be a registered owner. An OBSERVED
//      (audit-only, no owner set) store is NOT refused to it:
//      SSH keys, cloud CLI credentials, .npmrc/.netrc
//      and .env files are read by legitimate installs (git+ssh deps,
//      private registries, credential providers), so such a read is allowed
//      and recorded by file_open's ordinary verdict=1 emission.
//
// A package manager exec'd by another package manager (apt -> dpkg) is
// re-stamped to depth 1 by userspace; one exec'd by a lifecycle script
// (postinst -> npm) keeps its inherited depth. That decision lives in the
// agent (origin_classifier.rs::stamps_package_manager_root) because only it
// knows the corpus's binary names - the kernel just counts forks.
// Value layout: bits 0-6 are the depth, bit 7 (PKG_LIFECYCLE_DISTRO) says the
// install root is an OS package manager (apt/dpkg, rpm, pacman, apk, zypper -
// the corpus's scripts_manage_persistence flag). Their maintainer scripts run
// as root, are signed by the distribution, and LEGITIMATELY manage
// persistence: update-rc.d symlinks into /etc/rc*.d, deb-systemd-helper
// aliases and mkdirs under /etc/systemd/system, pam-auth-update rewrites
// /etc/pam.d/common-*, and a root script can `systemctl enable` a unit over
// D-Bus, which no file hook ever sees. Denying those breaks package
// configuration without stopping a root attacker, so for DISTRO descendants
// the persistence rule is visibility only (verdict 6, never -EACCES), while
// the locked-store rule stays a deny for everyone - a maintainer script has
// no more business reading a wallet than an npm hook does. A language
// ecosystem's install script (npm, pip, cargo ...) has no legitimate
// persistence business at all, and there the deny is decisive.
#define PKG_LIFECYCLE_ROOT       1
#define PKG_LIFECYCLE_DESCENDANT 2
#define PKG_LIFECYCLE_DEPTH_MASK 0x3f
// Set once, never cleared: this process has exec'd an image that is neither a
// registered credential helper nor a registered package-manager image - i.e.
// arbitrary code has run in it. Inherited across fork, so it taints the whole
// subtree below the point where the chain was broken.
//
// It exists because both of the rules below used to read the process's
// CURRENT image, which `exec` makes a lie: `exec` swaps the program while
// keeping the process, so a lifecycle script that runs `exec gh` stops
// looking like "a script ran gh" (denied) and starts looking like "the
// package manager ran gh itself" (allowed, and legitimately so - that is how
// `go mod download` authenticates a private fetch). Measured live: a script
// forking gh was denied, the same script exec'ing gh was allowed, and the
// same trick with `exec mvn` re-rooted the whole subtree out of the install
// context entirely. Depth alone cannot separate them, because both land at
// the same depth. What separates them is whether anything other than a
// helper or a manager has run in that process on the way there.
#define PKG_LIFECYCLE_RAN_OTHER_CODE 0x40
#define PKG_LIFECYCLE_DISTRO     0x80
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);  // an npm/cargo install runs thousands of lifecycle scripts
    __type(key, struct process_key);
    __type(value, uint8_t);
} pkg_lifecycle_pids SEC(".maps");

// An exec's ProcessCreate + EnvironmentMarkers, filled at sys_enter_execve(at)
// and held by THREAD id until tracepoint_sched_process_exec (a successful exec;
// its old_pid is that thread id even when a non-leader thread exec'd) emits
// them. Before, every attempt was emitted at the syscall: a
// `$PATH` search produced one pair per folder tried (56 events for one cargo
// launch), and the agent, handling them tens of ms to seconds later, read the
// process's install mark after a short-lived process had already exited.
// LRU: an entry left by a thread whose last exec failed is reclaimed (and
// deleted at that thread's exit), so the map never fills up and refuses.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 512);
    __type(key, uint32_t);
    __type(value, struct exec_stash);
} exec_stash_map SEC(".maps");

// Where the execve tracepoints build an exec's events (3.2 KB: far over the
// 512-byte BPF stack).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct exec_stash);
} exec_stash_scratch SEC(".maps");

// Directories where a persistence entry would be planted - autostart, user
// systemd units, cron. Keyed by the DIRECTORY's own (dev, ino), populated
// from the support corpus's persistence_locations at startup, and consulted
// for the parent of any file being created or written. A directory identity
// is used rather than a path so a symlinked or bind-mounted route to the same
// directory is the same entry.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct resource_id);
    __type(value, uint8_t);
} persistence_dirs_map SEC(".maps");

// The other half of the persistence corpus: `append_file` locations -
// ~/.bashrc, /etc/crontab, /etc/ld.so.preload - which are single FILES, not
// directories anyone drops entries into. Keyed by (parent dir identity, leaf
// name hash), the same path_name_id shape protected_path_names_map uses, so
// the entry exists whether or not the file does today (a descendant creating
// a missing ~/.zshrc is exactly as much persistence as appending to one),
// and survives the file being replaced by rename. These used to be
// registered as their PARENT directory instead, which made /etc and
// $HOME themselves "persistence dirs": any install descendant creating any
// file in /etc was denied - useradd's /etc/passwd+, ldconfig's
// /etc/ld.so.cache~ - one apt install of a shared library away from the
// same broken transaction the depth fix above closed.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct path_name_id);
    __type(value, uint8_t);
} persistence_names_map SEC(".maps");

// Package-manager image identities (dev, ino), resolved by the agent from
// the package_managers corpus's binary names at startup. Consulted by
// bprm_creds_for_exec to re-root the install depth synchronously at exec -
// see that hook's comment and pkg_lifecycle_pids' doc.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct resource_id);
    __type(value, uint8_t);
} pkg_manager_images SEC(".maps");

// Runtime-revocation plan: Antitheft-only, (pid, start_time) -> reason
// bitflags. Populated entirely from userspace (agent/src/runtime_integrity.rs)
// via the generic update_map_entry/delete_map_entry FFI path (BpfMapType::
// RevokedPidMap), never kernel-self-stamped -- unlike protected_owner_pids
// above, there's no exec-time pattern to match here, only a later runtime
// finding (unsafe memory-exec event, or a ptrace attach) that revokes an
// already-registered owner's standing. Consulted by file_open/file_permission
// alongside resource_owner_map: presence with a non-zero value means "deny
// even if otherwise a registered owner." Value type is uint32_t (not uint8_t
// like protected_owner_pids) to leave room for distinguishing revocation
// reasons later; today any non-zero value denies.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct process_key);
    __type(value, uint32_t);
} revoked_pid_map SEC(".maps");

// Chain identity (B2): every resolved
// owner file - binaries, scripts, AppImages - keyed by (dev, ino), value =
// OWNER_* flags the exec hook stamps onto the process (OWNER_PROTECTED is
// always set; OWNER_JIT_SELFEXEC comes from the corpus). Populated from
// userspace alongside resource_owner_exact; Antitheft-only.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct resource_id);
    __type(value, uint32_t);
} owner_images SEC(".maps");

// Credential helpers a package manager launches DIRECTLY to authenticate a
// fetch - git, gh, ssh, git-credential-*. Keyed by (dev, ino) like
// owner_images, populated from the corpus's credential_helpers.json.
//
// The supply-chain rule below denies an install's descendants EVERY protected
// secret regardless of ownership, which is right for a lifecycle script and
// wrong for the fetch itself: reproduced live, `gh auth status` succeeds run
// directly and is refused its own config.yml under `go run`, so a private
// module cannot authenticate. These binaries are exempt from that deny at
// fork depth 2 ONLY - a DIRECT child of the package manager, which is what a
// fetch is. A lifecycle script always sits at least one shell deeper
// (npm -> sh -c postinstall -> gh is depth 3), so the exemption covers the
// fetch path without opening the attack path.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct resource_id);
    __type(value, uint8_t);
} credential_helper_images SEC(".maps");

// Package-owned system libraries whose live CONTENT no longer matches what
// their package manager recorded, keyed by (dev, ino) like owner_images.
// Antitheft-only, and filled entirely by userspace (agent/src/
// modified_library_gate.rs) through the AddModifiedLibrary/
// RemoveModifiedLibrary/ClearModifiedLibraries FFI - the kernel never adds to
// it. Consulted by mmap_file for a protected-owner process ONLY, BEFORE the
// three trust rules of the untrusted-.so deny (root-owned, user-owned exec
// origin, own storage dir): those rules trust a root-owned file by its owner
// alone, which is exactly how a trojaned /usr/lib/.../libfoo.so passes.
// A hit takes the same path as that deny (EVT_IMAGE_LOAD verdict 1, -EACCES),
// no new event, no new alert.
//
// FAIL OPEN by construction: an empty map denies nothing, a missing/full map
// is a failed userspace write that leaves the set smaller, and the agent
// clears the whole set the moment the package database it judged against
// changes. Small on purpose: on an untampered machine this holds zero
// entries, and userspace refuses to write a mass of them at once (a mass
// mismatch means the digest table is wrong, not that a mass of libraries was
// modified).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct resource_id);
    __type(value, uint8_t);
} modified_system_libraries SEC(".maps");

// Chain identity: (pid, start_time) -> the owner image this process's chain
// started from. See struct exec_origin. Written by bprm_creds_for_exec and
// tracepoint_sched_process_fork, read by is_resource_owner, deleted on exit
// and on a credential change.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);  // every descendant of an owner image carries one
    __type(key, struct process_key);
    __type(value, struct exec_origin);
} exec_origin_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);  // every process of an interactive terminal tree, a parallel build included
    __type(key, uint32_t);
    __type(value, uint8_t);
} admin_session_pids SEC(".maps");

// Phase 6: composite key.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct resource_id);
    __type(value, uint8_t);
} newly_created_inodes SEC(".maps");

// Phase 6: composite key.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct resource_id);
    __type(value, uint8_t);
} protected_static_inodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, uint32_t);
    __type(value, uint8_t);
} env_read_count_map SEC(".maps");

// P2-9: Per-CPU atomic sequence counter for event ordering
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, uint64_t);
} seq_counter SEC(".maps");

struct fs_batch_key {
    uint32_t pid;
    uint32_t op_type; // 1 = READ, 2 = WRITE, 3 = DELETE, 4 = MMAP_EXEC, 5 = EXEC, 6 = SYSCALL
    uint64_t inode;
};

struct fs_batch_value {
    uint64_t count;
    uint64_t last_flush;
    char file_path[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct fs_batch_key);
    __type(value, struct fs_batch_value);
} fs_batch_map SEC(".maps");

struct scratch_buf {
    char path[256];
    struct fs_batch_value new_val;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct scratch_buf);
} scratch_map SEC(".maps");

// Ring buffer for sending events to kinnect-agent
// P2-12: Increased to 16MB to reduce event loss under high load
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    // Alert-visibility audit: live-verified via bpf_printk on a
    // real, busy desktop (Chrome + Codium + Docker + virt-manager all
    // running) that bpf_ringbuf_reserve() was failing for a rare, isolated
    // antitheft owner-check deny (a single denied `cat` of a protected
    // file) - confirmed NOT saturated by that check itself (only 2 hits in
    // a 5s trace window), so the pressure comes from this ring buffer's
    // aggregate volume across every OTHER hook on a real system, not any
    // one antitheft-specific path. Same class of problem P2-12 already
    // doubled this for once; 64MB is a further, empirically-motivated
    // safety margin, not a guess.
    __uint(max_entries, 1 << 26); // 64MB (was 16MB, was 4MB)
} telemetry_ringbuf SEC(".maps");

// Telemetry drop accounting. bpf_ringbuf_reserve() returning
// NULL when the buffer is full is the only way an event is lost, and every
// one of this file's reserve sites handles that with a bare `if (event)` -
// no counter, no log, nothing anywhere. libbpf's consumer side has no
// lost-event notion for a ringbuf either, so a drop left no trace at all,
// and "the agent never saw that exec" was indistinguishable from "that exec
// never happened". Exec is counted first because it is the one measured:
// roughly 1 in 8 lost under container workloads, which silently weakens
// every rule that needs a process's first exec.
//
// PER-CPU so counting costs no atomic on the hot path; the reader sums.
// Only the exec producers are wired up - the other reserve sites in this
// file remain uncounted, and doing them needs a mechanical pass over all of
// them rather than a guess about which matter.
#define STAT_EXEC_EMITTED 0
#define STAT_EXEC_DROPPED 1

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, uint32_t);
    __type(value, uint64_t);
} telemetry_stats SEC(".maps");

// Real kernel start_time for every running process, keyed by tgid
// . Userspace needs this to address the (pid, start_time) maps
// for a process that predates the daemon: /proc/<pid>/stat's starttime is
// quantized to USER_HZ by a one-way floor conversion, so a key built from it
// essentially never matches the task's real nanosecond value. antitheft's
// startup backfill was writing exactly such keys - the kernel could not find
// them on lookup (so every pre-existing protected app was unprotected at the
// kernel level, an open gap its own module doc describes), and the exit
// handler could not find them to delete either, so they accumulated for the
// life of the daemon in a map that fails OPEN when full.
//
// Filled on demand by the iter/task program below, which userspace drives by
// reading the iterator fd. Read-mostly and small: one entry per live process,
// overwritten on each refresh, never consulted by any enforcement path.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, uint32_t);
    __type(value, uint64_t);
} task_start_times SEC(".maps");

static __always_inline void bump_stat(uint32_t idx) {
    uint64_t *slot = bpf_map_lookup_elem(&telemetry_stats, &idx);
    if (slot) {
        // Per-CPU array: this CPU owns its own copy, so a plain increment is
        // race-free without __sync_fetch_and_add.
        *slot += 1;
    }
}

struct tty_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t len;
    uint8_t  is_write;
    char     comm[16];
    char     data[1024];
} __attribute__((packed));

struct tty_read_req {
    struct file *file;
    // The user-space destination resolved from the iov_iter on entry - the
    // kretprobe only receives the return value and cannot reach the iter.
    void *buf;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4MB
} tty_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint32_t); // thread ID
    __type(value, struct tty_read_req);
} pending_tty_reads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);  // an LRU
    __type(key, uint64_t);
    __type(value, uint64_t);
} dns_cache_map SEC(".maps");

// ---------------------------------------------------------------------------
// Firewall — egress-only in-kernel CIDR table (Firewall design plan, 2026-08).
//
// Two LPM_TRIE maps (v4/v6 need separate fixed-width keys — LPM_TRIE keys
// can't be variable-length). Userspace (warden's EbpfBackend,
// warden/src/firewall/backend.rs) owns the desired-state diff and issues
// one bpf_map_update_elem/delete_elem per CIDR; rule_id in fw_value is for
// audit/introspection only (bulk revoke-by-rule happens in userspace, which
// tracks which CIDRs belong to which rule — LPM_TRIE has no secondary index
// for that). Checked only from lsm/socket_connect (egress) — socket_listen
// and socket_accept do not enforce (see those hooks' comments below);
// real inbound eBPF enforcement would need an XDP/TC program this codebase
// doesn't have yet, so inbound blocking stays iptables/nftables-only.
#define FW_ACTION_ALLOW 0
#define FW_ACTION_DENY  1

struct fw_key4 {
    uint32_t prefixlen; // must be first field, in bits (0-32) — LPM_TRIE requirement
    uint8_t  addr[4];   // network-byte-order IPv4
} __attribute__((packed));

struct fw_key6 {
    uint32_t prefixlen; // bits, 0-128
    uint8_t  addr[16];
} __attribute__((packed));

struct fw_value {
    uint32_t rule_id;   // opaque id from warden's firewall_rules.json — audit only
    uint16_t port;      // 0 = any. LPM_TRIE can't match on port (not part of the
                         // key's prefix bytes), so this is informational only —
                         // a port-scoped rule is enforced precisely by iptables
                         // instead (see reconcile::select_backend_for_rule) and
                         // applied here as CIDR-wide to avoid under-blocking.
    uint8_t  proto;     // 0=any, 6=TCP, 17=UDP — not matched here, audit only
    uint8_t  direction; // reserved for future ingress support; always egress today
    uint8_t  action;    // FW_ACTION_ALLOW | FW_ACTION_DENY
    uint8_t  _pad[3];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC); // required by the kernel for LPM_TRIE
    __uint(max_entries, 131072);
    __type(key, struct fw_key4);
    __type(value, struct fw_value);
} fw_rules_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 32768);
    __type(key, struct fw_key6);
    __type(value, struct fw_value);
} fw_rules_v6 SEC(".maps");


#endif  // KINNECTOR_BPF_MAPS_H
