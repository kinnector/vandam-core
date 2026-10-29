#ifndef KINNECTOR_CLOUD_ABI_H
#define KINNECTOR_CLOUD_ABI_H

// Wire layout shared by kinnector_cloud.bpf.c (kernel side), cloud_collectors.cpp
// (loader/drain) and the FFI structs the antitheft agent mirrors in ffi.rs.
// Layout only, no logic. Every struct is naturally aligned with no implicit
// padding: the agent reads them as raw bytes.
//
// bench/netbench, bench/filebench for the measurements this shape comes from.

#if defined(__bpf__)
/* vmlinux.h already supplies __u8 .. __u64 */
#elif defined(__linux__)
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

#if defined(_MSC_VER)
#define CLOUD_ABI_INLINE static __forceinline
#else
#define CLOUD_ABI_INLINE static inline __attribute__((always_inline))
#endif

#define CLOUD_ABI_VERSION 1

// ---- ring buffer records (network) ------------------------------------------

#define CLOUD_REC_TCP_CLOSE 1  // one record when a TCP connection closes
#define CLOUD_REC_TCP_LIVE  2  // long-lived connection whose counters changed since the last scan
#define CLOUD_REC_DNS       3  // a DNS query seen on a UDP send to port 53

#define CLOUD_DIR_OUT 0
#define CLOUD_DIR_IN  1

// flags
#define CLOUD_F_ESTABLISHED 0x01  // the handshake completed (peer sequence known)
#define CLOUD_F_ERROR       0x02  // sk_err was set at close (refused, reset, timed out)

struct cloud_net_rec {
    __u64 dur_ns;
    __u64 tx;          // bytes sent by this side, from the kernel's own counters
    __u64 rx;          // bytes received
    __u64 proc_start;  // group leader task->start_time of the owner
    __u64 cookie;      // unique per connection, so a live report and the close report can be told apart
    __u32 tgid;
    __u32 err;         // sk_err (positive errno) when CLOUD_F_ERROR
    __u16 family;      // AF_INET (2) / AF_INET6 (10)
    __u16 dport;       // remote port, host order
    __u16 lport;       // local port, host order
    __u8 kind;         // CLOUD_REC_TCP_*
    __u8 dir;          // CLOUD_DIR_*
    __u8 flags;
    __u8 pad[7];
    __u8 daddr[16];    // remote address (4 bytes used for IPv4)
};

#define CLOUD_DNS_PAYLOAD 112

struct cloud_dns_rec {
    __u64 proc_start;
    __u32 tgid;
    __u16 len;         // payload bytes valid
    __u8 kind;         // CLOUD_REC_DNS
    __u8 pad;
    __u8 payload[CLOUD_DNS_PAYLOAD];  // raw DNS message start (header + QNAME)
};

// ---- folded maps, drained by userspace ------------------------------------

// UDP peers, folded per (process, peer). Also drained by userspace.
struct cloud_udp_key {
    __u64 proc_start;
    __u32 tgid;
    __u16 dport;
    __u16 family;
    __u8 daddr[16];
};

struct cloud_udp_val {
    __u64 tx;
    __u64 rx;
    __u64 pkts;
    __u64 first_ns;
    __u64 last_ns;
    __u16 lport;
    __u8 dir;          // direction of the first packet seen
    __u8 pad[5];
};

// File opens, folded per (process, project folder, operation, file-type class).
#define CLOUD_OP_READ  0
#define CLOUD_OP_WRITE 1

struct cloud_file_key {
    __u64 proc_start;
    __u64 dev;         // kernel-encoded s_dev of the file's filesystem
    __u64 proj_ino;    // inode of the project folder
    __u64 ext;         // up to 8 lowercase characters of the extension, little endian, 0 = none
                       // (contract v6: 4 before, which folded .sqlite3 into .sqli and .jsonl into .json)
    __u32 tgid;
    __u32 op;          // CLOUD_OP_*
};

// Registers per HyperLogLog sketch (directory rows since v5, file rows since v10): one BYTE each,
// 1.04/sqrt(64) ~= 13% standard error. See cloud_dir_hll_val below for the layout rationale.
#define CLOUD_HLL_M 64

struct cloud_file_val {
    __u64 count;
    __u64 first_ns;
    __u64 last_ns;
    // contract v10: the sum of the opened file's i_size over the FIRST open of each inode by this
    // process and op (file_seen, an LRU set of CLOUD_FILE_SEEN_MAX entries); a re-open adds
    // nothing. After an eviction a re-open counts again, so the error only ever raises the sum.
    // v9 summed every open (a VM image reopened 295 times summed to ~65 TB). File size, not
    // bytes read.
    __u64 bytes;
    // contract v10: the distinct-inode sketch of the files counted in `bytes` (same hash and
    // register rule as cloud_dir_hll_val), so the cloud can tell the same files read by several
    // processes of one story from different files.
    __u8 hll[CLOUD_HLL_M];
};

// The per-process first-open set behind cloud_file_val.bytes. One entry per (process, inode, op);
// an LRU map, so the bound is machine-wide (262,144 entries, ~26 MB, so an IDE or a search
// tool reading a whole large monorepo keeps every inode it read; still an LRU, and an eviction only ever raises a sum).
#define CLOUD_FILE_SEEN_MAX 262144

// Map and ring sizes of the cloud object (sized for modern developer and user machines, every
// failed insert counted). A hash map's kernel memory is about max_entries * (48 + key + value) bytes plus 16
// bytes per bucket (a power of two); a ring buffer's is its byte size. Maps marked NO_PREALLOC in
// kinnector_cloud.bpf.c hold memory only for the entries they use.
#define CLOUD_NET_RING_BYTES   (4u << 20)  // net close/live and DNS records, drained by the poll thread every 100 ms
#define CLOUD_UDP_FOLD_MAX       65536    // (process, peer) UDP flows between two drains
#define CLOUD_FILE_FOLD_MAX      65536    // (process, project, extension, op) file rows between two drains
#define CLOUD_SCOPE_ROOTS_MAX     4096    // home directories and user-data mounts (NO_PREALLOC)
#define CLOUD_SKIP_DIRS_MAX      16384    // pinned skip locations (NO_PREALLOC)
#define CLOUD_SCOPE_CACHE_MAX    65536    // LRU cache of per-directory scope verdicts (an eviction costs a re-walk, never data)
#define CLOUD_PROJ_PATH_MAX      65536    // project folders ever named (never drained, so it must outlast days; NO_PREALLOC)
// The exact-name set's DEFAULT size. The loader grows it (and name_ext_ok) to the policy's own
// size before the load, so a policy never names more than the kernel holds.
#define CLOUD_NAME_EXACT_ENTRIES  1024
struct cloud_file_seen_key {
    __u64 proc_start;
    __u64 dev;
    __u64 ino;
    __u32 tgid;
    __u32 op;
};

// The first file seen inside a project folder, so userspace can name the folder.
// Written once per (dev, project inode), never rewritten.
#define CLOUD_PATH_MAX 192

struct cloud_dir_key {
    __u64 dev;
    __u64 ino;
};

struct cloud_proj_val {
    __u32 root_kind;   // CLOUD_ROOT_*
    __u32 pad;
    char path[CLOUD_PATH_MAX];  // full path of the first file seen
};

#define CLOUD_ROOT_HOME      1
#define CLOUD_ROOT_DATA      2
#define CLOUD_ROOT_REMOVABLE 3

// ---- what the FFI hands to the agent ----------------------------------------
//
// cloud_net_rec (above) is passed through unchanged. The rest are decoded by the
// loader so the agent never touches BPF map layouts.

#define CLOUD_DNS_NAME_MAX 128

struct cloud_dns_name {
    __u64 proc_start;
    __u32 tgid;
    __u16 qtype;
    __u16 pad;
    char name[CLOUD_DNS_NAME_MAX];  // lowercased, NUL terminated, only [a-z0-9._-]
};

struct cloud_udp_row {
    struct cloud_udp_key key;
    struct cloud_udp_val val;
};

struct cloud_file_row {
    struct cloud_file_key key;
    struct cloud_file_val val;
};

struct cloud_proj_row {
    __u64 dev;
    __u64 ino;
    __u32 root_kind;
    __u32 pad;
    char path[CLOUD_PATH_MAX];
};

// The agent reads these as raw bytes, so a size change is an ABI change.
#ifdef __cplusplus
#define CLOUD_ABI_SIZE(T, N) static_assert(sizeof(T) == (N), #T " size changed")
#else
#define CLOUD_ABI_SIZE(T, N) _Static_assert(sizeof(struct T) == (N), #T " size changed")
#endif
#ifdef __cplusplus
CLOUD_ABI_SIZE(cloud_net_rec, 80);
CLOUD_ABI_SIZE(cloud_dns_rec, 128);
CLOUD_ABI_SIZE(cloud_udp_key, 32);
CLOUD_ABI_SIZE(cloud_udp_val, 48);
CLOUD_ABI_SIZE(cloud_file_key, 40);
CLOUD_ABI_SIZE(cloud_file_val, 32 + CLOUD_HLL_M);
CLOUD_ABI_SIZE(cloud_file_seen_key, 32);
CLOUD_ABI_SIZE(cloud_proj_val, 200);
CLOUD_ABI_SIZE(cloud_dns_name, 144);
CLOUD_ABI_SIZE(cloud_udp_row, 80);
CLOUD_ABI_SIZE(cloud_file_row, 72 + CLOUD_HLL_M);
CLOUD_ABI_SIZE(cloud_proj_row, 216);
#endif

// ---- counters ---------------------------------------------------------------

enum cloud_stat {
    CLOUD_STAT_NET_RING_FULL = 0,   // network record dropped, ring buffer full
    CLOUD_STAT_FILE_MAP_FULL = 1,   // a new file-fold row could not be inserted
    CLOUD_STAT_UDP_MAP_FULL  = 2,
    CLOUD_STAT_PROJ_MAP_FULL = 3,
    CLOUD_STAT_DNS_RING_FULL = 4,
    CLOUD_STAT_FILE_OPENS    = 5,   // regular-file opens seen while the file collector was on
    CLOUD_STAT_FILE_IN_SCOPE = 6,
    CLOUD_STAT_STAMP_FAIL    = 7,   // a connection could not be stamped (socket storage full): its bytes are never reported
    CLOUD_STAT_MAX
};

// ---- process lifecycle: fork, exec, exit (Phase 2 revised) ----
//
// Its own ring buffer (life_rb) with variable-length records: one fixed header
// (struct cloud_life_rec) followed, for an exec, by `exe_len` bytes of absolute
// executable path, `argv_len` bytes of the raw argument block (the arguments
// NUL-separated, exactly the bytes /proc/<pid>/cmdline shows) and `env_len` bytes of
// the raw environment block (NAME=value strings, NUL-separated, what /proc/<pid>/environ
// shows). None of them is NUL terminated by the kernel side; all are attacker-chosen
// bytes, so the reader must not assume UTF-8. The environment is RAW and may hold
// secrets: the agent must filter it before anything leaves the machine.
//
// A process key is (tgid, start): `start` is the GROUP LEADER's task->start_time on
// the monotonic clock, the same key every other cloud collector uses. `pstart` is
// the same for the real parent (what getppid() reports).
//
// The FFI hands the agent these records unchanged, each padded to 8 bytes.

#define CLOUD_LIFE_FORK 1  // a new PROCESS (never a thread) was created
#define CLOUD_LIFE_EXEC 2  // an exec SUCCEEDED (the point of no return was passed)
#define CLOUD_LIFE_EXIT 3  // the last thread of a process exited

#define CLOUD_LIFE_ARGV_MAX 8192  // bytes of arguments kept; more sets CLOUD_LIFE_F_ARGV_TRUNC
#define CLOUD_LIFE_EXE_MAX  1024  // exe path buffer including its NUL, so at most 1023 bytes
// Bytes of environment kept; more sets CLOUD_LIFE_F_ENV_TRUNC. The cloud object can be built
// with -DCLOUD_LIFE_ENV_MAX=8192 (the documented fallback if the hook cost breaks its budget),
// or 0 to leave the environment out entirely (used to measure what it costs).
#ifndef CLOUD_LIFE_ENV_MAX
#define CLOUD_LIFE_ENV_MAX  16384
#endif

#define CLOUD_LIFE_F_ARGV_TRUNC 0x01  // the argument block was longer than CLOUD_LIFE_ARGV_MAX
#define CLOUD_LIFE_F_ARGV_FAIL  0x02  // the arguments could not be read: argv_len is 0 though argv_total may not be
#define CLOUD_LIFE_F_EXE_RAW    0x04  // exe is bprm->filename as the caller wrote it (maybe relative): no resolved path was available
#define CLOUD_LIFE_F_EXE_NONE   0x08  // no executable path at all
#define CLOUD_LIFE_F_ENV_TRUNC  0x10  // the environment block was longer than CLOUD_LIFE_ENV_MAX
#define CLOUD_LIFE_F_ENV_FAIL   0x20  // the environment could not be read: env_len is 0 though env_total may not be

struct cloud_life_rec {
    __u64 ts_ns;       // bpf_ktime_get_ns() (CLOCK_MONOTONIC) at the event
    __u64 start;       // this process's group-leader start_time
    __u64 pstart;      // the real parent's group-leader start_time (0 if it has none)
    __u32 tgid;
    __u32 ptgid;       // real parent's tgid (getppid())
    __u32 aux;         // exit: the raw wait status (exit code << 8, or the signal in the low 7 bits, 0x80 = core); exec: bprm->argc
    __u32 argv_len;    // exec: argument bytes that follow the exe bytes
    __u32 argv_total;  // exec: the argument block's real size (>= argv_len)
    __u16 exe_len;     // exec: exe path bytes that follow the header
    __u8 kind;         // CLOUD_LIFE_*
    __u8 flags;        // CLOUD_LIFE_F_*
    __u32 env_len;     // exec: environment bytes that follow the argument bytes
    __u32 env_total;   // exec: the environment block's real size (>= env_len)
    __u32 envc;        // exec: bprm->envc, the exact number of environment strings
    __u32 pad;
};

// Bytes that follow the header: exe, then argv, then env.
#define CLOUD_LIFE_BODY(h) ((__u32)(h)->exe_len + (h)->argv_len + (h)->env_len)
// The largest record, before padding to 8.
#define CLOUD_LIFE_REC_MAX (64 + CLOUD_LIFE_EXE_MAX + CLOUD_LIFE_ARGV_MAX + CLOUD_LIFE_ENV_MAX)

// Kernel-side counters of the lifecycle programs (a separate array from cloud_stat, so
// the layout the agent already reads does not move).
enum cloud_life_stat {
    CLOUD_LIFE_STAT_FORKS = 0,          // fork records submitted
    CLOUD_LIFE_STAT_EXECS = 1,          // exec records submitted
    CLOUD_LIFE_STAT_EXITS = 2,          // exit records submitted
    CLOUD_LIFE_STAT_FORK_DROP = 3,      // dropped: the ring buffer was full
    CLOUD_LIFE_STAT_EXEC_DROP = 4,
    CLOUD_LIFE_STAT_EXIT_DROP = 5,
    CLOUD_LIFE_STAT_ARGV_FAIL = 6,      // execs whose argument block could not be read
    CLOUD_LIFE_STAT_ARGV_TRUNC = 7,     // execs whose argument block was cut at CLOUD_LIFE_ARGV_MAX
    CLOUD_LIFE_STAT_EXE_RAW = 8,        // execs that fell back to the unresolved bprm->filename
    CLOUD_LIFE_STAT_ENV_FAIL = 9,       // execs whose environment block could not be read
    CLOUD_LIFE_STAT_ENV_TRUNC = 10,     // execs whose environment block was cut at CLOUD_LIFE_ENV_MAX
    CLOUD_LIFE_STAT_MAX
};

#ifdef __cplusplus
CLOUD_ABI_SIZE(cloud_life_rec, 64);
#endif

// ---- directory rows for file names ("Directory rows v2") ----
//
// The folded file rows above say HOW MANY files were opened, not WHICH. Directory records travel on
// a second, finer key: (process, EXACT parent directory, operation). Every nested directory is its
// own key. An open is ELIGIBLE one of three ways, each creating or feeding a directory key on its
// own: its extension is on the whitelist, or (if not) its file name matches the name mask (an
// exact-name set and a few prefix masks - CLOUD_NAME_PREFIXES), or (if not) its file name matches
// the separate, broader dir-eligibility prefix policy (CLOUD_DIR_PREFIXES - its own list, not the
// name mask's). With no policy loaded every open is eligible (the extension route, whatever the
// extension). Everything else stays counted in the coarse fold rows and nothing else.
//
// Per directory key the kernel keeps one counter (`opens`, the ELIGIBLE opens in that directory,
// nothing else) and the first/last timestamps in the dir_state map, which userspace drains like the
// fold map (delete on read). No name is sampled for an ordinary eligible open (the old
// `names_first`/`names_rand` reservoir and `names_all` measurement mode are gone) - a name is sent,
// unconditionally, ONLY when the name-mask route matched (masks are rare; the point is a name like
// wallet.dat never depends on a coin flip). The extension and dir-prefix routes instead feed two new
// breakdown maps keyed by (directory, extension) or (directory, prefix id): a count and the sum of
// `i_size` at open time (a proxy for data volume; see cloud_dir_bytes_val). Every eligible open,
// whichever route, also feeds a HyperLogLog-style sketch of the directory's distinct files
// (cloud_dir_hll_val/dir_distinct_hll) so "1 file opened 100 times" is told apart from "100 files
// opened once". `dir_rows_on` is the single switch for the whole mechanism (dir_state, the two
// breakdown maps, the sketch and mask names); off, the verifier removes it and the maps/ring sit at
// their minimum size.
//
// Bounds: a directory key costs kernel memory, so the dir_state map has a fixed size
// (CLOUD_DIR_STATE_MAX; an eligible open that cannot create its key is counted, CLOUD_NAME_STAT_DIR_MAP_FULL),
// and one process may create at most `dir_proc_max` NEW keys per drain epoch (counted per process
// in dir_proc, drained with it: the opens that fell in directories over the bound are counted
// exactly, the directories themselves only as attempts, because the kernel keeps no record of a
// directory it refused). Every eligible open is accounted exactly one way:
//   eligible == sum(dir_state opens) + sum(dir_proc drop_opens) + DIR_MAP_FULL + DIR_PROC_FULL.
// The two breakdown maps and the sketch map are each their own fixed-size hash map (CLOUD_DIR_EXT_FOLD_MAX,
// CLOUD_DIR_PREFIX_FOLD_MAX, CLOUD_DIR_STATE_MAX respectively): a breakdown or sketch key that does not
// fit is dropped and counted (CLOUD_NAME_STAT_EXT_FOLD_FULL / _PREFIX_FOLD_FULL / _HLL_MAP_FULL), same
// idiom as dir_state, independent of the per-process directory-creation bound above (that bound limits
// distinct DIRECTORIES, not distinct extensions or prefix ids within an already-eligible one).
//
// The policy (DATA supplied by the caller, empty by default = every open eligible): extension
// values (the same 4-character value cloud_file_key.ext carries) in a hash map, and a bounded
// test of the file's own name on every open whose extension did not match. The policy is known
// before the load, so cheap early rejects are baked into the object's read-only data: a bloom
// filter over the extension values and one over the exact names, the exact-name length range and
// the prefix masks themselves, so most non-eligible opens never reach a map lookup.
//
// The path is attacker-chosen bytes (a file's name): not necessarily UTF-8, never trusted.
// A path longer than CLOUD_NAME_PATH_MAX bytes cannot be resolved into the buffer
// (bpf_d_path fails with ENAMETOOLONG) and is counted, not truncated: a cut path is not the
// path of any file.

#define CLOUD_NAME_PATH_MAX   256   // path bytes, without the NUL
#define CLOUD_NAME_BUF        264   // buffer, room for the NUL and a multiple of 8
#define CLOUD_NAME_EXACT_MAX   31   // longest file name the exact-name set can hold
#define CLOUD_NAME_EXACT_BUF   32
#define CLOUD_NAME_PREFIXES     8   // name-mask prefix masks (send a NAME on match)
#define CLOUD_NAME_PREFIX_MAX   8   // bytes in one prefix mask
#define CLOUD_NAME_EXTS      1024   // whitelisted extension values (default map size; the loader grows it to the policy)
#define CLOUD_DIR_STATE_MAX 131072  // directory keys the kernel holds between two drains
#define CLOUD_DIR_PROC_MAX   16384  // processes tracked for the per-process bound between two drains
#define CLOUD_DIR_PROC_DEFAULT 16384 // default: new directory keys one process may create per drain epoch
#define CLOUD_BLOOM_WORDS      64   // 64 x 64 = 4096 bits per bloom filter
// The broader, separate eligibility-only prefix policy ("Directory rows v2"):
// a prefix match here grants a directory record on its own, same as the name
// mask, but sends no name and is not the name mask's own prefix list (CLOUD_NAME_PREFIXES).
#define CLOUD_DIR_PREFIXES      8   // eligibility-only prefix masks
#define CLOUD_DIR_EXT_FOLD_MAX   131072  // (directory, extension) breakdown keys the kernel holds between two drains
#define CLOUD_DIR_PREFIX_FOLD_MAX 32768  // (directory, eligibility-prefix) breakdown keys the kernel holds between two drains (8192 before)

// A prefix mask: `mask` selects the first bytes of a file name read as a little-endian u64, `bits`
// are their required value. mask 0 = unused slot.
struct cloud_name_prefix {
    __u64 mask;
    __u64 bits;
};

// Load-time configuration of the file_open program, written into the object's read-only data
// before it is loaded (so the verifier sees constants and removes the code a mode does not use).
//
// Directory rows v2 removed the reservoir sample (`names_first`/`names_rand`/
// `names_all`): a name is now sent ONLY for an exact-name mask match, unconditionally, never for an
// ordinary eligible open. `dir_rows_on` is the single switch for the whole v2 mechanism (dir_state,
// dir_ext_fold, dir_prefix_fold, dir_distinct_hll, names_rb); with it off the verifier removes the
// mechanism the same way "both reservoir counts zero" used to.
struct cloud_cfg {
    __u32 dir_rows_on;    // nonzero: the directory-row mechanism runs at all (dir_state, the ext/prefix
                          // folds, the HLL sketch and mask names); 0 = compiled out, maps at minimum size
    __u32 policy_on;      // nonzero: the extension whitelist, the name mask and the dir-prefix policy decide eligibility
    __u32 dir_proc_max;   // new directory keys one process may create per drain epoch
    __u32 name_len_min;   // shortest / longest exact name (both 0 when there is none)
    __u32 name_len_max;
    __u32 prefix_any;     // nonzero: at least one NAME-MASK prefix mask (applies to a name of any length)
    __u32 dir_prefix_any; // nonzero: at least one dir-ELIGIBILITY prefix mask loaded (see dir_prefixes)
    __u32 pad;
    __u64 ext_bloom[CLOUD_BLOOM_WORDS];   // bit cloud_bloom_ext(e) is set for every whitelisted extension e
    __u64 name_bloom[CLOUD_BLOOM_WORDS];  // bit cloud_bloom_name(w) is set for every exact name
    struct cloud_name_prefix prefixes[CLOUD_NAME_PREFIXES];      // name-mask prefixes (send a NAME)
    struct cloud_name_prefix dir_prefixes[CLOUD_DIR_PREFIXES];   // eligibility-only prefixes (no name sent)
};

// The bloom filters' hashes, shared by the kernel program and the loader so they agree. `w` is a
// file name as four little-endian u64 words, NUL padded (bytes past the name are zero).
CLOUD_ABI_INLINE __u32 cloud_bloom_ext(__u64 ext) {
    return (__u32)((ext * 0x9E3779B97F4A7C15ull) >> 52);
}
CLOUD_ABI_INLINE __u32 cloud_bloom_name(__u64 w0, __u64 w1, __u64 w2, __u64 w3) {
    __u64 h = w0 * 0x9E3779B97F4A7C15ull;
    h ^= h >> 29;
    h += w1 * 0xC2B2AE3D27D4EB4Full;
    h ^= h >> 31;
    h += w2 * 0x165667B19E3779F9ull;
    h ^= h >> 27;
    h += w3 * 0x27D4EB2F165667C5ull;
    h ^= h >> 32;
    return (__u32)((h * 0x9E3779B97F4A7C15ull) >> 52);
}

// The exact-name set's key: the file name, NUL padded.
struct cloud_name_exact {
    char name[CLOUD_NAME_EXACT_BUF];
};

// A directory key: one process, one exact parent directory, one operation.
struct cloud_dirid {
    __u64 proc_start;   // group leader task->start_time
    __u64 dev;          // kernel-encoded s_dev
    __u64 ino;          // inode of the parent directory
    __u32 tgid;
    __u32 op;           // CLOUD_OP_*
};

struct cloud_dir_val {
    __u64 opens;        // eligible opens in this directory since the last drain; also the open's number for the sampler
    __u64 first_ns;
    __u64 last_ns;
};

// What userspace hands the agent for one drained directory key.
struct cloud_dir_row {
    struct cloud_dirid key;
    struct cloud_dir_val val;
};

// ---------------------------------------------------------------------------
// Directory rows v2: per-directory
// extension and prefix breakdown, distinct-file cardinality, byte size. Names are no longer
// sampled for ordinary eligible opens (the 4+4 reservoir is gone); a name is sent only for an
// exact-name mask match (unchanged from the fix, CLOUD_NAME_F_MASKED).
// ---------------------------------------------------------------------------

// The extension-breakdown key: one directory key (see cloud_dirid; op is inside it) plus the
// extension. Populated only on the extension-whitelist eligibility route.
struct cloud_dir_ext_key {
    struct cloud_dirid dir;
    __u64 ext;   // as cloud_file_key.ext: up to 8 lowercase characters, little endian
};

// The prefix-breakdown key: one directory key plus which prefix slot matched (an index into
// cloud_cfg.dir_prefixes, NOT cloud_cfg.prefixes - the name mask's own prefix list). Populated
// only on the dir-eligibility-prefix route.
struct cloud_dir_prefix_key {
    struct cloud_dirid dir;
    __u32 prefix_id;
    __u32 pad;   // always 0
};

// Shared value shape for both breakdowns: a count of eligible opens and the sum of their
// files' i_size AT OPEN TIME (a proxy for data volume, not bytes actually read or written -
// hooking vfs_read/vfs_write was rejected as far too costly, see the plan doc).
struct cloud_dir_bytes_val {
    __u64 count;
    __u64 bytes;
    __u64 first_ns;
    __u64 last_ns;
};

// What userspace hands the agent for one drained ext/prefix breakdown entry (same row shape,
// two different drain calls so the agent never has to guess which key type it got).
struct cloud_dir_ext_row {
    struct cloud_dir_ext_key key;
    struct cloud_dir_bytes_val val;
};
struct cloud_dir_prefix_row {
    struct cloud_dir_prefix_key key;
    struct cloud_dir_bytes_val val;
};

// The distinct-file HyperLogLog sketch, one per (directory, op), fed by every eligible open
// whichever route made it eligible (extension, prefix or mask) - unlike the ext/prefix
// breakdowns, there is no per-extension or per-prefix split here, just one cardinality
// estimate for the whole directory. m = CLOUD_HLL_M registers, one BYTE each (not bit-packed):
// a bucket is a straight array index, no cross-byte shifting in the hot path, at the cost of
// 64 bytes per key instead of 48 for 6-bit registers - a deliberate simplicity-over-density
// trade against a BPF verifier that already has enough to prove elsewhere. A byte comfortably
// holds any realistic leading-zero-run count (bounded by the hash width, never close to 255).
// CLOUD_HLL_M (registers per sketch) is defined above cloud_file_val, which embeds a sketch too.
struct cloud_dir_hll_val {
    __u8 reg[CLOUD_HLL_M];
};
struct cloud_dir_hll_row {
    struct cloud_dirid key;   // (proc_start, dev, ino, tgid, op) - no ext/prefix split
    struct cloud_dir_hll_val val;
};

// The per-process bound of new directory keys per drain epoch.
struct cloud_dir_proc_key {
    __u64 proc_start;
    __u32 tgid;
    __u32 pad;
};

struct cloud_dir_proc_val {
    __u64 created;      // directory keys this process has created (attempts included) in this epoch
    __u64 drop_dirs;    // eligible opens that wanted a NEW key and were refused (an upper bound of the directories refused)
    __u64 drop_opens;   // eligible opens refused: the exact count
};

// What userspace hands the agent for a process that hit the bound.
struct cloud_dir_drop_row {
    struct cloud_dir_proc_key key;
    __u64 dirs;
    __u64 opens;
};

// cloud_name_rec.flags bit 0: this open was eligible through the NAME MASK, not the extension
// whitelist. The agent gives a masked name priority over the ordinary 4+4 sample when it builds a
// directory record's names, so a rare exact match (wallet.dat, id_rsa) is not lost to a coin flip
// in a directory that also holds many whitelisted-extension files.
#define CLOUD_NAME_F_MASKED 0x1
// cloud_name_rec.flags bit 1 (Directory rows v2): this record's `path` is the
// DIRECTORY's own full path, not a file's. Sent exactly once, unconditionally, the moment a new
// directory key is created in dir_state - whichever eligibility route caused it, mask or not. This
// is the only way the agent learns a directory's path now that ordinary (non-mask) opens never
// send a name: without it, a directory eligible only via the extension or dir-prefix route (no
// mask match ever) would never be identifiable on the wire. `len`/`nth` are as for any record;
// `nth` is always 0 here (meaningless for a directory path).
#define CLOUD_NAME_F_DIRPATH 0x2

struct cloud_name_rec {
    struct cloud_dirid key;      // the directory key this open counted in
    __u64 ts_ns;                 // bpf_ktime_get_ns() at the open
    __u16 len;                   // path bytes, without the NUL
    __u16 flags;                 // bit 0: CLOUD_NAME_F_MASKED; bit 1: CLOUD_NAME_F_DIRPATH; the rest reserved, 0
    __u32 nth;                   // this open's running number in its directory key (1 = the first eligible open); 0 for a CLOUD_NAME_F_DIRPATH record
    char path[CLOUD_NAME_BUF];   // the file's (or, if CLOUD_NAME_F_DIRPATH, the directory's) full path, NUL terminated
};

// Kernel-side counters of the name capture (a separate array from cloud_stat, so the layout the
// agent already reads does not move).
enum cloud_name_stat {
    CLOUD_NAME_STAT_EMITTED = 0,    // name records submitted
    CLOUD_NAME_STAT_RING_FULL = 1,  // dropped: the ring buffer was full
    CLOUD_NAME_STAT_TOO_LONG = 2,   // dropped: the path is longer than CLOUD_NAME_PATH_MAX
    CLOUD_NAME_STAT_DPATH_FAIL = 3, // dropped: bpf_d_path failed for another reason
    CLOUD_NAME_STAT_ELIGIBLE = 4,   // eligible opens (extension on the whitelist or a name match; all with no policy)
    CLOUD_NAME_STAT_DIR_MAP_FULL = 5,  // eligible opens whose new directory key did not fit in dir_state
    CLOUD_NAME_STAT_DIR_PROC_FULL = 6, // eligible opens refused because the per-process table was full
    CLOUD_NAME_STAT_EXT_FOLD_FULL = 7,    // an extension-breakdown key did not fit in dir_ext_fold
    CLOUD_NAME_STAT_PREFIX_FOLD_FULL = 8, // a prefix-breakdown key did not fit in dir_prefix_fold
    CLOUD_NAME_STAT_HLL_MAP_FULL = 9,     // a distinct-file sketch key did not fit in dir_distinct_hll
    CLOUD_NAME_STAT_MAX
};

#ifdef __cplusplus
CLOUD_ABI_SIZE(cloud_cfg, 1312);
CLOUD_ABI_SIZE(cloud_name_prefix, 16);
CLOUD_ABI_SIZE(cloud_name_exact, 32);
CLOUD_ABI_SIZE(cloud_dirid, 32);
CLOUD_ABI_SIZE(cloud_dir_val, 24);
CLOUD_ABI_SIZE(cloud_dir_row, 56);
CLOUD_ABI_SIZE(cloud_dir_proc_key, 16);
CLOUD_ABI_SIZE(cloud_dir_proc_val, 24);
CLOUD_ABI_SIZE(cloud_dir_drop_row, 32);
CLOUD_ABI_SIZE(cloud_name_rec, 312);
CLOUD_ABI_SIZE(cloud_dir_ext_key, 40);
CLOUD_ABI_SIZE(cloud_dir_prefix_key, 40);
CLOUD_ABI_SIZE(cloud_dir_bytes_val, 32);
CLOUD_ABI_SIZE(cloud_dir_ext_row, 72);
CLOUD_ABI_SIZE(cloud_dir_prefix_row, 72);
CLOUD_ABI_SIZE(cloud_dir_hll_val, CLOUD_HLL_M);
CLOUD_ABI_SIZE(cloud_dir_hll_row, 32 + CLOUD_HLL_M);
#endif

// ---------------------------------------------------------------------------
// v7: move/rename/link/symlink rows (copy and move telemetry).
// ---------------------------------------------------------------------------
//
// One record per ELIGIBLE rename(2)/link(2)/symlink(2), raw (not folded): these are rare
// compared to file opens, and the design wants the full destination name (the rename-into-a-
// watched-name shape IS the poisoning signal - npm, cargo and editors write a temp file, then
// rename it into place, which an extension/mask-only file_open view never sees as a discrete
// event). Eligibility is decided on the DESTINATION name (the file/link being created or
// replaced), through the exact same eligible()/scope machinery cloud_file_open already uses
// (an eligible open's extension, the name mask, or the dir-eligibility prefix policy) - a temp
// name (`.foo.tmp`, `foo~`) fails every route and produces no row, only the rename into the
// real name does. Directories are identified by (dev, ino) only, the same convention
// cloud_dir_key/cloud_dirid already use: no new path resolution is attempted here (no `struct
// file*` is available in these LSM hooks to bpf_d_path from), so the cloud recovers a
// directory's path by joining on (dev, ino) against a DirRow the same process already produced
// for an ordinary file_open in that same directory - true in practice for exactly the shapes
// this exists to catch (a package manager or editor that reads/writes other files in a project
// directory before or after the rename).
//
// copy(2) is deliberately NOT a hook here (v7 note): no dev/ino pair identifies a
// copy's destination (a plain open() + write(), `i_size` at open is 0 there), so it is a cloud-
// side correlation of two file_open rows, not kernel work. A cross-filesystem `mv` is userspace
// copy-then-unlink for the same reason - already visible through cloud_file_open/inode_unlink,
// no new kernel program needed for it.

#define CLOUD_MOVE_RENAME  1  // rename(2): old_dentry existed, new_dentry may have existed (replaced)
#define CLOUD_MOVE_LINK    2  // link(2): old_dentry is the existing file being hardlinked
#define CLOUD_MOVE_SYMLINK 3  // symlink(2): new symlink created pointing at an arbitrary (unresolved) string target

// cloud_move_rec.flags bit 0: same meaning as CLOUD_NAME_F_MASKED - the destination name matched
// the exact-name mask (high value: id_rsa, wallet.dat, .npmrc) rather than only the extension or
// dir-eligibility-prefix route.
#define CLOUD_MOVE_F_MASKED 0x1
// bit 1: old_dev/old_ino are not meaningful (symlink(2) has no source file - `old_name` is a raw
// string target, not resolved to an inode in-kernel).
#define CLOUD_MOVE_F_NO_SOURCE 0x2

struct cloud_move_rec {
    __u64 ts_ns;
    __u64 proc_start;   // group leader task->start_time, the same process key every cloud collector uses
    __u64 old_dev;      // old parent directory's kernel-encoded s_dev (0 with CLOUD_MOVE_F_NO_SOURCE)
    __u64 old_ino;      // old parent directory's inode (0 with CLOUD_MOVE_F_NO_SOURCE)
    __u64 new_dev;      // new (destination) parent directory's kernel-encoded s_dev
    __u64 new_ino;      // new (destination) parent directory's inode
    __u32 tgid;
    __u8 op;             // CLOUD_MOVE_*
    __u8 flags;          // CLOUD_MOVE_F_*
    __u16 name_len;      // destination basename bytes, no NUL
    char name[CLOUD_NAME_EXACT_BUF];  // destination basename only (not a full path), NUL padded
};

// Kernel-side counters of the move/link/symlink programs (own array, so the layout the agent
// already reads does not move).
enum cloud_move_stat {
    CLOUD_MOVE_STAT_EMITTED = 0,     // move records submitted
    CLOUD_MOVE_STAT_RING_FULL = 1,   // dropped: the ring buffer was full
    CLOUD_MOVE_STAT_OUT_OF_SCOPE = 2, // destination directory not in scope (skip_fs/no scope root)
    CLOUD_MOVE_STAT_NOT_ELIGIBLE = 3, // destination name matched no eligibility route
    CLOUD_MOVE_STAT_MAX
};

#ifdef __cplusplus
CLOUD_ABI_SIZE(cloud_move_rec, 88);
#endif

#endif  // KINNECTOR_CLOUD_ABI_H
