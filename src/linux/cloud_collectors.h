#ifndef KINNECTOR_LINUX_CLOUD_COLLECTORS_H
#define KINNECTOR_LINUX_CLOUD_COLLECTORS_H

// Loader and drain side of the cloud-tier collectors (kinnector_cloud.bpf.c).
//
// Independent of EbpfLoader on purpose: its own object, its own maps, nothing
// pinned. The links are held by this process, so they detach the moment it exits
// however it exits. Every program is loaded and attached on its own merits: one
// the running kernel rejects costs that one detection, never the others and never
// the enforcement object.
//

#include <atomic>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "kinnector/cloud_abi.h"

struct bpf_object;
struct bpf_link;
struct ring_buffer;

namespace kinnector::lnx {

enum CloudFeature : uint32_t {
    kCloudNet = 1u << 0,    // TCP in/out, UDP peers and bytes, DNS names
    kCloudFiles = 1u << 1,  // ordinary file opens folded by project folder
    kCloudLife = 1u << 2,   // process fork, exec (with arguments) and exit
    kCloudMoves = 1u << 3,  // v7: rename/link/symlink rows on an eligible destination
};

struct CloudProgStatus {
    std::string name;
    bool loaded = false;
    bool attached = false;
    std::string error;
};

class CloudCollectors {
public:
    static CloudCollectors& Instance();

    // Loads kinnector_cloud.bpf.o and attaches whatever the kernel accepts. True
    // when at least one program is attached. Idempotent while running.
    bool Start(const std::string& object_path, uint32_t features, int scan_secs = 10);
    void Stop();
    bool Running() const { return running_.load(); }
    std::vector<CloudProgStatus> Status() const;

    // Directory rows v2: the single
    // switch for the whole directory-row mechanism (dir_state, the extension/prefix breakdown
    // folds, the distinct-file HLL sketch and mask names - cloud_abi.h). No more sampling: a name
    // is sent only for an exact-name mask match, unconditionally. Load-time setting: call BEFORE
    // Start(); a running loader keeps what it started with. Off (the default) turns the whole
    // mechanism off, and the names ring and the directory maps are created at their minimum size.
    void SetDirRowsOn(bool on);
    // Which opens are eligible at all: extension values (cloud_file_key.ext) and, for a file whose
    // extension is not on the list, exact file names and prefix masks (at most CLOUD_NAME_PREFIX_MAX
    // bytes each, at most CLOUD_NAME_PREFIXES of them) matched against the basename - a match here
    // sends a NAME. All three empty (the default) = every open is eligible (the extension route).
    // Call BEFORE Start(): the loader bakes the early rejects into the object's read-only data and
    // fills the kernel maps right after the load.
    void SetNamePolicy(std::vector<uint64_t> exts, std::vector<std::string> names, std::vector<std::string> prefixes);
    // The separate, broader dir-eligibility prefix policy: a prefix match here
    // grants a directory record on its own, same as the name mask, but sends no name and is its own
    // list, not shared with SetNamePolicy's prefixes. At most CLOUD_DIR_PREFIXES entries of at most
    // CLOUD_NAME_PREFIX_MAX bytes each. Call BEFORE Start().
    void SetDirPrefixPolicy(std::vector<std::string> prefixes);
    // New directory keys one process may create per drain epoch (kernel-side safety bound, see
    // cloud_abi.h); 0 = CLOUD_DIR_PROC_DEFAULT. Before Start().
    void SetDirProcMax(uint32_t n);
    // Size of the name ring in bytes (a power of two, a multiple of the page size); 0 = the
    // object's own 4 MiB. Before Start(). For tests and measurements.
    void SetNamesRingBytes(uint32_t bytes);

    // Scope (files). `posix_dev` is stat()'s st_dev, converted here to the kernel's
    // encoding. Call Commit() after a batch so the per-directory verdict cache
    // (which may hold "out of scope" for directories visited before the roots were
    // registered) is flushed.
    bool AddScopeRoot(uint64_t posix_dev, uint64_t ino, uint32_t kind);
    bool RemoveScopeRoot(uint64_t posix_dev, uint64_t ino);
    bool AddSkipDir(uint64_t posix_dev, uint64_t ino);
    bool RemoveSkipDir(uint64_t posix_dev, uint64_t ino);
    void ClearScope();
    void CommitScope();

    // Drains. Each returns the number of rows written, at most `cap`.
    size_t DrainNet(cloud_net_rec* out, size_t cap);
    size_t DrainDns(cloud_dns_name* out, size_t cap);
    size_t DrainUdp(cloud_udp_row* out, size_t cap);
    size_t DrainFiles(cloud_file_row* out, size_t cap);
    size_t DrainProjects(cloud_proj_row* out, size_t cap);  // each project reported once

    // Directory keys (kCloudFiles, names on): the eligible-open counter and timestamps of every
    // directory key since the last drain; a drain removes them (delete on read, like the fold
    // rows). It first drains the per-process bound table (starting a new epoch for the bound),
    // whose drops are held for DrainDirDrops. Returns the rows written, at most `cap`.
    size_t DrainDirs(cloud_dir_row* out, size_t cap);
    // The processes that hit the per-process bound since the last call (opens exact, dirs an upper
    // bound), one row per process, and removes them. Filled by DrainDirs.
    size_t DrainDirDrops(cloud_dir_drop_row* out, size_t cap);
    // Name records (kCloudFiles), oldest first: the full path of a name-mask match on a directory
    // key, with the key (struct cloud_name_rec). Returns the number written, at
    // most `cap`; a drain removes what it returns. The bytes after a path's NUL are zeroed.
    size_t DrainNames(cloud_name_rec* out, size_t cap);
    // Directory rows v2: the extension and prefix breakdown rows (count + summed i_size) since the
    // last drain; a drain removes them (delete on read, like dir_state). Returns the rows written,
    // at most `cap`.
    size_t DrainDirExtFold(cloud_dir_ext_row* out, size_t cap);
    size_t DrainDirPrefixFold(cloud_dir_prefix_row* out, size_t cap);
    // The distinct-file HLL sketch rows (one per directory key) since the last drain; a drain
    // removes them. The estimate itself is computed from the raw registers, not here (agent-side
    // arithmetic). Returns the rows written, at most `cap`.
    size_t DrainDirHll(cloud_dir_hll_row* out, size_t cap);
    // Summed per-CPU counters of the name capture (enum cloud_name_stat), then in slot
    // CLOUD_NAME_STAT_MAX the name records this loader dropped (queue full).
    void NameStats(uint64_t* out, size_t n) const;
    // Kernel memory the named map holds, from the map's fdinfo `memlock` line (0 if unknown).
    uint64_t MapMemoryBytes(const char* map_name) const;
    // Entries of the loaded name policy the running collectors could NOT hold: out[0] extension
    // values, out[1] exact names, out[2] prefixes (name mask and dir-eligibility). A level for the
    // current load, not a delta; reset by every Start. 0 everywhere when the policy fits.
    void PolicyStats(uint64_t* out, size_t n) const;

    // Process lifecycle records (kCloudLife), oldest first, in the order the kernel
    // submitted them to its one ring buffer. Copies WHOLE records into `out` (each
    // struct cloud_life_rec plus its exe and argv bytes, padded to 8 bytes) while they
    // fit in `cap` bytes; `cap` should be at least CLOUD_LIFE_REC_MAX or a large record
    // never fits. Returns the bytes written; `*nrecs` (optional) gets the record count.
    size_t DrainLife(uint8_t* out, size_t cap, size_t* nrecs);
    // Summed per-CPU counters of the lifecycle programs (enum cloud_life_stat), then in
    // slot CLOUD_LIFE_STAT_MAX the records this loader dropped (queue full or malformed).
    void LifeStats(uint64_t* out, size_t n) const;

    // v7: move/rename/link/symlink records (kCloudMoves), oldest first. Rare next to file
    // opens, so no fold/cap dance - one record per eligible event, queue bounded by count.
    // Returns the number of rows written, at most `cap`; a drain removes what it returns.
    size_t DrainMoves(cloud_move_rec* out, size_t cap);
    // Summed per-CPU counters of the move programs (enum cloud_move_stat), then in slot
    // CLOUD_MOVE_STAT_MAX the records this loader dropped (queue full or malformed).
    void MoveStats(uint64_t* out, size_t n) const;

    // Kernel run counters per attached program (needs BPF_STATS_RUN_TIME enabled,
    // see bpf_enable_stats or the kernel.bpf_stats_enabled sysctl). Used by the
    // performance gate; reads the kernel's own numbers, never wall-clock time.
    struct ProgRunStat {
        std::string name;
        uint64_t run_cnt = 0;
        uint64_t run_time_ns = 0;
    };
    std::vector<ProgRunStat> RunStats() const;

    // Summed per-CPU counters (enum cloud_stat), plus records this loader itself
    // dropped because the agent did not drain fast enough (index CLOUD_STAT_MAX).
    void Stats(uint64_t* out, size_t n) const;

private:
    CloudCollectors() = default;
    ~CloudCollectors() { Stop(); }
    CloudCollectors(const CloudCollectors&) = delete;
    CloudCollectors& operator=(const CloudCollectors&) = delete;

    static int OnRecord(void* ctx, void* data, size_t sz);
    static int OnLifeRecord(void* ctx, void* data, size_t sz);
    static int OnNameRecord(void* ctx, void* data, size_t sz);
    static int OnMoveRecord(void* ctx, void* data, size_t sz);
    void PollLoop();
    void ScanLoop();
    int MapFd(const char* name) const;

    mutable std::mutex mu_;
    std::atomic<bool> running_{false};
    bpf_object* obj_ = nullptr;
    std::vector<bpf_link*> links_;
    bpf_link* iter_link_ = nullptr;
    ring_buffer* rb_ = nullptr;
    std::vector<CloudProgStatus> status_;
    int scan_secs_ = 10;
    std::thread poll_thread_;
    std::thread scan_thread_;

    mutable std::mutex q_mu_;
    std::deque<cloud_net_rec> net_q_;
    std::deque<cloud_dns_name> dns_q_;
    uint64_t q_dropped_ = 0;

    // Lifecycle records, one heap block per record. Bounded by bytes: an exec with a
    // long argument list is up to ~9 KB, so a count alone would not bound memory.
    mutable std::mutex life_mu_;
    std::deque<std::vector<uint8_t>> life_q_;
    size_t life_q_bytes_ = 0;
    uint64_t life_q_dropped_ = 0;

    // Name records: what the kernel sent for the sampled opens of each directory key. Bounded by
    // count (a record is 312 bytes, so 65536 is about 19 MiB). A full queue drops the NEWEST record
    // and counts it: the earliest records are the ones that name a directory first.
    mutable std::mutex name_mu_;
    std::deque<cloud_name_rec> name_q_;
    uint64_t name_q_dropped_ = 0;

    // v7 move/link/symlink records: rare, one per eligible event, count-bounded like name_q_.
    mutable std::mutex move_mu_;
    std::deque<cloud_move_rec> move_q_;
    uint64_t move_q_dropped_ = 0;
    uint32_t dir_proc_max_ = 0;
    std::mutex dir_mu_;
    // filled by DrainDirs, emptied by DrainDirDrops: (proc_start, tgid) -> (dirs, opens)
    std::map<std::pair<uint64_t, uint32_t>, std::pair<uint64_t, uint64_t>> dir_drops_;
    bool dir_rows_on_ = false;
    uint32_t names_ring_bytes_ = 0;
    std::vector<uint64_t> policy_exts_;
    std::vector<std::string> policy_names_;
    std::vector<std::string> policy_prefixes_;
    std::vector<std::string> dir_prefix_policy_;
    // PolicyStats: extension values, exact names, prefixes not held by the current load.
    uint64_t policy_unheld_[3] = {0, 0, 0};

    std::mutex proj_mu_;
    std::set<std::pair<uint64_t, uint64_t>> proj_reported_;
};

// For measurement tools that load several builds of the object at once (cloud_multiperf_tool.cpp),
// and for the loader itself: the load-time configuration (with the policy's early rejects baked in),
// written into an OPENED object, and the policy maps of a LOADED one.
cloud_cfg BuildCloudCfg(bool dir_rows_on, bool policy, uint32_t dir_proc_max, const std::vector<uint64_t>& exts,
                        const std::vector<std::string>& names, const std::vector<std::string>& prefixes,
                        const std::vector<std::string>& dir_prefixes);
// `n_exts`/`n_names`: the policy's size, so the policy maps are grown to hold all of it.
void PrepareCloudObject(bpf_object* o, const cloud_cfg& cfg, uint32_t names_ring_bytes, size_t n_exts = 0, size_t n_names = 0);
void FillCloudPolicy(bpf_object* o, const std::vector<uint64_t>& exts, const std::vector<std::string>& names);

// Extracts the query name and type from the start of a DNS message. Returns false
// for anything that is not a plain single-question query with a sane name. The
// name is attacker-chosen text, so it is bounded and restricted to hostname
// characters here, before it goes anywhere.
bool ParseDnsQuery(const uint8_t* msg, size_t len, char* name, size_t name_cap, uint16_t* qtype);

}  // namespace kinnector::lnx

#endif  // KINNECTOR_LINUX_CLOUD_COLLECTORS_H
