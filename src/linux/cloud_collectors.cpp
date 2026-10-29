#include "cloud_collectors.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>

namespace kinnector::lnx {

namespace {

// Records waiting for the agent (net, DNS, names, moves), each queue on its own. Heap memory,
// held only while the agent falls behind: 262,144 net records are 20 MiB.
// A full queue drops and counts.
constexpr size_t kMaxQueued = 262144;
// Lifecycle records waiting for the agent: about 128 MiB is several minutes of a 3,600 exec/s
// burst at typical record sizes, and bounded when every exec carries
// its full 25 KB.
constexpr size_t kMaxLifeQueueBytes = 128u << 20;

// stat()'s st_dev (glibc encoding) to the kernel's internal dev_t, the value the
// BPF side reads from sb->s_dev. See ebpf_loader.cpp's ToKernelDevEncoding.
uint64_t KernelDev(uint64_t posix_dev) {
    dev_t d = static_cast<dev_t>(posix_dev);
    return (static_cast<uint64_t>(major(d)) << 20) | static_cast<uint64_t>(minor(d));
}

struct ProgSpec {
    const char* name;
    uint32_t feature;
};

const ProgSpec kPrograms[] = {
    {"cloud_connect", kCloudNet},   {"cloud_accept", kCloudNet},    {"cloud_tcp_close", kCloudNet},
    {"cloud_tcp_scan", kCloudNet},  {"cloud_udp_send", kCloudNet},  {"cloud_udp6_send", kCloudNet},
    {"cloud_udp_recv", kCloudNet},  {"cloud_udp6_recv", kCloudNet}, {"cloud_dns4", kCloudNet},
    {"cloud_dns6", kCloudNet},      {"cloud_file_open", kCloudFiles},
    // Lifecycle. cloud_life_exe is the resolved-path half of cloud_life_exec: if the
    // kernel rejects it the exec records still flow, with the unresolved filename.
    {"cloud_life_fork", kCloudLife}, {"cloud_life_exec", kCloudLife}, {"cloud_life_exit", kCloudLife},
    {"cloud_life_exe", kCloudLife},
    // v7: rename/link/symlink rows on an eligible destination.
    {"cloud_move_rename", kCloudMoves}, {"cloud_move_link", kCloudMoves}, {"cloud_move_symlink", kCloudMoves},
};

bool Wanted(const char* name, uint32_t features) {
    for (const auto& p : kPrograms) {
        if (std::strcmp(p.name, name) == 0) return (p.feature & features) != 0;
    }
    return false;
}

// Silent unless KINNECTOR_CLOUD_DEBUG is set, then everything libbpf says,
// including the verifier log of a rejected program.
int LibbpfPrint(enum libbpf_print_level level, const char* fmt, va_list ap) {
    static const bool verbose = std::getenv("KINNECTOR_CLOUD_DEBUG") != nullptr;
    if (!verbose) return 0;
    return vfprintf(stderr, fmt, ap);
}

// Writes the load-time configuration into the object's read-only data (the internal `.rodata`
// map, whose only variable is `cloud_cfg`). An object whose layout is not exactly that is left
// on its compiled-in defaults rather than guessed at.
void ApplyCfg(bpf_object* o, const cloud_cfg& cfg) {
    bpf_map* m;
    bpf_object__for_each_map(m, o) {
        if (!bpf_map__is_internal(m)) continue;
        const char* n = bpf_map__name(m);
        size_t len = std::strlen(n);
        if (len < 7 || std::strcmp(n + len - 7, ".rodata") != 0) continue;
        size_t sz = 0;
        void* d = bpf_map__initial_value(m, &sz);
        if (d && sz == sizeof(cfg)) {
            std::memcpy(d, &cfg, sizeof(cfg));
        } else {
            std::cerr << "cloud collectors: unexpected .rodata layout (" << sz << " bytes), file-name settings not applied" << std::endl;
        }
        return;
    }
}

// A policy name must be 1..CLOUD_NAME_EXACT_MAX bytes to be held in the exact-name set.
bool NameFits(const std::string& n) { return !n.empty() && n.size() <= CLOUD_NAME_EXACT_MAX; }

// Fills one prefix-mask slot array (either cfg.prefixes, the name mask's own list, or
// cfg.dir_prefixes, the separate broader eligibility-only list) from a list of prefix strings.
// Returns the number of slots filled. Shared because both lists have the identical mask/bits shape
// and the identical "empty, over 8 bytes or too many" reject.
uint32_t FillPrefixes(struct cloud_name_prefix* slots, uint32_t max_slots, const std::vector<std::string>& prefixes,
                      const char* what, uint64_t* unheld) {
    uint32_t slot = 0;
    for (const auto& p : prefixes) {
        if (p.empty() || p.size() > CLOUD_NAME_PREFIX_MAX || slot >= max_slots) {
            std::cerr << "cloud collectors: " << what << " prefix entry '" << p << "' not stored (empty, over 8 bytes or too many)"
                      << std::endl;
            if (unheld) (*unheld)++;
            continue;
        }
        cloud_name_prefix& v = slots[slot++];
        for (size_t i = 0; i < p.size(); i++) {
            v.mask |= 0xffull << (8 * i);
            v.bits |= static_cast<uint64_t>(static_cast<uint8_t>(p[i])) << (8 * i);
        }
    }
    return slot;
}

// The load-time configuration, including the cheap early rejects of the policy: the two bloom
// filters (over the extension values and over the exact names), the exact names' length range and
// the prefix masks themselves. The kernel program reads them as constants, so they must be
// computed BEFORE the object is loaded and with the same hashes (cloud_abi.h). Entries that
// cannot be held (a name or prefix that is empty or too long, too many prefixes) are skipped here
// and reported once, and counted in `unheld` (when given: exts, names, prefixes), so a policy
// never silently names less than the caller asked for.
cloud_cfg BuildCfg(bool dir_rows_on, bool policy, uint32_t dir_proc_max, const std::vector<uint64_t>& exts,
                   const std::vector<std::string>& names, const std::vector<std::string>& prefixes,
                   const std::vector<std::string>& dir_prefixes, uint64_t* unheld = nullptr) {
    cloud_cfg c;
    std::memset(&c, 0, sizeof(c));
    c.dir_rows_on = dir_rows_on ? 1u : 0u;
    c.policy_on = policy ? 1u : 0u;
    c.dir_proc_max = dir_proc_max ? dir_proc_max : CLOUD_DIR_PROC_DEFAULT;
    for (uint64_t e : exts) {
        if (e == 0) continue;
        uint32_t b = cloud_bloom_ext(e);
        c.ext_bloom[(b >> 6) % CLOUD_BLOOM_WORDS] |= 1ull << (b & 63);
    }
    bool have_name = false;
    for (const auto& n : names) {
        if (!NameFits(n)) {
            std::cerr << "cloud collectors: name policy entry '" << n << "' not stored (empty or over 31 bytes)" << std::endl;
            if (unheld) unheld[1]++;
            continue;
        }
        uint64_t w[4] = {0, 0, 0, 0};
        std::memcpy(w, n.data(), n.size());
        uint32_t b = cloud_bloom_name(w[0], w[1], w[2], w[3]);
        c.name_bloom[(b >> 6) % CLOUD_BLOOM_WORDS] |= 1ull << (b & 63);
        uint32_t len = static_cast<uint32_t>(n.size());
        if (!have_name || len < c.name_len_min) c.name_len_min = len;
        if (!have_name || len > c.name_len_max) c.name_len_max = len;
        have_name = true;
    }
    c.prefix_any = FillPrefixes(c.prefixes, CLOUD_NAME_PREFIXES, prefixes, "name mask", unheld ? &unheld[2] : nullptr) > 0 ? 1u : 0u;
    c.dir_prefix_any =
        FillPrefixes(c.dir_prefixes, CLOUD_DIR_PREFIXES, dir_prefixes, "dir-eligibility", unheld ? &unheld[2] : nullptr) > 0 ? 1u : 0u;
    return c;
}

// The policy maps' size for a policy of `n` entries: never below the compiled default, and never
// below the policy itself, so no entry of a valid policy can fail for lack of room.
uint32_t PolicyMapEntries(size_t n, uint32_t compiled_default) {
    size_t want = std::max<size_t>(n, compiled_default);
    return static_cast<uint32_t>(std::min<size_t>(want, 1u << 20));
}

// Opens the object and enables exactly `enable`. Returns null with `err` set.
bpf_object* OpenWith(const std::string& path, const std::vector<std::string>& enable, const cloud_cfg& cfg,
                     uint32_t names_ring_bytes, size_t n_exts, size_t n_names, std::string* err) {
    bpf_object* o = bpf_object__open_file(path.c_str(), nullptr);
    if (!o) {
        *err = "open failed: " + std::string(std::strerror(errno));
        return nullptr;
    }
    PrepareCloudObject(o, cfg, names_ring_bytes, n_exts, n_names);
    bpf_program* p;
    bpf_object__for_each_program(p, o) {
        const char* n = bpf_program__name(p);
        bool on = std::find(enable.begin(), enable.end(), n) != enable.end();
        bpf_program__set_autoload(p, on);
    }
    return o;
}

}  // namespace

static void FillPolicy(int ext_fd, int exact_fd, const std::vector<uint64_t>& exts, const std::vector<std::string>& names,
                       uint64_t* unheld);

cloud_cfg BuildCloudCfg(bool dir_rows_on, bool policy, uint32_t dir_proc_max, const std::vector<uint64_t>& exts,
                        const std::vector<std::string>& names, const std::vector<std::string>& prefixes,
                        const std::vector<std::string>& dir_prefixes) {
    return BuildCfg(dir_rows_on, policy, dir_proc_max, exts, names, prefixes, dir_prefixes);
}

void PrepareCloudObject(bpf_object* o, const cloud_cfg& cfg, uint32_t names_ring_bytes, size_t n_exts, size_t n_names) {
    ApplyCfg(o, cfg);
    // The policy maps hold at least the whole policy (Tetragon sizes its filter maps to the
    // policy the same way, pkg/sensors/tracing: SetMaxEntries(len(...)) before the load).
    if (bpf_map* m = bpf_object__find_map_by_name(o, "name_ext_ok")) bpf_map__set_max_entries(m, PolicyMapEntries(n_exts, CLOUD_NAME_EXTS));
    if (bpf_map* m = bpf_object__find_map_by_name(o, "name_exact"))
        bpf_map__set_max_entries(m, PolicyMapEntries(n_names, CLOUD_NAME_EXACT_ENTRIES));
    // With the mechanism off it is compiled out by the verifier, so its ring and maps are created
    // at their minimum size instead of holding a few MiB of kernel memory for nothing.
    if (!cfg.dir_rows_on) {
        if (bpf_map* rb = bpf_object__find_map_by_name(o, "names_rb")) bpf_map__set_max_entries(rb, 4096);
        if (bpf_map* rb = bpf_object__find_map_by_name(o, "move_rb")) bpf_map__set_max_entries(rb, 4096);
        if (bpf_map* m = bpf_object__find_map_by_name(o, "dir_state")) bpf_map__set_max_entries(m, 1);
        if (bpf_map* m = bpf_object__find_map_by_name(o, "dir_proc")) bpf_map__set_max_entries(m, 1);
        if (bpf_map* m = bpf_object__find_map_by_name(o, "dir_ext_fold")) bpf_map__set_max_entries(m, 1);
        if (bpf_map* m = bpf_object__find_map_by_name(o, "dir_prefix_fold")) bpf_map__set_max_entries(m, 1);
        if (bpf_map* m = bpf_object__find_map_by_name(o, "dir_distinct_hll")) bpf_map__set_max_entries(m, 1);
    } else if (names_ring_bytes) {
        bpf_map* rb = bpf_object__find_map_by_name(o, "names_rb");
        if (rb) bpf_map__set_max_entries(rb, names_ring_bytes);
    }
}

void FillCloudPolicy(bpf_object* o, const std::vector<uint64_t>& exts, const std::vector<std::string>& names) {
    bpf_map* e = bpf_object__find_map_by_name(o, "name_ext_ok");
    bpf_map* n = bpf_object__find_map_by_name(o, "name_exact");
    FillPolicy(e ? bpf_map__fd(e) : -1, n ? bpf_map__fd(n) : -1, exts, names, nullptr);
}

CloudCollectors& CloudCollectors::Instance() {
    static CloudCollectors inst;
    return inst;
}

int CloudCollectors::MapFd(const char* name) const {
    if (!obj_) return -1;
    bpf_map* m = bpf_object__find_map_by_name(obj_, name);
    return m ? bpf_map__fd(m) : -1;
}

bool CloudCollectors::Start(const std::string& object_path, uint32_t features, int scan_secs) {
    std::lock_guard<std::mutex> lock(mu_);
    if (running_.load()) return true;
    libbpf_set_print(LibbpfPrint);
    scan_secs_ = scan_secs > 0 ? scan_secs : 10;
    status_.clear();
    policy_unheld_[0] = policy_unheld_[1] = policy_unheld_[2] = 0;

    std::vector<std::string> want;
    for (const auto& p : kPrograms) {
        if (p.feature & features) want.emplace_back(p.name);
    }
    if (want.empty()) return false;

    // First try everything together. If the kernel rejects any program the whole
    // load fails, so fall back to trying each program alone and keep the ones that
    // load. That is what keeps one incompatible hook (a renamed function, a changed
    // argument list) from disabling the rest.
    std::string err;
    std::vector<std::string> ok = want;
    bool policy = !policy_exts_.empty() || !policy_names_.empty() || !policy_prefixes_.empty() || !dir_prefix_policy_.empty();
    const cloud_cfg cfg =
        BuildCfg(dir_rows_on_, policy, dir_proc_max_, policy_exts_, policy_names_, policy_prefixes_, dir_prefix_policy_, policy_unheld_);
    const bool dir_rows_active = cfg.dir_rows_on != 0;
    const size_t n_exts = policy_exts_.size(), n_names = policy_names_.size();
    bpf_object* o = OpenWith(object_path, ok, cfg, names_ring_bytes_, n_exts, n_names, &err);
    if (!o) {
        std::cerr << "cloud collectors: " << err << " (" << object_path << ")" << std::endl;
        return false;
    }
    int rc = bpf_object__load(o);
    if (rc != 0) {
        bpf_object__close(o);
        o = nullptr;
        ok.clear();
        for (const auto& name : want) {
            std::string e;
            bpf_object* probe = OpenWith(object_path, {name}, cfg, names_ring_bytes_, n_exts, n_names, &e);
            CloudProgStatus st;
            st.name = name;
            if (probe) {
                int r = bpf_object__load(probe);
                if (r == 0) {
                    ok.push_back(name);
                    st.loaded = true;
                } else {
                    st.error = "load rejected: " + std::string(std::strerror(-r));
                }
                bpf_object__close(probe);
            } else {
                st.error = e;
            }
            status_.push_back(st);
        }
        if (ok.empty()) {
            std::cerr << "cloud collectors: the kernel rejected every program" << std::endl;
            return false;
        }
        o = OpenWith(object_path, ok, cfg, names_ring_bytes_, n_exts, n_names, &err);
        if (!o || bpf_object__load(o) != 0) {
            if (o) bpf_object__close(o);
            std::cerr << "cloud collectors: reload of the accepted set failed" << std::endl;
            return false;
        }
        for (auto& st : status_) st.loaded = std::find(ok.begin(), ok.end(), st.name) != ok.end();
    } else {
        for (const auto& name : want) {
            CloudProgStatus st;
            st.name = name;
            st.loaded = true;
            status_.push_back(st);
        }
    }
    obj_ = o;
    // The name policy goes into its maps before any program is attached, so no open is ever
    // judged against a half-filled policy.
    if (policy && dir_rows_active) FillPolicy(MapFd("name_ext_ok"), MapFd("name_exact"), policy_exts_, policy_names_, policy_unheld_);

    size_t attached = 0;
    bpf_program* p;
    bpf_object__for_each_program(p, obj_) {
        const char* n = bpf_program__name(p);
        if (!Wanted(n, features) || std::find(ok.begin(), ok.end(), n) == ok.end()) continue;
        CloudProgStatus* st = nullptr;
        for (auto& s : status_) {
            if (s.name == n) st = &s;
        }
        bpf_link* l = nullptr;
        if (std::strcmp(n, "cloud_tcp_scan") == 0) {
            l = bpf_program__attach_iter(p, nullptr);
            iter_link_ = libbpf_get_error(l) ? nullptr : l;
        } else {
            l = bpf_program__attach(p);
        }
        long e = libbpf_get_error(l);
        if (e) {
            if (st) st->error = "attach failed: " + std::string(std::strerror(static_cast<int>(-e)));
            continue;
        }
        if (std::strcmp(n, "cloud_tcp_scan") != 0) links_.push_back(l);
        if (st) st->attached = true;
        attached++;
    }
    if (attached == 0) {
        bpf_object__close(obj_);
        obj_ = nullptr;
        return false;
    }

    int rb_fd = MapFd("cloud_rb");
    if (rb_fd >= 0 && (features & kCloudNet)) {
        rb_ = ring_buffer__new(rb_fd, &CloudCollectors::OnRecord, this, nullptr);
    }
    // The lifecycle ring is a second ring of the same poller (one epoll, one thread).
    int life_fd = MapFd("life_rb");
    if (life_fd >= 0 && (features & kCloudLife)) {
        if (!rb_) {
            rb_ = ring_buffer__new(life_fd, &CloudCollectors::OnLifeRecord, this, nullptr);
        } else if (ring_buffer__add(rb_, life_fd, &CloudCollectors::OnLifeRecord, this) != 0) {
            std::cerr << "cloud collectors: could not poll the lifecycle ring" << std::endl;
        }
    }
    // The file-name ring, when the file collector is on, its program attached and names are on
    // (with names off the ring is at its minimum size and nothing is ever written to it).
    int names_fd = MapFd("names_rb");
    bool file_prog_attached = false;
    for (const auto& s : status_) {
        if (s.name == "cloud_file_open" && s.attached) file_prog_attached = true;
    }
    if (names_fd >= 0 && (features & kCloudFiles) && file_prog_attached && dir_rows_active) {
        if (!rb_) {
            rb_ = ring_buffer__new(names_fd, &CloudCollectors::OnNameRecord, this, nullptr);
        } else if (ring_buffer__add(rb_, names_fd, &CloudCollectors::OnNameRecord, this) != 0) {
            std::cerr << "cloud collectors: could not poll the file-name ring" << std::endl;
        }
    }
    // v7: the move ring, same "eligibility needs the policy on" gate the file-name ring uses.
    int move_fd = MapFd("move_rb");
    if (move_fd >= 0 && (features & kCloudMoves) && dir_rows_active) {
        if (!rb_) {
            rb_ = ring_buffer__new(move_fd, &CloudCollectors::OnMoveRecord, this, nullptr);
        } else if (ring_buffer__add(rb_, move_fd, &CloudCollectors::OnMoveRecord, this) != 0) {
            std::cerr << "cloud collectors: could not poll the move ring" << std::endl;
        }
    }
    running_ = true;
    if (rb_) poll_thread_ = std::thread(&CloudCollectors::PollLoop, this);
    if (iter_link_) scan_thread_ = std::thread(&CloudCollectors::ScanLoop, this);
    return true;
}

void CloudCollectors::Stop() {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (!running_.exchange(false)) return;
    }
    if (poll_thread_.joinable()) poll_thread_.join();
    if (scan_thread_.joinable()) scan_thread_.join();
    std::lock_guard<std::mutex> lock(mu_);
    if (rb_) {
        ring_buffer__free(rb_);
        rb_ = nullptr;
    }
    for (bpf_link* l : links_) bpf_link__destroy(l);
    links_.clear();
    if (iter_link_) {
        bpf_link__destroy(iter_link_);
        iter_link_ = nullptr;
    }
    if (obj_) {
        bpf_object__close(obj_);
        obj_ = nullptr;
    }
    {
        std::lock_guard<std::mutex> l(life_mu_);
        life_q_.clear();
        life_q_bytes_ = 0;
    }
    {
        std::lock_guard<std::mutex> l(name_mu_);
        name_q_.clear();
        name_q_dropped_ = 0;
    }
    {
        std::lock_guard<std::mutex> l(move_mu_);
        move_q_.clear();
        move_q_dropped_ = 0;
    }
    {
        std::lock_guard<std::mutex> l(dir_mu_);
        dir_drops_.clear();
    }
    std::lock_guard<std::mutex> q(q_mu_);
    net_q_.clear();
    dns_q_.clear();
}

std::vector<CloudProgStatus> CloudCollectors::Status() const {
    std::lock_guard<std::mutex> lock(mu_);
    return status_;
}

int CloudCollectors::OnRecord(void* ctx, void* data, size_t sz) {
    auto* self = static_cast<CloudCollectors*>(ctx);
    // The two record layouts have different sizes, which is how they are told apart.
    if (sz == sizeof(cloud_net_rec)) {
        std::lock_guard<std::mutex> q(self->q_mu_);
        if (self->net_q_.size() >= kMaxQueued) {
            self->net_q_.pop_front();
            self->q_dropped_++;
        }
        self->net_q_.push_back(*static_cast<const cloud_net_rec*>(data));
    } else if (sz == sizeof(cloud_dns_rec)) {
        const auto* r = static_cast<const cloud_dns_rec*>(data);
        cloud_dns_name out;
        std::memset(&out, 0, sizeof(out));
        if (!ParseDnsQuery(r->payload, r->len, out.name, sizeof(out.name), &out.qtype)) return 0;
        out.proc_start = r->proc_start;
        out.tgid = r->tgid;
        std::lock_guard<std::mutex> q(self->q_mu_);
        if (self->dns_q_.size() >= kMaxQueued) {
            self->dns_q_.pop_front();
            self->q_dropped_++;
        }
        self->dns_q_.push_back(out);
    }
    return 0;
}

// One lifecycle record: the header says how many exe and argument bytes follow, and
// the ring record must be exactly that long. Anything else is a bug or an ABI drift,
// counted and dropped rather than passed on.
int CloudCollectors::OnLifeRecord(void* ctx, void* data, size_t sz) {
    auto* self = static_cast<CloudCollectors*>(ctx);
    std::lock_guard<std::mutex> l(self->life_mu_);
    const auto* h = static_cast<const cloud_life_rec*>(data);
    if (sz < sizeof(cloud_life_rec) || sz != sizeof(cloud_life_rec) + CLOUD_LIFE_BODY(h) || sz > CLOUD_LIFE_REC_MAX) {
        self->life_q_dropped_++;
        return 0;
    }
    size_t padded = (sz + 7) & ~static_cast<size_t>(7);
    while (!self->life_q_.empty() && self->life_q_bytes_ + padded > kMaxLifeQueueBytes) {
        self->life_q_bytes_ -= self->life_q_.front().size();
        self->life_q_.pop_front();
        self->life_q_dropped_++;
    }
    std::vector<uint8_t> rec(padded, 0);
    std::memcpy(rec.data(), data, sz);
    self->life_q_bytes_ += rec.size();
    self->life_q_.push_back(std::move(rec));
    return 0;
}

void CloudCollectors::SetDirRowsOn(bool on) {
    std::lock_guard<std::mutex> lock(mu_);
    dir_rows_on_ = on;
}

void CloudCollectors::SetNamePolicy(std::vector<uint64_t> exts, std::vector<std::string> names,
                                    std::vector<std::string> prefixes) {
    std::lock_guard<std::mutex> lock(mu_);
    policy_exts_ = std::move(exts);
    policy_names_ = std::move(names);
    policy_prefixes_ = std::move(prefixes);
}

void CloudCollectors::SetDirPrefixPolicy(std::vector<std::string> prefixes) {
    std::lock_guard<std::mutex> lock(mu_);
    dir_prefix_policy_ = std::move(prefixes);
}

void CloudCollectors::SetNamesRingBytes(uint32_t bytes) {
    std::lock_guard<std::mutex> lock(mu_);
    names_ring_bytes_ = bytes;
}

void CloudCollectors::SetDirProcMax(uint32_t n) {
    std::lock_guard<std::mutex> lock(mu_);
    dir_proc_max_ = n;
}

// Fills the extension and exact-name maps of a loaded object (the confirmation behind the bloom
// filters and the prefix masks that BuildCfg baked into the read-only data). Entries the maps
// cannot hold (too many extensions, a name that is empty or too long) are reported: a policy that
// silently drops an entry would name less than the caller asked for.
// Every such entry is also COUNTED in `unheld` (exts, names; when given), which the agent reads
// through cloud_policy_stats and sends to the cloud: a stderr line alone once hid 42 unwatched
// names for days.
static void FillPolicy(int ext_fd, int exact_fd, const std::vector<uint64_t>& exts, const std::vector<std::string>& names,
                       uint64_t* unheld) {
    uint8_t one = 1;
    for (uint64_t e : exts) {
        if (e != 0 && (ext_fd < 0 || bpf_map_update_elem(ext_fd, &e, &one, BPF_ANY) != 0)) {
            std::cerr << "cloud collectors: extension policy entry not stored" << std::endl;
            if (unheld) unheld[0]++;
        }
    }
    for (const auto& n : names) {
        if (!NameFits(n)) continue;  // reported and counted by BuildCfg
        cloud_name_exact k;
        std::memset(&k, 0, sizeof(k));
        std::memcpy(k.name, n.data(), n.size());
        if (exact_fd < 0 || bpf_map_update_elem(exact_fd, &k, &one, BPF_ANY) != 0) {
            std::cerr << "cloud collectors: name policy entry '" << n << "' not stored" << std::endl;
            if (unheld) unheld[1]++;
        }
    }
}

void CloudCollectors::PolicyStats(uint64_t* out, size_t n) const {
    std::lock_guard<std::mutex> lock(mu_);
    for (size_t i = 0; i < n; i++) out[i] = i < 3 ? policy_unheld_[i] : 0;
}

// One name record: exactly a cloud_name_rec, or it is counted and dropped (an ABI drift must not
// be passed on as if it were a path).
int CloudCollectors::OnNameRecord(void* ctx, void* data, size_t sz) {
    auto* self = static_cast<CloudCollectors*>(ctx);
    std::lock_guard<std::mutex> l(self->name_mu_);
    if (sz != sizeof(cloud_name_rec)) {
        self->name_q_dropped_++;
        return 0;
    }
    // A full queue keeps what it has and drops the new record: the earliest records are the ones
    // that name a directory first, and "the first directories seen win" (agent caps).
    if (self->name_q_.size() >= kMaxQueued) {
        self->name_q_dropped_++;
        return 0;
    }
    cloud_name_rec r;
    std::memcpy(&r, data, sizeof(r));
    // The ring memory is reused, so the bytes after the path hold older paths: never hand them on.
    size_t len = r.len < CLOUD_NAME_PATH_MAX ? r.len : CLOUD_NAME_PATH_MAX;
    std::memset(r.path + len, 0, sizeof(r.path) - len);
    r.len = static_cast<uint16_t>(len);
    self->name_q_.push_back(r);
    return 0;
}

size_t CloudCollectors::DrainNames(cloud_name_rec* out, size_t cap) {
    std::lock_guard<std::mutex> l(name_mu_);
    size_t n = std::min(cap, name_q_.size());
    for (size_t i = 0; i < n; i++) {
        out[i] = name_q_.front();
        name_q_.pop_front();
    }
    return n;
}

// v7: one move/link/symlink record: exactly a cloud_move_rec, or it is counted and dropped
// (same ABI-drift discipline as OnNameRecord).
int CloudCollectors::OnMoveRecord(void* ctx, void* data, size_t sz) {
    auto* self = static_cast<CloudCollectors*>(ctx);
    std::lock_guard<std::mutex> l(self->move_mu_);
    if (sz != sizeof(cloud_move_rec)) {
        self->move_q_dropped_++;
        return 0;
    }
    if (self->move_q_.size() >= kMaxQueued) {
        self->move_q_dropped_++;
        return 0;
    }
    cloud_move_rec r;
    std::memcpy(&r, data, sizeof(r));
    size_t len = r.name_len < CLOUD_NAME_EXACT_MAX ? r.name_len : CLOUD_NAME_EXACT_MAX;
    std::memset(r.name + len, 0, sizeof(r.name) - len);
    r.name_len = static_cast<uint16_t>(len);
    self->move_q_.push_back(r);
    return 0;
}

size_t CloudCollectors::DrainMoves(cloud_move_rec* out, size_t cap) {
    std::lock_guard<std::mutex> l(move_mu_);
    size_t n = std::min(cap, move_q_.size());
    for (size_t i = 0; i < n; i++) {
        out[i] = move_q_.front();
        move_q_.pop_front();
    }
    return n;
}

void CloudCollectors::MoveStats(uint64_t* out, size_t n) const {
    for (size_t i = 0; i < n; i++) out[i] = 0;
    int fd = MapFd("move_stats");
    int ncpu = libbpf_num_possible_cpus();
    if (fd >= 0 && ncpu > 0) {
        std::vector<uint64_t> vals(static_cast<size_t>(ncpu));
        for (uint32_t i = 0; i < CLOUD_MOVE_STAT_MAX && i < n; i++) {
            if (bpf_map_lookup_elem(fd, &i, vals.data()) == 0) {
                for (uint64_t v : vals) out[i] += v;
            }
        }
    }
    if (n > CLOUD_MOVE_STAT_MAX) {
        std::lock_guard<std::mutex> l(move_mu_);
        out[CLOUD_MOVE_STAT_MAX] = move_q_dropped_;
    }
}

void CloudCollectors::NameStats(uint64_t* out, size_t n) const {
    for (size_t i = 0; i < n; i++) out[i] = 0;
    int fd = MapFd("name_stats");
    int ncpu = libbpf_num_possible_cpus();
    if (fd >= 0 && ncpu > 0) {
        std::vector<uint64_t> vals(static_cast<size_t>(ncpu));
        for (uint32_t i = 0; i < CLOUD_NAME_STAT_MAX && i < n; i++) {
            if (bpf_map_lookup_elem(fd, &i, vals.data()) == 0) {
                for (uint64_t v : vals) out[i] += v;
            }
        }
    }
    if (n > CLOUD_NAME_STAT_MAX) {
        std::lock_guard<std::mutex> l(name_mu_);
        out[CLOUD_NAME_STAT_MAX] = name_q_dropped_;
    }
}

uint64_t CloudCollectors::MapMemoryBytes(const char* map_name) const {
    int fd = MapFd(map_name);
    if (fd < 0) return 0;
    char p[64];
    std::snprintf(p, sizeof(p), "/proc/self/fdinfo/%d", fd);
    FILE* f = std::fopen(p, "r");
    if (!f) return 0;
    char line[256];
    uint64_t v = 0;
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strncmp(line, "memlock:", 8) == 0) v = std::strtoull(line + 8, nullptr, 10);
    }
    std::fclose(f);
    return v;
}

size_t CloudCollectors::DrainLife(uint8_t* out, size_t cap, size_t* nrecs) {
    size_t used = 0, n = 0;
    std::lock_guard<std::mutex> l(life_mu_);
    while (!life_q_.empty() && used + life_q_.front().size() <= cap) {
        const auto& r = life_q_.front();
        std::memcpy(out + used, r.data(), r.size());
        used += r.size();
        life_q_bytes_ -= r.size();
        life_q_.pop_front();
        n++;
    }
    if (nrecs) *nrecs = n;
    return used;
}

void CloudCollectors::LifeStats(uint64_t* out, size_t n) const {
    for (size_t i = 0; i < n; i++) out[i] = 0;
    int fd = MapFd("life_stats");
    int ncpu = libbpf_num_possible_cpus();
    if (fd >= 0 && ncpu > 0) {
        std::vector<uint64_t> vals(static_cast<size_t>(ncpu));
        for (uint32_t i = 0; i < CLOUD_LIFE_STAT_MAX && i < n; i++) {
            if (bpf_map_lookup_elem(fd, &i, vals.data()) == 0) {
                for (uint64_t v : vals) out[i] += v;
            }
        }
    }
    if (n > CLOUD_LIFE_STAT_MAX) {
        std::lock_guard<std::mutex> l(life_mu_);
        out[CLOUD_LIFE_STAT_MAX] = life_q_dropped_;
    }
}

void CloudCollectors::PollLoop() {
    // The lifecycle programs never wake the poller (BPF_RB_NO_WAKEUP), so epoll alone
    // would not report their records: consume every ring at least every 100 ms.
    while (running_.load()) {
        ring_buffer__poll(rb_, 100);
        ring_buffer__consume(rb_);
    }
    ring_buffer__poll(rb_, 0);
    ring_buffer__consume(rb_);
}

void CloudCollectors::ScanLoop() {
    char buf[4096];
    while (running_.load()) {
        int fd = bpf_iter_create(bpf_link__fd(iter_link_));
        if (fd >= 0) {
            while (read(fd, buf, sizeof(buf)) > 0) {
            }
            close(fd);
        }
        for (int i = 0; i < scan_secs_ * 10 && running_.load(); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

size_t CloudCollectors::DrainNet(cloud_net_rec* out, size_t cap) {
    std::lock_guard<std::mutex> q(q_mu_);
    size_t n = std::min(cap, net_q_.size());
    for (size_t i = 0; i < n; i++) {
        out[i] = net_q_.front();
        net_q_.pop_front();
    }
    return n;
}

size_t CloudCollectors::DrainDns(cloud_dns_name* out, size_t cap) {
    std::lock_guard<std::mutex> q(q_mu_);
    size_t n = std::min(cap, dns_q_.size());
    for (size_t i = 0; i < n; i++) {
        out[i] = dns_q_.front();
        dns_q_.pop_front();
    }
    return n;
}

// Lookup-and-delete of a hash map in batches: rows are removed as they are read,
// so a drain never reports the same counts twice. The batch call holds the bucket
// lock, so an increment cannot slip between the read and the delete.
static size_t DrainMap(int fd, size_t key_sz, size_t val_sz, size_t cap,
                       const std::function<void(const void*, const void*)>& emit) {
    if (fd < 0 || cap == 0) return 0;
    constexpr size_t kBatch = 128;
    std::vector<uint8_t> keys(kBatch * key_sz), vals(kBatch * val_sz);
    size_t total = 0;
    __u64 token = 0;
    bool first = true;
    bool batch_ok = true;
    while (total < cap) {
        __u32 count = static_cast<__u32>(std::min(kBatch, cap - total));
        __u64 next = 0;
        LIBBPF_OPTS(bpf_map_batch_opts, opts);
        int rc = bpf_map_lookup_and_delete_batch(fd, first ? nullptr : &token, &next, keys.data(), vals.data(),
                                                 &count, &opts);
        for (__u32 i = 0; i < count; i++) {
            emit(keys.data() + i * key_sz, vals.data() + i * val_sz);
            total++;
        }
        first = false;
        token = next;
        if (rc == -ENOENT) return total;  // the end of the map
        if (rc != 0) {
            batch_ok = false;  // ENOSPC (a bucket larger than the buffer) or no batch support
            break;
        }
    }
    if (batch_ok || total >= cap) return total;

    // Fallback: walk the keys, read each, delete it. Not atomic against a
    // concurrent increment (a count landing between the two calls is lost), which
    // is the reason the batch call is preferred.
    std::vector<uint8_t> cur(key_sz), next(key_sz), val(val_sz);
    std::vector<std::vector<uint8_t>> ks;
    bool have = false;
    while (bpf_map_get_next_key(fd, have ? cur.data() : nullptr, next.data()) == 0) {
        cur = next;
        have = true;
        ks.push_back(cur);
        if (ks.size() >= cap - total) break;
    }
    for (auto& k : ks) {
        if (bpf_map_lookup_elem(fd, k.data(), val.data()) != 0) continue;
        bpf_map_delete_elem(fd, k.data());
        emit(k.data(), val.data());
        total++;
    }
    return total;
}

size_t CloudCollectors::DrainUdp(cloud_udp_row* out, size_t cap) {
    size_t n = 0;
    DrainMap(MapFd("udp_fold"), sizeof(cloud_udp_key), sizeof(cloud_udp_val), cap,
             [&](const void* k, const void* v) {
                 std::memcpy(&out[n].key, k, sizeof(cloud_udp_key));
                 std::memcpy(&out[n].val, v, sizeof(cloud_udp_val));
                 n++;
             });
    return n;
}

size_t CloudCollectors::DrainFiles(cloud_file_row* out, size_t cap) {
    size_t n = 0;
    DrainMap(MapFd("file_fold"), sizeof(cloud_file_key), sizeof(cloud_file_val), cap,
             [&](const void* k, const void* v) {
                 std::memcpy(&out[n].key, k, sizeof(cloud_file_key));
                 std::memcpy(&out[n].val, v, sizeof(cloud_file_val));
                 n++;
             });
    return n;
}

size_t CloudCollectors::DrainDirs(cloud_dir_row* out, size_t cap) {
    // The per-process bound table first: emptying it starts a new epoch for the bound. Whatever it
    // says a process was refused is held for DrainDirDrops.
    {
        std::lock_guard<std::mutex> l(dir_mu_);
        DrainMap(MapFd("dir_proc"), sizeof(cloud_dir_proc_key), sizeof(cloud_dir_proc_val), CLOUD_DIR_PROC_MAX,
                 [&](const void* k, const void* v) {
                     const auto* pk = static_cast<const cloud_dir_proc_key*>(k);
                     const auto* pv = static_cast<const cloud_dir_proc_val*>(v);
                     if (pv->drop_opens == 0 && pv->drop_dirs == 0) return;
                     auto& slot = dir_drops_[{pk->proc_start, pk->tgid}];
                     slot.first += pv->drop_dirs;
                     slot.second += pv->drop_opens;
                 });
    }
    size_t n = 0;
    DrainMap(MapFd("dir_state"), sizeof(cloud_dirid), sizeof(cloud_dir_val), cap, [&](const void* k, const void* v) {
        std::memcpy(&out[n].key, k, sizeof(cloud_dirid));
        std::memcpy(&out[n].val, v, sizeof(cloud_dir_val));
        n++;
    });
    return n;
}

size_t CloudCollectors::DrainDirExtFold(cloud_dir_ext_row* out, size_t cap) {
    size_t n = 0;
    DrainMap(MapFd("dir_ext_fold"), sizeof(cloud_dir_ext_key), sizeof(cloud_dir_bytes_val), cap,
             [&](const void* k, const void* v) {
                 std::memcpy(&out[n].key, k, sizeof(cloud_dir_ext_key));
                 std::memcpy(&out[n].val, v, sizeof(cloud_dir_bytes_val));
                 n++;
             });
    return n;
}

size_t CloudCollectors::DrainDirPrefixFold(cloud_dir_prefix_row* out, size_t cap) {
    size_t n = 0;
    DrainMap(MapFd("dir_prefix_fold"), sizeof(cloud_dir_prefix_key), sizeof(cloud_dir_bytes_val), cap,
             [&](const void* k, const void* v) {
                 std::memcpy(&out[n].key, k, sizeof(cloud_dir_prefix_key));
                 std::memcpy(&out[n].val, v, sizeof(cloud_dir_bytes_val));
                 n++;
             });
    return n;
}

size_t CloudCollectors::DrainDirHll(cloud_dir_hll_row* out, size_t cap) {
    size_t n = 0;
    DrainMap(MapFd("dir_distinct_hll"), sizeof(cloud_dirid), sizeof(cloud_dir_hll_val), cap,
             [&](const void* k, const void* v) {
                 std::memcpy(&out[n].key, k, sizeof(cloud_dirid));
                 std::memcpy(&out[n].val, v, sizeof(cloud_dir_hll_val));
                 n++;
             });
    return n;
}

size_t CloudCollectors::DrainDirDrops(cloud_dir_drop_row* out, size_t cap) {
    std::lock_guard<std::mutex> l(dir_mu_);
    size_t n = 0;
    while (n < cap && !dir_drops_.empty()) {
        auto it = dir_drops_.begin();
        std::memset(&out[n], 0, sizeof(out[n]));
        out[n].key.proc_start = it->first.first;
        out[n].key.tgid = it->first.second;
        out[n].dirs = it->second.first;
        out[n].opens = it->second.second;
        dir_drops_.erase(it);
        n++;
    }
    return n;
}

size_t CloudCollectors::DrainProjects(cloud_proj_row* out, size_t cap) {
    int fd = MapFd("proj_path");
    if (fd < 0) return 0;
    std::lock_guard<std::mutex> lock(proj_mu_);
    size_t n = 0;
    cloud_dir_key cur{}, next{};
    bool have = false;
    while (n < cap) {
        int rc = bpf_map_get_next_key(fd, have ? &cur : nullptr, &next);
        if (rc != 0) break;
        cur = next;
        have = true;
        auto id = std::make_pair(static_cast<uint64_t>(cur.dev), static_cast<uint64_t>(cur.ino));
        if (proj_reported_.count(id)) continue;
        cloud_proj_val v;
        if (bpf_map_lookup_elem(fd, &cur, &v) != 0) continue;
        out[n].dev = cur.dev;
        out[n].ino = cur.ino;
        out[n].root_kind = v.root_kind;
        out[n].pad = 0;
        std::memcpy(out[n].path, v.path, sizeof(out[n].path));
        out[n].path[sizeof(out[n].path) - 1] = 0;
        proj_reported_.insert(id);
        n++;
    }
    return n;
}

std::vector<CloudCollectors::ProgRunStat> CloudCollectors::RunStats() const {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<ProgRunStat> out;
    if (!obj_) return out;
    bpf_program* p;
    bpf_object__for_each_program(p, obj_) {
        if (!bpf_program__autoload(p)) continue;
        struct bpf_prog_info info = {};
        __u32 len = sizeof(info);
        if (bpf_obj_get_info_by_fd(bpf_program__fd(p), &info, &len) != 0) continue;
        out.push_back({bpf_program__name(p), info.run_cnt, info.run_time_ns});
    }
    return out;
}

void CloudCollectors::Stats(uint64_t* out, size_t n) const {
    for (size_t i = 0; i < n; i++) out[i] = 0;
    int fd = MapFd("cloud_stats");
    int ncpu = libbpf_num_possible_cpus();
    if (fd >= 0 && ncpu > 0) {
        std::vector<uint64_t> vals(static_cast<size_t>(ncpu));
        for (uint32_t i = 0; i < CLOUD_STAT_MAX && i < n; i++) {
            if (bpf_map_lookup_elem(fd, &i, vals.data()) == 0) {
                for (uint64_t v : vals) out[i] += v;
            }
        }
    }
    if (n > CLOUD_STAT_MAX) {
        std::lock_guard<std::mutex> q(q_mu_);
        out[CLOUD_STAT_MAX] = q_dropped_;
    }
}

// ---- scope -------------------------------------------------------------------

bool CloudCollectors::AddScopeRoot(uint64_t posix_dev, uint64_t ino, uint32_t kind) {
    int fd = MapFd("scope_roots");
    if (fd < 0) return false;
    cloud_dir_key k{KernelDev(posix_dev), ino};
    uint8_t v = static_cast<uint8_t>(kind);
    return bpf_map_update_elem(fd, &k, &v, BPF_ANY) == 0;
}

bool CloudCollectors::RemoveScopeRoot(uint64_t posix_dev, uint64_t ino) {
    int fd = MapFd("scope_roots");
    if (fd < 0) return false;
    cloud_dir_key k{KernelDev(posix_dev), ino};
    return bpf_map_delete_elem(fd, &k) == 0;
}

bool CloudCollectors::AddSkipDir(uint64_t posix_dev, uint64_t ino) {
    int fd = MapFd("skip_dirs");
    if (fd < 0) return false;
    cloud_dir_key k{KernelDev(posix_dev), ino};
    uint8_t v = 1;
    return bpf_map_update_elem(fd, &k, &v, BPF_ANY) == 0;
}

bool CloudCollectors::RemoveSkipDir(uint64_t posix_dev, uint64_t ino) {
    int fd = MapFd("skip_dirs");
    if (fd < 0) return false;
    cloud_dir_key k{KernelDev(posix_dev), ino};
    return bpf_map_delete_elem(fd, &k) == 0;
}

static void WipeMap(int fd, size_t key_sz) {
    if (fd < 0) return;
    std::vector<uint8_t> cur(key_sz), next(key_sz);
    bool have = false;
    std::vector<std::vector<uint8_t>> keys;
    while (bpf_map_get_next_key(fd, have ? cur.data() : nullptr, next.data()) == 0) {
        cur = next;
        have = true;
        keys.push_back(cur);
    }
    for (auto& k : keys) bpf_map_delete_elem(fd, k.data());
}

void CloudCollectors::ClearScope() {
    WipeMap(MapFd("scope_roots"), sizeof(cloud_dir_key));
    WipeMap(MapFd("skip_dirs"), sizeof(cloud_dir_key));
    CommitScope();
}

void CloudCollectors::CommitScope() {
    // The cache may hold "out of scope" for a directory that is in scope now (or
    // the reverse). Dropping it makes every directory be resolved again.
    WipeMap(MapFd("scope_cache"), sizeof(cloud_dir_key));
}

// ---- DNS ---------------------------------------------------------------------

bool ParseDnsQuery(const uint8_t* msg, size_t len, char* name, size_t name_cap, uint16_t* qtype) {
    if (len < 17 || name_cap < 2) return false;
    uint16_t flags = static_cast<uint16_t>(msg[2] << 8 | msg[3]);
    uint16_t qd = static_cast<uint16_t>(msg[4] << 8 | msg[5]);
    if (flags & 0x8000) return false;  // a response, not a query
    if (qd != 1) return false;
    size_t pos = 12, o = 0;
    while (true) {
        if (pos >= len) return false;
        uint8_t l = msg[pos++];
        if (l == 0) break;
        if (l > 63) return false;  // compression pointers do not appear in a question
        if (pos + l > len) return false;
        if (o != 0) {
            if (o + 1 >= name_cap) return false;
            name[o++] = '.';
        }
        for (uint8_t i = 0; i < l; i++) {
            unsigned char c = msg[pos + i];
            if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c + 32);
            bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) return false;
            if (o + 1 >= name_cap) return false;
            name[o++] = static_cast<char>(c);
        }
        pos += l;
    }
    if (o == 0 || pos + 2 > len) return false;
    name[o] = 0;
    *qtype = static_cast<uint16_t>(msg[pos] << 8 | msg[pos + 1]);
    return true;
}

}  // namespace kinnector::lnx
