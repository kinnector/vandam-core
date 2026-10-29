// Paired cost measurement of lsm/file_open: several configurations (and builds) of the cloud object
// are loaded AT THE SAME TIME, each with only its cloud_file_open program attached, so every open
// runs all of them back to back and the kernel's own per-program run counters give each one's cost
// over exactly the same opens in the same instant. The VM's timing is bimodal (about 400 ns in one
// phase and 1,000 ns in the next for the same program): a variant measured alone, or even
// interleaved a few seconds apart, is dominated by which phase it landed in. Variants measured
// together see the same phase, so the differences between them are meaningful. Not part of the
// product. Needs root, and only ever runs in the 6.18 VM.
//
//   kinnector-cloud-multiperf <kinnector_cloud.bpf.o> --policy-file F [--object2 <noearly.o>] [--reverse] [--sweep N]
//
// The variants, in attach order (two `off` at both ends show any order bias: whoever runs second
// finds the inode and dentry hot):
//   off1      the whole directory-row mechanism off (the floor)
//   on        the mechanism on, no policy (every open eligible, EXT route, no name sent)
//   policyext the extension whitelist alone (the name mask rejects on its length gate)
//   policy    the full policy (extensions, exact names, prefix)
//   policyne  the full policy, built without the early rejects (-DCLOUD_EXP_NO_EARLY), with --object2
//   off2      the mechanism off again
// Workloads: standard (the check-cloud-perf.sh one: 20 folders x 10 .txt files, 200,000 warm opens),
// hot (200 .pdf files in 10 directories, 200,000 warm opens: the steady state of an eligible open),
// build (source and object files, 100,000 opens, nothing eligible under the policy), sweep (N mixed
// cold files), wide (20,000 directories of 4 files: the node_modules shape).
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "cloud_collectors.h"

using namespace kinnector::lnx;

namespace {

struct Policy {
    std::vector<uint64_t> exts;
    std::vector<std::string> names, prefixes;
    bool any() const { return !exts.empty() || !names.empty() || !prefixes.empty(); }
};

uint64_t ExtValue(const std::string& e) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8 && i < e.size(); i++) v |= static_cast<uint64_t>(static_cast<unsigned char>(e[i])) << (8 * i);
    return v;
}

std::vector<std::string> JsonStrings(const std::string& doc, const std::string& key) {
    std::vector<std::string> out;
    size_t k = doc.find("\"" + key + "\"");
    if (k == std::string::npos) return out;
    size_t open = doc.find('[', k), close = doc.find(']', k);
    if (open == std::string::npos || close == std::string::npos || close < open) return out;
    size_t i = open;
    while (true) {
        size_t a = doc.find('"', i + 1);
        if (a == std::string::npos || a > close) break;
        size_t b = doc.find('"', a + 1);
        if (b == std::string::npos || b > close) break;
        out.push_back(doc.substr(a + 1, b - a - 1));
        i = b;
    }
    return out;
}

bool LoadPolicy(const std::string& path, Policy* p) {
    FILE* f = std::fopen(path.c_str(), "r");
    if (!f) return false;
    std::string doc;
    char buf[4096];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) doc.append(buf, n);
    std::fclose(f);
    for (const auto& e : JsonStrings(doc, "ext")) p->exts.push_back(ExtValue(e));
    p->names = JsonStrings(doc, "names");
    p->prefixes = JsonStrings(doc, "prefixes");
    return true;
}

struct Variant {
    std::string name;
    bool dir_rows;
    bool use_policy;
    Policy policy;
    std::string object;
};

struct Loaded {
    Variant v;
    bpf_object* obj = nullptr;
    bpf_program* prog = nullptr;
    bpf_link* link = nullptr;
    ring_buffer* rb = nullptr;
};

int NoopRecord(void*, void*, size_t) { return 0; }

uint64_t KernelDev(uint64_t posix_dev) {
    dev_t d = static_cast<dev_t>(posix_dev);
    return (static_cast<uint64_t>(major(d)) << 20) | static_cast<uint64_t>(minor(d));
}

// Deletes every key of a map (between workloads, so one workload's directory keys never fill the map for the next).
void WipeMap(bpf_object* o, const char* name, size_t key_sz) {
    bpf_map* m = bpf_object__find_map_by_name(o, name);
    if (!m) return;
    int fd = bpf_map__fd(m);
    std::vector<uint8_t> cur(key_sz), next(key_sz);
    std::vector<std::vector<uint8_t>> keys;
    bool have = false;
    while (bpf_map_get_next_key(fd, have ? cur.data() : nullptr, next.data()) == 0) {
        cur = next;
        have = true;
        keys.push_back(cur);
    }
    for (auto& k : keys) bpf_map_delete_elem(fd, k.data());
}

bool Open(Loaded* l, const std::string& obj_default) {
    const Variant& v = l->v;
    l->obj = bpf_object__open_file((v.object.empty() ? obj_default : v.object).c_str(), nullptr);
    if (!l->obj) return false;
    cloud_cfg cfg = BuildCloudCfg(v.dir_rows, v.use_policy && v.policy.any(), 0, v.policy.exts, v.policy.names, v.policy.prefixes, {});
    PrepareCloudObject(l->obj, cfg, 0);
    bpf_program* p;
    bpf_object__for_each_program(p, l->obj) {
        bool on = std::strcmp(bpf_program__name(p), "cloud_file_open") == 0;
        bpf_program__set_autoload(p, on);
        if (on) l->prog = p;
    }
    if (!l->prog || bpf_object__load(l->obj) != 0) return false;
    if (v.use_policy && v.policy.any()) FillCloudPolicy(l->obj, v.policy.exts, v.policy.names);
    if (cfg.dir_rows_on) {
        bpf_map* rb = bpf_object__find_map_by_name(l->obj, "names_rb");
        if (rb) l->rb = ring_buffer__new(bpf_map__fd(rb), NoopRecord, nullptr, nullptr);
    }
    return true;
}

void SetScope(Loaded& l, const struct stat& st) {
    bpf_map* m = bpf_object__find_map_by_name(l.obj, "scope_roots");
    if (!m) return;
    cloud_dir_key k{KernelDev(st.st_dev), st.st_ino};
    uint8_t kind = CLOUD_ROOT_HOME;
    bpf_map_update_elem(bpf_map__fd(m), &k, &kind, BPF_ANY);
    WipeMap(l.obj, "scope_cache", sizeof(cloud_dir_key));
}

void ClearScope(Loaded& l) {
    WipeMap(l.obj, "scope_roots", sizeof(cloud_dir_key));
    WipeMap(l.obj, "scope_cache", sizeof(cloud_dir_key));
    WipeMap(l.obj, "dir_state", sizeof(cloud_dirid));
    WipeMap(l.obj, "dir_proc", sizeof(cloud_dir_proc_key));
    WipeMap(l.obj, "file_fold", sizeof(cloud_file_key));
}

struct Stat {
    uint64_t cnt = 0, ns = 0;
};

Stat StatOf(const Loaded& l) {
    struct bpf_prog_info info = {};
    __u32 len = sizeof(info);
    Stat s;
    if (bpf_obj_get_info_by_fd(bpf_program__fd(l.prog), &info, &len) == 0) {
        s.cnt = info.run_cnt;
        s.ns = info.run_time_ns;
    }
    return s;
}

std::string MakeBase() {
    const char* cands[] = {"/var/tmp/kinn-mperf-XXXXXX", "/root/kinn-mperf-XXXXXX", "./kinn-mperf-XXXXXX"};
    for (const char* c : cands) {
        std::string t = c;
        struct statfs sfs;
        std::string parent = t.substr(0, t.find_last_of('/'));
        if (parent.empty()) parent = ".";
        if (statfs(parent.c_str(), &sfs) != 0) continue;
        if (sfs.f_type == 0x01021994 || sfs.f_type == 0x794c7630) continue;
        std::vector<char> buf(t.begin(), t.end());
        buf.push_back(0);
        if (mkdtemp(buf.data())) return buf.data();
    }
    return "";
}

void Touch(const std::string& p) {
    int fd = open(p.c_str(), O_WRONLY | O_CREAT, 0600);
    if (fd >= 0) close(fd);
}

void OpenAll(const std::vector<std::string>& files, int rounds) {
    for (int r = 0; r < rounds; r++) {
        for (const auto& f : files) {
            int fd = open(f.c_str(), O_RDONLY);
            if (fd >= 0) close(fd);
        }
    }
}

// Runs `body` (the timed opens) and prints, per variant, the calls and ns per call over exactly that span.
void Timed(std::vector<Loaded>& ls, const char* workload, const std::function<void()>& body) {
    std::vector<Stat> before, after;
    for (auto& l : ls) before.push_back(StatOf(l));
    body();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    for (auto& l : ls) after.push_back(StatOf(l));
    std::printf("workload %-9s", workload);
    for (size_t i = 0; i < ls.size(); i++) {
        uint64_t c = after[i].cnt - before[i].cnt, n = after[i].ns - before[i].ns;
        std::printf(" %s=%.1f(%llu)", ls[i].v.name.c_str(), c ? static_cast<double>(n) / static_cast<double>(c) : 0.0, (unsigned long long)c);
    }
    std::printf("\n");
    std::fflush(stdout);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <kinnector_cloud.bpf.o> --policy-file F [--object2 O] [--reverse] [--sweep N] [--reps R]\n", argv[0]);
        return 2;
    }
    Policy policy;
    std::string object2;
    bool reverse = false;
    size_t sweep = 30000;
    int reps = 1;
    for (int i = 2; i < argc; i++) {
        if (!std::strcmp(argv[i], "--policy-file") && i + 1 < argc) {
            if (!LoadPolicy(argv[++i], &policy)) {
                std::fprintf(stderr, "cannot read the policy file\n");
                return 2;
            }
        } else if (!std::strcmp(argv[i], "--object2") && i + 1 < argc) {
            object2 = argv[++i];
        } else if (!std::strcmp(argv[i], "--reverse")) {
            reverse = true;
        } else if (!std::strcmp(argv[i], "--sweep") && i + 1 < argc) {
            sweep = static_cast<size_t>(std::strtoull(argv[++i], nullptr, 10));
        } else if (!std::strcmp(argv[i], "--reps") && i + 1 < argc) {
            reps = std::atoi(argv[++i]);
        }
    }
    if (geteuid() != 0) {
        std::fprintf(stderr, "must run as root\n");
        return 2;
    }
    int stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
    if (stats_fd < 0) {
        std::fprintf(stderr, "cannot enable BPF run-time stats\n");
        return 2;
    }
    const std::string obj = argv[1];
    Policy none;
    std::vector<Variant> vs = {{"off1", false, false, none, ""}, {"on", true, false, none, ""}};
    Policy ext_only;
    ext_only.exts = policy.exts;
    if (policy.any()) {
        vs.push_back({"policyext", true, true, ext_only, ""});
        vs.push_back({"policy", true, true, policy, ""});
        if (!object2.empty()) vs.push_back({"policyne", true, true, policy, object2});
    }
    vs.push_back({"off2", false, false, none, ""});
    if (reverse) std::reverse(vs.begin(), vs.end());

    std::vector<Loaded> ls(vs.size());
    for (size_t i = 0; i < vs.size(); i++) {
        ls[i].v = vs[i];
        if (!Open(&ls[i], obj)) {
            std::fprintf(stderr, "variant %s: load failed\n", vs[i].name.c_str());
            return 2;
        }
    }
    // Attach in this order: each open then runs the programs in it.
    for (auto& l : ls) {
        l.link = bpf_program__attach(l.prog);
        if (libbpf_get_error(l.link)) {
            std::fprintf(stderr, "variant %s: attach failed\n", l.v.name.c_str());
            return 2;
        }
    }
    std::atomic<bool> stop{false};
    std::thread poller([&] {
        while (!stop.load()) {
            for (auto& l : ls) {
                if (l.rb) ring_buffer__poll(l.rb, 0);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    });

    std::string base = MakeBase();
    if (base.empty()) {
        std::fprintf(stderr, "no real filesystem\n");
        stop = true;
        poller.join();
        return 2;
    }
    struct stat st;
    stat(base.c_str(), &st);
    std::printf("variants (attach order):");
    for (auto& l : ls) std::printf(" %s", l.v.name.c_str());
    std::printf("\n");

    auto run_workload = [&](const char* name, const std::vector<std::string>& files, int rounds, bool hostname_too) {
        for (auto& l : ls) ClearScope(l);
        for (auto& l : ls) SetScope(l, st);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        Timed(ls, name, [&] {
            for (int r = 0; r < rounds; r++) {
                for (size_t i = 0; i < files.size(); i++) {
                    int fd = open(files[i].c_str(), O_RDONLY);
                    if (fd >= 0) close(fd);
                    if (hostname_too && (i & 3) == 0) {
                        int o = open("/etc/hostname", O_RDONLY);
                        if (o >= 0) close(o);
                    }
                }
            }
        });
    };

    std::string docs = base + "/Documents";
    mkdir(docs.c_str(), 0700);

    // standard: 20 project folders, 10 .txt files each, 200,000 opens
    std::vector<std::string> standard;
    for (int d = 0; d < 20; d++) {
        std::string proj = docs + "/p" + std::to_string(d), sub = proj + "/src";
        mkdir(proj.c_str(), 0700);
        mkdir(sub.c_str(), 0700);
        for (int f = 0; f < 10; f++) {
            standard.push_back(sub + "/f" + std::to_string(f) + ".txt");
            Touch(standard.back());
        }
    }
    // hot: 200 .pdf files in 10 directories
    std::vector<std::string> hot;
    for (int d = 0; d < 10; d++) {
        std::string dir = docs + "/h" + std::to_string(d);
        mkdir(dir.c_str(), 0700);
        for (int f = 0; f < 20; f++) {
            hot.push_back(dir + "/d" + std::to_string(f) + ".pdf");
            Touch(hot.back());
        }
    }
    // build: source and object files in a few directories, none eligible under the policy
    std::vector<std::string> build;
    {
        const char* exts[] = {"c", "h", "o", "d", "a", "so", "S", "in"};
        for (int d = 0; d < 8; d++) {
            std::string dir = docs + "/b" + std::to_string(d);
            mkdir(dir.c_str(), 0700);
            for (int f = 0; f < 125; f++) {
                build.push_back(dir + "/m" + std::to_string(f) + "." + exts[f % 8]);
                Touch(build.back());
            }
        }
    }
    // sweep: nfiles mixed files in 30 project folders (10% documents, keys, archives...), 5,001 no-extension files in one
    std::vector<std::string> sw;
    {
        static const struct { const char* ext; int n; } kMix[] = {{"pdf", 30}, {"docx", 20}, {"jpg", 15}, {"zip", 15}, {"pem", 10}, {"kdbx", 5},
                                                                  {"db", 5},   {"c", 300},   {"h", 200},  {"o", 200},  {"log", 100}, {"", 100}};
        const size_t per_proj = sweep / 30;
        for (size_t p = 0; p < 30; p++) {
            std::string proj = docs + "/sw" + std::to_string(p);
            mkdir(proj.c_str(), 0700);
            size_t made = 0;
            for (const auto& m : kMix) {
                size_t want = static_cast<size_t>(m.n) * per_proj / 1000;
                for (size_t i = 0; i < want && made < per_proj; i++, made++) {
                    sw.push_back(proj + "/f" + std::to_string(made) + (m.ext[0] ? std::string(".") + m.ext : ""));
                    Touch(sw.back());
                }
            }
        }
        std::string rare_dir = docs + "/gitobjs";
        mkdir(rare_dir.c_str(), 0700);
        for (int i = 0; i < 5000; i++) {
            sw.push_back(rare_dir + "/o" + std::to_string(i));
            Touch(sw.back());
        }
        sw.push_back(rare_dir + "/id_rsa");
        Touch(sw.back());
    }
    // wide: 20,000 directories of 4 files (README.md, package.json, index.js, LICENSE)
    std::vector<std::string> wide;
    {
        std::string nm = docs + "/nm";
        mkdir(nm.c_str(), 0700);
        for (int g = 0; g < 100; g++) {
            std::string gd = nm + "/g" + std::to_string(g);
            mkdir(gd.c_str(), 0700);
            for (int d = 0; d < 200; d++) {
                std::string dir = gd + "/pkg" + std::to_string(d);
                mkdir(dir.c_str(), 0700);
                for (const char* n : {"/README.md", "/package.json", "/index.js", "/LICENSE"}) {
                    wide.push_back(dir + n);
                    Touch(wide.back());
                }
            }
        }
    }

    for (int r = 0; r < reps; r++) {
        std::printf("rep %d\n", r + 1);
        run_workload("standard", standard, 200000 / static_cast<int>(standard.size()) + 1, true);
        run_workload("hot", hot, 1000, false);
        run_workload("build", build, 100, false);
        run_workload("sweep", sw, 1, false);
        run_workload("wide", wide, 1, false);
    }

    // What each variant did with the wide tree, from its own counters (summed per-CPU array).
    for (auto& l : ls) {
        bpf_map* m = bpf_object__find_map_by_name(l.obj, "name_stats");
        if (!m) continue;
        int ncpu = libbpf_num_possible_cpus();
        std::vector<uint64_t> vals(static_cast<size_t>(ncpu));
        uint64_t s[CLOUD_NAME_STAT_MAX] = {};
        for (uint32_t i = 0; i < CLOUD_NAME_STAT_MAX; i++) {
            if (bpf_map_lookup_elem(bpf_map__fd(m), &i, vals.data()) == 0) {
                for (uint64_t v : vals) s[i] += v;
            }
        }
        std::printf("counters %-9s emitted=%llu ring_full=%llu too_long=%llu eligible=%llu dir_map_full=%llu dir_proc_full=%llu\n", l.v.name.c_str(),
                    (unsigned long long)s[CLOUD_NAME_STAT_EMITTED], (unsigned long long)s[CLOUD_NAME_STAT_RING_FULL], (unsigned long long)s[CLOUD_NAME_STAT_TOO_LONG],
                    (unsigned long long)s[CLOUD_NAME_STAT_ELIGIBLE], (unsigned long long)s[CLOUD_NAME_STAT_DIR_MAP_FULL], (unsigned long long)s[CLOUD_NAME_STAT_DIR_PROC_FULL]);
    }

    stop = true;
    poller.join();
    for (auto& l : ls) {
        if (l.link) bpf_link__destroy(l.link);
        if (l.rb) ring_buffer__free(l.rb);
        if (l.obj) bpf_object__close(l.obj);
    }
    close(stats_fd);
    std::string cmd = "rm -rf '" + base + "'";
    if (system(cmd.c_str()) != 0) {}
    return 0;
}
