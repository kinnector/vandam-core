// Performance gate for the cloud-tier collectors: drives a fixed workload through
// the real programs and compares the kernel's OWN per-program run counters against
// a per-hook budget. Wall-clock time is never used: the LVH VMs drift by 2x, the
// bpf_stats counters do not (antitheft-cloud/bench/*/RESULTS.md).
//
//   kinnector-cloud-perf <kinnector_cloud.bpf.o> [--json]
//
// Exit 0 within budget, 1 over budget, 2 could not run. Needs root. Run it in the
// 6.18 VM, never on the desktop. Budgets are about 3x the
// measured cost, so they catch a real regression without flapping on noise; if a
// change legitimately raises a cost, raise the budget here in the same commit and
// say why.
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <thread>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include "cloud_collectors.h"

using kinnector::lnx::CloudCollectors;

namespace {

struct Budget {
    const char* prog;
    double max_ns_per_call;
    uint64_t min_calls;  // fewer than this and the workload did not exercise it
};

// Measured on 6.18.46 (bench/*/RESULTS.md and this tool): file_open about 400 ns,
// per-call UDP hooks 30-100 ns, connection stamping and close a few microseconds.
const Budget kBudgets[] = {
    {"cloud_file_open", 1500, 50000},
    {"cloud_connect", 2500, 1000},
    {"cloud_accept", 4000, 1000},
    {"cloud_tcp_close", 12000, 1000},
    {"cloud_udp_send", 800, 10000},
    {"cloud_udp_recv", 800, 10000},
    {"cloud_dns4", 400, 10000},
    // Lifecycle. Exec is per process (a few microseconds is fine: an exec syscall itself costs
    // hundreds); fork and exit also run for every THREAD created or ended, where they must
    // return almost at once, so half of their calls in this workload are that cheap path.
    // Measured 0.6 us for fork and exit and 4.1 us for exec with the reader never woken
    // (BPF_RB_NO_WAKEUP); waking it per event cost 3.2 us, 2.8 us and 9.4 us.
    {"cloud_life_fork", 1500, 3000},
    // Measured 2.5 to 4.8 us on the VM (a task-storage slot allocated and freed per exec, plus
    // bpf_d_path); the VM's own timing drifts by 2x between runs.
    {"cloud_life_exe", 9000, 1500},
    {"cloud_life_exec", 8000, 1500},
    {"cloud_life_exit", 1500, 3000},
};

std::string MakeBase() {
    const char* cands[] = {"/var/tmp/kinn-perf-XXXXXX", "/root/kinn-perf-XXXXXX", "./kinn-perf-XXXXXX"};
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

void FileWorkload(const std::string& base) {
    // 20 project folders three levels below the root, 10 files each, opened many times.
    std::vector<std::string> files;
    std::string docs = base + "/Documents";
    mkdir(docs.c_str(), 0700);
    for (int d = 0; d < 20; d++) {
        std::string proj = docs + "/p" + std::to_string(d);
        mkdir(proj.c_str(), 0700);
        std::string sub = proj + "/src";
        mkdir(sub.c_str(), 0700);
        for (int f = 0; f < 10; f++) {
            std::string p = sub + "/f" + std::to_string(f) + ".txt";
            int fd = open(p.c_str(), O_WRONLY | O_CREAT, 0600);
            if (fd >= 0) close(fd);
            files.push_back(p);
        }
    }
    // Files outside every scope root, to exercise the out-of-scope path.
    for (int i = 0; i < 200000; i++) {
        int fd = open(files[static_cast<size_t>(i) % files.size()].c_str(), O_RDONLY);
        if (fd >= 0) close(fd);
        if ((i & 3) == 0) {
            int o = open("/etc/hostname", O_RDONLY);
            if (o >= 0) close(o);
        }
    }
    std::string cmd = "rm -rf '" + base + "'";
    if (system(cmd.c_str()) != 0) {}
}

void TcpWorkload() {
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || listen(ls, 128) != 0) return;
    socklen_t l = sizeof(a);
    getsockname(ls, reinterpret_cast<sockaddr*>(&a), &l);
    char buf[64] = {};
    for (int i = 0; i < 3000; i++) {
        int c = socket(AF_INET, SOCK_STREAM, 0);
        // RST on close: no TIME_WAIT pile-up, so the run does not exhaust ports.
        linger lg{1, 0};
        setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
        if (connect(c, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0) {
            int s = accept(ls, nullptr, nullptr);
            if (write(c, buf, sizeof(buf)) < 0) {}
            if (s >= 0) {
                if (read(s, buf, sizeof(buf)) < 0) {}
                setsockopt(s, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
                close(s);
            }
        }
        close(c);
    }
    close(ls);
}

void UdpWorkload() {
    int srv = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(srv, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return;
    socklen_t l = sizeof(a);
    getsockname(srv, reinterpret_cast<sockaddr*>(&a), &l);
    int cli = socket(AF_INET, SOCK_DGRAM, 0);
    char buf[256] = {};
    for (int i = 0; i < 60000; i++) {
        if (sendto(cli, buf, 200, 0, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) continue;
        if (recv(srv, buf, sizeof(buf), 0) < 0) {}
    }
    close(cli);
    close(srv);
}

// Processes and threads: 2000 fork+exec+exit of /bin/true (one with a 4 KB argument each
// fifth time, so the argument copy is in the average), 2000 fork-only children, and 4000
// threads. The thread part is what most real workloads (go, rustc, java) are made of.
void LifeWorkload() {
    std::string big(4000, 'x');
    std::string bigenv = "KINN_PERF_PAD=" + std::string(12000, 'e');
    for (int i = 0; i < 2000; i++) {
        pid_t c = fork();
        if (c == 0) {
            char a0[] = "true";
            if (i % 5 == 0) {
                // a long argument and a 12 KB environment on every fifth exec; the others carry
                // this process's own environment (a login session's, a few KB)
                char* av[] = {a0, const_cast<char*>(big.c_str()), nullptr};
                char* ev[] = {const_cast<char*>(bigenv.c_str()), nullptr};
                execve("/bin/true", av, ev);
            } else {
                char* av[] = {a0, nullptr};
                execv("/bin/true", av);
            }
            _exit(97);
        }
        int st = 0;
        if (c > 0) waitpid(c, &st, 0);
    }
    for (int i = 0; i < 2000; i++) {
        pid_t c = fork();
        if (c == 0) _exit(0);
        int st = 0;
        if (c > 0) waitpid(c, &st, 0);
    }
    for (int i = 0; i < 4000; i++) {
        std::thread([] {}).join();
    }
}

// The file-name sweep (--sweep N): N files in 30 project folders, 10% of them "interesting"
// (documents, images, archives, keys, databases) and the rest boring (source, objects, logs and
// files with no extension, the git-object shape), opened once each in a scrambled order. The
// files are created BEFORE the scope root is registered (so their creation is not an in-scope
// open). Then a "rare" phase: one id_rsa opened after 5,000 boring no-extension files in one
// project. With --names all this is the cost and the loss of naming every open; otherwise it is
// the cost of the sample, and how many of the interesting files ended up with a name (the point
// of the name policy). Reports the file_open hook's cost over just these opens.
struct SweepResult {
    uint64_t opens = 0, calls = 0, run_ns = 0;
    uint64_t names_emitted = 0, distinct_named = 0, interesting_named = 0, ring_full = 0, loader_dropped = 0;
    uint64_t eligible = 0, dir_keys = 0, dir_opens = 0;  // directory model: eligible opens, keys drained, sum of their counters
    bool rare_named = false;
};

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

// The strings of `"key": [ "a", "b" ]` in a small JSON document. Enough for the policy file the
// agent reads too ({ "ext": [...], "names": [...], "prefixes": [...] }); not a JSON parser.
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

// The files of the sweep, created once (out of scope) and opened by every phase.
struct SweepSet {
    std::string base;
    std::vector<std::string> files, rare_files;
    std::string rare;
    std::set<std::string> interesting;
};

bool MakeSweepSet(size_t nfiles, SweepSet* set) {
    std::string base = MakeBase();
    if (base.empty()) return false;
    set->base = base;
    std::string docs = base + "/Documents";
    mkdir(docs.c_str(), 0700);
    const size_t nproj = 30;
    std::vector<std::string>& files = set->files;
    std::set<std::string>& interesting = set->interesting;
    // Per project: 100 interesting (30 pdf, 20 docx, 15 jpg, 15 zip, 10 pem, 5 kdbx, 5 db) and
    // 900 boring (300 c, 200 h, 200 o, 100 log, 100 with no extension), scaled to nfiles.
    static const struct { const char* ext; int n; bool good; } kMix[] = {
        {"pdf", 30, true}, {"docx", 20, true}, {"jpg", 15, true}, {"zip", 15, true}, {"pem", 10, true},
        {"kdbx", 5, true}, {"db", 5, true},    {"c", 300, false}, {"h", 200, false},  {"o", 200, false},
        {"log", 100, false}, {"", 100, false},
    };
    const size_t per_proj = nfiles / nproj;
    for (size_t p = 0; p < nproj; p++) {
        std::string proj = docs + "/sw" + std::to_string(p);
        mkdir(proj.c_str(), 0700);
        size_t made = 0;
        for (const auto& m : kMix) {
            size_t want = static_cast<size_t>(m.n) * per_proj / 1000;
            for (size_t i = 0; i < want && made < per_proj; i++, made++) {
                std::string path = proj + "/f" + std::to_string(made) + (m.ext[0] ? std::string(".") + m.ext : "");
                int fd = open(path.c_str(), O_WRONLY | O_CREAT, 0600);
                if (fd >= 0) close(fd);
                files.push_back(path);
                if (m.good) interesting.insert(path);
            }
        }
    }
    // The rare case: one id_rsa among 5000 no-extension files (the shape of a git object store).
    std::string rare_dir = docs + "/gitobjs";
    mkdir(rare_dir.c_str(), 0700);
    std::vector<std::string>& rare_files = set->rare_files;
    for (int i = 0; i < 5000; i++) {
        std::string path = rare_dir + "/o" + std::to_string(i);
        int fd = open(path.c_str(), O_WRONLY | O_CREAT, 0600);
        if (fd >= 0) close(fd);
        rare_files.push_back(path);
    }
    set->rare = rare_dir + "/id_rsa";
    {
        int fd = open(set->rare.c_str(), O_WRONLY | O_CREAT, 0600);
        if (fd >= 0) close(fd);
    }
    // Scramble the order (a fixed permutation) so the interesting files are spread among the rest.
    for (size_t i = files.size(); i > 1; i--) {
        static uint64_t s = 0x9e3779b97f4a7c15ull;
        s = s * 6364136223846793005ull + 1442695040888963407ull;
        std::swap(files[i - 1], files[(s >> 33) % i]);
    }
    return true;
}

// One pass over the sweep set with whatever the collectors are configured for: registers the
// scope root, opens every file once (the rare id_rsa last), and reports. `report` prints the
// per-name detail; the cost line is always returned in the result.
SweepResult SweepPhase(CloudCollectors& cc, const SweepSet& set, bool report) {
    SweepResult res;
    const std::vector<std::string>& files = set.files;
    const std::vector<std::string>& rare_files = set.rare_files;
    const std::string& rare = set.rare;
    const std::set<std::string>& interesting = set.interesting;
    // The standard workload's scope root may name a directory number this directory reuses:
    // start from an empty scope.
    cc.ClearScope();
    struct stat st;
    stat(set.base.c_str(), &st);
    cc.AddScopeRoot(st.st_dev, st.st_ino, CLOUD_ROOT_HOME);
    cc.CommitScope();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    {
        // The standard workload's rows are still in the kernel map: take them out, so the sweep's
        // key count below is the sweep's own.
        std::vector<cloud_file_row> old(8192);
        (void)cc.DrainFiles(old.data(), old.size());
        std::vector<cloud_name_rec> oldn(4096);
        while (cc.DrainNames(oldn.data(), oldn.size()) > 0) {}
        std::vector<cloud_dir_row> oldd(4096);
        while (cc.DrainDirs(oldd.data(), oldd.size()) > 0) {}
    }

    auto file_open_stat = [&] {
        for (auto& s : cc.RunStats()) {
            if (s.name == "cloud_file_open") return s;
        }
        return CloudCollectors::ProgRunStat{};
    };
    uint64_t s0[CLOUD_STAT_MAX + 1], s1[CLOUD_STAT_MAX + 1], n0[CLOUD_NAME_STAT_MAX + 1], n1[CLOUD_NAME_STAT_MAX + 1];
    cc.Stats(s0, CLOUD_STAT_MAX + 1);
    cc.NameStats(n0, CLOUD_NAME_STAT_MAX + 1);
    auto a = file_open_stat();
    for (const auto& p : files) {
        int fd = open(p.c_str(), O_RDONLY);
        if (fd >= 0) close(fd);
    }
    for (const auto& p : rare_files) {
        int fd = open(p.c_str(), O_RDONLY);
        if (fd >= 0) close(fd);
    }
    {
        int fd = open(rare.c_str(), O_RDONLY);  // last, after 5000 boring no-extension opens
        if (fd >= 0) close(fd);
    }
    auto b = file_open_stat();
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    cc.Stats(s1, CLOUD_STAT_MAX + 1);
    cc.NameStats(n1, CLOUD_NAME_STAT_MAX + 1);

    res.opens = s1[CLOUD_STAT_FILE_IN_SCOPE] - s0[CLOUD_STAT_FILE_IN_SCOPE];
    res.calls = b.run_cnt - a.run_cnt;
    res.run_ns = b.run_time_ns - a.run_time_ns;

    std::set<std::string> want(files.begin(), files.end()), seen;
    want.insert(rare_files.begin(), rare_files.end());
    want.insert(rare);
    std::vector<cloud_name_rec> buf(4096);
    uint64_t drained = 0, valid = 0, path_bytes = 0;
    std::set<std::string> good_named;
    std::set<std::tuple<uint64_t, uint64_t, uint32_t, uint32_t>> keys_named;  // directory keys that got a name
    for (;;) {
        size_t n = cc.DrainNames(buf.data(), buf.size());
        if (n == 0) break;
        for (size_t i = 0; i < n; i++) {
            drained++;
            std::string p(buf[i].path, buf[i].len);
            path_bytes += p.size();
            keys_named.insert({buf[i].key.dev, buf[i].key.ino, buf[i].key.tgid, buf[i].key.op});
            if (want.count(p)) {
                valid++;
                seen.insert(p);
                if (interesting.count(p)) good_named.insert(p);
            }
        }
    }
    // The fold rows of the whole sweep: how many keys there were, and how many of them got a name.
    std::vector<cloud_file_row> rows(8192);
    size_t nrows = cc.DrainFiles(rows.data(), rows.size());
    {
        std::vector<cloud_dir_row> dr(4096);
        for (;;) {
            size_t n = cc.DrainDirs(dr.data(), dr.size());
            if (n == 0) break;
            res.dir_keys += n;
            for (size_t i = 0; i < n; i++) res.dir_opens += dr[i].val.opens;
        }
    }
    res.eligible = n1[CLOUD_NAME_STAT_ELIGIBLE] - n0[CLOUD_NAME_STAT_ELIGIBLE];
    res.names_emitted = n1[0] - n0[0];
    res.distinct_named = seen.size();
    res.interesting_named = good_named.size();
    res.rare_named = seen.count(rare) != 0;
    res.ring_full = n1[1] - n0[1];
    res.loader_dropped = n1[CLOUD_NAME_STAT_MAX];
    if (!report) return res;
    std::printf("sweep: files=%zu+%zu in_scope_opens=%llu names_emitted=%llu (%.2f%% of opens) ring_full=%llu too_long=%llu "
                "loader_dropped=%llu drained=%llu real_files=%llu distinct=%zu fold_keys=%zu dirs_with_names=%zu avg_path=%.1f\n",
                files.size(), rare_files.size() + 1, (unsigned long long)res.opens, (unsigned long long)(n1[0] - n0[0]),
                res.opens ? 100.0 * static_cast<double>(n1[0] - n0[0]) / static_cast<double>(res.opens) : 0.0,
                (unsigned long long)(n1[1] - n0[1]), (unsigned long long)(n1[2] - n0[2]),
                (unsigned long long)n1[CLOUD_NAME_STAT_MAX], (unsigned long long)drained, (unsigned long long)valid,
                seen.size(), nrows, keys_named.size(), drained ? static_cast<double>(path_bytes) / static_cast<double>(drained) : 0.0);
    std::printf("sweep: eligible opens=%llu (%.2f%% of in-scope opens), directory keys=%llu, sum of their counters=%llu (equal to eligible: %s)\n",
                (unsigned long long)res.eligible, res.opens ? 100.0 * static_cast<double>(res.eligible) / static_cast<double>(res.opens) : 0.0,
                (unsigned long long)res.dir_keys, (unsigned long long)res.dir_opens, res.eligible == res.dir_opens ? "yes" : "NO");
    std::printf("sweep: interesting files=%zu named=%zu (%.1f%%); names spent on interesting files=%.1f%%; rare id_rsa among %zu "
                "no-extension files named=%s\n",
                interesting.size(), good_named.size(),
                interesting.empty() ? 0.0 : 100.0 * static_cast<double>(good_named.size()) / static_cast<double>(interesting.size()),
                seen.empty() ? 0.0 : 100.0 * static_cast<double>(good_named.size()) / static_cast<double>(seen.size()),
                rare_files.size(), seen.count(rare) ? "YES" : "NO");
    std::printf("sweep: cloud_file_open %llu calls, %.1f ns/call over the sweep\n", (unsigned long long)res.calls,
                res.calls ? static_cast<double>(res.run_ns) / static_cast<double>(res.calls) : 0.0);
    return res;
}

void RemoveSweepSet(const SweepSet& set) {
    if (set.base.empty()) return;
    std::string cmd = "rm -rf '" + set.base + "'";
    if (system(cmd.c_str()) != 0) {}
}

SweepResult SweepWorkload(CloudCollectors& cc, size_t nfiles) {
    SweepSet set;
    if (!MakeSweepSet(nfiles, &set)) return SweepResult{};
    SweepResult r = SweepPhase(cc, set, true);
    RemoveSweepSet(set);
    return r;
}

// --compare N: every variant of the directory-row policy, N times, in ONE process, interleaved
// (variant 1, 2, ... k, 1, 2, ... k, ...), each with the collectors restarted for it and one
// pass over the same warm sweep files. The VM's timing drifts by up to 2x between processes
// and boots, but a few seconds apart it barely moves, so these are the numbers to compare.
struct Variant {
    const char* name;
    bool dir_rows;
    const Policy* policy;
    const char* object = nullptr;  // another build of the object for this variant (paired against the others)
};

void Compare(CloudCollectors& cc, const char* object, size_t nfiles, int reps, const std::vector<Variant>& variants) {
    SweepSet set;
    if (!MakeSweepSet(nfiles, &set)) return;
    std::map<std::string, std::vector<double>> ns;
    std::map<std::string, SweepResult> last;
    const uint32_t feats = kinnector::lnx::kCloudNet | kinnector::lnx::kCloudFiles | kinnector::lnx::kCloudLife;
    for (int r = 0; r < reps; r++) {
        for (const auto& v : variants) {
            cc.Stop();
            cc.SetDirRowsOn(v.dir_rows);
            cc.SetNamePolicy(v.policy ? v.policy->exts : std::vector<uint64_t>{}, v.policy ? v.policy->names : std::vector<std::string>{},
                             v.policy ? v.policy->prefixes : std::vector<std::string>{});
            if (!cc.Start(v.object ? v.object : object, feats, 2)) {
                std::fprintf(stderr, "collectors did not start for %s\n", v.name);
                return;
            }
            SweepResult res = SweepPhase(cc, set, false);
            double per = res.calls ? static_cast<double>(res.run_ns) / static_cast<double>(res.calls) : 0.0;
            ns[v.name].push_back(per);
            last[v.name] = res;
            std::printf("compare rep %d %-10s %8.1f ns/open  (%llu opens, eligible %llu, dir keys %llu, %llu names, interesting named %llu, rare %s, ring_full %llu)\n",
                        r + 1, v.name, per, (unsigned long long)res.opens, (unsigned long long)res.eligible, (unsigned long long)res.dir_keys,
                        (unsigned long long)res.names_emitted, (unsigned long long)res.interesting_named, res.rare_named ? "yes" : "no",
                        (unsigned long long)res.ring_full);
            std::fflush(stdout);
        }
    }
    cc.Stop();
    std::printf("compare summary over %d reps (ns per open of the file_open hook, the sweep files, median [min-max]):\n", reps);
    for (const auto& v : variants) {
        auto x = ns[v.name];
        std::sort(x.begin(), x.end());
        const auto& l = last[v.name];
        std::printf("  %-10s %8.1f [%7.1f - %7.1f]  names %llu, distinct %llu, interesting %llu/%zu, rare %s\n", v.name,
                    x.empty() ? 0.0 : x[x.size() / 2], x.empty() ? 0.0 : x.front(), x.empty() ? 0.0 : x.back(),
                    (unsigned long long)l.names_emitted, (unsigned long long)l.distinct_named,
                    (unsigned long long)l.interesting_named, set.interesting.size(), l.rare_named ? "yes" : "no");
    }
    RemoveSweepSet(set);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
                     "usage: %s <kinnector_cloud.bpf.o> [--json] [--dir-rows off|on] [--policy-file F] [--sweep N]\n"
                     "  dir-rows on (the default) is the v2 mechanism: ext/prefix breakdown, HLL, mask names\n",
                     argv[0]);
        return 2;
    }
    bool json = false;
    size_t sweep = 0;
    bool dir_rows_on = true;
    std::string names_mode = "on";
    Policy policy, policy_code;
    std::string policy_file, object2;
    int compare = 0;
    for (int i = 2; i < argc; i++) {
        if (std::strcmp(argv[i], "--json") == 0) {
            json = true;
        } else if (std::strcmp(argv[i], "--object2") == 0 && i + 1 < argc) {
            object2 = argv[++i];
        } else if (std::strcmp(argv[i], "--sweep") == 0 && i + 1 < argc) {
            sweep = static_cast<size_t>(std::strtoull(argv[++i], nullptr, 10));
        } else if (std::strcmp(argv[i], "--compare") == 0 && i + 1 < argc) {
            compare = static_cast<int>(std::strtol(argv[++i], nullptr, 10));
        } else if (std::strcmp(argv[i], "--policy-code-file") == 0 && i + 1 < argc) {
            if (!LoadPolicy(argv[++i], &policy_code)) {
                std::fprintf(stderr, "cannot read the policy file\n");
                return 2;
            }
        } else if (std::strcmp(argv[i], "--policy-file") == 0 && i + 1 < argc) {
            policy_file = argv[++i];
            if (!LoadPolicy(policy_file, &policy)) {
                std::fprintf(stderr, "cannot read %s\n", policy_file.c_str());
                return 2;
            }
        } else if ((std::strcmp(argv[i], "--dir-rows") == 0 || std::strcmp(argv[i], "--names") == 0) && i + 1 < argc) {
            names_mode = argv[++i];
            if (names_mode == "off") {
                dir_rows_on = false;
            } else if (names_mode == "on") {
                dir_rows_on = true;
            } else {
                std::fprintf(stderr, "--dir-rows takes off or on\n");
                return 2;
            }
        }
    }
    if (geteuid() != 0) {
        std::fprintf(stderr, "must run as root: loading BPF programs is how the numbers are obtained\n");
        return 2;
    }
    // The kernel only accumulates run time while stats are enabled; the fd holds them on.
    int stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
    if (stats_fd < 0) {
        std::fprintf(stderr, "cannot enable BPF run-time stats\n");
        return 2;
    }

    auto& cc = CloudCollectors::Instance();
    if (compare > 0) {
        // Every variant of the directory-row policy, interleaved, in this one process (see Compare).
        std::vector<Variant> vs = {{"off", false, nullptr}, {"on", true, nullptr}};
        Policy ext_only;
        if (policy.any()) {
            ext_only.exts = policy.exts;
            // Directory model: the policy variants, the extension whitelist alone (the name mask is
            // rejected on its length gate without reading the name), the full policy, and, when a second
            // build of the object is given (-DCLOUD_EXP_NO_EARLY), the full policy without the early rejects.
            vs.push_back(Variant{"policyext", true, &ext_only});
            vs.push_back(Variant{"policy71", true, &policy});
            if (!object2.empty()) vs.push_back(Variant{"policy71ne", true, &policy, object2.c_str()});
        }
        if (policy_code.any()) vs.push_back(Variant{"policycode", true, &policy_code});
        Compare(cc, argv[1], sweep ? sweep : 30000, compare, vs);
        close(stats_fd);
        return 0;
    }
    cc.SetDirRowsOn(dir_rows_on);
    if (policy.any()) cc.SetNamePolicy(policy.exts, policy.names, policy.prefixes);
    if (!cc.Start(argv[1], kinnector::lnx::kCloudNet | kinnector::lnx::kCloudFiles | kinnector::lnx::kCloudLife, 2)) {
        std::fprintf(stderr, "collectors did not start\n");
        return 2;
    }
    std::string base = MakeBase();
    if (base.empty()) {
        std::fprintf(stderr, "no real filesystem to build the file workload on\n");
        return 2;
    }
    struct stat st;
    stat(base.c_str(), &st);
    cc.AddScopeRoot(st.st_dev, st.st_ino, CLOUD_ROOT_HOME);
    cc.CommitScope();

    std::printf("directory rows: mode=%s policy=%s (%zu ext, %zu names, %zu prefixes)\n", names_mode.c_str(),
                policy.any() ? policy_file.c_str() : "none", policy.exts.size(), policy.names.size(), policy.prefixes.size());
    FileWorkload(base);
    TcpWorkload();
    UdpWorkload();
    LifeWorkload();
    // Let the poller hand the lifecycle records to the queue before the counters are read.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // The budget below is for the standard workload only: read it before the sweep.
    std::map<std::string, CloudCollectors::ProgRunStat> got;
    for (auto& s : cc.RunStats()) got[s.name] = s;
    uint64_t stats[CLOUD_STAT_MAX + 1];
    cc.Stats(stats, CLOUD_STAT_MAX + 1);
    uint64_t lstats[CLOUD_LIFE_STAT_MAX + 1];
    cc.LifeStats(lstats, CLOUD_LIFE_STAT_MAX + 1);
    uint64_t nstats[CLOUD_NAME_STAT_MAX + 1];
    cc.NameStats(nstats, CLOUD_NAME_STAT_MAX + 1);
    std::printf("names (standard workload): emitted=%llu ring_full=%llu too_long=%llu dpath_fail=%llu loader_dropped=%llu\n",
                (unsigned long long)nstats[0], (unsigned long long)nstats[1], (unsigned long long)nstats[2],
                (unsigned long long)nstats[3], (unsigned long long)nstats[CLOUD_NAME_STAT_MAX]);
    // Kernel memory of the maps the file collector owns (fdinfo memlock).
    std::printf("kernel memory: file_fold=%llu names_rb=%llu dir_state=%llu dir_proc=%llu name_ext_ok=%llu name_exact=%llu name_stats=%llu "
                "life_rb=%llu cloud_rb=%llu bytes\n",
                (unsigned long long)cc.MapMemoryBytes("file_fold"), (unsigned long long)cc.MapMemoryBytes("names_rb"),
                (unsigned long long)cc.MapMemoryBytes("dir_state"), (unsigned long long)cc.MapMemoryBytes("dir_proc"),
                (unsigned long long)cc.MapMemoryBytes("name_ext_ok"), (unsigned long long)cc.MapMemoryBytes("name_exact"),
                (unsigned long long)cc.MapMemoryBytes("name_stats"),
                (unsigned long long)cc.MapMemoryBytes("life_rb"), (unsigned long long)cc.MapMemoryBytes("cloud_rb"));
    if (sweep) SweepWorkload(cc, sweep);
    cc.Stop();
    close(stats_fd);

    int failures = 0;
    if (json) std::printf("{\"kernel_programs\":[");
    bool first = true;
    for (const auto& b : kBudgets) {
        auto it = got.find(b.prog);
        double ns = 0;
        uint64_t calls = 0;
        bool present = it != got.end();
        if (present) {
            calls = it->second.run_cnt;
            ns = calls ? static_cast<double>(it->second.run_time_ns) / static_cast<double>(calls) : 0;
        }
        bool exercised = present && calls >= b.min_calls;
        bool over = exercised && ns > b.max_ns_per_call;
        // A program that did not attach, or that the workload did not reach, is a
        // failure of the gate itself: a check that measures nothing must not pass.
        bool bad = over || !exercised;
        failures += bad ? 1 : 0;
        if (json) {
            std::printf("%s{\"prog\":\"%s\",\"calls\":%llu,\"ns_per_call\":%.1f,\"budget_ns\":%.0f,\"ok\":%s}",
                        first ? "" : ",", b.prog, (unsigned long long)calls, ns, b.max_ns_per_call, bad ? "false" : "true");
            first = false;
        } else {
            std::printf("%-18s calls %-9llu %8.1f ns/call  budget %6.0f  %s\n", b.prog, (unsigned long long)calls, ns,
                        b.max_ns_per_call,
                        !present ? "NOT ATTACHED" : (!exercised ? "NOT EXERCISED" : (over ? "OVER BUDGET" : "ok")));
        }
    }
    if (json) std::printf("]}\n");
    std::printf("drops: net_ring=%llu file_map=%llu udp_map=%llu proj_map=%llu dns_ring=%llu  opens=%llu in_scope=%llu\n",
                (unsigned long long)stats[0], (unsigned long long)stats[1], (unsigned long long)stats[2],
                (unsigned long long)stats[3], (unsigned long long)stats[4], (unsigned long long)stats[5],
                (unsigned long long)stats[6]);
    if (stats[CLOUD_STAT_FILE_MAP_FULL] || stats[CLOUD_STAT_UDP_MAP_FULL] || stats[CLOUD_STAT_PROJ_MAP_FULL]) {
        std::printf("map capacity exceeded during the gate workload\n");
        failures++;
    }
    std::printf("life: forks=%llu execs=%llu exits=%llu drops(fork/exec/exit)=%llu/%llu/%llu argv_fail=%llu trunc=%llu exe_raw=%llu env_fail=%llu env_trunc=%llu loader_dropped=%llu\n",
                (unsigned long long)lstats[0], (unsigned long long)lstats[1], (unsigned long long)lstats[2],
                (unsigned long long)lstats[3], (unsigned long long)lstats[4], (unsigned long long)lstats[5],
                (unsigned long long)lstats[6], (unsigned long long)lstats[7], (unsigned long long)lstats[8],
                (unsigned long long)lstats[CLOUD_LIFE_STAT_ENV_FAIL], (unsigned long long)lstats[CLOUD_LIFE_STAT_ENV_TRUNC],
                (unsigned long long)lstats[CLOUD_LIFE_STAT_MAX]);
    // The lifecycle stream is only worth its cost if it loses nothing on this workload.
    if (lstats[CLOUD_LIFE_STAT_FORK_DROP] || lstats[CLOUD_LIFE_STAT_EXEC_DROP] || lstats[CLOUD_LIFE_STAT_EXIT_DROP] ||
        lstats[CLOUD_LIFE_STAT_MAX]) {
        std::printf("lifecycle records were dropped during the gate workload\n");
        failures++;
    }
    std::printf(failures ? "PERF GATE FAILED (%d)\n" : "perf gate passed\n", failures);
    return failures ? 1 : 0;
}
