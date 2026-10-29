// Raw dump of the file-name records, one tab-separated line each, for simulating OFFLINE which name
// budget (per row or per folder) would name what (antitheft-cloud/bench/lifecycle/names-budget.awk).
// SUPERSEDED by Directory rows v2: a name is sent ONLY for an
// exact-name mask match now, never for an ordinary eligible open, so there is no more "all" mode to
// dump from - this tool with no policy loaded records nothing. Left buildable, not rewritten: its own
// offline-budget question (how many names would a per-row/per-folder cap have kept) is moot once
// ordinary opens are never named at all; the ext/prefix breakdown maps are what carries that data now.
// Not part of the product. Needs root, and only ever runs in the 6.18 VM.
//
//   kinnector-cloud-names-dump <kinnector_cloud.bpf.o> <out.tsv> [scope_root ...]   until SIGTERM/SIGINT
//
// The scope is the roots on the command line (default /root), kind HOME, with the agent's fixed skip
// directories under each (`.cache`, `.cargo/registry`, `.rustup`, `.npm/_cacache`, `.gradle/caches`,
// `.m2/repository`). The lifecycle and network programs are off: this measures the file collector alone.
//
// Columns: wall_ms (CLOCK_REALTIME when the record was drained, within ~50 ms of the open), tgid, dir_ino
// (the parent directory's inode: the directory model's key, no longer the project folder), ext (always 0:
// the record no longer carries it), op (0 read, 1 write), nth (the open's number in its directory key), path. A path holding a tab or newline is written with them replaced by a space (the dump is for
// statistics, not for forensics).
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "cloud_collectors.h"

using kinnector::lnx::CloudCollectors;

static std::atomic<bool> g_stop{false};
static void OnSig(int) { g_stop = true; }

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <kinnector_cloud.bpf.o> <out.tsv> [scope_root ...]\n", argv[0]);
        return 2;
    }
    if (geteuid() != 0) {
        std::fprintf(stderr, "must run as root\n");
        return 2;
    }
    FILE* out = std::fopen(argv[2], "w");
    if (!out) {
        std::perror("open output");
        return 2;
    }
    std::vector<std::string> roots;
    for (int i = 3; i < argc; i++) roots.emplace_back(argv[i]);
    if (roots.empty()) roots.emplace_back("/root");

    auto& cc = CloudCollectors::Instance();
    cc.SetDirRowsOn(true);  // v2: with no mask policy loaded, this records nothing (see the file header)
    if (!cc.Start(argv[1], kinnector::lnx::kCloudFiles, 10)) {
        std::fprintf(stderr, "collectors did not start\n");
        return 2;
    }
    static const char* kSkip[] = {".cache", ".cargo/registry", ".rustup", ".npm/_cacache", ".gradle/caches", ".m2/repository"};
    for (const auto& r : roots) {
        struct stat st;
        if (stat(r.c_str(), &st) == 0) cc.AddScopeRoot(st.st_dev, st.st_ino, CLOUD_ROOT_HOME);
        for (const char* s : kSkip) {
            std::string p = r + "/" + s;
            if (stat(p.c_str(), &st) == 0) cc.AddSkipDir(st.st_dev, st.st_ino);
        }
    }
    cc.CommitScope();
    std::signal(SIGTERM, OnSig);
    std::signal(SIGINT, OnSig);
    std::fprintf(stderr, "dumping every in-scope open to %s (scope:", argv[2]);
    for (const auto& r : roots) std::fprintf(stderr, " %s", r.c_str());
    std::fprintf(stderr, ")\n");

    std::vector<cloud_name_rec> buf(4096);
    uint64_t total = 0;
    auto drain = [&] {
        for (;;) {
            size_t n = cc.DrainNames(buf.data(), buf.size());
            if (n == 0) break;
            long long wall = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            for (size_t i = 0; i < n; i++) {
                std::string p(buf[i].path, buf[i].len);
                for (char& c : p) {
                    if (c == '\t' || c == '\n') c = ' ';
                }
                // The directory model dropped the extension from the record key (0 here, derive it from the path).
                std::fprintf(out, "%lld\t%u\t%llu\t%x\t%u\t%u\t%s\n", wall, buf[i].key.tgid, (unsigned long long)buf[i].key.ino, 0u,
                             buf[i].key.op, buf[i].nth, p.c_str());
            }
            total += n;
        }
    };
    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        drain();
    }
    drain();
    std::fflush(out);
    uint64_t ns[CLOUD_NAME_STAT_MAX + 1];
    cc.NameStats(ns, CLOUD_NAME_STAT_MAX + 1);
    std::fprintf(stderr, "records=%llu emitted=%llu ring_full=%llu too_long=%llu dpath_fail=%llu loader_dropped=%llu\n",
                 (unsigned long long)total, (unsigned long long)ns[0], (unsigned long long)ns[1], (unsigned long long)ns[2],
                 (unsigned long long)ns[3], (unsigned long long)ns[CLOUD_NAME_STAT_MAX]);
    cc.Stop();
    std::fclose(out);
    return 0;
}
