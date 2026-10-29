// Raw dump of the cloud lifecycle records (fork, exec with arguments, exit), one JSON
// object per line, for checking the kernel programs against an independent ground truth
// (antitheft-cloud/bench/lifecycle: ftrace on the same monotonic clock). Not part of the
// product. Needs root, and only ever runs in the 6.18 VM.
//
//   kinnector-cloud-life-dump <kinnector_cloud.bpf.o> [out.jsonl]     until SIGTERM/SIGINT
//
// Times are the raw ones: ts and start are CLOCK_MONOTONIC nanoseconds. `argv` is the
// argument block split at NULs; every byte outside printable ASCII is written as \u00XX
// (a byte, not a code point), so the dump is lossless and needs no UTF-8 assumption.
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

static void Esc(std::string& out, const char* p, size_t n) {
    static const char* hex = "0123456789abcdef";
    out += '"';
    for (size_t i = 0; i < n; i++) {
        unsigned char c = static_cast<unsigned char>(p[i]);
        if (c == '"' || c == '\\') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c >= 0x20 && c < 0x7f) {
            out += static_cast<char>(c);
        } else {
            out += "\\u00";
            out += hex[c >> 4];
            out += hex[c & 15];
        }
    }
    out += '"';
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <kinnector_cloud.bpf.o> [out.jsonl]\n", argv[0]);
        return 2;
    }
    if (geteuid() != 0) {
        std::fprintf(stderr, "must run as root\n");
        return 2;
    }
    FILE* out = argc > 2 ? std::fopen(argv[2], "w") : stdout;
    if (!out) {
        std::perror("open output");
        return 2;
    }
    std::signal(SIGTERM, OnSig);
    std::signal(SIGINT, OnSig);
    auto& cc = CloudCollectors::Instance();
    if (!cc.Start(argv[1], kinnector::lnx::kCloudLife, 10)) {
        std::fprintf(stderr, "collectors did not start (KINNECTOR_CLOUD_DEBUG=1 for the verifier log)\n");
        return 2;
    }
    for (const auto& p : cc.Status()) std::fprintf(stderr, "prog %-18s loaded=%d attached=%d %s\n", p.name.c_str(), p.loaded, p.attached, p.error.c_str());
    std::fprintf(stderr, "ready\n");
    std::fflush(stderr);

    std::vector<uint8_t> buf(4 << 20);
    unsigned long long n = 0;
    auto pump = [&]() {
        for (;;) {
            size_t nrecs = 0;
            size_t got = cc.DrainLife(buf.data(), buf.size(), &nrecs);
            if (got == 0) break;
            size_t off = 0;
            for (size_t i = 0; i < nrecs; i++) {
                cloud_life_rec h;
                std::memcpy(&h, buf.data() + off, sizeof(h));
                const char* p = reinterpret_cast<const char*>(buf.data() + off + sizeof(h));
                std::string line = "{\"k\":\"";
                line += h.kind == CLOUD_LIFE_FORK ? "fork" : h.kind == CLOUD_LIFE_EXEC ? "exec" : "exit";
                line += "\",\"tgid\":" + std::to_string(h.tgid) + ",\"start\":" + std::to_string(h.start) +
                        ",\"ptgid\":" + std::to_string(h.ptgid) + ",\"pstart\":" + std::to_string(h.pstart) +
                        ",\"ts\":" + std::to_string(h.ts_ns) + ",\"aux\":" + std::to_string(h.aux) +
                        ",\"flags\":" + std::to_string(h.flags);
                if (h.kind == CLOUD_LIFE_EXEC) {
                    line += ",\"argv_total\":" + std::to_string(h.argv_total) + ",\"argv_len\":" + std::to_string(h.argv_len) + ",\"exe\":";
                    Esc(line, p, h.exe_len);
                    line += ",\"argv\":[";
                    const char* a = p + h.exe_len;
                    size_t left = h.argv_len, first = 1;
                    while (left > 0) {
                        const char* z = static_cast<const char*>(std::memchr(a, 0, left));
                        size_t len = z ? static_cast<size_t>(z - a) : left;
                        if (!first) line += ',';
                        first = 0;
                        Esc(line, a, len);
                        size_t adv = z ? len + 1 : len;
                        a += adv;
                        left -= adv;
                    }
                    line += ']';
                    // The environment, raw (this tool is for the VM only; the agent filters it).
                    line += ",\"env_total\":" + std::to_string(h.env_total) + ",\"env_len\":" + std::to_string(h.env_len) +
                            ",\"envc\":" + std::to_string(h.envc) + ",\"env\":[";
                    const char* e = p + h.exe_len + h.argv_len;
                    size_t eleft = h.env_len, efirst = 1;
                    while (eleft > 0) {
                        const char* z = static_cast<const char*>(std::memchr(e, 0, eleft));
                        size_t len = z ? static_cast<size_t>(z - e) : eleft;
                        if (!efirst) line += ',';
                        efirst = 0;
                        Esc(line, e, len);
                        size_t adv = z ? len + 1 : len;
                        e += adv;
                        eleft -= adv;
                    }
                    line += ']';
                }
                line += "}\n";
                std::fwrite(line.data(), 1, line.size(), out);
                n++;
                off += (sizeof(h) + CLOUD_LIFE_BODY(&h) + 7) & ~static_cast<size_t>(7);
            }
        }
    };
    while (!g_stop.load()) {
        pump();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    pump();
    uint64_t ls[CLOUD_LIFE_STAT_MAX + 1];
    cc.LifeStats(ls, CLOUD_LIFE_STAT_MAX + 1);
    std::fprintf(stderr,
                 "records=%llu kernel: forks=%llu execs=%llu exits=%llu drops(fork/exec/exit)=%llu/%llu/%llu argv_fail=%llu argv_trunc=%llu exe_raw=%llu env_fail=%llu env_trunc=%llu loader_dropped=%llu\n",
                 n, (unsigned long long)ls[0], (unsigned long long)ls[1], (unsigned long long)ls[2], (unsigned long long)ls[3],
                 (unsigned long long)ls[4], (unsigned long long)ls[5], (unsigned long long)ls[6], (unsigned long long)ls[7],
                 (unsigned long long)ls[8], (unsigned long long)ls[CLOUD_LIFE_STAT_ENV_FAIL],
                 (unsigned long long)ls[CLOUD_LIFE_STAT_ENV_TRUNC], (unsigned long long)ls[CLOUD_LIFE_STAT_MAX]);
    cc.Stop();
    if (out != stdout) std::fclose(out);
    return 0;
}
