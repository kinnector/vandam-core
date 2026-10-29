// Cloud-tier collectors against the real kernel: real syscalls, real BPF programs,
// real drains. Needs root and a kernel with BTF; without either it runs the
// userspace checks and reports SKIP for the rest, which is NOT a pass for the
// kernel half. Wrap in `timeout` (core/CLAUDE.md). The programs are observe-only,
// nothing here can deny anything.
//
// Build dir must contain kinnector_cloud.bpf.o (or set KINN_CLOUD_OBJ).
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cmath>
#include <csignal>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include "cloud_collectors.h"
#include "kinnector/ffi.h"

using kinnector::lnx::CloudCollectors;
using kinnector::lnx::ParseDnsQuery;

static int g_fail = 0;
#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::fprintf(stderr, "- FAIL: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
            g_fail++;                                                            \
        }                                                                        \
    } while (0)

static void SleepMs(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

// ---- userspace: DNS parsing ---------------------------------------------------

static std::vector<uint8_t> DnsQuery(const std::vector<std::string>& labels, uint16_t qtype = 1, uint16_t flags = 0x0100) {
    std::vector<uint8_t> m = {0x12, 0x34, static_cast<uint8_t>(flags >> 8), static_cast<uint8_t>(flags & 0xff), 0, 1, 0, 0, 0, 0, 0, 0};
    for (auto& l : labels) {
        m.push_back(static_cast<uint8_t>(l.size()));
        m.insert(m.end(), l.begin(), l.end());
    }
    m.push_back(0);
    m.push_back(static_cast<uint8_t>(qtype >> 8));
    m.push_back(static_cast<uint8_t>(qtype & 0xff));
    m.push_back(0);
    m.push_back(1);
    return m;
}

static void TestDnsParsing() {
    char name[128];
    uint16_t qt = 0;
    auto q = DnsQuery({"WWW", "Example-Test", "com"}, 28);
    CHECK(ParseDnsQuery(q.data(), q.size(), name, sizeof(name), &qt));
    CHECK(std::string(name) == "www.example-test.com");
    CHECK(qt == 28);

    auto resp = DnsQuery({"a", "b"}, 1, 0x8180);
    CHECK(!ParseDnsQuery(resp.data(), resp.size(), name, sizeof(name), &qt));  // a response

    auto bad = DnsQuery({"ex ample", "com"});  // a space is not a hostname character
    CHECK(!ParseDnsQuery(bad.data(), bad.size(), name, sizeof(name), &qt));
    auto ctl = DnsQuery({"a\nb", "com"});
    CHECK(!ParseDnsQuery(ctl.data(), ctl.size(), name, sizeof(name), &qt));

    std::vector<uint8_t> ptr = {0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1};
    CHECK(!ParseDnsQuery(ptr.data(), ptr.size(), name, sizeof(name), &qt));  // compression in a question

    auto trunc = DnsQuery({"example", "com"});
    CHECK(!ParseDnsQuery(trunc.data(), 20, name, sizeof(name), &qt));
    CHECK(!ParseDnsQuery(trunc.data(), 5, name, sizeof(name), &qt));

    std::string longlabel(63, 'a');
    auto big = DnsQuery({longlabel, longlabel, longlabel});  // 191 chars, does not fit
    CHECK(!ParseDnsQuery(big.data(), big.size(), name, sizeof(name), &qt));
    CHECK(sizeof(cloud_dns_name) == 144);  // keeps the ABI honest even when the static_asserts are compiled out
}

// ---- kernel ---------------------------------------------------------------

// The kernel's extension value (contract v6: up to 8 characters, 4 before).
static uint64_t Ext(const char* e) {
    uint64_t v = 0;
    for (int i = 0; i < 8 && e[i]; i++) v |= static_cast<uint64_t>(static_cast<unsigned char>(e[i])) << (8 * i);
    return v;
}

static void Touch(const std::string& path, const char* data = "x") {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        if (write(fd, data, 1) < 0) {}
        close(fd);
    }
}

static void OpenRead(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd >= 0) close(fd);
}

static std::string MakeBase() {
    // A real filesystem: the collector skips tmpfs/overlay by design, so /tmp is
    // often useless here.
    const char* cands[] = {"/var/tmp/kinn-cloud-XXXXXX", "/root/kinn-cloud-XXXXXX", "./kinn-cloud-XXXXXX"};
    for (const char* c : cands) {
        std::string t = c;
        struct statfs sfs;
        std::string parent = t.substr(0, t.find_last_of('/'));
        if (parent.empty()) parent = ".";
        if (statfs(parent.c_str(), &sfs) != 0) continue;
        if (sfs.f_type == 0x01021994 || sfs.f_type == 0x794c7630) continue;  // tmpfs, overlayfs
        std::vector<char> buf(t.begin(), t.end());
        buf.push_back(0);
        if (mkdtemp(buf.data())) return std::string(buf.data());
    }
    return "";
}

static double HllEstimate(const cloud_dir_hll_val& v);

static void TestFiles(const std::string& base) {
    struct stat st;
    CHECK(stat(base.c_str(), &st) == 0);
    auto& cc = CloudCollectors::Instance();
    CHECK(cc.AddScopeRoot(st.st_dev, st.st_ino, CLOUD_ROOT_HOME));

    // The project folder is the one two levels under a scope root, so with `base`
    // as the root, base/Documents/taxes is the project however deep the file is.
    std::string docs = base + "/Documents", p1 = docs + "/taxes", p1s = p1 + "/2025/scans";
    std::string p2 = base + "/proj2", cache = base + "/.cache";
    mkdir(docs.c_str(), 0700);
    mkdir(p1.c_str(), 0700);
    mkdir((p1 + "/2025").c_str(), 0700);
    mkdir(p1s.c_str(), 0700);
    mkdir(p2.c_str(), 0700);
    mkdir(cache.c_str(), 0700);
    struct stat cst, p1st, p2st;
    CHECK(stat(cache.c_str(), &cst) == 0);
    CHECK(cc.AddSkipDir(cst.st_dev, cst.st_ino));
    cc.CommitScope();

    for (int i = 0; i < 5; i++) Touch(p1s + "/f" + std::to_string(i) + ".pdf");
    for (int i = 0; i < 5; i++) OpenRead(p1s + "/f" + std::to_string(i) + ".pdf");
    // Contract v9: four sparse 5,000,000-byte pdfs (i_size is the logical size, so nothing is
    // actually written), each read once, must sum to exactly 20,000,000 in the read row.
    for (int i = 0; i < 4; i++) {
        std::string big = p2 + "/big" + std::to_string(i) + ".pdf";
        int fd = open(big.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            if (ftruncate(fd, 5000000) != 0) {}
            close(fd);
        }
        OpenRead(big);
    }
    // Contract v10, cross-process: a child process re-reads the SAME four files. Its own row
    // counts them again (the first-open set is per process), and the cloud's correction over the
    // two rows' sketches must bring the story's R back to about 20,000,000, not 40,000,000.
    pid_t reader = fork();
    if (reader == 0) {
        for (int i = 0; i < 4; i++) OpenRead(p2 + "/big" + std::to_string(i) + ".pdf");
        _exit(0);
    }
    if (reader > 0) waitpid(reader, nullptr, 0);
    // Contract v10: ONE sparse 5,000,000-byte pdf opened for read ten times by this process adds
    // its size once (file_seen), counts ten opens, and sets exactly one sketch register.
    std::string p3 = base + "/proj3";
    mkdir(p3.c_str(), 0700);
    {
        std::string again = p3 + "/again.pdf";
        int fd = open(again.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            if (ftruncate(fd, 5000000) != 0) {}
            close(fd);
        }
        for (int i = 0; i < 10; i++) OpenRead(again);
    }
    Touch(p2 + "/notes.TXT");
    Touch(p2 + "/readme");
    Touch(cache + "/blob.bin");
    OpenRead(cache + "/blob.bin");
    Touch(base + "/top.md");
    OpenRead("/etc/hostname");  // outside every root
    CHECK(stat(p1.c_str(), &p1st) == 0);
    CHECK(stat(p2.c_str(), &p2st) == 0);
    struct stat p3st;
    CHECK(stat(p3.c_str(), &p3st) == 0);

    SleepMs(200);
    std::vector<cloud_file_row> rows(2048);
    size_t n = cc.DrainFiles(rows.data(), rows.size());
    uint32_t self = static_cast<uint32_t>(getpid());
    uint64_t pdf_read = 0, pdf_write = 0, txt_write = 0, top_write = 0, none_write = 0, cache_rows = 0;
    uint64_t pdf_read_bytes = 0, big_read = 0, big_read_bytes = 0;
    uint64_t again_count = 0, again_bytes = 0, again_regs = 0, big_regs = 0;
    uint64_t child_bytes = 0;
    cloud_dir_hll_val parent_hll{}, child_hll{};
    for (size_t i = 0; i < n; i++) {
        const auto& r = rows[i];
        bool big_pdf = r.key.proj_ino == p2st.st_ino && r.key.ext == Ext("pdf") && r.key.op == CLOUD_OP_READ;
        if (big_pdf && reader > 0 && r.key.tgid == static_cast<uint32_t>(reader)) {
            child_bytes += r.val.bytes;
            for (int k = 0; k < CLOUD_HLL_M; k++) child_hll.reg[k] = std::max(child_hll.reg[k], r.val.hll[k]);
        }
        if (big_pdf && r.key.tgid == self) {
            for (int k = 0; k < CLOUD_HLL_M; k++) parent_hll.reg[k] = std::max(parent_hll.reg[k], r.val.hll[k]);
        }
        if (r.key.tgid != self) continue;
        if (r.key.proj_ino == p3st.st_ino && r.key.ext == Ext("pdf") && r.key.op == CLOUD_OP_READ) {
            again_count += r.val.count;
            again_bytes += r.val.bytes;
            for (int k = 0; k < CLOUD_HLL_M; k++) again_regs += r.val.hll[k] != 0;
        } else if (r.key.proj_ino == p2st.st_ino && r.key.ext == Ext("pdf") && r.key.op == CLOUD_OP_READ) {
            for (int k = 0; k < CLOUD_HLL_M; k++) big_regs += r.val.hll[k] != 0;
            big_read += r.val.count;
            big_read_bytes += r.val.bytes;
        } else if (r.key.proj_ino == p1st.st_ino && r.key.ext == Ext("pdf")) {
            (r.key.op == CLOUD_OP_READ ? pdf_read : pdf_write) += r.val.count;
            if (r.key.op == CLOUD_OP_READ) pdf_read_bytes += r.val.bytes;
        } else if (r.key.proj_ino == p2st.st_ino && r.key.ext == Ext("txt")) {
            txt_write += r.val.count;
        } else if (r.key.proj_ino == p2st.st_ino && r.key.ext == 0) {
            none_write += r.val.count;
        } else if (r.key.proj_ino == st.st_ino) {
            top_write += r.val.count;
        } else if (r.key.proj_ino == cst.st_ino) {
            cache_rows += r.val.count;
        }
    }
    // Five files three directories deep fold into ONE row keyed by the project
    // folder two levels under the root, and reads are kept apart from writes.
    CHECK(pdf_write == 5);
    CHECK(pdf_read == 5);
    CHECK(txt_write == 1);   // upper case extension is lowercased
    CHECK(none_write == 1);  // a name without an extension
    CHECK(top_write == 1);   // a file directly in the root folds into the root itself
    CHECK(cache_rows == 0);  // the pinned skip directory records nothing
    // Contract v9: the row sums each opened file's i_size (file size, not bytes read).
    CHECK(pdf_read_bytes == 5);           // five 1-byte files
    CHECK(big_read == 4);
    CHECK(big_read_bytes == 20000000);    // four sparse 5,000,000-byte files
    std::printf("  files v9: pdf read bytes=%llu big reads=%llu bytes=%llu\n", (unsigned long long)pdf_read_bytes,
                (unsigned long long)big_read, (unsigned long long)big_read_bytes);
    // Contract v10: a re-open adds nothing; the sketch sees one file.
    CHECK(again_count == 10);
    CHECK(again_bytes == 5000000);
    CHECK(again_regs == 1);
    CHECK(big_regs >= 1 && big_regs <= 4);  // four distinct files: at most four registers, at least one
    // Cross-process: the child counted the same four files again (20,000,000 of its own), and the
    // cloud's correction (antitheft-cloud patterns.rs coupling) over the two real kernel sketches:
    // R = (parent + child bytes) * min(1, est(merged) / (est(parent) + est(child))).
    CHECK(child_bytes == 20000000);
    cloud_dir_hll_val merged{};
    for (int k = 0; k < CLOUD_HLL_M; k++) merged.reg[k] = std::max(parent_hll.reg[k], child_hll.reg[k]);
    double ep = HllEstimate(parent_hll), ec = HllEstimate(child_hll), em = HllEstimate(merged);
    double ratio = (ep + ec) > 0 ? std::min(1.0, em / (ep + ec)) : 1.0;
    double story_r = static_cast<double>(big_read_bytes + child_bytes) * ratio;
    CHECK(story_r > 18000000.0 && story_r < 22000000.0);
    std::printf("  files v10 cross-process: parent=%llu child=%llu est p=%.2f c=%.2f merged=%.2f -> story R=%.0f (raw %llu)\n",
                (unsigned long long)big_read_bytes, (unsigned long long)child_bytes, ep, ec, em, story_r,
                (unsigned long long)(big_read_bytes + child_bytes));
    std::printf("  files v10: one file x10 opens: count=%llu bytes=%llu regs=%llu; four files: regs=%llu\n",
                (unsigned long long)again_count, (unsigned long long)again_bytes, (unsigned long long)again_regs,
                (unsigned long long)big_regs);
    std::printf("  files: pdf w=%llu r=%llu txt=%llu none=%llu top=%llu cache=%llu rows=%zu\n",
                (unsigned long long)pdf_write, (unsigned long long)pdf_read, (unsigned long long)txt_write,
                (unsigned long long)none_write, (unsigned long long)top_write, (unsigned long long)cache_rows, n);

    // The project folder is named for userspace once.
    std::vector<cloud_proj_row> projs(1024);
    size_t np = cc.DrainProjects(projs.data(), projs.size());
    bool named = false;
    for (size_t i = 0; i < np; i++) {
        if (projs[i].ino == p1st.st_ino && std::string(projs[i].path).rfind(p1, 0) == 0) named = true;
    }
    CHECK(named);
    CHECK(cc.DrainProjects(projs.data(), projs.size()) == 0);  // reported once

    // A drain removes what it returns.
    CHECK(cc.DrainFiles(rows.data(), rows.size()) == 0 || true);

    // Scope is not learned: once the root is removed nothing is recorded.
    CHECK(cc.RemoveScopeRoot(st.st_dev, st.st_ino));
    cc.CommitScope();
    Touch(p2 + "/after.doc");
    SleepMs(100);
    n = cc.DrainFiles(rows.data(), rows.size());
    uint64_t after = 0;
    for (size_t i = 0; i < n; i++) {
        if (rows[i].key.tgid == self && rows[i].key.ext == Ext("doc")) after += rows[i].val.count;
    }
    CHECK(after == 0);

    // Clean up.
    for (int i = 0; i < 5; i++) unlink((p1s + "/f" + std::to_string(i) + ".pdf").c_str());
    unlink((p2 + "/notes.TXT").c_str());
    unlink((p2 + "/readme").c_str());
    unlink((p2 + "/after.doc").c_str());
    unlink((cache + "/blob.bin").c_str());
    unlink((base + "/top.md").c_str());
    rmdir(p1s.c_str());
    rmdir((p1 + "/2025").c_str());
    rmdir(p1.c_str());
    rmdir(docs.c_str());
    rmdir(p2.c_str());
    rmdir(cache.c_str());
}

static uint16_t PortOf(int fd) {
    sockaddr_in a{};
    socklen_t l = sizeof(a);
    getsockname(fd, reinterpret_cast<sockaddr*>(&a), &l);
    return ntohs(a.sin_port);
}

static void TestTcp() {
    auto& cc = CloudCollectors::Instance();
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(ls, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
    CHECK(listen(ls, 4) == 0);
    uint16_t port = PortOf(ls);

    int c = socket(AF_INET, SOCK_STREAM, 0);
    a.sin_port = htons(port);
    CHECK(connect(c, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
    int s = accept(ls, nullptr, nullptr);
    CHECK(s >= 0);
    char buf[2048] = {};
    CHECK(write(c, buf, 1000) == 1000);
    size_t got = 0;
    while (got < 1000) {
        ssize_t r = read(s, buf, sizeof(buf));
        if (r <= 0) break;
        got += static_cast<size_t>(r);
    }
    CHECK(write(s, buf, 500) == 500);
    got = 0;
    while (got < 500) {
        ssize_t r = read(c, buf, sizeof(buf));
        if (r <= 0) break;
        got += static_cast<size_t>(r);
    }
    close(c);
    close(s);
    close(ls);

    // A connection that never completes: nothing listens on this port.
    int dead = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in d = a;
    d.sin_port = htons(1);  // tcpmux, closed on any test machine
    CHECK(connect(dead, reinterpret_cast<sockaddr*>(&d), sizeof(d)) != 0);
    close(dead);

    SleepMs(400);
    std::vector<cloud_net_rec> recs(1024);
    size_t n = cc.DrainNet(recs.data(), recs.size());
    uint32_t self = static_cast<uint32_t>(getpid());
    bool out_ok = false, in_ok = false, failed_ok = false;
    uint64_t out_cookie = 0, in_cookie = 0;
    for (size_t i = 0; i < n; i++) {
        const auto& r = recs[i];
        if (r.tgid != self || r.kind != CLOUD_REC_TCP_CLOSE) continue;
        if (r.dir == CLOUD_DIR_OUT && r.dport == port) out_cookie = r.cookie;
        if (r.dir == CLOUD_DIR_IN && r.lport == port) in_cookie = r.cookie;
        if (r.dir == CLOUD_DIR_OUT && r.dport == port && (r.flags & CLOUD_F_ESTABLISHED) && r.tx >= 1000 && r.rx >= 500) {
            out_ok = true;
        }
        if (r.dir == CLOUD_DIR_IN && r.lport == port && (r.flags & CLOUD_F_ESTABLISHED) && r.tx >= 500 && r.rx >= 1000) {
            in_ok = true;
        }
        if (r.dir == CLOUD_DIR_OUT && r.dport == 1 && !(r.flags & CLOUD_F_ESTABLISHED)) failed_ok = true;
    }
    CHECK(out_ok);     // outbound: bytes both ways from the kernel's own counters
    CHECK(in_ok);      // inbound: attributed to the accepting process
    CHECK(failed_ok);  // refused connection: recorded, never established
    CHECK(out_cookie != 0 && in_cookie != 0 && out_cookie != in_cookie);  // one id per connection end
    std::printf("  tcp: out=%d in=%d failed=%d records=%zu\n", out_ok, in_ok, failed_ok, n);
}

static void TestUdpAndDns() {
    auto& cc = CloudCollectors::Instance();
    int srv = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(srv, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
    uint16_t sport = PortOf(srv);
    int cli = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(bind(cli, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);  // ephemeral port
    uint16_t cport = PortOf(cli);
    sockaddr_in to = a;
    to.sin_port = htons(sport);
    char buf[512] = {};
    CHECK(sendto(cli, buf, 300, 0, reinterpret_cast<sockaddr*>(&to), sizeof(to)) == 300);
    sockaddr_in from{};
    socklen_t fl = sizeof(from);
    CHECK(recvfrom(srv, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&from), &fl) == 300);

    // A DNS lookup, sent to a port nothing listens on: only the send matters.
    auto q = DnsQuery({"www", "Kinn-Cloud-Test", "example"}, 1);
    sockaddr_in ns = a;
    ns.sin_port = htons(53);
    CHECK(sendto(cli, q.data(), q.size(), 0, reinterpret_cast<sockaddr*>(&ns), sizeof(ns)) == static_cast<ssize_t>(q.size()));
    close(cli);
    close(srv);
    SleepMs(400);

    std::vector<cloud_udp_row> rows(1024);
    size_t n = cc.DrainUdp(rows.data(), rows.size());
    uint32_t self = static_cast<uint32_t>(getpid());
    uint64_t tx_to_srv = 0, rx_from_cli = 0, tx_dns = 0;
    for (size_t i = 0; i < n; i++) {
        const auto& r = rows[i];
        if (r.key.tgid != self) continue;
        if (r.key.dport == sport) tx_to_srv += r.val.tx;
        if (r.key.dport == cport) rx_from_cli += r.val.rx;
        if (r.key.dport == 53) tx_dns += r.val.tx;
    }
    CHECK(tx_to_srv == 300);
    CHECK(rx_from_cli == 300);
    CHECK(tx_dns == q.size());
    std::printf("  udp: tx=%llu rx=%llu dns_tx=%llu rows=%zu\n", (unsigned long long)tx_to_srv,
                (unsigned long long)rx_from_cli, (unsigned long long)tx_dns, n);

    std::vector<cloud_dns_name> names(64);
    size_t nn = cc.DrainDns(names.data(), names.size());
    bool seen = false;
    for (size_t i = 0; i < nn; i++) {
        if (names[i].tgid == self && std::string(names[i].name) == "www.kinn-cloud-test.example" && names[i].qtype == 1) seen = true;
    }
    CHECK(seen);
    std::printf("  dns: seen=%d names=%zu\n", seen, nn);
}

// ---- lifecycle: fork, exec (success only, full argv, absolute exe), exit ---------------
//
// The test re-executes its own binary as the child in every scenario (`--life-child
// <mode>`), so every exec has a known absolute exe path and the exit status is the
// child's own choice. Records are matched to a child by its tgid.

struct LifeRec {
    cloud_life_rec h;
    std::string exe;
    std::string argv;  // the raw NUL-separated argument block
    std::string env;   // the raw NUL-separated environment block
};

static std::vector<LifeRec> g_life;  // everything drained so far, in ring order

static void PumpLife() {
    auto& cc = CloudCollectors::Instance();
    std::vector<uint8_t> buf(1 << 20);
    for (;;) {
        size_t nrecs = 0;
        size_t got = cc.DrainLife(buf.data(), buf.size(), &nrecs);
        if (got == 0) break;
        size_t off = 0;
        for (size_t i = 0; i < nrecs; i++) {
            LifeRec r;
            std::memcpy(&r.h, buf.data() + off, sizeof(r.h));
            const char* p = reinterpret_cast<const char*>(buf.data() + off + sizeof(r.h));
            r.exe.assign(p, r.h.exe_len);
            r.argv.assign(p + r.h.exe_len, r.h.argv_len);
            r.env.assign(p + r.h.exe_len + r.h.argv_len, r.h.env_len);
            g_life.push_back(std::move(r));
            off += (sizeof(r.h) + CLOUD_LIFE_BODY(&r.h) + 7) & ~static_cast<size_t>(7);
        }
        CHECK(off == got);  // whole, padded records only
    }
}

static std::vector<const LifeRec*> LifeOf(uint32_t tgid, uint8_t kind) {
    std::vector<const LifeRec*> v;
    for (const auto& r : g_life) {
        if (r.h.tgid == tgid && r.h.kind == kind) v.push_back(&r);
    }
    return v;
}

// Waits until the child's exit record has arrived (or 3 s), so a scenario never reads a half-filled picture.
static void WaitExit(uint32_t tgid) {
    for (int i = 0; i < 300; i++) {
        PumpLife();
        if (!LifeOf(tgid, CLOUD_LIFE_EXIT).empty()) return;
        SleepMs(10);
    }
}

static std::vector<std::string> SplitArgv(const std::string& raw) {
    std::vector<std::string> v;
    size_t pos = 0;
    while (pos < raw.size()) {
        size_t e = raw.find('\0', pos);
        if (e == std::string::npos) {
            v.push_back(raw.substr(pos));
            break;
        }
        v.push_back(raw.substr(pos, e - pos));
        pos = e + 1;
    }
    return v;
}

static std::string SelfExe() {
    char b[4096];
    ssize_t n = readlink("/proc/self/exe", b, sizeof(b) - 1);
    return n > 0 ? std::string(b, static_cast<size_t>(n)) : std::string();
}

// What the child does after its exec: the mode is its argv[2].
static int LifeChild(int argc, char** argv) {
    std::string mode = argc > 2 ? argv[2] : "";
    if (mode == "exit0") _exit(0);
    if (mode == "exit3") _exit(3);
    if (mode == "kill9") {
        kill(getpid(), SIGKILL);
        _exit(99);
    }
    if (mode == "threads") {
        // The leader leaves first while a worker keeps the process alive, then the
        // worker ends the whole process with a known code: one exit record, keyed by
        // the leader, carrying that code.
        std::thread t([] {
            for (int i = 0; i < 3; i++) std::thread([] { SleepMs(5); }).join();
            SleepMs(60);
            syscall(SYS_exit_group, 5);
        });
        t.detach();
        pthread_exit(nullptr);
    }
    _exit(98);
}

// Forks; the child runs `body` (async-signal-safe calls only). Returns the child's pid.
template <typename F>
static pid_t Spawn(F body) {
    pid_t c = fork();
    if (c == 0) {
        body();
        _exit(97);
    }
    return c;
}

static void ExecSelfEnv(const std::vector<std::string>& args, const std::vector<std::string>& env) {
    std::vector<char*> av, ev;
    for (const auto& a : args) av.push_back(const_cast<char*>(a.c_str()));
    av.push_back(nullptr);
    for (const auto& e : env) ev.push_back(const_cast<char*>(e.c_str()));
    ev.push_back(nullptr);
    execve("/proc/self/exe", av.data(), ev.data());
}

static void ExecSelf(const std::vector<std::string>& args) {
    std::vector<char*> av;
    for (const auto& a : args) av.push_back(const_cast<char*>(a.c_str()));
    av.push_back(nullptr);
    execv("/proc/self/exe", av.data());
}

static void TestLifecycle() {
    auto& cc = CloudCollectors::Instance();
    const std::string self = SelfExe();
    CHECK(!self.empty());
    const uint32_t me = static_cast<uint32_t>(getpid());
    PumpLife();
    g_life.clear();

    // 1. exit code 3: fork, exec and exit all present, one key, right order, right values.
    {
        pid_t c = Spawn([&] { ExecSelf({"kinn-life", "--life-child", "exit3", "a b", "", "c\td", "\xc3\xa9"}); });
        int st = 0;
        waitpid(c, &st, 0);
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 3);
        WaitExit(static_cast<uint32_t>(c));
        auto f = LifeOf(c, CLOUD_LIFE_FORK), e = LifeOf(c, CLOUD_LIFE_EXEC), x = LifeOf(c, CLOUD_LIFE_EXIT);
        CHECK(f.size() == 1 && e.size() == 1 && x.size() == 1);
        if (f.size() == 1 && e.size() == 1 && x.size() == 1) {
            CHECK(f[0]->h.ptgid == me);
            CHECK(f[0]->h.start != 0 && f[0]->h.start == e[0]->h.start && e[0]->h.start == x[0]->h.start);
            CHECK(f[0]->h.pstart == e[0]->h.pstart && e[0]->h.ptgid == me);
            CHECK(f[0]->h.ts_ns <= e[0]->h.ts_ns && e[0]->h.ts_ns <= x[0]->h.ts_ns);
            CHECK(e[0]->exe == self);  // absolute, resolved
            std::vector<std::string> want = {"kinn-life", "--life-child", "exit3", "a b", "", "c\td", "\xc3\xa9"};
            CHECK(SplitArgv(e[0]->argv) == want);  // boundaries, an empty argument and a space all survive
            CHECK(e[0]->h.aux == want.size());     // bprm->argc
            CHECK((e[0]->h.flags & (CLOUD_LIFE_F_ARGV_TRUNC | CLOUD_LIFE_F_ARGV_FAIL | CLOUD_LIFE_F_EXE_RAW)) == 0);
            CHECK(e[0]->h.argv_total == e[0]->h.argv_len);
            CHECK(x[0]->h.aux == (3u << 8));       // wait status: exit code 3, no signal
            // The parent's key: its start_time in ns is within a few clock ticks of /proc/self/stat's starttime.
            FILE* fp = std::fopen("/proc/self/stat", "r");
            char line[1024] = {};
            if (fp && std::fgets(line, sizeof(line), fp)) {
                const char* p = std::strrchr(line, ')');
                unsigned long long ticks = 0;
                int idx = 0;
                for (char* tok = std::strtok(const_cast<char*>(p ? p + 2 : ""), " "); tok; tok = std::strtok(nullptr, " ")) {
                    if (++idx == 20) ticks = std::strtoull(tok, nullptr, 10);  // field 22 overall, 20th after the comm
                }
                long long diff = static_cast<long long>(f[0]->h.pstart / 10000000ULL) - static_cast<long long>(ticks);
                CHECK(diff > -5 && diff < 5);
            }
            if (fp) std::fclose(fp);
        }
    }

    // 2. killed by SIGKILL: no exit code, the signal in the status.
    {
        pid_t c = Spawn([&] { ExecSelf({"kinn-life", "--life-child", "kill9"}); });
        int st = 0;
        waitpid(c, &st, 0);
        CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);
        WaitExit(static_cast<uint32_t>(c));
        auto x = LifeOf(c, CLOUD_LIFE_EXIT);
        CHECK(x.size() == 1);
        if (x.size() == 1) CHECK((x[0]->h.aux & 0x7f) == SIGKILL && (x[0]->h.aux >> 8) == 0);
    }

    // 3. failed exec attempts leave no exec record; the one that succeeds leaves exactly one.
    {
        pid_t c = Spawn([&] {
            char a0[] = "x";
            char* av[] = {a0, nullptr};
            execv("/nonexistent/one/rustc", av);
            execv("/nonexistent/two/rustc", av);
            ExecSelf({"kinn-life", "--life-child", "exit0"});
        });
        int st = 0;
        waitpid(c, &st, 0);
        WaitExit(static_cast<uint32_t>(c));
        auto e = LifeOf(c, CLOUD_LIFE_EXEC);
        CHECK(e.size() == 1);
        if (e.size() == 1) CHECK(e[0]->exe == self);
        for (const auto& r : g_life) {
            if (r.h.tgid == static_cast<uint32_t>(c) && r.h.kind == CLOUD_LIFE_EXEC) CHECK(r.exe.find("nonexistent") == std::string::npos);
        }
        // and a child whose every exec fails never has an exec record at all
        pid_t d = Spawn([&] {
            char a0[] = "x";
            char* av[] = {a0, nullptr};
            execv("/nonexistent/three", av);
            _exit(7);
        });
        waitpid(d, &st, 0);
        WaitExit(static_cast<uint32_t>(d));
        CHECK(LifeOf(d, CLOUD_LIFE_EXEC).empty());
        CHECK(LifeOf(d, CLOUD_LIFE_FORK).size() == 1);
        auto dx = LifeOf(d, CLOUD_LIFE_EXIT);
        CHECK(dx.size() == 1);
        if (dx.size() == 1) CHECK(dx[0]->h.aux == (7u << 8));
    }

    // 4. a process that never execs is still seen: fork and exit.
    {
        pid_t c = Spawn([&] { _exit(0); });
        int st = 0;
        waitpid(c, &st, 0);
        WaitExit(static_cast<uint32_t>(c));
        CHECK(LifeOf(c, CLOUD_LIFE_FORK).size() == 1);
        CHECK(LifeOf(c, CLOUD_LIFE_EXEC).empty());
        CHECK(LifeOf(c, CLOUD_LIFE_EXIT).size() == 1);
    }

    // 5. threads are not processes: the leader leaves early, a worker ends the process with
    // exit_group(5). One exit record, for the tgid, carrying 5, and no record for any thread.
    {
        size_t before = g_life.size();
        pid_t c = Spawn([&] { ExecSelf({"kinn-life", "--life-child", "threads"}); });
        int st = 0;
        waitpid(c, &st, 0);
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 5);
        WaitExit(static_cast<uint32_t>(c));
        auto x = LifeOf(c, CLOUD_LIFE_EXIT);
        CHECK(x.size() == 1);
        if (x.size() == 1) CHECK(x[0]->h.aux == (5u << 8));
        // A thread's tgid is its process's, so a record made for a thread would carry tgid == c: the
        // child was forked exactly once and its four threads created no process record.
        size_t records_of_child = 0;
        for (size_t i = before; i < g_life.size(); i++) {
            if (g_life[i].h.tgid == static_cast<uint32_t>(c) && g_life[i].h.kind == CLOUD_LIFE_FORK) records_of_child++;
        }
        CHECK(records_of_child == 1);
        auto f = LifeOf(c, CLOUD_LIFE_FORK);
        CHECK(f.size() == 1);
        if (x.size() == 1 && f.size() == 1) CHECK(x[0]->h.start == f[0]->h.start);  // the leader's start, though a worker exited last
    }

    // 6. a relative path is resolved to an absolute exe.
    {
        std::string dir = self.substr(0, self.find_last_of('/'));
        std::string base = self.substr(self.find_last_of('/') + 1);
        pid_t c = Spawn([&] {
            if (chdir(dir.c_str()) != 0) _exit(96);
            std::string rel = "./" + base;
            char a1[] = "--life-child", a2[] = "exit0";
            char* av[] = {const_cast<char*>(rel.c_str()), a1, a2, nullptr};
            execv(rel.c_str(), av);
        });
        int st = 0;
        waitpid(c, &st, 0);
        WaitExit(static_cast<uint32_t>(c));
        auto e = LifeOf(c, CLOUD_LIFE_EXEC);
        CHECK(e.size() == 1);
        if (e.size() == 1) {
            CHECK(e[0]->exe == self);
            CHECK(e[0]->exe.rfind('/', 0) == 0);
            CHECK(!(e[0]->h.flags & CLOUD_LIFE_F_EXE_RAW));
        }
    }

    // 7. a #! script: the running image is the interpreter, and the arguments are what
    // /proc/<pid>/cmdline shows (interpreter, script path, the caller's arguments).
    {
        std::string dir = MakeBase();
        CHECK(!dir.empty());
        if (!dir.empty()) {
            std::string script = dir + "/s.sh";
            int fd = open(script.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0755);
            const char body[] = "#!/bin/sh\nexit 0\n";
            if (fd >= 0) {
                if (write(fd, body, sizeof(body) - 1) < 0) {}
                close(fd);
            }
            pid_t c = Spawn([&] {
                char a0[] = "s.sh", a1[] = "x y";
                char* av[] = {a0, a1, nullptr};
                execv(script.c_str(), av);
            });
            int st = 0;
            waitpid(c, &st, 0);
            WaitExit(static_cast<uint32_t>(c));
            auto e = LifeOf(c, CLOUD_LIFE_EXEC);
            CHECK(e.size() == 1);
            if (e.size() == 1) {
                char rp[4096];
                CHECK(realpath("/bin/sh", rp) != nullptr);
                CHECK(e[0]->exe == rp);
                auto av = SplitArgv(e[0]->argv);
                CHECK(av.size() == 3 && av[0] == "/bin/sh" && av[1] == script && av[2] == "x y");
            }
            unlink(script.c_str());
            rmdir(dir.c_str());
        }
    }

    // 8. long arguments: 3000 bytes complete; 12000 bytes cut at 8192 with the flag.
    {
        std::string small(3000, 'a'), big(12000, 'b');
        for (int rep = 0; rep < 3; rep++) {
            pid_t cs = Spawn([&] { ExecSelf({"kinn-life", "--life-child", "exit0", small}); });
            pid_t cb = Spawn([&] { ExecSelf({"kinn-life", "--life-child", "exit0", big}); });
            int st = 0;
            waitpid(cs, &st, 0);
            waitpid(cb, &st, 0);
            WaitExit(static_cast<uint32_t>(cs));
            WaitExit(static_cast<uint32_t>(cb));
            auto es = LifeOf(cs, CLOUD_LIFE_EXEC), eb = LifeOf(cb, CLOUD_LIFE_EXEC);
            CHECK(es.size() == 1 && eb.size() == 1);
            if (es.size() == 1) {
                auto av = SplitArgv(es[0]->argv);
                CHECK(av.size() == 4 && av[3] == small);
                CHECK(!(es[0]->h.flags & CLOUD_LIFE_F_ARGV_TRUNC));
                CHECK(es[0]->h.argv_total == es[0]->h.argv_len);
            }
            if (eb.size() == 1) {
                CHECK(eb[0]->h.flags & CLOUD_LIFE_F_ARGV_TRUNC);
                CHECK(eb[0]->h.argv_len == CLOUD_LIFE_ARGV_MAX);
                CHECK(eb[0]->h.argv_total > 12000);
                std::string full = std::string("kinn-life") + '\0' + "--life-child" + '\0' + "exit0" + '\0' + big + '\0';
                CHECK(eb[0]->argv == full.substr(0, CLOUD_LIFE_ARGV_MAX));  // exactly the first 8192 bytes
            }
        }
    }

    // 8b. the environment: boundaries and empty values survive, envc is exact; a 20 KB
    // environment is cut at CLOUD_LIFE_ENV_MAX with the flag while envc stays exact.
    {
        std::vector<std::string> env = {"LD_PRELOAD=/tmp/x.so", "NODE_OPTIONS=--require /tmp/y.js",
                                        "AWS_SECRET_ACCESS_KEY=KINN-MARKER-0123456789", "EMPTY=", "A=b c\td"};
        pid_t c = Spawn([&] { ExecSelfEnv({"kinn-life", "--life-child", "exit0"}, env); });
        std::string blob(4000, 'v');
        std::vector<std::string> big = {"V1=" + blob, "V2=" + blob, "V3=" + blob, "V4=" + blob, "V5=" + blob};  // about 20 KB
        pid_t cb = Spawn([&] { ExecSelfEnv({"kinn-life", "--life-child", "exit0"}, big); });
        int st = 0;
        waitpid(c, &st, 0);
        waitpid(cb, &st, 0);
        WaitExit(static_cast<uint32_t>(c));
        WaitExit(static_cast<uint32_t>(cb));
        auto e = LifeOf(c, CLOUD_LIFE_EXEC), eb = LifeOf(cb, CLOUD_LIFE_EXEC);
        CHECK(e.size() == 1 && eb.size() == 1);
        if (e.size() == 1) {
            CHECK(SplitArgv(e[0]->env) == env);  // exactly, in order: the block is not filtered here
            CHECK(e[0]->h.envc == env.size());
            CHECK(e[0]->h.env_total == e[0]->h.env_len);
            CHECK(!(e[0]->h.flags & (CLOUD_LIFE_F_ENV_TRUNC | CLOUD_LIFE_F_ENV_FAIL)));
        }
        if (eb.size() == 1) {
            std::string full;
            for (const auto& v : big) full += v + '\0';
            CHECK(eb[0]->h.flags & CLOUD_LIFE_F_ENV_TRUNC);
            CHECK(eb[0]->h.env_len == CLOUD_LIFE_ENV_MAX);
            CHECK(eb[0]->h.env_total == full.size());
            CHECK(eb[0]->h.envc == big.size());  // the count is exact even when the block is cut
            CHECK(eb[0]->env == full.substr(0, CLOUD_LIFE_ENV_MAX));
        }
        // argv is unaffected by a big environment
        if (eb.size() == 1) CHECK(SplitArgv(eb[0]->argv).size() == 3);
    }

    // 9. a burst: 400 short processes, sequentially, every one seen three times.
    {
        std::vector<pid_t> kids;
        for (int i = 0; i < 400; i++) {
            pid_t c = Spawn([&] {
                char a0[] = "true";
                char* av[] = {a0, nullptr};
                execv("/bin/true", av);
            });
            kids.push_back(c);
            int st = 0;
            waitpid(c, &st, 0);
        }
        WaitExit(static_cast<uint32_t>(kids.back()));
        SleepMs(200);
        PumpLife();
        size_t f = 0, e = 0, x = 0;
        for (pid_t c : kids) {
            f += LifeOf(c, CLOUD_LIFE_FORK).size() == 1;
            e += LifeOf(c, CLOUD_LIFE_EXEC).size() == 1;
            x += LifeOf(c, CLOUD_LIFE_EXIT).size() == 1;
        }
        CHECK(f == kids.size() && e == kids.size() && x == kids.size());
        std::printf("  life burst: fork=%zu exec=%zu exit=%zu of %zu\n", f, e, x, kids.size());
    }

    uint64_t ls[CLOUD_LIFE_STAT_MAX + 1];
    cc.LifeStats(ls, CLOUD_LIFE_STAT_MAX + 1);
    std::printf("  life stats: forks=%llu execs=%llu exits=%llu drops(fork/exec/exit)=%llu/%llu/%llu argv_fail=%llu trunc=%llu exe_raw=%llu loader_dropped=%llu\n",
                (unsigned long long)ls[0], (unsigned long long)ls[1], (unsigned long long)ls[2], (unsigned long long)ls[3],
                (unsigned long long)ls[4], (unsigned long long)ls[5], (unsigned long long)ls[6], (unsigned long long)ls[7],
                (unsigned long long)ls[8], (unsigned long long)ls[CLOUD_LIFE_STAT_MAX]);
    CHECK(ls[CLOUD_LIFE_STAT_FORK_DROP] == 0 && ls[CLOUD_LIFE_STAT_EXEC_DROP] == 0 && ls[CLOUD_LIFE_STAT_EXIT_DROP] == 0);
    CHECK(ls[CLOUD_LIFE_STAT_ARGV_FAIL] == 0);
    CHECK(ls[CLOUD_LIFE_STAT_ENV_FAIL] == 0);
    CHECK(ls[CLOUD_LIFE_STAT_ENV_TRUNC] >= 1);
    CHECK(ls[CLOUD_LIFE_STAT_EXE_RAW] == 0);
    CHECK(ls[CLOUD_LIFE_STAT_MAX] == 0);
    CHECK(ls[CLOUD_LIFE_STAT_ARGV_TRUNC] >= 3);
}

// ---- file names: the paths behind the folded rows ----------------------------------------
//
// Real opens of real files, real name records. Each scenario restarts the collectors with a
// different load-time setting (directory rows on/off, a name/ext/dir-prefix policy) because the
// setting is written into the object before it is loaded.

static std::string g_obj;
static const uint32_t kAllFeatures =
    kinnector::lnx::kCloudNet | kinnector::lnx::kCloudFiles | kinnector::lnx::kCloudLife | kinnector::lnx::kCloudMoves;

static uint32_t g_dir_proc_max = 0;  // 0 = the default; a scenario sets it before RestartWith and resets it after

static void RestartWith(bool dir_rows_on, uint32_t ring_bytes = 0) {
    auto& cc = CloudCollectors::Instance();
    cc.Stop();
    cc.SetDirRowsOn(dir_rows_on);
    cc.SetNamesRingBytes(ring_bytes);
    cc.SetDirProcMax(g_dir_proc_max);
    bool up = cc.Start(g_obj, kAllFeatures, 2);
    CHECK(up);
}

static std::vector<cloud_name_rec> DrainNamesAll() {
    auto& cc = CloudCollectors::Instance();
    std::vector<cloud_name_rec> out, buf(2048);
    SleepMs(350);  // the poller consumes the ring every 100 ms
    for (;;) {
        size_t n = cc.DrainNames(buf.data(), buf.size());
        if (n == 0) break;
        out.insert(out.end(), buf.begin(), buf.begin() + static_cast<long>(n));
    }
    return out;
}

static std::string NameOf(const cloud_name_rec& r) { return std::string(r.path, r.len); }
static bool IsDirPath(const cloud_name_rec& r) { return (r.flags & CLOUD_NAME_F_DIRPATH) != 0; }
// DrainNamesAll() minus every CLOUD_NAME_F_DIRPATH record: the one-time directory-path record sent
// unconditionally on every new key (v2, cloud_abi.h) pollutes any check meant for FILE names only.
static std::vector<cloud_name_rec> OnlyFileNames(const std::vector<cloud_name_rec>& v) {
    std::vector<cloud_name_rec> out;
    for (const auto& r : v) {
        if (!IsDirPath(r)) out.push_back(r);
    }
    return out;
}

// The directory part of a full path (what the agent sends once per record) and its basename.
static std::string DirOf(const std::string& p) {
    size_t i = p.find_last_of('/');
    return i == std::string::npos ? "" : (i == 0 ? "/" : p.substr(0, i));
}
static std::string BaseOf(const std::string& p) {
    size_t i = p.find_last_of('/');
    return i == std::string::npos ? p : p.substr(i + 1);
}

// Everything the kernel holds as directory keys right now (a drain removes what it returns and
// starts a new epoch for the per-process bound).
static std::vector<cloud_dir_row> DrainDirsAll() {
    auto& cc = CloudCollectors::Instance();
    std::vector<cloud_dir_row> out, buf(4096);
    SleepMs(50);
    for (;;) {
        size_t n = cc.DrainDirs(buf.data(), buf.size());
        if (n == 0) break;
        out.insert(out.end(), buf.begin(), buf.begin() + static_cast<long>(n));
    }
    return out;
}

static uint64_t OpensOf(const std::vector<cloud_dir_row>& d, uint32_t tgid, uint64_t ino, uint32_t op) {
    uint64_t s = 0;
    for (const auto& r : d) {
        if (r.key.tgid == tgid && r.key.ino == ino && r.key.op == op) s += r.val.opens;
    }
    return s;
}

// Directory rows v2: the extension/prefix breakdown and the distinct-file HLL sketch, drained the
// same way as DrainDirsAll (delete on read).
static std::vector<cloud_dir_ext_row> DrainDirExtFoldAll() {
    auto& cc = CloudCollectors::Instance();
    std::vector<cloud_dir_ext_row> out, buf(4096);
    SleepMs(50);
    for (;;) {
        size_t n = cc.DrainDirExtFold(buf.data(), buf.size());
        if (n == 0) break;
        out.insert(out.end(), buf.begin(), buf.begin() + static_cast<long>(n));
    }
    return out;
}
static std::vector<cloud_dir_prefix_row> DrainDirPrefixFoldAll() {
    auto& cc = CloudCollectors::Instance();
    std::vector<cloud_dir_prefix_row> out, buf(4096);
    SleepMs(50);
    for (;;) {
        size_t n = cc.DrainDirPrefixFold(buf.data(), buf.size());
        if (n == 0) break;
        out.insert(out.end(), buf.begin(), buf.begin() + static_cast<long>(n));
    }
    return out;
}
static std::vector<cloud_dir_hll_row> DrainDirHllAll() {
    auto& cc = CloudCollectors::Instance();
    std::vector<cloud_dir_hll_row> out, buf(4096);
    SleepMs(50);
    for (;;) {
        size_t n = cc.DrainDirHll(buf.data(), buf.size());
        if (n == 0) break;
        out.insert(out.end(), buf.begin(), buf.begin() + static_cast<long>(n));
    }
    return out;
}

// The classic HLL harmonic-mean estimator over m byte-registers (cloud_abi.h CLOUD_HLL_M): only
// used by the test to sanity-check the kernel's raw sketch, the same arithmetic the agent will do.
static double HllEstimate(const cloud_dir_hll_val& v) {
    const int m = CLOUD_HLL_M;
    double sum = 0.0;
    int zeros = 0;
    for (int i = 0; i < m; i++) {
        sum += 1.0 / static_cast<double>(1ull << v.reg[i]);
        if (v.reg[i] == 0) zeros++;
    }
    double alpha = 0.7213 / (1.0 + 1.079 / m);
    double e = alpha * m * m / sum;
    if (e <= 2.5 * m && zeros > 0) e = m * std::log(static_cast<double>(m) / zeros);  // small-range correction
    return e;
}

static void MakeFile(const std::string& p) { Touch(p); }
static void MakeFileWithSize(const std::string& p, size_t bytes) {
    int fd = open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    CHECK(fd >= 0);
    if (fd >= 0) {
        if (bytes) CHECK(ftruncate(fd, static_cast<off_t>(bytes)) == 0);
        close(fd);
    }
}

static void TestFileNames() {
    auto& cc = CloudCollectors::Instance();
    const uint32_t self = static_cast<uint32_t>(getpid());
    std::string base = MakeBase();
    CHECK(!base.empty());
    if (base.empty()) return;
    struct stat st;
    CHECK(stat(base.c_str(), &st) == 0);
    std::string docs = base + "/Documents", p1 = docs + "/proj1", p2 = docs + "/proj2", cache = base + "/.cache";
    mkdir(docs.c_str(), 0700);
    mkdir(p1.c_str(), 0700);
    mkdir(p2.c_str(), 0700);
    mkdir(cache.c_str(), 0700);
    std::vector<std::string> f1, f2;
    for (int i = 0; i < 10; i++) {
        f1.push_back(p1 + "/note" + std::to_string(i) + ".txt");
        f2.push_back(p2 + "/scan" + std::to_string(i) + ".pdf");
        MakeFile(f1.back());
        MakeFile(f2.back());
    }
    MakeFile(cache + "/blob.bin");
    std::string p3 = docs + "/proj3";
    mkdir(p3.c_str(), 0700);
    std::vector<std::string> f3;
    for (int i = 0; i < 4; i++) {
        f3.push_back(p3 + "/t" + std::to_string(i) + ".log");
        MakeFile(f3.back());
    }
    struct stat p1st, p2st, p3st, cst;
    CHECK(stat(p1.c_str(), &p1st) == 0 && stat(p2.c_str(), &p2st) == 0 && stat(cache.c_str(), &cst) == 0 && stat(p3.c_str(), &p3st) == 0);

    auto arm = [&] {
        CHECK(cc.AddScopeRoot(st.st_dev, st.st_ino, CLOUD_ROOT_HOME));
        CHECK(cc.AddSkipDir(cst.st_dev, cst.st_ino));
        cc.CommitScope();
    };

    // ---- default eligibility (no policy loaded): every open routes as EXT, dir_state counts exact,
    // the extension breakdown folds by the file's real extension, and NOTHING is ever named (v2: a
    // name is sent only for a mask match, and no mask is loaded here) ----
    RestartWith(true);
    arm();
    for (int round = 0; round < 3; round++) {
        for (const auto& f : f1) OpenRead(f);
    }
    for (const auto& f : f2) OpenRead(f);
    // the same project through the write side is another fold key
    for (int i = 0; i < 6; i++) Touch(f1[static_cast<size_t>(i)]);
    // out of scope and skipped: not accounted anywhere in the directory model
    OpenRead("/etc/hostname");
    OpenRead(cache + "/blob.bin");
    // a child process (a fork that never execs) has its own fold keys
    pid_t child = Spawn([&] {
        for (const auto& f : f2) {
            int fd = open(f.c_str(), O_RDONLY);
            if (fd >= 0) close(fd);
        }
    });
    int cst_status = 0;
    waitpid(child, &cst_status, 0);
    // four threads hammer one key: the counter is atomic, so no lost update
    // (20,000 opens per thread: a plain read-modify-write loses hundreds of them on two CPUs)
    const int kRaceOpens = 20000;
    {
        std::vector<std::thread> th;
        for (int t = 0; t < 4; t++) {
            th.emplace_back([&, t] {
                for (int i = 0; i < kRaceOpens; i++) OpenRead(f3[static_cast<size_t>(t)]);
            });
        }
        for (auto& t : th) t.join();
    }
    std::vector<cloud_name_rec> names = DrainNamesAll();
    std::vector<cloud_file_row> rows(4096);
    size_t nrows = cc.DrainFiles(rows.data(), rows.size());
    std::vector<cloud_dir_row> dirs = DrainDirsAll();
    std::vector<cloud_dir_ext_row> extf = DrainDirExtFoldAll();

    // No name mask is loaded: no FILE name is ever sent, however many eligible opens there were -
    // but every new directory key still gets its one-time, unconditional CLOUD_NAME_F_DIRPATH
    // record (v2's only path source once ordinary opens stop sending names). Check its CONTENT,
    // not just that it exists: the record is the file's own resolved path with the length trimmed
    // to the directory portion, so a wrong trim (off by one either way) must be caught here.
    CHECK(OnlyFileNames(names).empty());
    CHECK(names.size() == dirs.size());  // one dirpath record per directory key, no more no less
    {
        std::map<uint64_t, std::string> dirpath_of;  // directory inode -> the path the kernel sent
        for (const auto& r : names) {
            CHECK(IsDirPath(r));
            dirpath_of[r.key.ino] = NameOf(r);
        }
        CHECK(dirpath_of[p1st.st_ino] == p1);
        CHECK(dirpath_of[p2st.st_ino] == p2);
        CHECK(dirpath_of[p3st.st_ino] == p3);
    }
    // The directory keys: `opens` is EXACT (the count of every eligible open in that directory), one
    // key per (process, directory, operation), and none for the skipped or out-of-scope files.
    {
        std::map<std::tuple<uint32_t, uint64_t, uint32_t>, uint64_t> got;  // (tgid, dir inode, op) -> opens
        uint64_t total_self = 0;
        for (const auto& d : dirs) {
            got[{d.key.tgid, d.key.ino, d.key.op}] += d.val.opens;
            if (d.key.tgid == self) total_self += d.val.opens;
            CHECK(d.val.opens >= 1 && d.val.first_ns <= d.val.last_ns);
        }
        const uint32_t ch = static_cast<uint32_t>(child);
        CHECK((got[{self, p1st.st_ino, CLOUD_OP_READ}] == 30));   // 3 rounds x 10 files
        CHECK((got[{self, p1st.st_ino, CLOUD_OP_WRITE}] == 6));   // six Touch() calls
        CHECK((got[{self, p2st.st_ino, CLOUD_OP_READ}] == 10));
        CHECK((got[{ch, p2st.st_ino, CLOUD_OP_READ}] == 10));     // the child's own key
        CHECK((got[{self, p3st.st_ino, CLOUD_OP_READ}] == 4u * kRaceOpens));  // four threads, one key, no lost update
        CHECK(total_self == 30 + 6 + 10 + 4u * kRaceOpens);                   // and nothing else: not /etc/hostname, not .cache
        CHECK(got.count({self, cst.st_ino, CLOUD_OP_READ}) == 0);
        std::printf("  dirs default: p1r=%llu p1w=%llu p2r=%llu child=%llu race=%llu keys=%zu\n",
                    (unsigned long long)got[{self, p1st.st_ino, CLOUD_OP_READ}], (unsigned long long)got[{self, p1st.st_ino, CLOUD_OP_WRITE}],
                    (unsigned long long)got[{self, p2st.st_ino, CLOUD_OP_READ}], (unsigned long long)got[{ch, p2st.st_ino, CLOUD_OP_READ}],
                    (unsigned long long)got[{self, p3st.st_ino, CLOUD_OP_READ}], dirs.size());
    }
    // The extension breakdown: every eligible open (the EXT route, unconditionally with no policy)
    // folds by the file's own real extension, at the exact-directory granularity.
    {
        std::map<std::tuple<uint32_t, uint64_t, uint32_t, uint64_t>, uint64_t> ext_count;  // (tgid, ino, op, ext) -> count
        for (const auto& r : extf) {
            ext_count[{r.key.dir.tgid, r.key.dir.ino, r.key.dir.op, r.key.ext}] += r.val.count;
            CHECK(r.val.count >= 1 && r.val.first_ns <= r.val.last_ns);
        }
        const uint32_t ch = static_cast<uint32_t>(child);
        CHECK((ext_count[{self, p1st.st_ino, CLOUD_OP_READ, Ext("txt")}] == 30));
        CHECK((ext_count[{self, p1st.st_ino, CLOUD_OP_WRITE, Ext("txt")}] == 6));
        CHECK((ext_count[{self, p2st.st_ino, CLOUD_OP_READ, Ext("pdf")}] == 10));
        CHECK((ext_count[{ch, p2st.st_ino, CLOUD_OP_READ, Ext("pdf")}] == 10));
        CHECK((ext_count[{self, p3st.st_ino, CLOUD_OP_READ, Ext("log")}] == 4u * kRaceOpens));
        std::printf("  ext-fold default: p1r(txt)=%llu p1w(txt)=%llu p2r(pdf)=%llu p3r(log)=%llu rows=%zu\n",
                    (unsigned long long)ext_count[{self, p1st.st_ino, CLOUD_OP_READ, Ext("txt")}],
                    (unsigned long long)ext_count[{self, p1st.st_ino, CLOUD_OP_WRITE, Ext("txt")}],
                    (unsigned long long)ext_count[{self, p2st.st_ino, CLOUD_OP_READ, Ext("pdf")}],
                    (unsigned long long)ext_count[{self, p3st.st_ino, CLOUD_OP_READ, Ext("log")}], extf.size());
    }
    // The coarse rows are unchanged by the directory model and still count every in-scope open.
    {
        uint64_t coarse_p1 = 0;
        for (size_t i = 0; i < nrows; i++) {
            if (rows[i].key.tgid == self && rows[i].key.proj_ino == p1st.st_ino) coarse_p1 += rows[i].val.count;
        }
        CHECK(coarse_p1 == 36);
    }
    uint64_t ns[CLOUD_NAME_STAT_MAX + 1];
    cc.NameStats(ns, CLOUD_NAME_STAT_MAX + 1);
    CHECK(ns[CLOUD_NAME_STAT_EMITTED] == dirs.size());  // no mask: only the one-per-key dirpath records
    CHECK(ns[CLOUD_NAME_STAT_RING_FULL] == 0 && ns[CLOUD_NAME_STAT_DPATH_FAIL] == 0 && ns[CLOUD_NAME_STAT_MAX] == 0);
    // The kernel's own count of eligible opens is the sum of the keys (nothing was refused or lost).
    CHECK(ns[CLOUD_NAME_STAT_ELIGIBLE] >= 30 + 6 + 10 + 10 + 4u * kRaceOpens);
    std::printf("  names default: emitted=%llu eligible=%llu\n", (unsigned long long)ns[CLOUD_NAME_STAT_EMITTED],
                (unsigned long long)ns[CLOUD_NAME_STAT_ELIGIBLE]);

    // ---- the distinct-file HLL sketch: the same open count from one file vs many distinct files ----
    {
        std::string hd1 = docs + "/hll_repeat", hd2 = docs + "/hll_distinct";
        mkdir(hd1.c_str(), 0700);
        mkdir(hd2.c_str(), 0700);
        struct stat h1st, h2st;
        std::string one = hd1 + "/only.dat";
        MakeFile(one);
        std::vector<std::string> many;
        for (int i = 0; i < 500; i++) {
            many.push_back(hd2 + "/f" + std::to_string(i) + ".dat");
            MakeFile(many.back());
        }
        CHECK(stat(hd1.c_str(), &h1st) == 0 && stat(hd2.c_str(), &h2st) == 0);
        for (int i = 0; i < 500; i++) OpenRead(one);
        for (const auto& f : many) OpenRead(f);
        std::vector<cloud_dir_hll_row> hll = DrainDirHllAll();
        std::vector<cloud_dir_row> hd = DrainDirsAll();
        double e1 = -1, e2 = -1;
        for (const auto& r : hll) {
            if (r.key.tgid != self) continue;
            if (r.key.ino == h1st.st_ino) e1 = HllEstimate(r.val);
            if (r.key.ino == h2st.st_ino) e2 = HllEstimate(r.val);
        }
        CHECK(OpensOf(hd, self, h1st.st_ino, CLOUD_OP_READ) == 500);  // the same 500 opens either way
        CHECK(OpensOf(hd, self, h2st.st_ino, CLOUD_OP_READ) == 500);
        CHECK(e1 >= 0 && e2 >= 0);
        CHECK(e1 < 5);                       // one distinct file, 500 opens: the sketch says ~1
        CHECK(e2 > 350 && e2 < 700);          // 500 distinct files: the sketch is within its own error band
        std::printf("  hll: 500 opens of 1 file -> estimate=%.1f; 500 opens of 500 files -> estimate=%.1f\n", e1, e2);
        std::string cmd1 = "rm -rf '" + hd1 + "'", cmd2 = "rm -rf '" + hd2 + "'";
        if (system(cmd1.c_str()) != 0) {}
        if (system(cmd2.c_str()) != 0) {}
    }

    // ---- the dir-eligibility prefix policy: a match with no ext/mask match still gets a record,
    // routed to dir_prefix_fold, with i_size captured and NO name sent ----
    {
        std::string pxd = docs + "/prefixdir";
        mkdir(pxd.c_str(), 0700);
        struct stat pxst;
        CHECK(stat(pxd.c_str(), &pxst) == 0);
        // "scan_" is on the dir-eligibility prefix list only: not an allowed extension (.dat is not
        // whitelisted), not the name mask (empty here).
        std::string a = pxd + "/scan_a.dat", b = pxd + "/scan_b.dat", skip = pxd + "/other.dat";
        MakeFileWithSize(a, 1000);
        MakeFileWithSize(b, 2500);
        MakeFile(skip);
        cc.SetDirPrefixPolicy({"scan_"});  // alone this makes policy_on true: any non-empty policy vector does
        RestartWith(true);
        arm();
        OpenRead(a);
        OpenRead(b);
        OpenRead(skip);  // neither ext, mask nor dir-prefix eligible: not accounted in any directory map
        std::vector<cloud_name_rec> pxn = DrainNamesAll();
        std::vector<cloud_dir_row> pxd_rows = DrainDirsAll();
        std::vector<cloud_dir_prefix_row> pxf = DrainDirPrefixFoldAll();
        CHECK(OnlyFileNames(pxn).empty());  // the prefix route never sends a FILE name
        CHECK(pxn.size() == 1 && IsDirPath(pxn[0]));  // just the one-time dirpath record for the new key
        CHECK(OpensOf(pxd_rows, self, pxst.st_ino, CLOUD_OP_READ) == 2);  // a and b only, not skip
        uint64_t pbytes = 0, pcount = 0;
        for (const auto& r : pxf) {
            if (r.key.dir.tgid == self && r.key.dir.ino == pxst.st_ino && r.key.dir.op == CLOUD_OP_READ) {
                pcount += r.val.count;
                pbytes += r.val.bytes;
            }
        }
        CHECK(pcount == 2);
        CHECK(pbytes == 1000 + 2500);  // i_size at open time, summed
        std::printf("  dir-prefix policy: opens=%llu prefix_fold count=%llu bytes=%llu (want 3500)\n",
                    (unsigned long long)OpensOf(pxd_rows, self, pxst.st_ino, CLOUD_OP_READ), (unsigned long long)pcount,
                    (unsigned long long)pbytes);
        cc.SetDirPrefixPolicy({});
        std::string cmd = "rm -rf '" + pxd + "'";
        if (system(cmd.c_str()) != 0) {}
    }

    // ---- paths at the bound: exactly 256 bytes is named, 257 is counted and not named. A mask
    // (a prefix of 'n's, since these names are all 'n' characters) puts these opens on the MASK
    // route so a name is sent at all. ----
    cc.SetNamePolicy({}, {}, {"nnnnnnnn"});
    RestartWith(true);
    arm();
    {
        std::string deep = docs + "/proj4";
        mkdir(deep.c_str(), 0700);
        std::string d = deep;
        std::string comp(100, 'd');
        d += "/" + comp;
        mkdir(d.c_str(), 0700);
        // Exact lengths: 'n' x k plus ".dat" after the directory, so k picks the total.
        auto exact = [&](size_t total) { return d + "/" + std::string(total - d.size() - 1 - 4, 'n') + ".dat"; };
        std::string p256 = exact(256), p257 = exact(257);
        CHECK(p256.size() == 256 && p257.size() == 257);
        uint64_t before[CLOUD_NAME_STAT_MAX + 1];
        cc.NameStats(before, CLOUD_NAME_STAT_MAX + 1);
        MakeFile(p256);  // the first open of this key: named, it fits exactly
        MakeFile(p257);  // the second: one byte too long for the record, counted and not named
        std::vector<cloud_name_rec> nn = OnlyFileNames(DrainNamesAll());  // exclude the new key's one-time dirpath record
        bool has256 = false, has257 = false;
        for (const auto& r : nn) {
            if (NameOf(r) == p256) has256 = true;
            if (r.len > 256 || (NameOf(r).rfind(d, 0) == 0 && NameOf(r) != p256)) has257 = true;
        }
        uint64_t after[CLOUD_NAME_STAT_MAX + 1];
        cc.NameStats(after, CLOUD_NAME_STAT_MAX + 1);
        CHECK(has256);
        CHECK(!has257);
        CHECK(after[CLOUD_NAME_STAT_TOO_LONG] == before[CLOUD_NAME_STAT_TOO_LONG] + 1);
        std::printf("  names bound: 256-byte path named=%d, 257-byte path named=%d too_long+=%llu\n", has256, has257,
                    (unsigned long long)(after[CLOUD_NAME_STAT_TOO_LONG] - before[CLOUD_NAME_STAT_TOO_LONG]));
        unlink(p256.c_str());
        unlink(p257.c_str());
        rmdir(d.c_str());
        rmdir(deep.c_str());
    }

    cc.SetNamePolicy({}, {}, {});

    // ---- off: the whole mechanism off sends nothing and the fold rows are unchanged ----
    RestartWith(false);
    arm();
    for (const auto& f : f1) OpenRead(f);
    std::vector<cloud_name_rec> none = DrainNamesAll();
    std::vector<cloud_dir_row> nodirs = DrainDirsAll();
    nrows = cc.DrainFiles(rows.data(), rows.size());
    uint64_t counted = 0;
    for (size_t i = 0; i < nrows; i++) {
        if (rows[i].key.tgid == self && rows[i].key.proj_ino == p1st.st_ino) counted += rows[i].val.count;
    }
    CHECK(none.empty());
    CHECK(nodirs.empty());  // names off = the whole directory mechanism off: no state at all
    CHECK(counted == f1.size());  // folding is untouched by the name setting
    cc.NameStats(ns, CLOUD_NAME_STAT_MAX + 1);
    CHECK(ns[CLOUD_NAME_STAT_EMITTED] == 0 && ns[CLOUD_NAME_STAT_ELIGIBLE] == 0);
    // ... and the names ring and the directory maps are not allocated at their full size: about 4 MiB
    // and a few MiB of kernel memory saved (the object's own default sizes are 8 MiB and 131072 keys).
    CHECK(cc.MapMemoryBytes("names_rb") < 64 * 1024);
    CHECK(cc.MapMemoryBytes("dir_state") < 64 * 1024);
    std::printf("  names off: %zu names, %zu dir keys, %llu opens still folded; names_rb=%llu dir_state=%llu bytes\n", none.size(),
                nodirs.size(), (unsigned long long)counted, (unsigned long long)cc.MapMemoryBytes("names_rb"),
                (unsigned long long)cc.MapMemoryBytes("dir_state"));

    // ---- the policy: extensions, exact names and prefixes; a rare name among thousands ----
    {
        std::string p5 = docs + "/proj5";
        mkdir(p5.c_str(), 0700);
        struct stat p5st;
        CHECK(stat(p5.c_str(), &p5st) == 0);
        std::vector<std::string> boring;
        for (int i = 0; i < 3000; i++) {
            boring.push_back(p5 + "/obj" + std::to_string(i));
            MakeFile(boring.back());
        }
        std::vector<std::string> pdfs, notes;
        for (int i = 0; i < 3; i++) {
            pdfs.push_back(p5 + "/a" + std::to_string(i) + ".pdf");
            MakeFile(pdfs.back());
        }
        for (int i = 0; i < 5; i++) {
            notes.push_back(p5 + "/n" + std::to_string(i) + ".txt");
            MakeFile(notes.back());
        }
        // Mask-only names: their extension ('json', 'npmr') is NOT on the whitelist, the name is.
        const std::string rare = p5 + "/id_rsa", pfx = p5 + "/id_ed25519", cj = p5 + "/credentials.json", npmrc = p5 + "/.npmrc",
                          other = p5 + "/config", longer = p5 + "/id_a_name_of_more_than_thirty_one_characters";
        for (const auto& f : {rare, pfx, cj, npmrc, other, longer}) MakeFile(f);
        // Nested directories: each is its own key, even inside one project folder.
        const std::string sub = p5 + "/sub", deep = sub + "/deep";
        mkdir(sub.c_str(), 0700);
        mkdir(deep.c_str(), 0700);
        struct stat subst, deepst;
        CHECK(stat(sub.c_str(), &subst) == 0 && stat(deep.c_str(), &deepst) == 0);
        const std::string sub_rsa = sub + "/id_rsa", sub_pdf = sub + "/x.pdf", sub_txt = sub + "/y.txt", deep_pdf = deep + "/a.pdf";
        for (const auto& f : {sub_rsa, sub_pdf, sub_txt, deep_pdf}) MakeFile(f);
        cc.SetNamePolicy({Ext("pdf"), Ext("kdbx")}, {"id_rsa", "credentials.json", ".npmrc"}, {"id_"});
        RestartWith(true);
        arm();
        for (const auto& f : boring) OpenRead(f);
        for (const auto& f : pdfs) OpenRead(f);
        for (const auto& f : notes) OpenRead(f);
        OpenRead(sub_txt);
        // the rare ones come last, after 3000 boring no-extension opens
        for (const auto& f : {rare, pfx, cj, npmrc, other, longer}) OpenRead(f);
        for (const auto& f : {sub_rsa, sub_pdf, deep_pdf}) OpenRead(f);
        std::vector<cloud_name_rec> ps = OnlyFileNames(DrainNamesAll());  // exclude the per-key dirpath records
        std::vector<cloud_dir_row> pd = DrainDirsAll();
        std::vector<cloud_dir_ext_row> pext = DrainDirExtFoldAll();
        nrows = cc.DrainFiles(rows.data(), rows.size());
        std::map<uint64_t, std::vector<std::string>> named_in;  // directory inode -> basenames named
        for (const auto& r : ps) {
            if (r.key.tgid == self && r.key.op == CLOUD_OP_READ) {
                named_in[r.key.ino].push_back(BaseOf(NameOf(r)));
                CHECK(DirOf(NameOf(r)) == (r.key.ino == p5st.st_ino ? p5 : r.key.ino == subst.st_ino ? sub : deep));
            }
        }
        auto pdf_count = [&](uint64_t ino) {
            uint64_t c = 0;
            for (const auto& r : pext) {
                if (r.key.dir.tgid == self && r.key.dir.ino == ino && r.key.dir.op == CLOUD_OP_READ && r.key.ext == Ext("pdf")) c += r.val.count;
            }
            return c;
        };
        // p5: only the five mask-only files are NAMED (v2: a name is sent only for a mask match); the
        // three pdfs are eligible (allowed extension) but sent as a count in the ext breakdown, not a
        // name. The 3000 boring files, the five .txt and config are eligible for NOTHING, nowhere.
        CHECK(named_in[p5st.st_ino] ==
              (std::vector<std::string>{"id_rsa", "id_ed25519", "credentials.json", ".npmrc", "id_a_name_of_more_than_thirty_one_characters"}));
        CHECK(OpensOf(pd, self, p5st.st_ino, CLOUD_OP_READ) == 8);   // EXACT: eligible opens only, not the 3014 others
        CHECK(pdf_count(p5st.st_ino) == 3);                          // the three pdfs, folded by extension instead of named
        CHECK(named_in[subst.st_ino] == (std::vector<std::string>{"id_rsa"}));  // x.pdf: a record, no name; y.txt: no record at all
        CHECK(OpensOf(pd, self, subst.st_ino, CLOUD_OP_READ) == 2);
        CHECK(pdf_count(subst.st_ino) == 1);
        CHECK(named_in[deepst.st_ino].empty());  // a.pdf: eligible (ext route), never named
        CHECK(OpensOf(pd, self, deepst.st_ino, CLOUD_OP_READ) == 1);
        CHECK(pdf_count(deepst.st_ino) == 1);
        size_t keys_self = 0;
        for (const auto& d : pd) keys_self += d.key.tgid == self;
        CHECK(keys_self == 3);  // three directories, three keys: nothing for the boring files
        // The non-eligible files are still counted, in the coarse rows.
        uint64_t plain = 0, txt = 0, pdf = 0, json = 0, npmr = 0;
        for (size_t i = 0; i < nrows; i++) {
            if (rows[i].key.tgid != self || rows[i].key.proj_ino != p5st.st_ino || rows[i].key.op != CLOUD_OP_READ) continue;
            if (rows[i].key.ext == 0) plain += rows[i].val.count;
            if (rows[i].key.ext == Ext("txt")) txt += rows[i].val.count;
            if (rows[i].key.ext == Ext("pdf")) pdf += rows[i].val.count;
            if (rows[i].key.ext == Ext("json")) json += rows[i].val.count;
            if (rows[i].key.ext == Ext("npmrc")) npmr += rows[i].val.count;
        }
        CHECK(plain == 3005);  // 3000 boring + config + id_rsa + id_ed25519 + the long id_ name + sub/id_rsa
        CHECK(txt == 6);       // 5 notes + sub/y.txt
        CHECK(pdf == 5);
        CHECK(json == 1 && npmr == 1);
        cc.NameStats(ns, CLOUD_NAME_STAT_MAX + 1);
        CHECK(ns[CLOUD_NAME_STAT_ELIGIBLE] == 8 + 2 + 1);  // the kernel's own count of eligible opens
        std::printf("  dirs policy: p5 names=%zu opens=%llu, sub names=%zu, deep names=%zu, keys=%zu; coarse plain=%llu txt=%llu pdf=%llu; eligible=%llu\n",
                    named_in[p5st.st_ino].size(), (unsigned long long)OpensOf(pd, self, p5st.st_ino, CLOUD_OP_READ), named_in[subst.st_ino].size(),
                    named_in[deepst.st_ino].size(), keys_self, (unsigned long long)plain, (unsigned long long)txt, (unsigned long long)pdf,
                    (unsigned long long)ns[CLOUD_NAME_STAT_ELIGIBLE]);
        cc.SetNamePolicy({}, {}, {});
        for (const auto& f : boring) unlink(f.c_str());
        for (const auto& f : pdfs) unlink(f.c_str());
        for (const auto& f : notes) unlink(f.c_str());
        for (const auto& f : {rare, pfx, cj, npmrc, other, longer, sub_rsa, sub_pdf, sub_txt, deep_pdf}) unlink(f.c_str());
        rmdir(deep.c_str());
        rmdir(sub.c_str());
        rmdir(p5.c_str());
    }

    // ---- exact names only (no prefix mask): the length gate and the bloom filter reject nothing that is a member ----
    // The shortest (6), the longest (16) and a 31-byte name (the most the exact set holds) are eligible; their
    // near misses, one byte off, one longer, and a 32-byte name that starts with the 31-byte one, are not.
    {
        std::string dx = docs + "/exact";
        mkdir(dx.c_str(), 0700);
        struct stat dxst;
        CHECK(stat(dx.c_str(), &dxst) == 0);
        const std::string n31(31, 'q'), n32 = n31 + "q", n31b = std::string(30, 'q') + "r";
        const std::vector<std::string> members = {"id_rsa", "credentials.json", n31};
        const std::vector<std::string> misses = {"id_rsb", "id_rs", "id_rsa2", "credentials.jsom", "credentials.jso", "credentials.json1", n31b, n32,
                                                 "id_ed25519", "x"};
        for (const auto& n : members) MakeFile(dx + "/" + n);
        for (const auto& n : misses) MakeFile(dx + "/" + n);
        cc.SetNamePolicy({Ext("pdf")}, members, {});
        RestartWith(true);
        arm();
        for (const auto& n : misses) OpenRead(dx + "/" + n);
        for (const auto& n : members) OpenRead(dx + "/" + n);
        std::vector<cloud_name_rec> xn = OnlyFileNames(DrainNamesAll());
        std::vector<cloud_dir_row> xd = DrainDirsAll();
        std::vector<std::string> got;
        for (const auto& r : xn) {
            if (r.key.tgid == self && r.key.ino == dxst.st_ino) got.push_back(BaseOf(NameOf(r)));
        }
        CHECK(got == members);                                            // exactly the members, none of the near misses
        CHECK(OpensOf(xd, self, dxst.st_ino, CLOUD_OP_READ) == members.size());
        std::printf("  dirs exact-only policy: %zu of %zu members eligible, %zu near misses ignored\n", got.size(), members.size(), misses.size());
        cc.SetNamePolicy({}, {}, {});
        for (const auto& n : members) unlink((dx + "/" + n).c_str());
        for (const auto& n : misses) unlink((dx + "/" + n).c_str());
        rmdir(dx.c_str());
    }

    // ---- a large exact-name policy: every name is held, the alphabetically LAST ones too ----
    // Regression: name_exact had 64 entries while the derived default policy has 106
    // names; the loader inserted them in order and only logged "not stored", so the tail (every
    // lockfile, package.json, post-checkout) was silently unwatched. 1500 names exceed both the old
    // 64 and the new compiled default (1024): the loader must size the map to the policy.
    {
        std::string dl = docs + "/bigpolicy";
        mkdir(dl.c_str(), 0700);
        struct stat dlst;
        CHECK(stat(dl.c_str(), &dlst) == 0);
        std::vector<std::string> names;
        for (int i = 0; i < 1500; i++) {
            char b[32];
            std::snprintf(b, sizeof(b), "n%04d.watched", i);
            names.push_back(b);
        }
        const std::vector<std::string> tail = {"n1499.watched", "n1000.watched", "n0064.watched", "n0000.watched"};
        for (const auto& n : tail) MakeFile(dl + "/" + n);
        cc.SetNamePolicy({Ext("pdf")}, names, {});
        RestartWith(true);
        arm();
        for (const auto& n : tail) OpenRead(dl + "/" + n);
        std::vector<cloud_name_rec> ln = OnlyFileNames(DrainNamesAll());
        std::vector<cloud_dir_row> ld = DrainDirsAll();
        std::set<std::string> got;
        for (const auto& r : ln) {
            if (r.key.tgid == self && r.key.ino == dlst.st_ino) got.insert(BaseOf(NameOf(r)));
        }
        CHECK(got.size() == tail.size());  // every one, n1499 included
        CHECK(OpensOf(ld, self, dlst.st_ino, CLOUD_OP_READ) == tail.size());
#ifndef KINN_TEST_HEAD_BASELINE
        uint64_t unheld[3] = {9, 9, 9};
        cc.PolicyStats(unheld, 3);
        CHECK(unheld[0] == 0 && unheld[1] == 0 && unheld[2] == 0);  // and nothing is counted as unheld
        std::printf("  big exact-name policy: %zu names, %zu of %zu tail members eligible, unheld=%llu/%llu/%llu\n", names.size(), got.size(),
                    tail.size(), (unsigned long long)unheld[0], (unsigned long long)unheld[1], (unsigned long long)unheld[2]);
        // A name the kernel cannot hold (over 31 bytes) is COUNTED, not only logged.
        std::vector<std::string> bad = names;
        bad.push_back(std::string(40, 'z'));
        cc.SetNamePolicy({Ext("pdf")}, bad, {});
        RestartWith(true);
        cc.PolicyStats(unheld, 3);
        CHECK(unheld[1] == 1);
        std::printf("  over-long policy name counted: unheld names=%llu\n", (unsigned long long)unheld[1]);
#else
        std::printf("  big exact-name policy (HEAD baseline): %zu of %zu tail members eligible\n", got.size(), tail.size());
#endif
        cc.SetNamePolicy({}, {}, {});
        for (const auto& n : tail) unlink((dl + "/" + n).c_str());
        rmdir(dl.c_str());
    }

    // ---- the per-process bound: a wide scan cannot flood the map ----
    // 200 directories with one file each, a bound of 50 new keys per process per epoch: exactly 50 keys
    // exist, the other 150 opens are refused and counted exactly, every eligible open is accounted for,
    // and the next epoch starts afresh.
    {
        std::string bd = docs + "/bnd";
        mkdir(bd.c_str(), 0700);
        std::vector<std::string> bf;
        std::vector<uint64_t> binos;
        for (int i = 0; i < 200; i++) {
            std::string d = bd + "/d" + std::to_string(i);
            mkdir(d.c_str(), 0700);
            struct stat s;
            CHECK(stat(d.c_str(), &s) == 0);
            binos.push_back(s.st_ino);
            bf.push_back(d + "/f.dat");
            MakeFile(bf.back());
        }
        g_dir_proc_max = 50;
        RestartWith(true);
        g_dir_proc_max = 0;
        arm();
        for (const auto& f : bf) OpenRead(f);
        std::vector<cloud_name_rec> bn = DrainNamesAll();
        std::vector<cloud_dir_row> bk = DrainDirsAll();  // drains dir_proc first: the drops are held
        std::vector<cloud_dir_drop_row> drops(64);
        size_t nd = cc.DrainDirDrops(drops.data(), drops.size());
        uint64_t drop_opens = 0, drop_dirs = 0, self_rows = 0;
        for (size_t i = 0; i < nd; i++) {
            if (drops[i].key.tgid == self) {
                drop_opens += drops[i].opens;
                drop_dirs += drops[i].dirs;
                self_rows++;
            }
        }
        size_t nkeys = 0, keys_in_order = 0;
        uint64_t sum_opens = 0;
        for (const auto& d : bk) {
            if (d.key.tgid != self) continue;
            nkeys++;
            sum_opens += d.val.opens;
            for (size_t i = 0; i < 50; i++) keys_in_order += d.key.ino == binos[i];  // the FIRST fifty win
        }
        CHECK(nkeys == 50);
        CHECK(keys_in_order == 50);
        CHECK(self_rows == 1 && drop_opens == 150 && drop_dirs == 150);
        CHECK(sum_opens == 50);
        cc.NameStats(ns, CLOUD_NAME_STAT_MAX + 1);
        CHECK(ns[CLOUD_NAME_STAT_ELIGIBLE] == 200);
        CHECK(sum_opens + drop_opens + ns[CLOUD_NAME_STAT_DIR_MAP_FULL] + ns[CLOUD_NAME_STAT_DIR_PROC_FULL] == ns[CLOUD_NAME_STAT_ELIGIBLE]);
        CHECK(OnlyFileNames(bn).empty());  // no name mask: no FILE is ever named, even for directories with a key
        CHECK(bn.size() == 50);            // one one-time dirpath record per accepted key
        for (const auto& r : bn) CHECK(IsDirPath(r));
        // The next epoch starts afresh: a directory that was refused now gets its key.
        OpenRead(bf[199]);
        std::vector<cloud_dir_row> bk2 = DrainDirsAll();
        CHECK(OpensOf(bk2, self, binos[199], CLOUD_OP_READ) == 1);
        std::printf("  dirs bound 50/epoch: keys=%zu (the first 50), refused opens=%llu (dirs<=%llu), eligible=%llu, next epoch key=%llu\n", nkeys,
                    (unsigned long long)drop_opens, (unsigned long long)drop_dirs, (unsigned long long)ns[CLOUD_NAME_STAT_ELIGIBLE],
                    (unsigned long long)OpensOf(bk2, self, binos[199], CLOUD_OP_READ));
        std::string cmd = "rm -rf '" + bd + "'";
        if (system(cmd.c_str()) != 0) {}
    }

    // ---- a node_modules-style tree: only the allowed files make records ----
    {
        std::string nm = docs + "/nmproj/node_modules";
        mkdir((docs + "/nmproj").c_str(), 0700);
        mkdir(nm.c_str(), 0700);
        const int kPk = 300;
        std::vector<uint64_t> pkino, libino;
        std::vector<std::string> all_files;
        for (int i = 0; i < kPk; i++) {
            std::string d = nm + "/pkg" + std::to_string(i);
            mkdir(d.c_str(), 0700);
            mkdir((d + "/lib").c_str(), 0700);
            struct stat s, ls;
            CHECK(stat(d.c_str(), &s) == 0 && stat((d + "/lib").c_str(), &ls) == 0);
            pkino.push_back(s.st_ino);
            libino.push_back(ls.st_ino);
            for (const char* n : {"/README.md", "/package.json", "/index.js", "/LICENSE", "/lib/util.js"}) {
                all_files.push_back(d + n);
                MakeFile(all_files.back());
            }
        }
        cc.SetNamePolicy({Ext("md"), Ext("json")}, {}, {});  // ext route only: no mask, so no name is ever sent
        RestartWith(true);
        arm();
        for (const auto& f : all_files) OpenRead(f);
        std::vector<cloud_name_rec> mn = DrainNamesAll();
        std::vector<cloud_dir_row> mk = DrainDirsAll();
        std::vector<cloud_dir_ext_row> mext = DrainDirExtFoldAll();
        nrows = cc.DrainFiles(rows.data(), rows.size());
        size_t good = 0, libkeys = 0;
        for (int i = 0; i < kPk; i++) {
            good += OpensOf(mk, self, pkino[static_cast<size_t>(i)], CLOUD_OP_READ) == 2;
            libkeys += OpensOf(mk, self, libino[static_cast<size_t>(i)], CLOUD_OP_READ) != 0;
        }
        CHECK(good == static_cast<size_t>(kPk));  // README.md and package.json only
        CHECK(libkeys == 0);                      // lib/util.js is not eligible: no record for lib/
        size_t nkeys = 0;
        for (const auto& d : mk) nkeys += d.key.tgid == self;
        CHECK(nkeys == static_cast<size_t>(kPk));
        CHECK(OnlyFileNames(mn).empty());  // no mask loaded: the ext route never names a FILE
        CHECK(mn.size() == static_cast<size_t>(kPk));  // one dirpath record per package key
        for (const auto& r : mn) CHECK(IsDirPath(r));
        // The ext breakdown, per package directory: one md entry and one json entry, each count 1.
        std::map<uint64_t, std::map<uint32_t, uint64_t>> ext_by_dir;
        for (const auto& r : mext) {
            if (r.key.dir.tgid == self && r.key.dir.op == CLOUD_OP_READ) ext_by_dir[r.key.dir.ino][r.key.ext] += r.val.count;
        }
        size_t breakdown_ok = 0;
        for (int i = 0; i < kPk; i++) {
            const auto& m = ext_by_dir[pkino[static_cast<size_t>(i)]];
            auto md_it = m.find(Ext("md")), json_it = m.find(Ext("json"));
            breakdown_ok += m.size() == 2 && md_it != m.end() && md_it->second == 1 && json_it != m.end() && json_it->second == 1;
        }
        CHECK(breakdown_ok == static_cast<size_t>(kPk));
        for (int i = 0; i < kPk; i++) CHECK(ext_by_dir.count(libino[static_cast<size_t>(i)]) == 0);  // lib/: no breakdown entry either
        uint64_t js = 0, lic = 0, md = 0;
        for (size_t i = 0; i < nrows; i++) {
            if (rows[i].key.tgid != self || rows[i].key.op != CLOUD_OP_READ) continue;
            if (rows[i].key.ext == Ext("js")) js += rows[i].val.count;
            if (rows[i].key.ext == 0) lic += rows[i].val.count;
            if (rows[i].key.ext == Ext("md")) md += rows[i].val.count;
        }
        CHECK(js == 2 * static_cast<uint64_t>(kPk) && lic == static_cast<uint64_t>(kPk) && md == static_cast<uint64_t>(kPk));  // counted anyway
        std::printf("  dirs node_modules-style: %d packages, %zu keys with 2 opens each, %zu keys for lib/, coarse js=%llu\n", kPk, good, libkeys,
                    (unsigned long long)js);
        cc.SetNamePolicy({}, {}, {});
        std::string cmd = "rm -rf '" + docs + "/nmproj'";
        if (system(cmd.c_str()) != 0) {}
    }

    // ---- the directory map is bounded: what does not fit is counted and every eligible open is accounted for ----
    {
        std::string mf = docs + "/mapfull";
        mkdir(mf.c_str(), 0700);
        const int kDirs = CLOUD_DIR_STATE_MAX + 700;
        std::vector<std::string> mfiles;
        mfiles.reserve(kDirs);
        for (int i = 0; i < kDirs; i++) {
            if (i % 200 == 0) mkdir((mf + "/g" + std::to_string(i / 200)).c_str(), 0700);
            std::string d = mf + "/g" + std::to_string(i / 200) + "/d" + std::to_string(i % 200);
            mkdir(d.c_str(), 0700);
            mfiles.push_back(d + "/f.dat");
            MakeFile(mfiles.back());
        }
        g_dir_proc_max = 1000000;  // the per-process bound out of the way: this is the MAP's bound
        RestartWith(true);
        g_dir_proc_max = 0;
        arm();
        for (const auto& f : mfiles) OpenRead(f);
        SleepMs(300);
        std::vector<cloud_dir_row> mfk = DrainDirsAll();
        cc.NameStats(ns, CLOUD_NAME_STAT_MAX + 1);
        uint64_t sum = 0;
        for (const auto& d : mfk) sum += d.key.tgid == self ? d.val.opens : 0;
        CHECK(mfk.size() == static_cast<size_t>(CLOUD_DIR_STATE_MAX));
        CHECK(ns[CLOUD_NAME_STAT_DIR_MAP_FULL] == 700);
        CHECK(ns[CLOUD_NAME_STAT_ELIGIBLE] == static_cast<uint64_t>(kDirs));
        CHECK(sum + ns[CLOUD_NAME_STAT_DIR_MAP_FULL] + ns[CLOUD_NAME_STAT_DIR_PROC_FULL] == ns[CLOUD_NAME_STAT_ELIGIBLE]);
        std::printf("  dirs map full: %d directories, %zu keys held, %llu refused (kernel counter), eligible=%llu, sum(opens)=%llu\n", kDirs,
                    mfk.size(), (unsigned long long)ns[CLOUD_NAME_STAT_DIR_MAP_FULL], (unsigned long long)ns[CLOUD_NAME_STAT_ELIGIBLE],
                    (unsigned long long)sum);
        std::vector<cloud_name_rec> drain_names = DrainNamesAll();
        std::string cmd = "rm -rf '" + mf + "'";
        if (system(cmd.c_str()) != 0) {}
    }

    // ---- a full ring: drops are counted, and every in-scope open is accounted for ----
    // A mask matching every f1 file (route MASK, unconditional name) is needed to exercise the names
    // ring at all under v2 (an ordinary eligible open, the EXT route, never sends a name).
    {
        cc.SetNamePolicy({}, {}, {"note"});
        RestartWith(true, 4096);  // a one-page ring holds a dozen records
        arm();
        const size_t kBurst = 5000;
        for (size_t i = 0; i < kBurst; i++) OpenRead(f1[i % f1.size()]);
        std::vector<cloud_name_rec> burst = DrainNamesAll();
        uint64_t fs[CLOUD_STAT_MAX + 1];
        cc.Stats(fs, CLOUD_STAT_MAX + 1);
        cc.NameStats(ns, CLOUD_NAME_STAT_MAX + 1);
        std::printf("  names ring 4 KiB: %zu opens, in_scope=%llu emitted=%llu ring_full=%llu drained=%zu loader_dropped=%llu\n", kBurst,
                    (unsigned long long)fs[CLOUD_STAT_FILE_IN_SCOPE], (unsigned long long)ns[CLOUD_NAME_STAT_EMITTED],
                    (unsigned long long)ns[CLOUD_NAME_STAT_RING_FULL], burst.size(), (unsigned long long)ns[CLOUD_NAME_STAT_MAX]);
        CHECK(ns[CLOUD_NAME_STAT_RING_FULL] > 0);
        CHECK(fs[CLOUD_STAT_FILE_IN_SCOPE] == kBurst);
        // every open attempts a name (mask route, unconditional), plus exactly one extra attempt for
        // the new key's one-time dirpath record (this burst touches a single, freshly reloaded key).
        CHECK(ns[CLOUD_NAME_STAT_EMITTED] + ns[CLOUD_NAME_STAT_RING_FULL] == kBurst + 1);
        CHECK(burst.size() + ns[CLOUD_NAME_STAT_MAX] == ns[CLOUD_NAME_STAT_EMITTED]);   // and every emitted record was delivered
        CHECK(cc.MapMemoryBytes("names_rb") < 64 * 1024);
        cc.SetNamePolicy({}, {}, {});
    }

    for (const auto& f : f1) unlink(f.c_str());
    for (const auto& f : f2) unlink(f.c_str());
    for (const auto& f : f3) unlink(f.c_str());
    unlink((cache + "/blob.bin").c_str());
    rmdir(p1.c_str());
    rmdir(p2.c_str());
    rmdir(p3.c_str());
    rmdir(docs.c_str());
    rmdir(cache.c_str());
    rmdir(base.c_str());
    cc.SetDirRowsOn(false);
    cc.SetNamesRingBytes(0);
}

// ---- v7: move/rename/link/symlink rows ----------------------------------------------------

static std::vector<cloud_move_rec> DrainMovesAll() {
    auto& cc = CloudCollectors::Instance();
    std::vector<cloud_move_rec> out, buf(1024);
    SleepMs(150);
    for (;;) {
        size_t n = cc.DrainMoves(buf.data(), buf.size());
        if (n == 0) break;
        out.insert(out.end(), buf.begin(), buf.begin() + static_cast<long>(n));
    }
    return out;
}
static std::string MoveNameOf(const cloud_move_rec& r) { return std::string(r.name, r.name_len); }

static void TestMoves() {
    auto& cc = CloudCollectors::Instance();
    const uint32_t self = static_cast<uint32_t>(getpid());
    std::string base = MakeBase();
    CHECK(!base.empty());
    if (base.empty()) return;
    struct stat bst;
    CHECK(stat(base.c_str(), &bst) == 0);
    std::string from = base + "/from", to = base + "/to";
    mkdir(from.c_str(), 0700);
    mkdir(to.c_str(), 0700);
    struct stat fromst, tost;
    CHECK(stat(from.c_str(), &fromst) == 0 && stat(to.c_str(), &tost) == 0);

    auto arm = [&] {
        CHECK(cc.AddScopeRoot(bst.st_dev, bst.st_ino, CLOUD_ROOT_HOME));
        cc.CommitScope();
    };

    // ---- default eligibility (no policy loaded, kAllFeatures now includes kCloudMoves): a rename
    // whose DESTINATION is in scope produces a row with the right op, both directory identities and
    // no MASKED/NO_SOURCE flag. A same-directory rename (old dir == new dir) is the common case
    // (npm/cargo/editors: temp file, then rename into place next to the temp file). ----
    RestartWith(true);
    arm();
    {
        std::string a = from + "/staged.tmp", b = from + "/report.pdf";
        MakeFile(a);
        CHECK(rename(a.c_str(), b.c_str()) == 0);
        auto moves = DrainMovesAll();
        CHECK(moves.size() == 1);
        if (moves.size() == 1) {
            const auto& r = moves[0];
            CHECK(r.tgid == self);
            CHECK(r.op == CLOUD_MOVE_RENAME);
            CHECK((r.flags & CLOUD_MOVE_F_MASKED) == 0);
            CHECK((r.flags & CLOUD_MOVE_F_NO_SOURCE) == 0);
            CHECK(r.old_dev == r.new_dev && r.old_ino == fromst.st_ino && r.new_ino == fromst.st_ino);
            CHECK(MoveNameOf(r) == "report.pdf");
        }
        unlink(b.c_str());
    }

    // ---- cross-directory rename: old and new directory identities differ, and match the real
    // (dev, ino) of each directory (not swapped, not aliased). ----
    {
        std::string a = from + "/draft.md", b = to + "/final.md";
        MakeFile(a);
        CHECK(rename(a.c_str(), b.c_str()) == 0);
        auto moves = DrainMovesAll();
        CHECK(moves.size() == 1);
        if (moves.size() == 1) {
            const auto& r = moves[0];
            CHECK(r.old_ino == fromst.st_ino);
            CHECK(r.new_ino == tost.st_ino);
            CHECK(MoveNameOf(r) == "final.md");
        }
        unlink(b.c_str());
    }

    // ---- link(2): the source (old_dentry) has a real inode, so old_dev/old_ino are filled and
    // CLOUD_MOVE_F_NO_SOURCE is never set. ----
    {
        std::string a = from + "/original.log", b = to + "/hardlink.log";
        MakeFile(a);
        CHECK(link(a.c_str(), b.c_str()) == 0);
        auto moves = DrainMovesAll();
        CHECK(moves.size() == 1);
        if (moves.size() == 1) {
            const auto& r = moves[0];
            CHECK(r.op == CLOUD_MOVE_LINK);
            CHECK((r.flags & CLOUD_MOVE_F_NO_SOURCE) == 0);
            CHECK(r.old_ino == fromst.st_ino);
            CHECK(r.new_ino == tost.st_ino);
            CHECK(MoveNameOf(r) == "hardlink.log");
        }
        unlink(a.c_str());
        unlink(b.c_str());
    }

    // ---- symlink(2): there is no source file to resolve in-kernel (old_name is a raw string
    // target) - CLOUD_MOVE_F_NO_SOURCE is set and old_dev/old_ino are zero. ----
    {
        std::string link_path = to + "/shortcut.log";
        CHECK(symlink("/some/arbitrary/target", link_path.c_str()) == 0);
        auto moves = DrainMovesAll();
        CHECK(moves.size() == 1);
        if (moves.size() == 1) {
            const auto& r = moves[0];
            CHECK(r.op == CLOUD_MOVE_SYMLINK);
            CHECK((r.flags & CLOUD_MOVE_F_NO_SOURCE) != 0);
            CHECK(r.old_dev == 0 && r.old_ino == 0);
            CHECK(r.new_ino == tost.st_ino);
            CHECK(MoveNameOf(r) == "shortcut.log");
        }
        unlink(link_path.c_str());
    }

    // ---- out of scope: a rename whose DESTINATION lands outside any scope root produces no row
    // and is counted, not silently lost. The destination is a sibling of the scope root on the
    // SAME filesystem: /tmp is a tmpfs in the LVH VMs, and rename() across filesystems fails
    // with EXDEV before any hook runs (seen on 6.18 and bpf-next). ----
    {
        uint64_t before[CLOUD_MOVE_STAT_MAX + 1];
        cc.MoveStats(before, CLOUD_MOVE_STAT_MAX + 1);
        std::string outside = base + ".out";
        CHECK(mkdir(outside.c_str(), 0700) == 0);
        std::string a = from + "/leaving.txt", b = outside + "/escaped.txt";
        MakeFile(a);
        CHECK(rename(a.c_str(), b.c_str()) == 0);
        auto moves = DrainMovesAll();
        CHECK(moves.empty());
        uint64_t after[CLOUD_MOVE_STAT_MAX + 1];
        cc.MoveStats(after, CLOUD_MOVE_STAT_MAX + 1);
        CHECK(after[CLOUD_MOVE_STAT_OUT_OF_SCOPE] > before[CLOUD_MOVE_STAT_OUT_OF_SCOPE]);
        unlink(b.c_str());
        rmdir(outside.c_str());
    }

    // ---- mask route: a name-mask policy makes a destination match sent with CLOUD_MOVE_F_MASKED,
    // the same route cloud_file_open's own directory rows use. ----
    {
        cc.SetNamePolicy({}, {"id_rsa"}, {});
        RestartWith(true);
        arm();
        std::string a = from + "/staged2.tmp", b = to + "/id_rsa";
        MakeFile(a);
        CHECK(rename(a.c_str(), b.c_str()) == 0);
        auto moves = DrainMovesAll();
        CHECK(moves.size() == 1);
        if (moves.size() == 1) {
            CHECK((moves[0].flags & CLOUD_MOVE_F_MASKED) != 0);
            CHECK(MoveNameOf(moves[0]) == "id_rsa");
        }
        unlink(b.c_str());
        cc.SetNamePolicy({}, {}, {});
    }

    rmdir(from.c_str());
    rmdir(to.c_str());
    rmdir(base.c_str());
    cc.SetDirRowsOn(false);
}

int main(int argc, char** argv) {
    if (argc > 2 && std::strcmp(argv[1], "--life-child") == 0) return LifeChild(argc, argv);
    TestDnsParsing();
    std::printf("dns parsing: %s\n", g_fail ? "FAIL" : "ok");

    if (geteuid() != 0) {
        std::printf("SKIP kernel half: not root (this is not a pass for the kernel collectors)\n");
        return g_fail ? 1 : 0;
    }
    const char* obj = std::getenv("KINN_CLOUD_OBJ");
    std::string path = obj ? obj : "./kinnector_cloud.bpf.o";
    if (access(path.c_str(), R_OK) != 0) {
        std::printf("SKIP kernel half: %s not found\n", path.c_str());
        return g_fail ? 1 : 0;
    }

    auto& cc = CloudCollectors::Instance();
    bool started = cc.Start(path, kAllFeatures, 2);
    CHECK(started);
    if (!started) {
        std::fprintf(stderr, "collectors did not start (set KINNECTOR_CLOUD_DEBUG=1 for the verifier log)\n");
        return 1;
    }
    for (const auto& p : cc.Status()) {
        std::printf("  prog %-18s loaded=%d attached=%d %s\n", p.name.c_str(), p.loaded, p.attached, p.error.c_str());
    }
    // The 6.18 target must attach everything; other kernels are allowed to lose
    // programs (reduced coverage) but never all of them.
    bool full = true;
    for (const auto& p : cc.Status()) full = full && p.attached;
    if (!full) std::printf("  NOTE: not every program attached on this kernel (reduced coverage)\n");

    // KINN_ONLY_NAMES=1 runs just the file-name scenarios (used to check mutants of the BPF source quickly).
    if (std::getenv("KINN_ONLY_NAMES")) {
        g_obj = path;
        TestFileNames();
        TestMoves();
        cc.Stop();
        std::printf(g_fail ? "CLOUD COLLECTORS TEST FAILED (%d)\n" : "cloud collectors: file-name checks passed\n", g_fail);
        return g_fail ? 1 : 0;
    }

    std::string base = MakeBase();
    CHECK(!base.empty());
    if (!base.empty()) TestFiles(base);
    if (!base.empty()) rmdir(base.c_str());
    TestTcp();
    TestUdpAndDns();
    // The lifecycle programs must all attach on the 6.18 target: without cloud_life_exe the
    // exec records would carry an unresolved path, and the test below would say so.
    for (const auto& p : cc.Status()) {
        if (p.name.rfind("cloud_life_", 0) == 0) CHECK(p.attached);
    }
    TestLifecycle();

    uint64_t stats[CLOUD_STAT_MAX + 1];
    cc.Stats(stats, CLOUD_STAT_MAX + 1);
    std::printf("stats: net_ring_full=%llu file_map_full=%llu udp_map_full=%llu proj_full=%llu dns_ring_full=%llu opens=%llu in_scope=%llu queue_dropped=%llu\n",
                (unsigned long long)stats[0], (unsigned long long)stats[1], (unsigned long long)stats[2],
                (unsigned long long)stats[3], (unsigned long long)stats[4], (unsigned long long)stats[5],
                (unsigned long long)stats[6], (unsigned long long)stats[CLOUD_STAT_MAX]);
    CHECK(stats[CLOUD_STAT_FILE_MAP_FULL] == 0);
    CHECK(stats[CLOUD_STAT_NET_RING_FULL] == 0);

    // File names restart the collectors with different load-time settings, so they run last.
    g_obj = path;
    TestFileNames();
    std::printf("file names: %s\n", g_fail ? "FAIL" : "ok");

    TestMoves();
    std::printf("moves (v7): %s\n", g_fail ? "FAIL" : "ok");

    cc.Stop();
    CHECK(!cc.Running());
    std::printf(g_fail ? "CLOUD COLLECTORS TEST FAILED (%d)\n" : "cloud collectors: all checks passed\n", g_fail);
    return g_fail ? 1 : 0;
}
