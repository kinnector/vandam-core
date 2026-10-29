// The one thing every
// existing ctest target in this suite does NOT do is issue a real syscall
// from a distinct unprivileged process against a protected resource and
// check the kernel actually returned -EACCES. This target does that. It is
// the regression base Phase 2 (PID-reuse), Phase 3 (owner-allowlist), and
// Phase 4 (config-driven install-binary detection) each extend with new
// cases below; Phase 5 (ptrace/kill) still needs one, once
// protected_owner_pids exists -- see the plan doc.
//
// Deliberately NOT graceful about missing BPF LSM support (unlike
// test_ebpf_loader.cpp's TestRealKernelMode, which skips quietly when
// IsMockMode()/!IsLsmActive()): this is the only target asserting actual
// kernel-level deny behavior, so silently no-op'ing here would defeat the
// point exactly the way the "Testing strategy" section calls out. Run as
// root on a kernel with "bpf" in /sys/kernel/security/lsm.
//
// Base scope: file_open's sensitive-inode read deny and file_permission's
// protected-static-inode write deny -- the two mechanisms Phase 1 activates
// telemetry/propagation around and the ones the plan's "bottom line" calls
// the core gap. ptrace_access_check/task_kill owner-process protection is
// left for Phase 5, once protected_owner_pids exists -- see the plan doc.
#include "ebpf_loader.h"
#include "test_helpers/bpf_object_path.h"
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <cstdio>
#include <sys/stat.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <fstream>
#include <sstream>
#include <climits>
#include <thread>
#include <mutex>
#include <pthread.h>
#include <functional>
#include <sys/uio.h>

using namespace kinnector::lnx;

namespace {

constexpr uint32_t kConfigBlockingEnabled = 0; // kinnector.bpf.c: CONFIG_BLOCKING_ENABLED
constexpr uint32_t kConfigDeploymentMode = 5;  // kinnector.bpf.c: CONFIG_DEPLOYMENT_MODE
constexpr uint32_t kConfigSelfInjectionProtection = 9; // kinnector_maps.h: CONFIG_SELF_INJECTION_PROTECTION
constexpr uint32_t kConfigOwnPid = 7;          // kinnector.bpf.c: CONFIG_OWN_PID
constexpr uint32_t kModeWarden = 1;            // kinnector.bpf.c: MODE_WARDEN
constexpr uint32_t kModeAntitheft = 2;         // kinnector.bpf.c: MODE_ANTITHEFT

// Must match kinnector.bpf.c's resource_owner_hash() / ebpf_loader.cpp's
// ResourceOwnerHash() exactly -- used here only to pick a "definitely not the
// probe" fake owner inode that provably hashes to a different 64-slot bucket,
// so the deny tests below can't flake on an accidental hash collision.
uint32_t ResourceOwnerHash(uint64_t exec_ino) {
    return static_cast<uint32_t>((exec_ino * 2654435761ULL) & 0x3FULL);
}

// Safety net for the sudo/su/pkexec lockout in linux_coverage_plan_phasing
// memory: this test runs as root with blocking_enabled=1 against real system
// paths (kWardenPinnedLinkPaths), and EbpfLoader::Stop() deliberately leaves
// those pins alive (correct for production, catastrophic for a test that
// crashes mid-run without reaching its own cleanup). unlink() is
// async-signal-safe, so a crash still drops every pin's last reference before
// the process dies -- do NOT call bpf_link__destroy()/anything from libbpf
// here, it is not guaranteed signal-safe.
extern "C" void ForceUnpinOnCrash(int sig) {
    for (size_t i = 0; i < kinnector::lnx::kWardenPinnedLinkPathsCount; ++i) {
        unlink(kinnector::lnx::kWardenPinnedLinkPaths[i]);
    }
    _exit(128 + sig);
}

void InstallCrashUnpinHandler() {
    struct sigaction sa{};
    sa.sa_handler = ForceUnpinOnCrash;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    for (int sig : {SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE, SIGTERM, SIGINT}) {
        sigaction(sig, &sa, nullptr);
    }
}

const char* ProbePath() {
    // Built alongside this test into build/bin by CMakeLists.txt; ctest's
    // working directory for this target is build/ (verified empirically --
    // add_test() default WORKING_DIRECTORY is the top build dir here).
    return "bin/kinnector-enforcement-probe";
}

// Runs the probe as a genuinely separate process via fork+exec (see
// enforcement_probe.cpp's header comment for why fork() alone isn't enough).
// Returns the probe's exit code: 0 on successful open(), or the errno the
// open() failed with, or -1 if the harness itself couldn't run the probe.
int RunProbe(const char* op, const std::string& path) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        execl(ProbePath(), ProbePath(), op, path.c_str(), (char*)nullptr);
        _exit(127); // exec itself failed -- distinguishable from any real errno
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return -1;
    }
    if (!WIFEXITED(status)) {
        std::cerr << "  probe did not exit normally (status=" << status << ")" << std::endl;
        return -1;
    }
    return WEXITSTATUS(status);
}

// Same as RunProbe, but for the two-path "rename" op (source, destination)
// instead of a single path.
int RunProbeRename(const std::string& source, const std::string& destination) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        execl(ProbePath(), ProbePath(), "rename", source.c_str(), destination.c_str(), (char*)nullptr);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return -1;
    }
    if (!WIFEXITED(status)) {
        std::cerr << "  probe did not exit normally (status=" << status << ")" << std::endl;
        return -1;
    }
    return WEXITSTATUS(status);
}

// Same as RunProbe, but against an arbitrary probe binary path rather than
// the fixed ProbePath() - storage-dir tests need to run the SAME op as two
// distinct identities (an "owner" copy and an "attacker" copy of the probe,
// see CopyProbeBinary below), which requires exec'ing two different files.
int RunProbeAt(const char* probe_path, const char* op, const std::string& path) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        execl(probe_path, probe_path, op, path.c_str(), (char*)nullptr);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return -1;
    }
    if (!WIFEXITED(status)) {
        std::cerr << "  probe did not exit normally (status=" << status << ")" << std::endl;
        return -1;
    }
    return WEXITSTATUS(status);
}

// UNCONFIRMED: a reader inside a bwrap sandbox
// was once observed denied a secret it legitimately owns, with package-
// manager marking off and the reader's (dev, ino) confirmed identical to a
// registered owner's by a plain userspace stat() - ruling out both the
// supply-chain rule and a stale/wrong owner registration. `unshare -m`,
// `unshare -mUr`, `chroot /`, `setuid(0)` and `setpriv --reuid 0` around the
// same reader all SUCCEEDED, so the earlier investigation deliberately did
// not chase further without "a purpose-built reproduction first, and a
// theory second" - this is that reproduction. The variable none of those
// five prior probes cover, and every real bwrap invocation (even the
// simplest) always exercises unconditionally: PR_SET_NO_NEW_PRIVS, a real
// user namespace via unshare(CLONE_NEWUSER) (bwrap is not setuid-root on
// this machine), a capability drop, and bwrap's own default seccomp-bpf
// filter. Isolating that one variable deliberately: same absolute path
// (`--ro-bind / /`, so the *view* of the filesystem is identical to the
// already-ruled-out `chroot /` case) plus the same namespace set the earlier
// probes already covered individually, but run through actual bwrap rather
// than raw unshare/setpriv - the one combination not yet tried.
bool BwrapAvailable() {
    return access("/usr/bin/bwrap", X_OK) == 0;
}

int RunProbeUnderBwrap(const char* probe_abs_path, const char* op, const std::string& path) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        execl("/usr/bin/bwrap", "bwrap",
              "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
              "--die-with-parent",
              "--ro-bind", "/", "/",
              "--",
              probe_abs_path, op, path.c_str(),
              (char*)nullptr);
        _exit(127); // exec itself failed (e.g. bwrap missing) -- distinguishable from any real errno
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return -1;
    }
    if (!WIFEXITED(status)) {
        std::cerr << "  bwrap-wrapped probe did not exit normally (status=" << status << ")" << std::endl;
        return -1;
    }
    return WEXITSTATUS(status);
}

// forks+execs the probe in "sleep <seconds>"
// mode and returns immediately without waiting, so the caller can attempt
// ptrace/kill against it from a third, unrelated process while it's still
// alive. Caller is responsible for eventually reaping it (it exits on its own
// once the sleep elapses, or immediately if a kill attempt against it succeeds).
// Starts the probe as a process kinnector.bpf.c will stamp
// TREE_ADMIN_SESSION, so the Warden admin-session rules in
// ptrace_access_check and task_kill can be exercised at all. That stamp has
// three preconditions (see the block above its bpf_map_update_elem):
//
//   1. a valid loginuid   - inherited across fork/exec from this test. If
//      this whole test binary was itself launched over SSH, this needs
//      sshd to have actually run PAM's session stack - `UsePAM yes` in
//      sshd_config AND `session required pam_loginuid.so` in
//      /etc/pam.d/sshd. A minimal/hardened image with `UsePAM no` (common
//      on container-oriented test images) skips PAM entirely regardless of
//      what /etc/pam.d/sshd says, so /proc/self/loginuid stays at the unset
//      sentinel (4294967295) for the whole SSH session and this fixture can
//      never stamp - TestWardenAdminSessionRulesAreWardenOnly's two
//      MODE_WARDEN control assertions then read "not denied" regardless of
//      whether the kernel logic is correct. Confirmed via `sshd -T | grep
//      -i usepam` before assuming a real regression; check `UsePAM` before
//      distrusting this test's result in any SSH-reached environment.
//   2. an UNTRACKED real_parent - hence the double fork: the intermediate is
//      reaped before the grandchild execs, so its real_parent is the init/
//      subreaper process, which is never in pid_tree_type_map,
//   3. a controlling TTY  - hence the pty; the grandchild opens the slave
//      after setsid(), which makes it the controlling terminal.
//
// The exec is held on a sync pipe until the intermediate has actually been
// reaped, because the stamp reads real_parent AT EXEC TIME - without the
// barrier this races and the fixture silently produces an unstamped process.
//
// `master_out` must stay open for the target's lifetime: closing the last
// master fd hangs up the pty and kills the session. The target is orphaned,
// so the caller cannot waitpid() it - kill it and let init reap.
pid_t StartProbeInAdminSession(const char* probe_path, int seconds, int& master_out) {
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0) {
        perror("posix_openpt/grantpt/unlockpt");
        if (master >= 0) close(master);
        return -1;
    }
    const char* sname = ptsname(master);
    if (!sname) { perror("ptsname"); close(master); return -1; }
    char slave_name[128];
    snprintf(slave_name, sizeof(slave_name), "%s", sname);

    int pidfd[2], syncfd[2];
    if (pipe(pidfd) != 0) { close(master); return -1; }
    if (pipe(syncfd) != 0) { close(master); close(pidfd[0]); close(pidfd[1]); return -1; }

    pid_t mid = fork();
    if (mid < 0) { perror("fork (admin-session fixture)"); close(master); return -1; }
    if (mid == 0) {
        close(pidfd[0]);
        close(syncfd[1]);
        pid_t inner = fork();
        if (inner == 0) {
            close(pidfd[1]);
            close(master);
            setsid(); // new session, no controlling terminal yet
            int slave = open(slave_name, O_RDWR); // as session leader: becomes the ctty
            if (slave < 0) _exit(126);
            dup2(slave, 0); dup2(slave, 1); dup2(slave, 2);
            if (slave > 2) close(slave);
            char go = 0;
            if (read(syncfd[0], &go, 1) != 1) _exit(125); // wait until orphaned
            close(syncfd[0]);
            char secs[16];
            snprintf(secs, sizeof(secs), "%d", seconds);
            execl(probe_path, probe_path, "sleep", secs, (char*)nullptr);
            _exit(127);
        }
        ssize_t w = write(pidfd[1], &inner, sizeof(inner));
        (void)w;
        _exit(0); // exit at once so `inner` re-parents to init
    }

    close(pidfd[1]);
    close(syncfd[0]);
    pid_t target = -1;
    if (read(pidfd[0], &target, sizeof(target)) != static_cast<ssize_t>(sizeof(target))) target = -1;
    close(pidfd[0]);
    waitpid(mid, nullptr, 0);   // reap the intermediate FIRST
    char go = 1;
    ssize_t w = write(syncfd[1], &go, 1); // only now may the grandchild exec
    (void)w;
    close(syncfd[1]);

    master_out = master;
    return target;
}

pid_t StartProbeSleeping(const char* probe_path, int seconds) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork (sleeper)");
        return -1;
    }
    if (pid == 0) {
        execl(probe_path, probe_path, "sleep", std::to_string(seconds).c_str(), (char*)nullptr);
        _exit(127);
    }
    return pid;
}

// Attempts ptrace(PTRACE_ATTACH) against `target` from a genuinely separate,
// unrelated process (never itself exec'd a protected_owner_binaries entry).
// Returns 0 on success (in which case it also detaches before exiting, so the
// target keeps running regardless of whether the LSM should have denied this),
// or the errno ptrace() failed with.
int AttackerPtraceAttach(pid_t target) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork (ptrace attacker)");
        return -1;
    }
    if (pid == 0) {
        if (ptrace(PTRACE_ATTACH, target, nullptr, nullptr) != 0) {
            _exit(errno);
        }
        // Attach unexpectedly succeeded -- release the target immediately so
        // it isn't left stopped regardless of what this test asserts.
        waitpid(target, nullptr, 0); // reap the SIGSTOP PTRACE_ATTACH generates
        ptrace(PTRACE_DETACH, target, nullptr, nullptr);
        _exit(0);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid (ptrace attacker)");
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// Attempts kill(target, sig) from a genuinely separate, unrelated process.
// Returns 0 on success or the errno kill() failed with.
int AttackerKill(pid_t target, int sig) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork (kill attacker)");
        return -1;
    }
    if (pid == 0) {
        _exit(kill(target, sig) == 0 ? 0 : errno);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid (kill attacker)");
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// Runs the probe as PID 1 of a brand-new, throwaway PID namespace: forks an
// intermediate process that calls unshare(CLONE_NEWPID) (which only affects
// that process's *future* children, not itself) and then forks again --
// the grandchild is born as PID 1 of the fresh namespace and exec's the
// probe there. bpf_get_current_pid_tgid() resolves relative to the calling
// task's own active PID namespace, so the grandchild is observed by the LSM
// hooks as pid=1 regardless of its real (outer-namespace) PID -- this is
// what makes pid_tree_type_map's PID-reuse bug (Phase 2) deterministically
// reproducible without waiting on real host-wide PID wraparound. Requires
// CAP_SYS_ADMIN (already guaranteed: the whole binary requires root).
int RunProbeInFreshPidNs(const char* probe_path, const char* op, const std::string& path) {
    pid_t mid = fork();
    if (mid < 0) {
        perror("fork (intermediate)");
        return -1;
    }
    if (mid == 0) {
        if (unshare(CLONE_NEWPID) != 0) {
            perror("unshare(CLONE_NEWPID)");
            _exit(126);
        }
        pid_t inner = fork();
        if (inner < 0) {
            perror("fork (inner, pid 1 of new ns)");
            _exit(126);
        }
        if (inner == 0) {
            execl(probe_path, probe_path, op, path.c_str(), (char*)nullptr);
            _exit(127);
        }
        int inner_status = 0;
        if (waitpid(inner, &inner_status, 0) < 0) {
            perror("waitpid (inner)");
            _exit(126);
        }
        _exit(WIFEXITED(inner_status) ? WEXITSTATUS(inner_status) : 125);
    }
    int status = 0;
    if (waitpid(mid, &status, 0) < 0) {
        perror("waitpid (intermediate)");
        return -1;
    }
    if (!WIFEXITED(status)) {
        std::cerr << "  intermediate process did not exit normally (status=" << status << ")" << std::endl;
        return -1;
    }
    return WEXITSTATUS(status);
}

// Byte-for-byte copy of the probe binary at a fresh path, so it gets a
// distinct inode from ProbePath()'s -- used only by the Phase 2 PID-reuse
// regression test, which needs a second "generically verified, but never
// itself an install binary" exec target that isn't the same inode as the one
// TestInstallBinaryMapConfigDrivenDetection registers in install_binary_map.
bool CopyProbeBinary(std::string& path_out, uint64_t& inode_out) {
    char tmpl[] = "/tmp/kinnector_e2e_probe_copy_XXXXXX";
    int out_fd = mkstemp(tmpl);
    if (out_fd < 0) {
        perror("mkstemp (probe copy)");
        return false;
    }
    int in_fd = open(ProbePath(), O_RDONLY);
    if (in_fd < 0) {
        perror("open (probe source)");
        close(out_fd);
        unlink(tmpl);
        return false;
    }
    char buf[65536];
    ssize_t n;
    bool ok = true;
    while ((n = read(in_fd, buf, sizeof(buf))) > 0) {
        if (write(out_fd, buf, static_cast<size_t>(n)) != n) {
            ok = false;
            break;
        }
    }
    if (n < 0) ok = false;
    close(in_fd);
    close(out_fd);
    if (!ok || chmod(tmpl, 0755) != 0) {
        unlink(tmpl);
        return false;
    }
    struct stat st{};
    if (stat(tmpl, &st) != 0) {
        unlink(tmpl);
        return false;
    }
    path_out = tmpl;
    inode_out = st.st_ino;
    return true;
}

// also returns st_dev, since every map this
// harness registers resources in now takes the canonical (dev, ino) identity.
bool MakeTempFile(std::string& path_out, uint64_t& inode_out, uint64_t& dev_out) {
    char tmpl[] = "/tmp/kinnector_e2e_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        perror("mkstemp");
        return false;
    }
    if (write(fd, "protected", 9) != 9) {
        close(fd);
        unlink(tmpl);
        return false;
    }
    close(fd);
    struct stat st{};
    if (stat(tmpl, &st) != 0) {
        unlink(tmpl);
        return false;
    }
    path_out = tmpl;
    inode_out = st.st_ino;
    dev_out = st.st_dev;
    return true;
}

int g_failures = 0;

// EbpfLoader has no removal API for sensitive_inodes_map/resource_owner_map
// (Add-only -- see AddSensitiveInode/AddResourceOwner), and every test below
// registers its temp file's (dev, ino) into one of those maps before
// unlink()ing it. Freeing the inode immediately let the filesystem recycle
// that exact inode number for a LATER test's fresh MakeTempFile() call within
// the same run, which then collided with the earlier, still-live-in-the-map
// registration -- causing spurious EACCES on completely unrelated files
// (including this harness's own mkstemp() calls). Deferring every cleanup to
// process exit keeps every inode this run has ever used alive (never freed,
// never recyclable) for the run's whole lifetime, eliminating the collision
// outright rather than just making it less likely.
std::vector<std::string> g_deferred_unlinks;
void DeferUnlink(const std::string& path) { g_deferred_unlinks.push_back(path); }
void RunDeferredUnlinks() {
    for (const auto& p : g_deferred_unlinks) unlink(p.c_str());
    g_deferred_unlinks.clear();
}

void Check(bool cond, const std::string& msg) {
    if (cond) {
        std::cout << "  - PASS: " << msg << std::endl;
    } else {
        std::cerr << "  - FAIL: " << msg << std::endl;
        g_failures++;
    }
}

// file_open's sensitive-inode deny (kinnector.bpf.c ~:1032-1056) only fires
// when the accessing process's process_threshold_map entry is exactly 1
// (freshly-exec'd, unclassified -- the default any untrusted binary gets
// once blocking_enabled=1, per bprm_creds_for_exec's `else if
// (blocking_enabled) { threshold = 1; }` branch). The probe binary is never
// added to trusted_exec_inodes ahead of this test, so it gets that default.
void TestSensitiveInodeReadDeny(EbpfLoader& loader) {
    std::cout << "[e2e] sensitive-inode read: unclassified process denied at open()..." << std::endl;
    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); unlink(path.c_str()); return; }

    int rc = RunProbe("open_read", path);
    DeferUnlink(path);
    Check(rc == EACCES, "open() denied with EACCES (got " + std::to_string(rc) + ")");
}

// file_permission's protected-static-inode deny (kinnector.bpf.c
// ~:1114-1124) fires for ANY nonzero threshold, not just ==1 -- run this
// before TestSensitiveInodeReadAllow below, which permanently registers the
// probe binary's exec inode with a nonzero (but non-1) trust level for the
// remainder of this process's lifetime and would otherwise make this test's
// "denied" assertion depend on run order instead of standing on its own.
void TestProtectedStaticInodeWriteDeny(EbpfLoader& loader) {
    std::cout << "[e2e] protected-static-inode write: unclassified process denied at open() for write..." << std::endl;
    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    if (!loader.AddProtectedStaticInode(dev, ino)) { Check(false, "AddProtectedStaticInode failed"); unlink(path.c_str()); return; }

    int rc = RunProbe("open_write", path);
    DeferUnlink(path);
    Check(rc == EACCES, "write-open denied with EACCES (got " + std::to_string(rc) + ")");
}

// Control case: proves the deny above isn't unconditional / a
// misconfigured always-block. bprm_creds_for_exec stores whatever nonzero
// value trusted_exec_inodes has for the exec'd binary as that process's
// threshold (kinnector.bpf.c ~:1663-1669); file_open's sensitive-inode
// check specifically tests `threshold == 1`, so a role-classified process
// (threshold=2, standing in for e.g. ROLE_DATABASE) takes the allow path
// even though it's still "nonzero". Run this last -- see the comment on
// TestProtectedStaticInodeWriteDeny above for why.
void TestSensitiveInodeReadAllowForClassifiedProcess(EbpfLoader& loader) {
    std::cout << "[e2e] sensitive-inode read: role-classified (threshold=2) process allowed at open() (control case)..." << std::endl;
    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); unlink(path.c_str()); return; }

    struct stat probe_st{};
    if (stat(ProbePath(), &probe_st) != 0) { Check(false, "could not stat probe binary"); unlink(path.c_str()); return; }
    if (!loader.AddTrustedExecInode(probe_st.st_ino, /*trust_level=*/2)) {
        Check(false, "AddTrustedExecInode failed");
        unlink(path.c_str());
        return;
    }

    int rc = RunProbe("open_read", path);
    DeferUnlink(path);
    Check(rc == 0, "open() succeeded (got " + std::to_string(rc) + ")");
}

// resource_owner_map must be entirely inert
// for a MODE_WARDEN (or unset-mode) deployment -- this is the regression test
// for the "Critical constraint" gating requirement, not just Phase 3's own
// mechanism. The resource here has an owner list that would deny the probe if
// consulted; if this test passes it proves resource_owner_map genuinely isn't
// being read outside MODE_ANTITHEFT, not just that it happens to allow this case.
void TestResourceOwnerMapIgnoredInWardenMode(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] resource_owner_map ignored under MODE_WARDEN (regression for the mode gate)..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeWarden)) {
        Check(false, "SetConfigValue(MODE_WARDEN) failed");
        return;
    }

    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); unlink(path.c_str()); return; }
    uint64_t fake_owner = probe_ino + 1;
    while (ResourceOwnerHash(fake_owner) == ResourceOwnerHash(probe_ino)) fake_owner++;
    if (!loader.AddResourceOwner(dev, ino, fake_owner)) { Check(false, "AddResourceOwner failed"); unlink(path.c_str()); return; }

    // Probe is not in the owner list -- if resource_owner_map were consulted,
    // this would be denied. It must succeed under MODE_WARDEN regardless.
    int rc = RunProbe("open_read", path);
    DeferUnlink(path);
    Check(rc == 0, "open() succeeded under MODE_WARDEN despite a denying owner list (got " + std::to_string(rc) + ")");
}

// Phase 3's load-bearing case: a third, unrelated (but otherwise generically
// trusted -- threshold=2, set by TestSensitiveInodeReadAllowForClassifiedProcess
// above) process is refused before the read completes because it isn't a
// configured owner of this specific resource, even though generic trust alone
// would have let it through the pre-existing threshold check.
void TestResourceOwnerAllowlistDenyUnrelatedProcess(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] resource owner-allowlist: unrelated process denied at open() under MODE_ANTITHEFT..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }

    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); unlink(path.c_str()); return; }
    uint64_t fake_owner = probe_ino + 1;
    while (ResourceOwnerHash(fake_owner) == ResourceOwnerHash(probe_ino)) fake_owner++;
    if (!loader.AddResourceOwner(dev, ino, fake_owner)) { Check(false, "AddResourceOwner failed"); unlink(path.c_str()); return; }

    int rc = RunProbe("open_read", path);
    DeferUnlink(path);
    Check(rc == EACCES, "open() denied with EACCES for a non-owner (got " + std::to_string(rc) + ")");
}

// Control case: the same resource, but with the probe's own exec inode added
// as one of (multiple) configured owners -- proves the deny above isn't
// unconditional and that resource_owner_map's bitmask correctly ORs more than
// one owner in without losing either.
void TestResourceOwnerAllowlistAllowConfiguredOwner(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] resource owner-allowlist: configured owner allowed at open() (control case)..." << std::endl;
    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); unlink(path.c_str()); return; }
    uint64_t other_owner = probe_ino + 1;
    while (ResourceOwnerHash(other_owner) == ResourceOwnerHash(probe_ino)) other_owner++;
    if (!loader.AddResourceOwner(dev, ino, other_owner)) { Check(false, "AddResourceOwner(other_owner) failed"); unlink(path.c_str()); return; }
    if (!loader.AddResourceOwner(dev, ino, probe_ino)) { Check(false, "AddResourceOwner(probe_ino) failed"); unlink(path.c_str()); return; }

    int rc = RunProbe("open_read", path);
    DeferUnlink(path);
    Check(rc == 0, "open() succeeded for a configured owner (got " + std::to_string(rc) + ")");
}

// A first version of this test execed ProbePath() directly
// (build/bin/kinnector-enforcement-probe, under this repo's checkout in
// /home/user/...) and got EACCES at execve() itself under bwrap, every time
// - which looked exactly like the UNCONFIRMED bwrap finding at first.
// Root-caused with strace (progload's rule: check what the kernel actually
// says before theorizing) rather than assumed: it reproduced with plain
// `ls`/`stat` too, on ANY path under /home/user, entirely without bwrap's
// probe op or our BPF LSM in the picture - `/home/user` is mode 750
// (owner-only traversal), and bwrap's `--unshare-user` maps only uid 0 into
// the sandbox's fresh user namespace by default, so root inside it has no
// CAP_DAC_OVERRIDE over an inode owned by an UNMAPPED uid (1000, "user") and
// is judged by the raw permission bits like any other uid - which deny
// "other" outright. A copy under /tmp (mode 1777, world-traversable) execs
// fine through the identical sandbox. This is ordinary Linux user-namespace
// UID-mapping behavior, unrelated to bwrap's sandboxing model, AppArmor, or
// antitheft's own owner check - confirmed by finding zero AppArmor/audit
// denials logged for either case. Using a CopyProbeBinary() copy (already
// under /tmp for exactly this reason - see its own doc comment) below
// isolates the actual variable this test exists to check.
void TestBwrapSandboxedOwnerCanStillReadItsOwnResource(EbpfLoader& loader) {
    std::cout << "[e2e] resource owner-allowlist: configured owner still allowed when reading from inside a real bwrap sandbox..." << std::endl;
    if (!BwrapAvailable()) {
        std::cout << "  - SKIP: /usr/bin/bwrap not present on this machine" << std::endl;
        return;
    }

    std::string probe_copy;
    uint64_t probe_copy_ino = 0;
    if (!CopyProbeBinary(probe_copy, probe_copy_ino)) { Check(false, "could not make a probe copy for the bwrap test"); return; }
    DeferUnlink(probe_copy);
    char probe_abs[PATH_MAX];
    if (!realpath(probe_copy.c_str(), probe_abs)) {
        Check(false, "could not resolve absolute path of the probe copy for bwrap exec");
        return;
    }

    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); unlink(path.c_str()); return; }
    if (!loader.AddResourceOwner(dev, ino, probe_copy_ino)) { Check(false, "AddResourceOwner(probe_copy_ino) failed"); unlink(path.c_str()); return; }

    // Control, using the SAME probe copy and resource (not just relying on
    // TestResourceOwnerAllowlistAllowConfiguredOwner above), so a failure of
    // the bwrap case below can be read against a same-run, same-identity
    // baseline rather than a different test's state.
    int direct_rc = RunProbeAt(probe_abs, "open_read", path);
    int bwrap_rc = RunProbeUnderBwrap(probe_abs, "open_read", path);
    DeferUnlink(path);

    Check(direct_rc == 0, "control: configured owner allowed outside any sandbox (got " + std::to_string(direct_rc) + ")");
    Check(bwrap_rc == 0,
          "configured owner, SAME probe binary, SAME resource, still allowed when read from inside a real bwrap "
          "sandbox (got " + std::to_string(bwrap_rc) +
          (bwrap_rc == EACCES ? " EACCES - reproduces the UNCONFIRMED bwrap finding; "
                                 "root cause is the no_new_privs+userns+capdrop+seccomp combination bwrap "
                                 "applies unconditionally, not the mount namespace (chroot / already ruled that out)"
                               : "") +
          ")");
}

// Gap fix (new secret files unprotected for up to
// 60s): glob_owned_dirs_map + lsm_d_instantiate (was a kprobe_d_instantiate
// pair - see kinnector_container_lsm_hooks.h). Mirrors
// exactly what antitheft's ownership.rs::sync_glob_owned_dir does in
// production -- register one seed file's owner, read back its real mask via
// GetResourceOwnerMask, then register the seed's PARENT DIRECTORY in
// glob_owned_dirs_map with that same mask. A SECOND file, created afterward
// with a real open(O_CREAT) and never itself touched by AddSensitiveInode/
// AddResourceOwner, must be governed by the SAME verdict the instant it's
// created -- proving the kernel-side synchronous carry-forward, not
// userspace polling (there is no polling loop in this test at all).
void TestGlobOwnedDirSyncProtection(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] glob_owned_dirs_map: brand-new file in a glob-root dir inherits protection synchronously..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }

    char dir_tmpl[] = "/tmp/kinnector_e2e_globdir_XXXXXX";
    if (!mkdtemp(dir_tmpl)) { Check(false, "mkdtemp failed"); return; }
    std::string dir_path = dir_tmpl;
    std::string seed_path = dir_path + "/seed";
    int fd = open(seed_path.c_str(), O_CREAT | O_WRONLY, 0644);
    if (fd < 0) { Check(false, "could not create seed file"); return; }
    if (write(fd, "seed", 4) < 0) { Check(false, "could not write seed file"); close(fd); return; }
    close(fd);

    struct stat seed_st{}, dir_st{};
    if (stat(seed_path.c_str(), &seed_st) != 0 || stat(dir_path.c_str(), &dir_st) != 0) {
        Check(false, "could not stat seed file/dir");
        return;
    }
    // The directory's registered owner is the PROBE (probe_ino) - matching
    // production, where the owner app itself is the one that later creates
    // its own second wallet/vault file. See this test's own module doc for
    // why a version of this that had the TEST HARNESS create the new file
    // directly was wrong: the harness process is registered nowhere, so the
    // instant the directory was armed, the harness's OWN open(O_CREAT) of
    // the new file was correctly denied by this very mechanism - proving it
    // works, but not the shape this test meant to exercise (owner creates,
    // a DIFFERENT non-owner later reads).
    if (!loader.AddSensitiveInode(seed_st.st_dev, seed_st.st_ino, /*category=*/1)) { Check(false, "AddSensitiveInode(seed) failed"); return; }
    if (!loader.AddResourceOwner(seed_st.st_dev, seed_st.st_ino, probe_ino)) { Check(false, "AddResourceOwner(seed, probe_ino) failed"); return; }
    uint64_t mask = loader.GetResourceOwnerMask(seed_st.st_dev, seed_st.st_ino);
    if (!loader.AddGlobOwnedDir(dir_st.st_dev, dir_st.st_ino, /*category=*/1, mask, seed_st.st_dev, seed_st.st_ino)) {
        Check(false, "AddGlobOwnedDir failed");
        return;
    }

    // The gap under test: a name never globbed, resolved, or registered by
    // anything - created by the OWNER (probe) after glob_owned_dirs_map was
    // armed, with no reconcile/discovery step in between.
    std::string brand_new_path = dir_path + "/brand_new_never_registered";
    int create_rc = RunProbe("open_write_create", brand_new_path);
    Check(create_rc == 0, "the directory's registered owner can create a brand-new file in it (got " + std::to_string(create_rc) + ")");

    int owner_read_rc = RunProbe("open_read", brand_new_path);
    Check(owner_read_rc == 0, "the owner can read the brand-new file it just created (got " + std::to_string(owner_read_rc) + ")");

    // This test process itself is registered as owner of nothing - reading
    // the brand-new file directly, in-process, with no fork/RunProbe
    // indirection, proves the deny is immediate: no reconcile, no polling,
    // no event loop runs between the create above and this read.
    int harness_fd = open(brand_new_path.c_str(), O_RDONLY);
    int harness_errno = harness_fd >= 0 ? 0 : errno;
    if (harness_fd >= 0) close(harness_fd);
    Check(harness_fd < 0 && harness_errno == EACCES,
          "a non-owner (this test process itself) is denied EACCES reading the brand-new file immediately (fd=" +
              std::to_string(harness_fd) + " errno=" + std::to_string(harness_errno) + ")");

    // A file OUTSIDE the glob-root directory must be completely unaffected.
    std::string unrelated_dir = dir_path + "_unrelated";
    mkdir(unrelated_dir.c_str(), 0755);
    std::string unrelated_path = unrelated_dir + "/not_a_wallet.txt";
    int fd3 = open(unrelated_path.c_str(), O_CREAT | O_WRONLY, 0644);
    if (fd3 >= 0) { if (write(fd3, "x", 1) < 0) { /* best-effort */ } close(fd3); }
    int unrelated_fd = open(unrelated_path.c_str(), O_RDONLY);
    if (unrelated_fd >= 0) close(unrelated_fd);
    Check(unrelated_fd >= 0, "a file outside the glob-root directory is completely unaffected (fd=" + std::to_string(unrelated_fd) + ")");
}

// file_permission's owner check is independent of protected_static_inodes/
// sensitive_inodes_map -- exercise it directly on a resource that is neither.
void TestResourceOwnerAllowlistWriteDeny(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] resource owner-allowlist: unrelated process denied at open() for write..." << std::endl;
    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    uint64_t fake_owner = probe_ino + 1;
    while (ResourceOwnerHash(fake_owner) == ResourceOwnerHash(probe_ino)) fake_owner++;
    if (!loader.AddResourceOwner(dev, ino, fake_owner)) { Check(false, "AddResourceOwner failed"); unlink(path.c_str()); return; }

    int rc = RunProbe("open_write", path);
    DeferUnlink(path);
    Check(rc == EACCES, "write-open denied with EACCES for a non-owner (got " + std::to_string(rc) + ")");
}

// A file a rename just swapped in. The kernel gives it the old identity's
// protection at once (sync_carry_forward_protection) by ALIASING it to the old
// identity's exact owner set, and follows that alias until the new identity has
// an exact set of its own; userspace then registers the new identity's owners.
// Registering them one call at a time makes the set authoritative on the FIRST,
// and until the last lands the kernel checks a PARTIAL set - an owner not in it
// yet is refused its own file (Chrome's own network service, refused
// between the daemon's own link and its executable's, alerted as "Google Chrome
// tried to change its encryption key"). Made by the owner (the probe) renaming a
// fresh file over a protected name, exactly what an atomic save does.
struct SwappedIdentity {
    std::string path;
    uint64_t dev = 0;
    uint64_t ino = 0;
};

bool MakeSwappedIdentity(EbpfLoader& loader, uint64_t probe_dev, uint64_t probe_ino, uint64_t second_owner_ino, SwappedIdentity& out) {
    std::string path;
    uint64_t ino = 0, dev = 0;
    if (!MakeTempFile(path, ino, dev)) return false;
    DeferUnlink(path);
    if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) return false;
    // Two registered owners, so a set holding only one of them is a real partial set.
    if (!loader.AddResourceOwnerExact(dev, ino, probe_dev, probe_ino)) return false;
    if (!loader.AddResourceOwnerExact(dev, ino, probe_dev, second_owner_ino)) return false;
    // The old identity stays alive under another name: a freed inode number gets recycled by a later
    // MakeTempFile and collides with its (add-only) registration (see DeferUnlink).
    std::string old_name = path + ".old";
    if (link(path.c_str(), old_name.c_str()) != 0) return false;
    DeferUnlink(old_name);
    std::string fresh = path + ".fresh";
    int fd = open(fresh.c_str(), O_CREAT | O_WRONLY, 0600);
    if (fd < 0) return false;
    bool wrote = write(fd, "swapped", 7) == 7;
    close(fd);
    if (!wrote) return false;
    if (RunProbeRename(fresh, path) != 0) return false;
    struct stat st{};
    if (stat(path.c_str(), &st) != 0 || (uint64_t)st.st_ino == ino) return false;
    out.path = path;
    out.dev = st.st_dev;
    out.ino = st.st_ino;
    return true;
}

void TestSwappedInIdentityNeverHasAPartialOwnerSet(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] swapped-in identity: its owner set is never partial while it is being registered..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }
    struct stat probe_st{};
    if (stat(ProbePath(), &probe_st) != 0) { Check(false, "could not stat probe binary"); return; }
    const uint64_t probe_dev = probe_st.st_dev;
    // Stand-ins for the daemon's own link and for a second owner (a launcher script).
    const uint64_t daemon_ino = probe_ino + 1;
    const uint64_t second_owner_ino = probe_ino + 2;

    // ---- The old order: one call per owner, the daemon's own link first. ----
    SwappedIdentity one_by_one;
    if (!MakeSwappedIdentity(loader, probe_dev, probe_ino, second_owner_ino, one_by_one)) { Check(false, "could not make a swapped-in identity"); return; }
    int aliased_rc = RunProbe("open_read", one_by_one.path);
    Check(aliased_rc == 0, "before anything is registered for it, the owner is admitted through the alias (got " + std::to_string(aliased_rc) + ")");
    if (!loader.AddResourceOwnerExact(one_by_one.dev, one_by_one.ino, probe_dev, daemon_ino)) { Check(false, "AddResourceOwnerExact(daemon link) failed"); return; }
    int partial_rc = RunProbe("open_read", one_by_one.path);
    Check(partial_rc == EACCES,
          "one call per owner: with only the daemon's link registered the real owner is refused its own file - the window the batch call closes (got " +
              std::to_string(partial_rc) + ")");
    if (!loader.AddResourceOwnerExact(one_by_one.dev, one_by_one.ino, probe_dev, probe_ino)) { Check(false, "AddResourceOwnerExact(owner) failed"); return; }
    int completed_rc = RunProbe("open_read", one_by_one.path);
    Check(completed_rc == 0, "control: once the owner's own call lands it is admitted again (got " + std::to_string(completed_rc) + ")");

    // ---- The batch call: the whole set at once. ----
    SwappedIdentity batched;
    if (!MakeSwappedIdentity(loader, probe_dev, probe_ino, second_owner_ino, batched)) { Check(false, "could not make a second swapped-in identity"); return; }
    int before_rc = RunProbe("open_read", batched.path);
    Check(before_rc == 0, "batch: the owner is admitted through the alias before the set is registered (got " + std::to_string(before_rc) + ")");
    const std::vector<std::pair<uint64_t, uint64_t>> owners = {{probe_dev, daemon_ino}, {probe_dev, second_owner_ino}, {probe_dev, probe_ino}};
    Check(loader.AddResourceOwnersExactBatch(batched.dev, batched.ino, owners), "AddResourceOwnersExactBatch succeeds");
    int after_rc = RunProbe("open_read", batched.path);
    Check(after_rc == 0, "batch: the owner is admitted once the whole set is registered (got " + std::to_string(after_rc) + ")");
    // A control that the set really is authoritative and not just "open to everyone".
    int harness_fd = open(batched.path.c_str(), O_RDONLY);
    int harness_errno = harness_fd >= 0 ? 0 : errno;
    if (harness_fd >= 0) close(harness_fd);
    Check(harness_fd < 0 && harness_errno == EACCES,
          "batch: a non-owner (this test process) is still refused (fd=" + std::to_string(harness_fd) + " errno=" + std::to_string(harness_errno) + ")");
}

// A protected identity is a (dev, inode NUMBER), and a number outlives its file: ext4 hands a freed
// number to the next file created nearby, and an atomic save frees one every time. Measured on the
// owner's own desktop, `Local State` alternates between exactly two numbers: each save's temp file
// is given the number the previous save freed. Whatever protection the kernel still held for the
// freed number is then inherited by that brand-new file (Chrome refused its own new
// temp file, alerted as "Google Chrome tried to change its encryption key").
//
// Creates files in `dir` until one is given `target_ino` again and returns the create-and-write's
// result for THAT file (0, or its errno); -2 if the number never came back. `as_owner` creates them
// as the probe (a registered owner), otherwise as this test process (an owner of nothing). Every
// file is kept until the end, so a lower free number is filled rather than handed back.
int CreateUntilInodeRecurs(const std::string& dir, uint64_t target_ino, const std::string& tag, bool as_owner, std::string* found_path = nullptr) {
    for (int i = 0; i < 256; ++i) {
        std::string path = dir + "/" + tag + std::to_string(i);
        int rc = 0;
        if (as_owner) {
            rc = RunProbe("open_write_create", path);
        } else {
            int fd = open(path.c_str(), O_WRONLY | O_CREAT, 0644);
            if (fd < 0) {
                rc = errno;
            } else {
                if (write(fd, "x", 1) < 0) rc = errno;
                close(fd);
            }
        }
        DeferUnlink(path);
        struct stat st{};
        if (stat(path.c_str(), &st) == 0 && (uint64_t)st.st_ino == target_ino) {
            if (found_path) *found_path = path;
            return rc;
        }
    }
    return -2;
}

// One protected "Local State" in its own directory, registered to {daemon stand-in, probe}. Under
// /var/tmp, not /tmp: tmpfs numbers its inodes from a counter and never hands one back, so only a
// disk filesystem (ext4 here, as on the desktop) shows the reuse at all.
bool MakeProtectedFileInOwnDir(EbpfLoader& loader, uint64_t probe_dev, uint64_t probe_ino, uint64_t daemon_ino, std::string& dir_out,
                               std::string& path_out, uint64_t& ino_out) {
    char tmpl[] = "/var/tmp/kinnector_e2e_recycle_XXXXXX";
    if (!mkdtemp(tmpl)) return false;
    dir_out = tmpl;
    path_out = dir_out + "/Local State";
    int fd = open(path_out.c_str(), O_CREAT | O_WRONLY, 0600);
    if (fd < 0) return false;
    bool wrote = write(fd, "protected", 9) == 9;
    close(fd);
    DeferUnlink(path_out);
    struct stat st{};
    if (!wrote || stat(path_out.c_str(), &st) != 0) return false;
    ino_out = st.st_ino;
    if (!loader.AddSensitiveInode(st.st_dev, st.st_ino, /*category=*/1)) return false;
    return loader.AddResourceOwnersExactBatch(st.st_dev, st.st_ino, {{probe_dev, daemon_ino}, {probe_dev, probe_ino}});
}

// The owner's atomic save, all of it done by the probe as Chrome does it: a fresh temp file created
// and written, then renamed over `path`, which frees the old identity's number. Returns the new
// identity (same filesystem as the old one).
bool OwnerAtomicSave(const std::string& path, const std::string& tmp_name, uint64_t& new_dev, uint64_t& new_ino) {
    std::string fresh = path.substr(0, path.rfind('/') + 1) + tmp_name;
    if (RunProbe("open_write_create", fresh) != 0) return false;
    if (RunProbeRename(fresh, path) != 0) return false;
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) return false;
    new_dev = st.st_dev;
    new_ino = st.st_ino;
    return true;
}

void TestFreedProtectedInodeNumberIsNotInheritedByANewFile(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] freed protected inode number: a new file given it inherits nothing..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }
    struct stat probe_st{};
    if (stat(ProbePath(), &probe_st) != 0) { Check(false, "could not stat probe binary"); return; }
    const uint64_t probe_dev = probe_st.st_dev;
    const uint64_t daemon_ino = probe_ino + 1;

    // ---- 1. The daemon followed the save and retired the old identity (apply_resource_swap). ----
    {
        std::string dir, path;
        uint64_t old_ino = 0, new_dev = 0, new_ino = 0;
        if (!MakeProtectedFileInOwnDir(loader, probe_dev, probe_ino, daemon_ino, dir, path, old_ino)) { Check(false, "retired: setup failed"); return; }
        // The old file outlives the save until the daemon has retired it (in the daemon, an open
        // fanotify event fd does this), so the retirement really lands before the free.
        std::string held = dir + "/held";
        if (link(path.c_str(), held.c_str()) != 0) { Check(false, "retired: could not hold the old file"); return; }
        if (!OwnerAtomicSave(path, ".tmp-save", new_dev, new_ino)) { Check(false, "retired: the owner's atomic save failed"); return; }
        Check(loader.AddResourceOwnersExactBatch(new_dev, new_ino, {{probe_dev, probe_ino}, {probe_dev, daemon_ino}}), "retired: new identity registered");
        loader.RemoveResourceOwnerExact(new_dev, old_ino, probe_dev, probe_ino);
        unlink(held.c_str());
        std::string recycled;
        int rc = CreateUntilInodeRecurs(dir, old_ino, "owner-new-", /*as_owner=*/true, &recycled);
        Check(rc != -2, "retired: the freed number came back to a new file in the same directory (filesystem recycles numbers)");
        Check(rc == 0, "retired: the owner may create and write a NEW file that was given the retired identity's number (got " + std::to_string(rc) + ")");
        if (rc == 0) {
            // The rest of Chrome's next save: that file is renamed over the protected name, and read
            // back before the daemon has registered anything for it.
            int rename_rc = RunProbeRename(recycled, path);
            Check(rename_rc == 0, "retired: the owner renames that file over the protected name (got " + std::to_string(rename_rc) + ")");
            int read_rc = RunProbe("open_read", path);
            Check(read_rc == 0, "retired: the owner reads the protected name, now at the recycled number, before any registration (got " + std::to_string(read_rc) + ")");
            int fd = open(path.c_str(), O_RDONLY);
            int err = fd >= 0 ? 0 : errno;
            if (fd >= 0) close(fd);
            Check(fd < 0 && err == EACCES, "retired: and a non-owner is refused it (errno=" + std::to_string(err) + ")");
        }
    }

    // ---- 2. The daemon missed a save and caught up later: a dead intermediate aliases into the retired identity. ----
    {
        std::string dir, path;
        uint64_t old_ino = 0, mid_dev = 0, mid_ino = 0, new_dev = 0, new_ino = 0;
        if (!MakeProtectedFileInOwnDir(loader, probe_dev, probe_ino, daemon_ino, dir, path, old_ino)) { Check(false, "missed save: setup failed"); return; }
        if (!OwnerAtomicSave(path, ".tmp-save-1", mid_dev, mid_ino)) { Check(false, "missed save: first save failed"); return; }
        if (!OwnerAtomicSave(path, ".tmp-save-2", new_dev, new_ino)) { Check(false, "missed save: second save failed"); return; }
        Check(loader.AddResourceOwnersExactBatch(new_dev, new_ino, {{probe_dev, probe_ino}, {probe_dev, daemon_ino}}), "missed save: newest identity registered");
        loader.RemoveResourceOwnerExact(new_dev, old_ino, probe_dev, probe_ino);
        int rc = CreateUntilInodeRecurs(dir, mid_ino, "owner-new-", /*as_owner=*/true);
        Check(rc != -2, "missed save: the intermediate's freed number came back to a new file");
        Check(rc == 0, "missed save: the owner may create and write a NEW file given the dead intermediate's number (got " + std::to_string(rc) + ")");
    }

    // ---- 3. Nothing retired yet: a program that owns nothing is given the freed number. ----
    {
        std::string dir, path;
        uint64_t old_ino = 0, new_dev = 0, new_ino = 0;
        if (!MakeProtectedFileInOwnDir(loader, probe_dev, probe_ino, daemon_ino, dir, path, old_ino)) { Check(false, "non-owner: setup failed"); return; }
        if (!OwnerAtomicSave(path, ".tmp-save", new_dev, new_ino)) { Check(false, "non-owner: the owner's atomic save failed"); return; }
        int rc = CreateUntilInodeRecurs(dir, old_ino, "other-new-", /*as_owner=*/false);
        Check(rc != -2, "non-owner: the freed number came back to a new file");
        Check(rc == 0, "non-owner: an unrelated program may create and write its own NEW file given a freed protected number (got " + std::to_string(rc) + ")");
        // Control: the file really at the protected path is still protected from that program.
        int fd = open(path.c_str(), O_RDONLY);
        int err = fd >= 0 ? 0 : errno;
        if (fd >= 0) close(fd);
        Check(fd < 0 && err == EACCES, "non-owner control: the swapped-in file at the protected path is still refused (errno=" + std::to_string(err) + ")");
        int owner_rc = RunProbe("open_read", path);
        Check(owner_rc == 0, "owner control: the owner still reads the swapped-in file at the protected path (got " + std::to_string(owner_rc) + ")");
    }

    // ---- 4. A new file given the number is protected for ITS owners, not its predecessor's. ----
    {
        std::string dir, path;
        uint64_t old_ino = 0, new_dev = 0, new_ino = 0;
        if (!MakeProtectedFileInOwnDir(loader, probe_dev, probe_ino, daemon_ino, dir, path, old_ino)) { Check(false, "new life: setup failed"); return; }
        if (!OwnerAtomicSave(path, ".tmp-save", new_dev, new_ino)) { Check(false, "new life: the owner's atomic save failed"); return; }
        std::string recycled;
        int rc = CreateUntilInodeRecurs(dir, old_ino, "other-app-", /*as_owner=*/false, &recycled);
        Check(rc != -2, "new life: the freed number came back to a new file");
        // Another app's file, registered to that app alone. Its owner shares the probe's mask slot,
        // so only the exact set can tell them apart.
        uint64_t other_owner = probe_ino + 1;
        while (ResourceOwnerHash(other_owner) != ResourceOwnerHash(probe_ino)) other_owner++;
        Check(loader.AddSensitiveInode(new_dev, old_ino, /*category=*/1), "new life: AddSensitiveInode");
        Check(loader.AddResourceOwnersExactBatch(new_dev, old_ino, {{probe_dev, other_owner}}), "new life: registered to its own owner");
        int probe_rc = RunProbe("open_read", recycled);
        Check(probe_rc == EACCES, "new life: the previous file's owner is refused the new file (got " + std::to_string(probe_rc) + ")");
    }
}

// The daemon binary's number is freed when a rebuilt or updated daemon has replaced it and the old
// one exits; pins left behind keep enforcing with nobody to update core_self_integrity_map. Before
// inode_free_security cleared the slot, the next file given that number could not be opened for
// writing by anyone (EPERM)
// after the agent binary was rebuilt. A file of this test's
// own under /var/tmp (ext4 in the VMs; /tmp is tmpfs and never reuses a number) stands in for the
// binary in slot 0, and slot 0 is put back to this process's own binary afterwards.
void TestFreedDaemonBinaryNumberRefusesNoNewFile(EbpfLoader& loader) {
    std::cout << "[e2e] freed daemon binary number: a new file given it can be written..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }
    char tmpl[] = "/var/tmp/kinnector_e2e_selfint_XXXXXX";
    if (!mkdtemp(tmpl)) { Check(false, "self-integrity: mkdtemp failed"); return; }
    const std::string dir = tmpl;
    const std::string old_bin = dir + "/antitheftd";
    int fd = open(old_bin.c_str(), O_CREAT | O_WRONLY, 0755);
    if (fd < 0) { Check(false, "self-integrity: could not create the stand-in binary"); return; }
    close(fd);
    struct stat st{};
    if (stat(old_bin.c_str(), &st) != 0) { Check(false, "self-integrity: could not stat the stand-in binary"); return; }
    const uint64_t old_ino = st.st_ino;

    Check(loader.SetSelfIntegrityIdentityTestOnly(0, st.st_dev, st.st_ino), "self-integrity: stand-in registered as the daemon binary");
    // Control: while it is the daemon binary, a writer that is not the package manager is refused.
    fd = open(old_bin.c_str(), O_WRONLY);
    int err = fd >= 0 ? 0 : errno;
    if (fd >= 0) close(fd);
    Check(fd < 0 && err == EPERM, "self-integrity control: writing the registered daemon binary is refused (errno=" + std::to_string(err) + ")");

    // The old binary goes; nothing holds it open, so its number is freed here.
    Check(unlink(old_bin.c_str()) == 0, "self-integrity: the stand-in binary is removed");
    uint64_t slot_dev = 1, slot_ino = 1;
    bool slot_read = loader.SelfIntegrityIdentityTestOnly(0, slot_dev, slot_ino);
    Check(slot_read && slot_dev == 0 && slot_ino == 0,
          "self-integrity: the freed number is no longer the daemon binary (slot reads " + std::to_string(slot_dev) + ":" + std::to_string(slot_ino) + ")");
    int rc = CreateUntilInodeRecurs(dir, old_ino, "new-", /*as_owner=*/false);
    Check(rc != -2, "self-integrity: the freed number came back to a new file (filesystem recycles numbers)");
    Check(rc == 0, "self-integrity: a program may create and write a NEW file given the old daemon binary's number (got " + std::to_string(rc) + ")");

    struct stat self_st{};
    if (stat("/proc/self/exe", &self_st) != 0 || !loader.SetSelfIntegrityIdentityTestOnly(0, self_st.st_dev, self_st.st_ino)) {
        Check(false, "self-integrity: could not put slot 0 back to this process's binary");
    }
}

// Chain identity, core-side. Owner identity is the composite
// (dev, ino), not a bare inode number: inode numbers are per-filesystem and
// small, so a file the attacker controls on any other mount can be given the
// same number. A bare-inode fallback would pass every other assertion in this
// file unchanged, which is precisely why this one is here.
void TestResourceOwnerExactRejectsWrongDevice(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] owner identity: exact registration on the wrong device denies the real owner..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }
    struct stat probe_st{};
    if (stat(ProbePath(), &probe_st) != 0) { Check(false, "could not stat probe binary"); return; }
    const uint64_t probe_dev = probe_st.st_dev;
    const uint64_t forged_dev = probe_dev ^ 0xFFFFull;

    std::string denied_path;
    uint64_t denied_ino, denied_dev;
    if (!MakeTempFile(denied_path, denied_ino, denied_dev)) { Check(false, "could not create temp resource"); return; }
    DeferUnlink(denied_path);
    if (!loader.AddSensitiveInode(denied_dev, denied_ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); return; }
    if (!loader.AddResourceOwnerExact(denied_dev, denied_ino, forged_dev, probe_ino)) {
        Check(false, "AddResourceOwnerExact(forged device) failed");
        return;
    }
    int rc = RunProbe("open_read", denied_path);
    Check(rc == EACCES, "the right inode on the wrong device is denied (got " + std::to_string(rc) + ")");

    // Control on a second resource: the same inode, registered with the
    // device it is actually on, is admitted. Without this the denial above
    // could just mean exact registration never works at all.
    std::string allowed_path;
    uint64_t allowed_ino, allowed_dev;
    if (!MakeTempFile(allowed_path, allowed_ino, allowed_dev)) { Check(false, "could not create control resource"); return; }
    DeferUnlink(allowed_path);
    if (!loader.AddSensitiveInode(allowed_dev, allowed_ino, /*category=*/1)) { Check(false, "AddSensitiveInode(control) failed"); return; }
    if (!loader.AddResourceOwnerExact(allowed_dev, allowed_ino, probe_dev, probe_ino)) {
        Check(false, "AddResourceOwnerExact(real device) failed");
        return;
    }
    rc = RunProbe("open_read", allowed_path);
    Check(rc == 0, "the same owner registered with its real device is allowed (got " + std::to_string(rc) + ")");
}

// Runs an arbitrary executable with no arguments and returns its exit code,
// or -1 if the harness itself could not run it. RunProbe() above always execs
// ProbePath(); the chain-identity scenario needs to exec a script whose
// interpreter is /bin/sh, which is the entire point of it.
int RunExecutable(const std::string& exe) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        execl(exe.c_str(), exe.c_str(), (char*)nullptr);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return -1;
    }
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

// Chain identity: exec origin and the removal path, core-side.
//
// An owner script never has itself as its `exe`: binfmt_script execs /bin/sh,
// which here execs /bin/cat. Keyed on the current exe alone, the only image
// ever checked owns nothing - which is the shape most of the corpus runs as
// (an AppImage is <app>.AppImage -> AppRun -> python3). The exec origin
// stamped from owner_images at bprm_creds_for_exec is what carries the
// application's identity across those execs.
//
// The removal half matters just as much: an owner image that cannot be
// withdrawn is a permanent grant, and the agent's reconcile pass relies on
// withdrawal actually taking the standing away.
// OWNER_NO_EXTERNAL_INHERIT. An app that spawns external
// helpers by design must not extend its owner standing to them. The two
// halves of this test differ in EXACTLY one way - whether the binary the
// owner script execs lives inside the owner's own install directory - so a
// pass proves the directory test is what decides, not anything else.
//
// Without the flag, bprm_creds_for_exec re-granted the chain on every exec,
// and is_resource_owner() matches on that chain, so BOTH halves would be
// allowed: a browser's native messaging host, or a game launched by Steam,
// could read the launcher's vault.
void TestNoExternalInheritanceDropsStandingOutsideTheInstallDir(EbpfLoader& loader) {
    std::cout << "[e2e] no_external_inheritance: an owner's external helper loses standing, an internal one keeps it..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }

    // A dedicated directory standing in for the app's install tree.
    char dir_tmpl[] = "/tmp/kinnector_e2e_app_XXXXXX";
    if (!mkdtemp(dir_tmpl)) { Check(false, "mkdtemp (app dir) failed"); return; }
    std::string app_dir = dir_tmpl;

    std::string resource;
    uint64_t res_ino, res_dev;
    if (!MakeTempFile(resource, res_ino, res_dev)) { Check(false, "could not create temp resource"); return; }
    DeferUnlink(resource);

    // An internal copy of cat, living beside the owner script.
    std::string internal_cat = app_dir + "/cat";
    {
        std::string cmd = "cp /bin/cat '" + internal_cat + "'";
        if (system(cmd.c_str()) != 0) { Check(false, "could not copy cat into the app dir"); return; }
    }
    DeferUnlink(internal_cat);

    auto write_script = [&](const std::string& path, const std::string& cat_path) -> bool {
        int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (fd < 0) return false;
        std::string body = "#!/bin/sh\nexec '" + cat_path + "' '" + resource + "' >/dev/null 2>&1\n";
        bool ok = write(fd, body.data(), body.size()) == static_cast<ssize_t>(body.size());
        close(fd);
        return ok && chmod(path.c_str(), 0755) == 0;
    };

    std::string ext_script = app_dir + "/app_external.sh";
    std::string int_script = app_dir + "/app_internal.sh";
    if (!write_script(ext_script, "/bin/cat") || !write_script(int_script, internal_cat)) {
        Check(false, "could not write the owner scripts");
        return;
    }
    DeferUnlink(ext_script);
    DeferUnlink(int_script);

    struct stat ext_st{}, int_st{}, cat_st{}, icat_st{}, sh_st{};
    if (stat(ext_script.c_str(), &ext_st) != 0 || stat(int_script.c_str(), &int_st) != 0 ||
        stat("/bin/cat", &cat_st) != 0 || stat(internal_cat.c_str(), &icat_st) != 0 ||
        stat("/bin/sh", &sh_st) != 0) {
        Check(false, "could not stat the test fixtures");
        return;
    }

    if (!loader.AddSensitiveInode(res_dev, res_ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); return; }
    // Both scripts own the resource, so the ONLY difference between the two
    // runs is where the exec'd binary lives.
    if (!loader.AddResourceOwnerExact(res_dev, res_ino, ext_st.st_dev, ext_st.st_ino) ||
        !loader.AddResourceOwnerExact(res_dev, res_ino, int_st.st_dev, int_st.st_ino)) {
        Check(false, "AddResourceOwnerExact(scripts) failed");
        return;
    }
    // kinnector.bpf.c: OWNER_PROTECTED | OWNER_NO_EXTERNAL_INHERIT.
    const uint32_t kOwnerProtected = 0x1u;
    const uint32_t kOwnerNoExternalInherit = 0x4u;
    if (!loader.AddOwnerImage(ext_st.st_dev, ext_st.st_ino, kOwnerProtected | kOwnerNoExternalInherit) ||
        !loader.AddOwnerImage(int_st.st_dev, int_st.st_ino, kOwnerProtected | kOwnerNoExternalInherit)) {
        Check(false, "AddOwnerImage failed");
        return;
    }
    // Same pre-classification requirement as the interpreter test above: an
    // unclassified actor is denied on a sensitive inode before the owner
    // check is ever reached.
    for (uint64_t ino : {static_cast<uint64_t>(sh_st.st_ino), static_cast<uint64_t>(cat_st.st_ino),
                         static_cast<uint64_t>(icat_st.st_ino), static_cast<uint64_t>(ext_st.st_ino),
                         static_cast<uint64_t>(int_st.st_ino)}) {
        if (!loader.AddTrustedExecInode(ino, 2)) { Check(false, "AddTrustedExecInode failed"); return; }
    }

    int internal_rc = RunExecutable(int_script);
    Check(internal_rc == 0,
          "a helper INSIDE the owner's install dir keeps the chain and reads the resource (got " +
              std::to_string(internal_rc) + ")");

    int external_rc = RunExecutable(ext_script);
    Check(external_rc != 0,
          "a helper OUTSIDE the owner's install dir loses standing and is denied (got " +
              std::to_string(external_rc) + ")");

    loader.RemoveOwnerImage(ext_st.st_dev, ext_st.st_ino);
    loader.RemoveOwnerImage(int_st.st_dev, int_st.st_ino);
    rmdir(app_dir.c_str());
}

// The `/usr/bin` and flatpak inheritance tripwire:
// the pass above proves the SIMPLE shapes (beside the owner, or
// in a subdirectory of the owner's own directory) - it says nothing about
// either shape a real install actually uses. This test pins both, so the
// gap is a measured, known limit instead of an assumption:
//
// 1. A SHARED system directory (the real `/usr/bin` shape, stood in here by
//    a dedicated temp dir playing the same role - writing test fixtures
//    into the real /usr/bin would pollute the host). `image_is_internal_to_
//    origin`'s only test is "does this new image's directory match the
//    owner's own directory" - it has no notion of package identity, so two
//    UNRELATED binaries that merely happen to share one directory both read
//    as "internal" to each other. This is the KNOWN LIMIT documented beside
//    `image_is_internal_to_origin` in kinnector_helpers.h, not a bug this
//    test is trying to catch - it exists so a future change to that walk
//    cannot silently make this worse (or better) without a test noticing.
//
// 2. A flatpak-shaped NESTED layout: the owner binary at
//    `<app>/files/bin/app` and a real sibling-subtree helper at
//    `<app>/files/lib/app/helper` - same flatpak install, but NOT reachable
//    by walking up from the helper (that walk only ever goes toward
//    `<app>/files/bin`'s ancestors, and `files/lib/...` is a sibling
//    branch, not an ancestor, at any depth). This is a real false-positive
//    risk on flatpak-packaged owners that has never been proven either way
//    before now - proven here to currently DENY, i.e. the helper loses
//    standing even though it ships inside the same install. Fixing it needs
//    the origin directory to be recorded at the app-bundle root rather than
//    the owner binary's own immediate directory, which is a design change,
//    not a test - left open, but no longer an unmeasured guess.
void TestNoExternalInheritanceSharedDirAndFlatpakLayout(EbpfLoader& loader) {
    std::cout << "[e2e] no_external_inheritance: shared-directory and flatpak-nested layouts..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }
    const uint32_t kOwnerProtected = 0x1u;
    const uint32_t kOwnerNoExternalInherit = 0x4u;
    const uint32_t kOwnerOriginRootUp1 = 0x10u;

    auto write_script = [](const std::string& path, const std::string& cat_path, const std::string& resource) -> bool {
        int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (fd < 0) return false;
        std::string body = "#!/bin/sh\nexec '" + cat_path + "' '" + resource + "' >/dev/null 2>&1\n";
        bool ok = write(fd, body.data(), body.size()) == static_cast<ssize_t>(body.size());
        close(fd);
        return ok && chmod(path.c_str(), 0755) == 0;
    };

    // ---- 1. Shared system directory (the /usr/bin shape) ----
    {
        char dir_tmpl[] = "/tmp/kinnector_e2e_shareddir_XXXXXX";
        if (!mkdtemp(dir_tmpl)) { Check(false, "mkdtemp (shared dir) failed"); return; }
        std::string shared_dir = dir_tmpl;

        std::string resource;
        uint64_t res_ino, res_dev;
        if (!MakeTempFile(resource, res_ino, res_dev)) { Check(false, "could not create temp resource"); return; }
        DeferUnlink(resource);

        // Two UNRELATED binaries, sharing only the directory - nothing else
        // ties them together, which is exactly the /usr/bin shape.
        std::string owner_script = shared_dir + "/owner_app";
        std::string unrelated_bin = shared_dir + "/unrelated_bin";
        if (!write_script(owner_script, "/bin/cat", resource)) { Check(false, "could not write owner script"); return; }
        {
            std::string cmd = "cp /bin/cat '" + unrelated_bin + "'";
            if (system(cmd.c_str()) != 0) { Check(false, "could not copy an unrelated binary into the shared dir"); return; }
        }
        DeferUnlink(owner_script);
        DeferUnlink(unrelated_bin);

        // A script that execs the unrelated sibling binary directly on the
        // resource - the shape the OWNER_NO_EXTERNAL_INHERIT test above uses.
        std::string launcher = shared_dir + "/owner_launches_sibling.sh";
        if (!write_script(launcher, unrelated_bin, resource)) { Check(false, "could not write launcher script"); return; }
        DeferUnlink(launcher);

        struct stat launcher_st{}, sh_st{}, unrelated_st{};
        if (stat(launcher.c_str(), &launcher_st) != 0 || stat("/bin/sh", &sh_st) != 0 ||
            stat(unrelated_bin.c_str(), &unrelated_st) != 0) {
            Check(false, "could not stat the shared-dir fixtures");
            return;
        }

        if (!loader.AddSensitiveInode(res_dev, res_ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); return; }
        if (!loader.AddResourceOwnerExact(res_dev, res_ino, launcher_st.st_dev, launcher_st.st_ino)) {
            Check(false, "AddResourceOwnerExact(launcher) failed");
            return;
        }
        if (!loader.AddOwnerImage(launcher_st.st_dev, launcher_st.st_ino, kOwnerProtected | kOwnerNoExternalInherit)) {
            Check(false, "AddOwnerImage(launcher) failed");
            return;
        }
        for (uint64_t ino : {static_cast<uint64_t>(sh_st.st_ino), static_cast<uint64_t>(unrelated_st.st_ino),
                             static_cast<uint64_t>(launcher_st.st_ino)}) {
            if (!loader.AddTrustedExecInode(ino, 2)) { Check(false, "AddTrustedExecInode failed"); return; }
        }

        int rc = RunExecutable(launcher);
        Check(rc == 0,
              "KNOWN LIMIT (documented in kinnector_helpers.h): an unrelated binary "
              "sharing the owner's directory reads the resource too (got " +
                  std::to_string(rc) + ") - a shared system directory like /usr/bin admits every binary in it");

        loader.RemoveOwnerImage(launcher_st.st_dev, launcher_st.st_ino);
        rmdir(shared_dir.c_str());
    }

    // ---- 2. Flatpak-shaped nested layout ----
    {
        char dir_tmpl[] = "/tmp/kinnector_e2e_flatpak_XXXXXX";
        if (!mkdtemp(dir_tmpl)) { Check(false, "mkdtemp (flatpak app dir) failed"); return; }
        std::string app_root = dir_tmpl;
        std::string bin_dir = app_root + "/files/bin";
        std::string lib_dir = app_root + "/files/lib/app";
        if (system(("mkdir -p '" + bin_dir + "'").c_str()) != 0 || system(("mkdir -p '" + lib_dir + "'").c_str()) != 0) {
            Check(false, "could not create the flatpak-shaped directory tree");
            return;
        }

        std::string resource;
        uint64_t res_ino, res_dev;
        if (!MakeTempFile(resource, res_ino, res_dev)) { Check(false, "could not create temp resource"); return; }
        DeferUnlink(resource);

        // The owner "binary" (files/bin/app) and its real helper, shipped in
        // a SIBLING subtree (files/lib/app/helper) - the shape flatpak's own
        // /app/{bin,lib,...} layout uses, not a subdirectory of files/bin.
        std::string owner_script = bin_dir + "/app";
        std::string helper = lib_dir + "/helper";
        if (!write_script(owner_script, "/bin/cat", resource)) { Check(false, "could not write owner script"); return; }
        {
            std::string cmd = "cp /bin/cat '" + helper + "'";
            if (system(cmd.c_str()) != 0) { Check(false, "could not copy cat into the flatpak lib dir"); return; }
        }
        DeferUnlink(owner_script);
        DeferUnlink(helper);

        std::string launcher = bin_dir + "/app_launches_helper.sh";
        if (!write_script(launcher, helper, resource)) { Check(false, "could not write launcher script"); return; }
        DeferUnlink(launcher);

        struct stat launcher_st{}, sh_st{}, helper_st{};
        if (stat(launcher.c_str(), &launcher_st) != 0 || stat("/bin/sh", &sh_st) != 0 ||
            stat(helper.c_str(), &helper_st) != 0) {
            Check(false, "could not stat the flatpak-layout fixtures");
            return;
        }

        if (!loader.AddSensitiveInode(res_dev, res_ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); return; }
        if (!loader.AddResourceOwnerExact(res_dev, res_ino, launcher_st.st_dev, launcher_st.st_ino)) {
            Check(false, "AddResourceOwnerExact(launcher) failed");
            return;
        }
        // OWNER_ORIGIN_ROOT_UP1 (new, fix): userspace
        // sets this for an owner it resolved to a Flatpak files/bin/<name>
        // layout, so bprm_creds_for_exec climbs one extra parent level when
        // stamping exec_origin.dir_dev/dir_ino - landing on files/ (an
        // ancestor of files/lib/app/helper too) instead of files/bin.
        if (!loader.AddOwnerImage(launcher_st.st_dev, launcher_st.st_ino,
                                   kOwnerProtected | kOwnerNoExternalInherit | kOwnerOriginRootUp1)) {
            Check(false, "AddOwnerImage(launcher) failed");
            return;
        }
        for (uint64_t ino : {static_cast<uint64_t>(sh_st.st_ino), static_cast<uint64_t>(helper_st.st_ino),
                             static_cast<uint64_t>(launcher_st.st_ino)}) {
            if (!loader.AddTrustedExecInode(ino, 2)) { Check(false, "AddTrustedExecInode failed"); return; }
        }

        int rc = RunExecutable(launcher);
        Check(rc == 0,
              "FIXED (OWNER_ORIGIN_ROOT_UP1): a real same-install flatpak helper "
              "in a sibling subtree (files/lib/app/helper, launched from files/bin/app) is now allowed "
              "(got " + std::to_string(rc) + ") - origin_dir is recorded at the bundle's files/ root for a "
              "flagged owner, which the sibling's ancestor walk can reach");

        loader.RemoveOwnerImage(launcher_st.st_dev, launcher_st.st_ino);
        if (system(("rm -rf '" + app_root + "'").c_str()) != 0) {
            std::cerr << "[e2e] warning: could not clean up " << app_root << std::endl;
        }
    }
}

// Destructive-ops gate (renaming is a real
// bypass): inode_rename's new check, mirroring file_open's owner-allowlist
// but for rename(2) of the resource's SOURCE path. A non-owner process could
// previously `mv` a protected secret with no check at all - is_resource_owner()
// only ever gated open()/mmap(). Two halves: a non-owner is denied (and the
// file provably stays put), and a real registered owner keeps the ability to
// rename its own resource (an app's own atomic-save rename must keep working).
void TestRenameOfProtectedResourceDeniedForNonOwner(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] destructive-ops: rename(2) of a protected resource is owner-gated..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }

    // ---- Non-owner: denied, and the file must not have moved. ----
    {
        std::string path;
        uint64_t ino, dev;
        if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
        DeferUnlink(path);
        if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); return; }
        uint64_t fake_owner = probe_ino + 1;
        while (ResourceOwnerHash(fake_owner) == ResourceOwnerHash(probe_ino)) fake_owner++;
        if (!loader.AddResourceOwner(dev, ino, fake_owner)) { Check(false, "AddResourceOwner failed"); return; }

        std::string dest = path + ".renamed";
        int rc = RunProbeRename(path, dest);
        Check(rc == EACCES, "rename() by a non-owner denied with EACCES (got " + std::to_string(rc) + ")");

        struct stat st{};
        Check(stat(path.c_str(), &st) == 0, "the resource must still exist at its ORIGINAL path after a denied rename");
        Check(stat(dest.c_str(), &st) != 0, "the destination must NOT exist - the rename must not have partially happened");
    }

    // ---- Control: a real registered owner can still rename its own resource. ----
    {
        std::string path;
        uint64_t ino, dev;
        if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
        if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); unlink(path.c_str()); return; }
        if (!loader.AddResourceOwner(dev, ino, probe_ino)) { Check(false, "AddResourceOwner(probe_ino) failed"); unlink(path.c_str()); return; }

        std::string dest = path + ".renamed-by-owner";
        int rc = RunProbeRename(path, dest);
        Check(rc == 0, "rename() by the registered owner succeeds (got " + std::to_string(rc) + ")");

        struct stat st{};
        Check(stat(dest.c_str(), &st) == 0, "the resource must exist at the NEW path after the owner's own rename");
        // DeferUnlink, not a direct unlink() - `dest` carries the SAME inode
        // as `path` (rename doesn't change it), and that inode is registered
        // in sensitive_inodes_map/resource_owner_map, which have no removal
        // API (see g_deferred_unlinks' own doc comment on exactly this
        // hazard). A direct unlink() here frees the inode number back to the
        // filesystem while the stale registration lives on - found live
        // ext4 handed that exact freed inode to the very next
        // test's mkstemp() (TestBasicProtectionEnforcesFilesButGrantsNoProcessPowers's
        // CopyProbeBinary(), called twice back-to-back), and the test
        // harness process - not the registered owner - got EACCES creating
        // its OWN brand-new temp file, misreported as "could not copy the
        // probe binaries". `path` was already renamed away by this point and
        // never held the live registration at unlink time, so it was never
        // the actual hazard, but is deferred too now for the same reason
        // every other temp file in this suite is.
        DeferUnlink(path);
        DeferUnlink(dest);
    }
}

// OWNER_BASIC_ONLY, the corpus's basic_protection tier: enforce
// the owner allowlist on the app's FILES, make no claim about its PROCESS.
// Both halves are checked, and the process half is an A/B against an
// otherwise identical owner image without the bit - so a pass shows the bit
// is what withholds the protection, not some unrelated ordering.
void TestBasicProtectionEnforcesFilesButGrantsNoProcessPowers(EbpfLoader& loader) {
    std::cout << "[e2e] basic_protection: files still owner-enforced, process gets no ptrace immunity..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }

    const uint32_t kOwnerProtected = 0x1u;
    const uint32_t kOwnerBasicOnly = 0x8u;

    // Fresh probe copies, so neither inode can be carrying protection from
    // protected_owner_binaries (which an earlier test registers for
    // ProbePath()) - that map grants at bprm independently of owner_images
    // and would mask what this test is measuring.
    std::string full_probe, basic_probe;
    uint64_t full_ino = 0, basic_ino = 0;
    if (!CopyProbeBinary(full_probe, full_ino) || !CopyProbeBinary(basic_probe, basic_ino)) {
        Check(false, "could not copy the probe binaries");
        return;
    }
    DeferUnlink(full_probe);
    DeferUnlink(basic_probe);
    struct stat full_st{}, basic_st{};
    if (stat(full_probe.c_str(), &full_st) != 0 || stat(basic_probe.c_str(), &basic_st) != 0) {
        Check(false, "could not stat the probe copies");
        return;
    }
    if (!loader.AddTrustedExecInode(full_st.st_ino, 2) || !loader.AddTrustedExecInode(basic_st.st_ino, 2)) {
        Check(false, "AddTrustedExecInode failed");
        return;
    }

    // --- Half 1: the file half. basic_protection still enforces ownership.
    std::string resource;
    uint64_t res_ino, res_dev;
    if (!MakeTempFile(resource, res_ino, res_dev)) { Check(false, "could not create temp resource"); return; }
    DeferUnlink(resource);
    if (!loader.AddSensitiveInode(res_dev, res_ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); return; }
    if (!loader.AddResourceOwnerExact(res_dev, res_ino, basic_st.st_dev, basic_st.st_ino)) {
        Check(false, "AddResourceOwnerExact(basic owner) failed");
        return;
    }
    if (!loader.AddOwnerImage(basic_st.st_dev, basic_st.st_ino, kOwnerProtected | kOwnerBasicOnly)) {
        Check(false, "AddOwnerImage(basic) failed");
        return;
    }

    int owner_rc = RunProbeAt(basic_probe.c_str(), "open_read", resource);
    Check(owner_rc == 0, "a basic_protection owner still reads its own resource (got " + std::to_string(owner_rc) + ")");

    int stranger_rc = RunProbeAt(full_probe.c_str(), "open_read", resource);
    Check(stranger_rc == EACCES,
          "a non-owner is still denied that resource under basic_protection (got " + std::to_string(stranger_rc) + ")");

    // --- Half 2: the process half. A/B on the bit alone.
    if (!loader.AddOwnerImage(full_st.st_dev, full_st.st_ino, kOwnerProtected)) {
        Check(false, "AddOwnerImage(full) failed");
        return;
    }

    pid_t full_pid = StartProbeSleeping(full_probe.c_str(), /*seconds=*/2);
    if (full_pid <= 0) { Check(false, "could not start the fully-protected sleeper"); return; }
    usleep(200000); // let bprm_creds_for_exec's stamp land
    int full_ptrace = AttackerPtraceAttach(full_pid);
    Check(full_ptrace == EACCES,
          "control: an owner image WITHOUT basic_protection denies a stranger's ptrace (got " +
              std::to_string(full_ptrace) + ")");
    AttackerKill(full_pid, SIGKILL);
    waitpid(full_pid, nullptr, 0);

    pid_t basic_pid = StartProbeSleeping(basic_probe.c_str(), /*seconds=*/2);
    if (basic_pid <= 0) { Check(false, "could not start the basic_protection sleeper"); return; }
    usleep(200000);
    int basic_ptrace = AttackerPtraceAttach(basic_pid);
    Check(basic_ptrace == 0,
          "basic_protection claims nothing about the process, so ptrace is NOT blocked (got " +
              std::to_string(basic_ptrace) + ")");
    AttackerKill(basic_pid, SIGKILL);
    waitpid(basic_pid, nullptr, 0);

    loader.RemoveOwnerImage(basic_st.st_dev, basic_st.st_ino);
    loader.RemoveOwnerImage(full_st.st_dev, full_st.st_ino);
}

// MODE AUDIT. ptrace_access_check's and task_kill's
// admin-session rules were the only two enforcement points in
// kinnector.bpf.c that were LIVE in an antitheft deployment with no
// antitheft opt-in anywhere: TREE_ADMIN_SESSION is stamped by that file
// itself, not from any userspace map. task_kill's contradicted the antitheft
// branch a few dozen lines below it, which says antitheft "does not make a
// process unkillable" - found live when one Claude Code instance's
// kill(pid, 0) liveness probe of another was refused with EPERM.
//
// A/B on deployment_mode alone against the SAME stamped target, so nothing
// but the mode differs between the two halves. The MODE_WARDEN half doubles
// as validation of the fixture: if the stamp did not land, it reads
// "allowed" and fails loudly rather than letting the antitheft half pass
// vacuously.
//
// signal 0 is used for the kill probe deliberately - it is exactly what the
// real incident used (a liveness check), and it exercises task_kill without
// actually signalling the target.
void TestWardenAdminSessionRulesAreWardenOnly(EbpfLoader& loader) {
    std::cout << "[e2e] mode audit: Warden's admin-session ptrace/kill rules are Warden-only..." << std::endl;

    int master = -1;
    pid_t target = StartProbeInAdminSession(ProbePath(), /*seconds=*/10, master);
    if (target <= 0) { Check(false, "could not start the admin-session fixture"); return; }
    usleep(400000); // let the exec, and the stamp it performs, land

    auto cleanup = [&]() {
        kill(target, SIGKILL); // orphaned: init reaps it, we cannot waitpid
        if (master >= 0) close(master);
        loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft);
    };

    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeWarden)) {
        Check(false, "SetConfigValue(MODE_WARDEN) failed");
        cleanup();
        return;
    }
    int w_ptrace = AttackerPtraceAttach(target);
    int w_kill = AttackerKill(target, 0);
    Check(w_ptrace == EACCES,
          "control (also proves the fixture is stamped): under MODE_WARDEN an admin-session target "
          "refuses a stranger's ptrace (got " + std::to_string(w_ptrace) + ")");
    Check(w_kill == EPERM,
          "control: under MODE_WARDEN an admin-session target refuses a stranger's signal (got " +
              std::to_string(w_kill) + ")");

    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        cleanup();
        return;
    }
    int a_ptrace = AttackerPtraceAttach(target);
    int a_kill = AttackerKill(target, 0);
    Check(a_ptrace == 0,
          "under MODE_ANTITHEFT Warden's admin-session ptrace rule does not fire (got " +
              std::to_string(a_ptrace) + ")");
    Check(a_kill == 0,
          "under MODE_ANTITHEFT Warden's admin-session kill rule does not fire, matching antitheft's "
          "own stated policy (got " + std::to_string(a_kill) + ")");

    cleanup();
}

// Depth-2 credential-helper exemption. The supply-chain rule
// denies an install's descendants EVERY protected secret regardless of
// ownership - correct for a lifecycle script, wrong for the fetch itself.
// Reproduced live before this exemption: `gh auth status` succeeds run
// directly and is refused its own config.yml underneath `go`, so a private
// module cannot authenticate.
//
// Depth is what separates the two, and this test pins exactly that. Both
// halves use the SAME package-manager script, the SAME credential-helper
// binary and the SAME resource; the only difference is how many forks sit
// between them:
//
//   pkgmgr -> cat            depth 2  = a fetch helper      -> allowed
//   pkgmgr -> sh -c -> cat   depth 3  = a lifecycle script  -> denied
//
// If the exemption ever widens from "== DESCENDANT" to "any depth", the
// second half starts passing as allowed and fails loudly.
void TestCredentialHelperExemptOnlyAtDepthTwo(EbpfLoader& loader) {
    std::cout << "[e2e] supply-chain: a credential helper is exempt at fork depth 2 and denied deeper..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }

    std::string resource;
    uint64_t res_ino, res_dev;
    if (!MakeTempFile(resource, res_ino, res_dev)) { Check(false, "could not create temp resource"); return; }
    DeferUnlink(resource);
    // A LOCKED secret: sensitive AND with an owner set. The
    // supply-chain rule refuses only locked stores (an ownerless, observed one
    // is allowed and recorded - TestInstallScriptRefusedOnlyLockedStores). The
    // owner is the helper itself, so the owner rule allows its read and a
    // refusal below can only be the supply-chain rule.
    if (!loader.AddSensitiveInode(res_dev, res_ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); return; }

    struct stat cat_st{}, sh_st{};
    if (stat("/bin/cat", &cat_st) != 0 || stat("/bin/sh", &sh_st) != 0) {
        Check(false, "could not stat /bin/cat and /bin/sh");
        return;
    }
    if (!loader.AddResourceOwnerExact(res_dev, res_ino, cat_st.st_dev, cat_st.st_ino)) {
        Check(false, "AddResourceOwnerExact(cat) failed");
        return;
    }
    // `cat` stands in for git/gh here - the allowlisted binary that reads the
    // credential. Registering it is what the agent does from
    // credential_helpers.json.
    if (!loader.AddCredentialHelperImage(cat_st.st_dev, cat_st.st_ino)) {
        Check(false, "AddCredentialHelperImage failed");
        return;
    }
    for (uint64_t ino : {static_cast<uint64_t>(cat_st.st_ino), static_cast<uint64_t>(sh_st.st_ino)}) {
        if (!loader.AddTrustedExecInode(ino, 2)) { Check(false, "AddTrustedExecInode failed"); return; }
    }

    auto write_script = [&](const std::string& path, const std::string& body) -> bool {
        int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (fd < 0) return false;
        std::string full = "#!/bin/sh\n" + body + "\n";
        bool ok = write(fd, full.data(), full.size()) == static_cast<ssize_t>(full.size());
        close(fd);
        return ok && chmod(path.c_str(), 0755) == 0;
    };

    // No `exec` in either body: the shell FORKS, so cat is a real child.
    char d2[] = "/tmp/kinnector_e2e_pm_depth2_XXXXXX";
    char d3[] = "/tmp/kinnector_e2e_pm_depth3_XXXXXX";
    int f2 = mkstemp(d2), f3 = mkstemp(d3);
    if (f2 < 0 || f3 < 0) { Check(false, "mkstemp (package-manager scripts) failed"); return; }
    close(f2); close(f3);
    std::string pm_depth2 = d2, pm_depth3 = d3;
    DeferUnlink(pm_depth2);
    DeferUnlink(pm_depth3);
    if (!write_script(pm_depth2, "/bin/cat '" + resource + "' >/dev/null 2>&1") ||
        !write_script(pm_depth3, "/bin/sh -c \"/bin/cat '" + resource + "' >/dev/null 2>&1\"")) {
        Check(false, "could not write the package-manager scripts");
        return;
    }

    struct stat pm2_st{}, pm3_st{};
    if (stat(pm_depth2.c_str(), &pm2_st) != 0 || stat(pm_depth3.c_str(), &pm3_st) != 0) {
        Check(false, "could not stat the package-manager scripts");
        return;
    }
    // Both scripts ARE the package manager: bprm_creds_for_exec re-roots them
    // to depth 1 on exec, and the kernel counts forks from there.
    const uint32_t kPkgLifecycleRoot = 1u;
    if (!loader.AddPackageManagerImage(pm2_st.st_dev, pm2_st.st_ino, kPkgLifecycleRoot) ||
        !loader.AddPackageManagerImage(pm3_st.st_dev, pm3_st.st_ino, kPkgLifecycleRoot)) {
        Check(false, "AddPackageManagerImage failed");
        return;
    }
    for (uint64_t ino : {static_cast<uint64_t>(pm2_st.st_ino), static_cast<uint64_t>(pm3_st.st_ino)}) {
        if (!loader.AddTrustedExecInode(ino, 2)) { Check(false, "AddTrustedExecInode failed"); return; }
    }

    int depth2_rc = RunExecutable(pm_depth2);
    Check(depth2_rc == 0,
          "a credential helper the package manager launched ITSELF (depth 2) reads the secret - the fetch "
          "can authenticate (got " + std::to_string(depth2_rc) + ")");

    int depth3_rc = RunExecutable(pm_depth3);
    Check(depth3_rc != 0,
          "the same helper one process deeper (depth 3, the lifecycle-script shape) is still denied (got " +
              std::to_string(depth3_rc) + ")");

    loader.RemoveCredentialHelperImage(cat_st.st_dev, cat_st.st_ino);
    loader.RemovePackageManagerImage(pm2_st.st_dev, pm2_st.st_ino);
    loader.RemovePackageManagerImage(pm3_st.st_dev, pm3_st.st_ino);
}

// A package install script (anything a package
// manager forked, depth >= 2) is refused only LOCKED stores - a sensitive inode
// WITH an owner set in resource_owner_map, i.e. a corpus store whose effective
// policy is deny - and persistence writes. An OBSERVED store (sensitive, no
// owner set: audit policy, or deny with no owner on this machine) is readable:
// legitimate installs read SSH keys (git+ssh deps), cloud CLI credentials
// (private registries), .npmrc/.netrc and .env files. Its open goes down
// file_open's ordinary path, whose verdict=1 EVT_FILE_OPEN is the record (the
// event itself is asserted by antitheft's test_pm_enforcement_matrix, which has
// a telemetry consumer; this harness has none).
//
// Attribution: every reader of the locked file (/bin/sh, /bin/cat) is one of
// its registered OWNERS, and the identical script run outside an install reads
// both files and writes the autostart entry, so each refusal inside the
// install can only be the supply-chain rule. Exit code bits: 4 = locked read
// failed, 2 = observed read failed, 1 = persistence write failed.
// Before this decision the result inside the install was 7 (the observed read
// refused too); now it is 5.
void TestInstallScriptRefusedOnlyLockedStores(EbpfLoader& loader) {
    std::cout << "[e2e] supply-chain: an install script is refused LOCKED stores and persistence writes, "
                 "and reads OBSERVED (audit-only) stores..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }

    std::string locked, observed;
    uint64_t locked_ino, locked_dev, observed_ino, observed_dev;
    if (!MakeTempFile(locked, locked_ino, locked_dev) || !MakeTempFile(observed, observed_ino, observed_dev)) {
        Check(false, "could not create the two temp stores");
        return;
    }
    DeferUnlink(locked);
    DeferUnlink(observed);

    struct stat cat_st{}, sh_st{};
    if (stat("/bin/cat", &cat_st) != 0 || stat("/bin/sh", &sh_st) != 0) {
        Check(false, "could not stat /bin/cat and /bin/sh");
        return;
    }
    // LOCKED: sensitive + an owner set (what OwnershipEngine::register_link
    // writes for a deny locator). OBSERVED: sensitive only (what
    // register_audit_only, package_sources and persistence_watch write).
    if (!loader.AddSensitiveInode(locked_dev, locked_ino, 1) ||
        !loader.AddResourceOwnersExactBatch(locked_dev, locked_ino,
                                            {{static_cast<uint64_t>(sh_st.st_dev), static_cast<uint64_t>(sh_st.st_ino)},
                                             {static_cast<uint64_t>(cat_st.st_dev), static_cast<uint64_t>(cat_st.st_ino)}})) {
        Check(false, "registering the locked store failed");
        return;
    }
    if (!loader.AddSensitiveInode(observed_dev, observed_ino, 1)) {
        Check(false, "registering the observed store failed");
        return;
    }
    Check(loader.GetResourceOwnerMask(observed_dev, observed_ino) == 0,
          "fixture: the observed store has no owner set (it is audit-only)");
    Check(loader.GetResourceOwnerMask(locked_dev, locked_ino) != 0, "fixture: the locked store has an owner set");

    char autostart_tmpl[] = "/tmp/kinnector_e2e_autostart_XXXXXX";
    if (!mkdtemp(autostart_tmpl)) { Check(false, "mkdtemp (autostart) failed"); return; }
    std::string autostart = autostart_tmpl;
    std::string planted = autostart + "/evil.desktop";
    struct stat as_st{};
    if (stat(autostart.c_str(), &as_st) != 0 || !loader.AddPersistenceDir(as_st.st_dev, as_st.st_ino)) {
        Check(false, "registering the autostart dir failed");
        rmdir(autostart.c_str());
        return;
    }

    auto write_script = [&](const std::string& path, const std::string& body) -> bool {
        int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (fd < 0) return false;
        std::string full = "#!/bin/sh\n" + body + "\n";
        bool ok = write(fd, full.data(), full.size()) == static_cast<ssize_t>(full.size());
        close(fd);
        return ok && chmod(path.c_str(), 0755) == 0;
    };
    char hook_tmpl[] = "/tmp/kinnector_e2e_lifecycle_hook_XXXXXX";
    char pm_tmpl[] = "/tmp/kinnector_e2e_pm_XXXXXX";
    int hf = mkstemp(hook_tmpl), pf = mkstemp(pm_tmpl);
    if (hf < 0 || pf < 0) { Check(false, "mkstemp (scripts) failed"); rmdir(autostart.c_str()); return; }
    close(hf); close(pf);
    std::string hook = hook_tmpl, pm = pm_tmpl;
    DeferUnlink(hook);
    DeferUnlink(pm);
    // The lifecycle hook: reads both stores and plants an autostart entry,
    // reporting each outcome as one bit of its exit code.
    if (!write_script(hook,
                      "rc=0\n"
                      "/bin/cat '" + locked + "' >/dev/null 2>&1 || rc=$((rc+4))\n"
                      "/bin/cat '" + observed + "' >/dev/null 2>&1 || rc=$((rc+2))\n"
                      "(echo evil > '" + planted + "') 2>/dev/null || rc=$((rc+1))\n"
                      "exit $rc") ||
        // The package manager: FORKS the hook (no `exec`), so the hook runs at
        // depth 2 and its cat at depth 3, like an npm postinstall.
        !write_script(pm, "/bin/sh '" + hook + "'\nexit $?")) {
        Check(false, "could not write the scripts");
        rmdir(autostart.c_str());
        return;
    }
    struct stat pm_st{};
    if (stat(pm.c_str(), &pm_st) != 0) { Check(false, "could not stat the package-manager script"); rmdir(autostart.c_str()); return; }
    for (uint64_t ino : {static_cast<uint64_t>(cat_st.st_ino), static_cast<uint64_t>(sh_st.st_ino),
                         static_cast<uint64_t>(pm_st.st_ino)}) {
        if (!loader.AddTrustedExecInode(ino, 2)) { Check(false, "AddTrustedExecInode failed"); rmdir(autostart.c_str()); return; }
    }

    // Control: the same hook with no install in progress does all three.
    int control_rc = RunExecutable(hook);
    Check(control_rc == 0,
          "control: outside an install the hook reads the locked store (its readers own it), reads the observed "
          "store and writes the autostart entry (got " + std::to_string(control_rc) + "; bits 4 locked, 2 observed, "
          "1 persistence)");
    unlink(planted.c_str());

    // A third-party package manager (no distro flag): its persistence rule denies.
    if (!loader.AddPackageManagerImage(pm_st.st_dev, pm_st.st_ino, /*flags=*/0)) {
        Check(false, "AddPackageManagerImage failed");
        rmdir(autostart.c_str());
        return;
    }
    int install_rc = RunExecutable(pm);
    Check(install_rc >= 0 && (install_rc & 4) != 0,
          "an install script is REFUSED the locked store, though its readers own it (got " + std::to_string(install_rc) + ")");
    Check(install_rc >= 0 && (install_rc & 2) == 0,
          "an install script READS the observed (audit-only) store - allowed, recorded, never refused (got " +
              std::to_string(install_rc) + ")");
    Check(install_rc >= 0 && (install_rc & 1) != 0,
          "an install script is still REFUSED the persistence write (got " + std::to_string(install_rc) + ")");
    struct stat planted_st{};
    Check(stat(planted.c_str(), &planted_st) != 0, "no autostart entry was planted by the install");

    loader.RemovePackageManagerImage(pm_st.st_dev, pm_st.st_ino);
    unlink(planted.c_str());
    rmdir(autostart.c_str());
}

// Persistence events (EVT_FILE_OPEN verdict 5/6/8) captured off the ring buffer by main's callback.
struct SeenPersistence {
    uint32_t pid;
    uint8_t verdict;
    uint8_t pkg;
    uint8_t op;
    std::string name;
    uint32_t parent = 0;
    uint64_t start = 0;
};
std::mutex g_persist_mu;
std::vector<SeenPersistence> g_persist;

// ProcessCreate events (EVT_PROCESS_CREATE) captured off the ring buffer by main's callback.
struct SeenExec {
    uint32_t pid;
    std::string image;
    uint8_t pkg;
    uint8_t verdicts;
};
std::mutex g_exec_mu;
std::vector<SeenExec> g_exec;

std::vector<SeenExec> ExecsOf(uint32_t pid) {
    std::lock_guard<std::mutex> lock(g_exec_mu);
    std::vector<SeenExec> out;
    for (const auto& e : g_exec)
        if (e.pid == pid) out.push_back(e);
    return out;
}

void CapturePersistence(const TelemetryEvent& ev) {
    if (static_cast<int>(ev.header.event_type) == 1) { // EVT_PROCESS_CREATE
        const auto& pc = ev.details.process_create;
        char image[513] = {0};
        memcpy(image, pc.child_image_path, 512);
        std::lock_guard<std::mutex> lock(g_exec_mu);
        if (g_exec.size() < 20000) g_exec.push_back({pc.child_pid, image, pc.pkg_lifecycle, pc.kernel_verdicts});
        return;
    }
    if (static_cast<int>(ev.header.event_type) != 16) return; // EVT_FILE_OPEN
    const uint8_t v = ev.details.file_open.verdict;
    if (v != 5 && v != 6 && v != 8) return;
    char name[513] = {0};
    memcpy(name, ev.details.file_open.file_path, 512);
    std::lock_guard<std::mutex> lock(g_persist_mu);
    g_persist.push_back({ev.header.pid, v, ev.details.file_open.pkg_lifecycle, ev.details.file_open.persist_op, name,
                         ev.details.file_open.parent_pid, ev.details.file_open.process_start_time});
}

// The first captured persistence event for `name` with operation `op`, waiting up to 3 s for it.
bool SeenPersistenceEvent(const std::string& name, uint8_t op, SeenPersistence* out) {
    for (int i = 0; i < 60; ++i) {
        {
            std::lock_guard<std::mutex> lock(g_persist_mu);
            for (const auto& s : g_persist) {
                if (s.name == name && s.op == op) {
                    if (out) *out = s;
                    return true;
                }
            }
        }
        usleep(50 * 1000);
    }
    return false;
}

// a snap refresh rewrote its mount units and the agent, which only learned of the change
// by re-reading the files, named their READERS (systemctl, systemd) as the writer. The kernel now
// reports every name-level write into a persistence location, by any process, with the writer's
// install mark and the operation; the decision is unchanged (an install's script is still refused).
void TestEveryPersistenceWriteNamesItsWriter(EbpfLoader& loader) {
    std::cout << "[e2e] persistence writes: every writer is reported, install scripts still refused..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }
    {
        // Earlier tests write persistence locations too (TestInstallScriptRefusedOnlyLockedStores plants
        // its own evil.desktop): only this test's events count.
        std::lock_guard<std::mutex> lock(g_persist_mu);
        g_persist.clear();
    }
    char drop_tmpl[] = "/tmp/kinnector_e2e_persist_drop_XXXXXX";
    char home_tmpl[] = "/tmp/kinnector_e2e_persist_home_XXXXXX";
    if (!mkdtemp(drop_tmpl) || !mkdtemp(home_tmpl)) { Check(false, "mkdtemp failed"); return; }
    const std::string drop = drop_tmpl, home = home_tmpl;
    struct stat drop_st{}, home_st{};
    if (stat(drop.c_str(), &drop_st) != 0 || stat(home.c_str(), &home_st) != 0 ||
        !loader.AddPersistenceDir(drop_st.st_dev, drop_st.st_ino) ||
        !loader.AddPersistenceName(home_st.st_dev, home_st.st_ino, ".bashrc")) {
        Check(false, "registering the persistence locations failed");
        return;
    }
    auto touch = [](const std::string& p) {
        int fd = open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) close(fd);
        return fd >= 0;
    };
    const uint32_t self = static_cast<uint32_t>(getpid());
    auto expect = [&](const std::string& name, uint8_t op, const std::string& what) {
        SeenPersistence s{};
        bool seen = SeenPersistenceEvent(name, op, &s);
        Check(seen, what + ": reported");
        if (seen) {
            Check(s.verdict == 8 && s.pid == self && s.pkg == 0,
                  what + ": as written by this process, in no install (verdict " + std::to_string(s.verdict) + ", pid " + std::to_string(s.pid) +
                      ", pkg " + std::to_string(s.pkg) + ")");
            Check(s.parent == static_cast<uint32_t>(getppid()) && s.start != 0,
                  what + ": with the writer's parent and start (parent " + std::to_string(s.parent) + ", start " + std::to_string(s.start) + ")");
        }
    };

    // ---- 1. A process in no install: every operation reported, none refused. ----
    Check(touch(drop + "/new.desktop"), "create in a drop dir is allowed");
    expect("new.desktop", 1, "create");
    Check(touch(drop + "/unit.tmp") && rename((drop + "/unit.tmp").c_str(), (drop + "/final.unit").c_str()) == 0, "atomic save in a drop dir is allowed");
    expect("final.unit", 3, "rename into (an atomic save, how snapd and dpkg write)");
    Check(symlink("/bin/true", (drop + "/link.desktop").c_str()) == 0, "symlink in a drop dir is allowed");
    expect("link.desktop", 6, "symlink");
    Check(unlink((drop + "/final.unit").c_str()) == 0, "unlink in a drop dir is allowed");
    expect("final.unit", 7, "unlink");
    Check(rename((drop + "/new.desktop").c_str(), (home + "/moved.desktop").c_str()) == 0, "rename away is allowed");
    expect("new.desktop", 4, "rename away");
    Check(touch(home + "/.bashrc"), "create of a registered file name is allowed");
    expect(".bashrc", 1, "create of a registered file name");
    Check(touch(home + "/other.txt"), "create of any other name beside it is allowed");
    Check(!SeenPersistenceEvent("other.txt", 1, nullptr), "an unregistered name in that folder is not a persistence write");

    // ---- 2. An install's script (third-party manager, no distro flag). ----
    const std::string planted = drop + "/hook-planted.desktop";
    char hook_tmpl[] = "/tmp/kinnector_e2e_persist_hook_XXXXXX";
    char pm_tmpl[] = "/tmp/kinnector_e2e_persist_pm_XXXXXX";
    int hf = mkstemp(hook_tmpl), pf = mkstemp(pm_tmpl);
    if (hf < 0 || pf < 0) { Check(false, "mkstemp (scripts) failed"); return; }
    close(hf);
    close(pf);
    const std::string hook = hook_tmpl, pm = pm_tmpl;
    DeferUnlink(hook);
    DeferUnlink(pm);
    auto write_script = [](const std::string& path, const std::string& body) {
        std::ofstream f(path);
        f << "#!/bin/sh\n" << body << "\n";
        f.close();
        return chmod(path.c_str(), 0755) == 0;
    };
    struct stat sh_st{}, pm_st{};
    if (!write_script(hook, "(echo evil > '" + planted + "') 2>/dev/null || exit 1\nexit 0") || !write_script(pm, "/bin/sh '" + hook + "'\nexit $?") ||
        stat("/bin/sh", &sh_st) != 0 || stat(pm.c_str(), &pm_st) != 0) {
        Check(false, "could not write the scripts");
        return;
    }
    for (uint64_t ino : {static_cast<uint64_t>(sh_st.st_ino), static_cast<uint64_t>(pm_st.st_ino)}) loader.AddTrustedExecInode(ino, 2);
    if (!loader.AddPackageManagerImage(pm_st.st_dev, pm_st.st_ino, /*flags=*/0)) { Check(false, "AddPackageManagerImage failed"); return; }

    int armed_rc = RunExecutable(pm);
    struct stat planted_st{};
    Check(armed_rc == 1 && stat(planted.c_str(), &planted_st) != 0, "armed: the install script is still refused the entry (got " + std::to_string(armed_rc) + ")");
    SeenPersistence s{};
    bool armed_seen = SeenPersistenceEvent("hook-planted.desktop", 1, &s) && s.verdict == 5 && (s.pkg & 0x3f) >= 2;
    Check(armed_seen, "armed: reported as refused, with the writer's install mark (verdict " + std::to_string(s.verdict) + ", pkg " + std::to_string(s.pkg) + ")");
    if (!armed_seen) {
        std::lock_guard<std::mutex> lock(g_persist_mu);
        for (const auto& e : g_persist)
            std::cout << "      captured: " << e.name << " op " << int(e.op) << " verdict " << int(e.verdict) << " pkg " << int(e.pkg) << " pid " << e.pid << std::endl;
    }

    {
        std::lock_guard<std::mutex> lock(g_persist_mu);
        g_persist.clear();
    }
    loader.SetConfigValue(kConfigBlockingEnabled, 0);
    int paused_rc = RunExecutable(pm);
    loader.SetConfigValue(kConfigBlockingEnabled, 1);
    Check(paused_rc == 0 && stat(planted.c_str(), &planted_st) == 0, "paused: nothing is refused (got " + std::to_string(paused_rc) + ")");
    s = {};
    Check(SeenPersistenceEvent("hook-planted.desktop", 1, &s) && s.verdict == 8 && (s.pkg & 0x3f) >= 2,
          "paused: still reported, with the install mark that would have refused it (verdict " + std::to_string(s.verdict) + ", pkg " +
              std::to_string(s.pkg) + ")");
    // the hook's `(echo evil > file)` is a subshell, a fork that writes and never execs, so
    // no ProcessCreate ever names it (antitheft read Claude Code's `>> ~/.bashrc` as "A process"). The
    // event names its parent, the hook's own shell, which did exec, and its start.
    {
        const bool writer_never_execd = ExecsOf(s.pid).empty();
        const auto parent_execs = ExecsOf(s.parent);
        Check(writer_never_execd && s.parent != 0 && s.parent != s.pid && !parent_execs.empty() && s.start != 0,
              "paused: a subshell that never exec'd is reported with its parent, which did (writer " + std::to_string(s.pid) + " execs " +
                  std::to_string(ExecsOf(s.pid).size()) + ", parent " + std::to_string(s.parent) + " execs " + std::to_string(parent_execs.size()) +
                  ", start " + std::to_string(s.start) + ")");
    }

    loader.RemovePackageManagerImage(pm_st.st_dev, pm_st.st_ino);
    for (const char* n : {"/hook-planted.desktop", "/link.desktop"}) unlink((drop + n).c_str());
    for (const char* n : {"/.bashrc", "/other.txt", "/moved.desktop"}) unlink((home + n).c_str());
    rmdir(drop.c_str());
    rmdir(home.c_str());
}

// an exec's events used to be emitted at the syscall, so a `$PATH` search produced one
// ProcessCreate per folder tried (56 events for one cargo launch), and the agent read the process's
// install mark from the map tens of ms to seconds later, after a short-lived process had exited.
// Now they are held until the exec succeeded and carry the kernel's verdict for it.
void* ExecFromThread(void*) {
    char* const argv[] = {const_cast<char*>("/bin/true"), nullptr};
    execv("/bin/true", argv);
    _exit(127);
}

void TestExecEventsOnlyForSuccessWithTheKernelsVerdict(EbpfLoader& loader) {
    std::cout << "[e2e] exec events: one per successful exec, carrying the kernel's install verdict..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }
    auto wait_events = [](uint32_t pid, size_t want) {
        for (int i = 0; i < 40 && ExecsOf(pid).size() < want; ++i) usleep(50 * 1000);
        usleep(200 * 1000); // and a little more, so any extra event would have arrived too
        return ExecsOf(pid);
    };

    // ---- 1. A $PATH search: three folders without `true`, then /bin. ----
    auto path_search = []() {
        pid_t child = fork();
        if (child == 0) {
            setenv("PATH", "/nonexistent-kinn-a:/nonexistent-kinn-b:/nonexistent-kinn-c:/bin:/usr/bin", 1);
            char* const argv[] = {const_cast<char*>("true"), nullptr};
            execvp("true", argv);
            _exit(127);
        }
        int st = 0;
        waitpid(child, &st, 0);
        return child;
    };
    auto misses_of = [](const std::vector<SeenExec>& v) {
        size_t n = 0;
        for (const auto& e : v)
            if (e.image.find("/nonexistent-kinn-") != std::string::npos) ++n;
        return n;
    };
    // Control: with the hold switched off (the old behaviour) every folder tried is an event.
    constexpr uint32_t kConfigExecAtSuccess = 13; // CONFIG_EXEC_AT_SUCCESS
    loader.SetConfigValue(kConfigExecAtSuccess, 0);
    pid_t control = path_search();
    loader.SetConfigValue(kConfigExecAtSuccess, 1);
    Check(misses_of(wait_events(static_cast<uint32_t>(control), 4)) == 3, "control: emitting at the syscall, each folder tried is an event");

    int status = 0;
    pid_t child = path_search();
    auto seen = wait_events(static_cast<uint32_t>(child), 1);
    size_t misses = misses_of(seen);
    Check(misses == 0, "a $PATH search: no event for the folders that do not have it (got " + std::to_string(misses) + ")");
    Check(seen.size() == 1 && seen[0].image.size() >= 5 && seen[0].image.compare(seen[0].image.size() - 5, 5, "/true") == 0,
          "a $PATH search: exactly one event, for the program that ran (got " + std::to_string(seen.size()) + ")");
    Check(!seen.empty() && (seen[0].verdicts & 0x01) && seen[0].pkg == 0,
          "an exec in no install carries the kernel's verdict: none (verdicts " + std::to_string(seen.empty() ? 0 : seen[0].verdicts) + ")");

    // ---- 2. The verdict for THIS exec: a package manager's own exec is the install root, its
    //         script's exec a descendant that ran other code. ----
    char hook_tmpl[] = "/tmp/kinnector_e2e_exec_hook_XXXXXX";
    char pm_tmpl[] = "/tmp/kinnector_e2e_exec_pm_XXXXXX";
    int hf = mkstemp(hook_tmpl), pf = mkstemp(pm_tmpl);
    if (hf < 0 || pf < 0) { Check(false, "mkstemp failed"); return; }
    close(hf);
    close(pf);
    const std::string hook = hook_tmpl, pm = pm_tmpl;
    DeferUnlink(hook);
    DeferUnlink(pm);
    {
        std::ofstream(hook) << "#!/bin/sh\nexit 0\n";
        std::ofstream(pm) << "#!/bin/sh\n/bin/sh '" << hook << "'\necho $$ > '" << pm << ".pid'\nexit 0\n";
    }
    chmod(hook.c_str(), 0755);
    chmod(pm.c_str(), 0755);
    DeferUnlink(pm + ".pid");
    struct stat pm_st{}, sh_st{};
    if (stat(pm.c_str(), &pm_st) != 0 || stat("/bin/sh", &sh_st) != 0 || !loader.AddPackageManagerImage(pm_st.st_dev, pm_st.st_ino, 0)) {
        Check(false, "registering the package manager failed");
        return;
    }
    loader.AddTrustedExecInode(sh_st.st_ino, 2);
    loader.AddTrustedExecInode(pm_st.st_ino, 2);
    {
        std::lock_guard<std::mutex> lock(g_exec_mu);
        g_exec.clear();
    }
    int rc = RunExecutable(pm);
    Check(rc == 0, "the package manager ran (got " + std::to_string(rc) + ")");
    std::ifstream pid_in(pm + ".pid");
    uint32_t pm_pid = 0;
    pid_in >> pm_pid;
    usleep(500 * 1000);
    bool root_seen = false, script_seen = false;
    {
        std::lock_guard<std::mutex> lock(g_exec_mu);
        for (const auto& e : g_exec) {
            if (!(e.verdicts & 0x01)) continue;
            if (e.pid == pm_pid && e.image == pm && (e.pkg & 0x3f) == 1) root_seen = true;
            if (e.image == "/bin/sh" && e.pid != pm_pid && (e.pkg & 0x3f) >= 2) script_seen = true;
        }
    }
    Check(root_seen, "the package manager's own exec carries the kernel's re-root to install root (depth 1)");
    Check(script_seen, "its script's exec carries the descendant mark, though it exited at once");
    loader.RemovePackageManagerImage(pm_st.st_dev, pm_st.st_ino);

    // ---- 3. A non-leader thread's exec (it becomes the leader): still emitted, as the process. ----
    pid_t threaded = fork();
    if (threaded == 0) {
        pthread_t t;
        if (pthread_create(&t, nullptr, ExecFromThread, nullptr) != 0) _exit(126);
        pause();
        _exit(125);
    }
    waitpid(threaded, &status, 0);
    seen = wait_events(static_cast<uint32_t>(threaded), 1);
    bool thread_exec = false;
    std::string got;
    for (const auto& e : seen) {
        if (e.image == "/bin/true" && (e.verdicts & 0x01)) thread_exec = true;
        got += " [" + e.image + " verdicts " + std::to_string(e.verdicts) + "]";
    }
    Check(thread_exec, "an exec from a non-leader thread is emitted as its process (got" + got + ")");
}

void TestOwnerImageCarriesIdentityThroughAnInterpreter(EbpfLoader& loader) {
    std::cout << "[e2e] owner image: identity survives script -> sh -> cat, and is withdrawn on removal..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }

    std::string resource;
    uint64_t res_ino, res_dev;
    if (!MakeTempFile(resource, res_ino, res_dev)) { Check(false, "could not create temp resource"); return; }
    DeferUnlink(resource);

    char script_tmpl[] = "/tmp/kinnector_e2e_owner_script_XXXXXX";
    int script_fd = mkstemp(script_tmpl);
    if (script_fd < 0) { Check(false, "mkstemp (owner script) failed"); return; }
    std::string script_body = "#!/bin/sh\nexec cat \"" + resource + "\" >/dev/null 2>&1\n";
    if (write(script_fd, script_body.data(), script_body.size()) != static_cast<ssize_t>(script_body.size())) {
        close(script_fd);
        Check(false, "could not write the owner script");
        return;
    }
    close(script_fd);
    std::string script = script_tmpl;
    DeferUnlink(script);
    if (chmod(script.c_str(), 0755) != 0) { Check(false, "chmod (owner script) failed"); return; }
    struct stat script_st{};
    if (stat(script.c_str(), &script_st) != 0) { Check(false, "could not stat the owner script"); return; }

    if (!loader.AddSensitiveInode(res_dev, res_ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); return; }
    // The SCRIPT owns the resource - no process ever runs with it as its exe.
    if (!loader.AddResourceOwnerExact(res_dev, res_ino, script_st.st_dev, script_st.st_ino)) {
        Check(false, "AddResourceOwnerExact(script) failed");
        return;
    }
    // OWNER_PROTECTED, mirroring kinnector.bpf.c's own define. Nothing here
    // maps executable memory, so this test measures identity, not the
    // self-injection switch.
    const uint32_t kOwnerProtected = 0x1u;
    if (!loader.AddOwnerImage(script_st.st_dev, script_st.st_ino, kOwnerProtected)) {
        Check(false, "AddOwnerImage failed");
        return;
    }

    // Every actor must be pre-classified Verified: file_open denies a
    // default-untrusted process on a sensitive inode before the owner check
    // is reached, which would make both results below read "denied" for a
    // reason that has nothing to do with chain identity.
    struct stat sh_st{}, cat_st{};
    if (stat("/bin/sh", &sh_st) != 0 || stat("/bin/cat", &cat_st) != 0) {
        Check(false, "could not stat /bin/sh and /bin/cat");
        return;
    }
    for (uint64_t ino : {static_cast<uint64_t>(sh_st.st_ino), static_cast<uint64_t>(cat_st.st_ino),
                         static_cast<uint64_t>(script_st.st_ino)}) {
        if (!loader.AddTrustedExecInode(ino, 2)) { Check(false, "AddTrustedExecInode failed"); return; }
    }

    int rc = RunExecutable(script);
    Check(rc == 0, "a registered owner script reads its own resource through sh and cat (got " + std::to_string(rc) + ")");

    if (!loader.RemoveOwnerImage(script_st.st_dev, script_st.st_ino)) {
        Check(false, "RemoveOwnerImage failed");
        return;
    }
    rc = RunExecutable(script);
    Check(rc != 0, "a fresh launch is denied once the owner image is withdrawn (got " + std::to_string(rc) + ")");
}

// "add a new package-manager binary via config
// only, confirm it's recognized as an install-context root without a kernel-object
// rebuild." The probe binary's name/path matches none of the old hardcoded
// is_install_binary() substrings (npm/yarn/pip/...), so under the pre-Phase-4 code
// this scenario was structurally impossible without editing kinnector.bpf.c and
// rebuilding. Signal used: bprm_creds_for_exec's install_binary_map hit sets
// TREE_INSTALL_CONTEXT, and file_open's sensitive-file deny is `threshold==1 OR
// is_install_session()` -- so even though probe is independently classified
// threshold=2 ("verified", proven to bypass this same deny on its own by
// TestSensitiveInodeReadAllowForClassifiedProcess above), registering it in
// install_binary_map via UpdateMapEntry alone (no .bpf.c change) must still
// deny it here through the is_install_session() branch specifically.
void TestInstallBinaryMapConfigDrivenDetection(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] install_binary_map: config-only registration recognized as install-context root..." << std::endl;
    if (!loader.UpdateMapEntry(BpfMapType::InstallBinaryMap, /*pid unused*/0, probe_ino, 1)) {
        Check(false, "UpdateMapEntry(InstallBinaryMap) failed");
        return;
    }

    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); unlink(path.c_str()); return; }

    int rc = RunProbe("open_read", path);
    DeferUnlink(path);
    Check(rc == EACCES, "open() denied with EACCES via config-only install-context marking (got " + std::to_string(rc) + ")");
}

// Regression for the thread-key bug in is_install_session() (fixed 6449762;
// flagged as unaudited by 92c2f26, which fixed the same defect in
// ptrace_access_check/task_kill).
//
// pid_tree_type_map is written by tracepoint_sched_process_fork keyed on the
// GROUP LEADER's start_time - a new thread's clone() rewrites that same key, so
// no thread ever gets an entry of its own. Both helpers looked the current
// process up with the CALLING THREAD's key, so they matched from the main
// thread only.
//
// This exercises the direction that is a HOLE rather than an over-denial, which
// is the reason the defect was worth fixing even though the visible symptom
// (92c2f26's six cargo failures) came from the other direction. file_open's
// sensitive-file deny is gated on `(threshold && *threshold > 0) ||
// is_install_session()`, and BOTH halves of that condition are thread-sensitive:
// the threshold lookup uses the same thread-level key. So on the previous
// object a worker thread of an install-context process failed both halves at
// once, skipped the whole block, and read a file its own main thread was
// correctly denied. That is a package-manager descendant reading a protected
// file by the trivial expedient of doing it on a thread.
//
// Must run after TestInstallBinaryMapConfigDrivenDetection, which is what
// registers ProbePath()'s inode in install_binary_map (so exec'ing it stamps
// TREE_INSTALL_CONTEXT) and which has already proven the main-thread deny in
// isolation. By this point the probe is also independently classified
// threshold=2, which is what makes this test sharp: 2 is not 1, so the
// `*threshold == 1` clause cannot deny, and is_install_session() is the only
// thing left that can.
void TestInstallContextAppliesToWorkerThreads(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] install-context deny applies to a WORKER THREAD too, not just the main thread..."
              << std::endl;

    if (!loader.UpdateMapEntry(BpfMapType::InstallBinaryMap, /*pid unused*/0, probe_ino, 1)) {
        Check(false, "UpdateMapEntry(InstallBinaryMap) failed");
        return;
    }

    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) {
        Check(false, "AddSensitiveInode failed");
        unlink(path.c_str());
        return;
    }
    DeferUnlink(path);

    std::string result_path = path + ".threadresult";
    // Plain fork+exec: unlike the admin-session fixture this process is our own
    // child, so it can be waited for. The probe writes both verdicts to
    // result_path (rename()d into place, so a partial line is never read).
    pid_t pid = fork();
    if (pid < 0) { Check(false, "fork failed"); return; }
    if (pid == 0) {
        execl(ProbePath(), ProbePath(), "thread_open_read", path.c_str(),
              result_path.c_str(), (char*)nullptr);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);

    std::string line;
    FILE* f = fopen(result_path.c_str(), "r");
    if (f) {
        char buf[128] = {0};
        if (fgets(buf, sizeof(buf), f)) line = buf;
        fclose(f);
    }
    unlink(result_path.c_str());

    int main_errno = -1, worker_errno = -1;
    if (line.empty() || sscanf(line.c_str(), "main=%d worker=%d", &main_errno, &worker_errno) != 2) {
        Check(false, "the thread probe produced no parseable result (exit " +
                         std::to_string(WEXITSTATUS(status)) + ")");
        return;
    }

    // The control. If this is not a deny, the install-context marking did not
    // take and the worker assertion below would be meaningless.
    Check(main_errno == EACCES,
          "control: the install-context process's main thread is denied (got " +
              std::to_string(main_errno) + ")");
    Check(worker_errno == EACCES,
          "REGRESSION 6449762: a worker thread of that same process is denied too (got " +
              std::to_string(worker_errno) + ")");
}

// , testing strategy item 2: the direct
// regression test for the bug the phase fixes. G1 execs the install_binary_map-
// registered probe (correctly self-marking TREE_INSTALL_CONTEXT) as PID 1 of a
// fresh PID namespace, then exits. G2 -- an unrelated process with its own
// distinct start_time, exec'ing a *copy* of the probe that is independently
// classified threshold=2 but NOT itself install-binary-registered -- is also
// observed as PID 1 of its own fresh namespace. With the pre-Phase-2 raw-pid
// key, G2 would incorrectly find G1's stale entry at key=1 and inherit
// TREE_INSTALL_CONTEXT, getting denied by file_open's `... OR
// is_install_session()` clause despite being independently verified and not
// itself an install binary. With the (pid, start_time) key, G2's lookup misses
// (different start_time), so it isn't wrongly denied.
// Leaves a recognisable pattern where the next call's frame will be, so a key whose padding is
// not zeroed carries garbage deterministically instead of whatever the stack happened to hold.
__attribute__((noinline)) void DirtyStack() {
    volatile unsigned char junk[4096];
    for (size_t i = 0; i < sizeof(junk); ++i) junk[i] = 0xA5;
}

// The agent reads pkg_lifecycle_pids back (`lookup_pkg_lifecycle`) for its re-root decision: the
// kernel's RAN_OTHER_CODE taint, and whether a process is already an install's root. The lookup
// built its process_key with a positional initializer, so the padding after `pid` was stack
// garbage and the hash never matched: every process read as absent (found from the
// agent logging "launched from inside a lifecycle script" for processes that were the root).
// A pid no process has, so nothing real gains install standing; removed again at the end.
void TestPkgLifecycleLookupReadsBackWhatWasWritten(EbpfLoader& loader) {
    std::cout << "[e2e] pkg_lifecycle_pids: a lookup finds what was written..." << std::endl;
    const uint32_t pid = 0x3ffffff0u;
    const uint64_t start = 0x123456789abcull;
    Check(loader.UpdateMapEntry(BpfMapType::PkgLifecyclePids, pid, start, 0x41), "pkg lifecycle: entry written");
    DirtyStack();
    int got = loader.LookupPkgLifecycle(pid, start);
    Check(got == 0x41, "pkg lifecycle: the lookup reads the written value back (got " + std::to_string(got) + ")");
    DirtyStack();
    int other = loader.LookupPkgLifecycle(pid, start + 1);
    Check(other == -1, "pkg lifecycle: another start time of the same pid is absent (got " + std::to_string(other) + ")");
    loader.DeleteMapEntry(BpfMapType::PkgLifecyclePids, pid, start);
    DirtyStack();
    Check(loader.LookupPkgLifecycle(pid, start) == -1, "pkg lifecycle: absent after the delete");
}

void TestPidReuseInstallContextNotInherited(EbpfLoader& loader) {
    std::cout << "[e2e] pid_tree_type_map: PID-reuse does not leak install-context across processes..." << std::endl;

    // G1: plant TREE_INSTALL_CONTEXT at (ns-relative pid=1, G1's start_time) by
    // actually exec'ing the install-binary-registered probe. Target file is a
    // plain unregistered temp file -- only the exec-time marking matters here.
    std::string decoy_path;
    uint64_t decoy_ino, decoy_dev;
    if (!MakeTempFile(decoy_path, decoy_ino, decoy_dev)) { Check(false, "could not create decoy resource for G1"); return; }
    int g1_rc = RunProbeInFreshPidNs(ProbePath(), "open_read", decoy_path);
    DeferUnlink(decoy_path);
    if (g1_rc != 0) {
        // probe_ino is already threshold=2 (verified) by this point in the
        // suite and the decoy file isn't sensitive, so G1's own open() should
        // succeed independent of the install-context marking under test.
        Check(false, "G1 (install-context planter) did not exit cleanly (got " + std::to_string(g1_rc) + ")");
        return;
    }

    // G2: a genuinely different exec target (distinct inode, so it can never
    // hit install_binary_map on its own merits), independently verified.
    std::string probe_copy_path;
    uint64_t probe_copy_ino;
    if (!CopyProbeBinary(probe_copy_path, probe_copy_ino)) { Check(false, "could not create probe copy for G2"); return; }
    if (!loader.AddTrustedExecInode(probe_copy_ino, /*trust_level=*/2)) {
        Check(false, "AddTrustedExecInode(probe copy) failed");
        unlink(probe_copy_path.c_str());
        return;
    }

    std::string target_path;
    uint64_t target_ino, target_dev;
    if (!MakeTempFile(target_path, target_ino, target_dev)) {
        Check(false, "could not create target resource for G2");
        unlink(probe_copy_path.c_str());
        return;
    }
    if (!loader.AddSensitiveInode(target_dev, target_ino, /*category=*/1)) {
        Check(false, "AddSensitiveInode(target) failed");
        unlink(probe_copy_path.c_str());
        unlink(target_path.c_str());
        return;
    }

    int g2_rc = RunProbeInFreshPidNs(probe_copy_path.c_str(), "open_read", target_path);
    DeferUnlink(probe_copy_path);
    DeferUnlink(target_path);
    Check(g2_rc == 0, "G2 (unrelated, also observed as pid=1) not denied by G1's install-context marker (got " + std::to_string(g2_rc) + ")");
}

// A ROOT-OWNED copy of the probe, which is what a configured owner binary
// looks like in production (a package-manager-installed application) and what
// the two tests below need in order to measure anything at all.
//
// ProbePath() itself is built by the developer's own uid, and mmap_file's
// untrusted-image deny refuses a protected process a PROT_EXEC
// mapping of a non-root-owned file unless its exec_origin chain vouches for
// it. Before the FIX below, protected_owner_binaries' stamping path never
// wrote an exec_origin entry, so nothing could vouch, and the ELF loader hit
// that deny while mapping the binary's own text segment - past
// load_elf_binary's point of no return, so the process died with SIGSEGV
// before the test's attacker ever ran. ptrace of the resulting zombie then
// returned EPERM from __ptrace_attach's exit_state check - not our EACCES -
// and the test read as "enforcement is broken" when the target had simply
// never lived. FIXED: bprm_creds_for_exec's
// protected_owner_binaries branch now seeds exec_origin_map for itself too,
// the same shape the owner_images branch already did - see
// TestProtectedOwnerBinaryUserOwnedSurvivesStartup below, which proves it
// directly with a real non-root-owned copy. These next two tests keep using
// a root-owned copy anyway, deliberately: they measure ptrace/kill behavior,
// not startup survival, and a root-owned file was never in mmap_file's
// untrusted-image path to begin with, so it isolates exactly what they mean
// to measure.
bool MakeRootOwnedProbeCopy(std::string& path_out, uint64_t& inode_out) {
    if (!CopyProbeBinary(path_out, inode_out)) return false;
    // Explicit rather than incidental: the copy is already root-owned because
    // this suite runs as root, but the tests below depend on that fact, so it
    // is stated instead of assumed.
    if (chown(path_out.c_str(), 0, 0) != 0) {
        perror("chown (root-owned probe copy)");
        return false;
    }
    return true;
}

// FIXED: the exact shape the SIGSEGV bug needed to
// fire - a NON-root-owned protected_owner_binaries entry, the real-world
// case (an AppImage, anything under $HOME). uid 65534 ("nobody"), same
// convention the untrusted-.so tests further down this file already use for
// "a real non-root owner." Before the fix, this process never survived its
// own startup; the assertion below is what proves it now does.
void TestProtectedOwnerBinaryUserOwnedSurvivesStartup(EbpfLoader& loader) {
    std::cout << "[e2e] protected_owner_binaries: a user-owned protected binary survives its own startup..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }

    std::string probe_path;
    uint64_t probe_ino = 0;
    if (!CopyProbeBinary(probe_path, probe_ino)) { Check(false, "could not create a probe copy"); return; }
    DeferUnlink(probe_path);
    if (chown(probe_path.c_str(), 65534, static_cast<gid_t>(-1)) != 0) {
        Check(false, "chown (non-root probe copy) failed");
        return;
    }

    if (!loader.UpdateMapEntry(BpfMapType::ProtectedOwnerBinaries, /*pid unused*/0, probe_ino, 1)) {
        Check(false, "UpdateMapEntry(ProtectedOwnerBinaries) failed");
        return;
    }

    pid_t pid = StartProbeSleeping(probe_path.c_str(), /*seconds=*/2);
    if (pid <= 0) { Check(false, "could not start the probe"); return; }
    usleep(200000); // let bprm_creds_for_exec's Phase 5 stamp (and this fix) land

    int liveness = 0;
    Check(waitpid(pid, &liveness, WNOHANG) == 0,
          "BEFORE THIS FIX this failed every time: the process is dead on startup "
          "(mmap_file denied its own text segment's PROT_EXEC mapping for lack of an "
          "exec_origin entry, past execve's point of no return -> a bare SIGSEGV, not "
          "a clean exec failure)");

    kill(pid, SIGKILL);
    waitpid(pid, nullptr, 0);
}

// the load-bearing case -- a configured owner
// process (stand-in: the probe binary, registered in protected_owner_binaries)
// must be denied ptrace_attach from an unrelated, unprivileged process under
// MODE_ANTITHEFT.
//
// SIGKILL is deliberately NOT denied, and the assertion below now proves that
// on purpose rather than by omission. Antitheft protects what executes inside
// a process and what it can reach on disk; making a process unkillable
// defends availability rather than secrets - killing a wallet steals nothing
// from it - while taking away the user's own force-quit of their own
// application.
void TestProtectedOwnerPtraceKillDeniedUnderAntitheft(EbpfLoader& loader, const std::string& owner_probe, uint64_t owner_ino) {
    std::cout << "[e2e] protected_owner_pids: unrelated process denied ptrace, still killable, under MODE_ANTITHEFT..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }
    if (!loader.UpdateMapEntry(BpfMapType::ProtectedOwnerBinaries, /*pid unused*/0, owner_ino, 1)) {
        Check(false, "UpdateMapEntry(ProtectedOwnerBinaries) failed");
        return;
    }

    pid_t owner_pid = StartProbeSleeping(owner_probe.c_str(), /*seconds=*/2);
    if (owner_pid <= 0) { Check(false, "could not start owner (sleeper) process"); return; }
    usleep(200000); // let bprm_creds_for_exec's Phase 5 stamp land before attacking

    // The whole measurement is meaningless against a process that died on
    // startup: ptrace of a zombie returns EPERM from __ptrace_attach, which
    // is indistinguishable from "the hook did not fire" unless it is checked
    // for. This assert is what turns that silent misread into a clear
    // failure - it is how the SIGSEGV above was found in the first place.
    int liveness = 0;
    Check(waitpid(owner_pid, &liveness, WNOHANG) == 0,
          "the protected owner process is still alive when the attack starts (a dead target makes every result below meaningless)");

    int ptrace_rc = AttackerPtraceAttach(owner_pid);
    Check(ptrace_rc == EACCES, "ptrace_attach denied with EACCES (got " + std::to_string(ptrace_rc) + ")");

    int kill_rc = AttackerKill(owner_pid, SIGKILL);
    Check(kill_rc == 0, "SIGKILL allowed against a protected owner (got " + std::to_string(kill_rc) + ")");

    // The ptrace attack failed; the kill succeeded, so reap the corpse rather
    // than waiting out the sleep.
    waitpid(owner_pid, nullptr, 0);
}

// Regression baseline for the case above / MODE_WARDEN pass-through: with the
// same protected_owner_binaries registration in place, a *new* owner process
// exec'd under MODE_WARDEN must never get stamped into protected_owner_pids in
// the first place (bprm_creds_for_exec's Phase 5 stamping is itself gated
// is_antitheft_mode()) -- so the identical attack that was denied above must
// succeed here, proving Warden's task_kill/ptrace_access_check behavior for a
// process that merely happens to match protected_owner_binaries is unchanged.
void TestProtectedOwnerKillAllowedUnderWarden(EbpfLoader& loader, const std::string& owner_probe) {
    std::cout << "[e2e] protected_owner_pids: SIGKILL allowed under MODE_WARDEN (regression baseline)..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeWarden)) {
        Check(false, "SetConfigValue(MODE_WARDEN) failed");
        return;
    }

    pid_t owner_pid = StartProbeSleeping(owner_probe.c_str(), /*seconds=*/5);
    if (owner_pid <= 0) { Check(false, "could not start owner (sleeper) process"); return; }
    usleep(200000);

    // Same matched-pair reasoning as the antitheft case: this baseline only
    // means "the kill was allowed" if there was something alive to kill.
    int liveness = 0;
    Check(waitpid(owner_pid, &liveness, WNOHANG) == 0,
          "the owner process is still alive under MODE_WARDEN when the attack starts");

    int kill_rc = AttackerKill(owner_pid, SIGKILL);
    Check(kill_rc == 0, "SIGKILL succeeded under MODE_WARDEN despite protected_owner_binaries registration (got " + std::to_string(kill_rc) + ")");
    waitpid(owner_pid, nullptr, 0); // reap -- exits immediately once SIGKILL lands
}

// Agent-core tamper resistance: a process that has set
// CONFIG_OWN_PID (production: antitheftd's own pid, set once at startup) is
// unkillable/unptraceable by anyone but itself, deployment-mode-independent
// (this check has no is_antitheft_mode() gate - CONFIG_OWN_PID being set at
// all is the activation signal). This process (the test harness) stands in
// for "the daemon" here - it sets its OWN pid as CONFIG_OWN_PID, then a
// genuinely separate forked process attacks it via the same
// AttackerKill/AttackerPtraceAttach helpers used against protected owners
// above.
void TestOwnPidUnkillableByAnyoneButItself(EbpfLoader& loader) {
    std::cout << "[e2e] CONFIG_OWN_PID: SIGKILL/SIGSTOP/ptrace denied from another process, self-signal still works..." << std::endl;
    pid_t self = getpid();
    if (!loader.SetConfigValue(kConfigOwnPid, static_cast<uint32_t>(self))) {
        Check(false, "SetConfigValue(CONFIG_OWN_PID) failed");
        return;
    }

    int kill_rc = AttackerKill(self, SIGKILL);
    Check(kill_rc == EPERM, "SIGKILL from another process denied with EPERM (got " + std::to_string(kill_rc) + ")");

    int stop_rc = AttackerKill(self, SIGSTOP);
    Check(stop_rc == EPERM, "SIGSTOP from another process denied with EPERM (got " + std::to_string(stop_rc) + ") - SIGSTOP bypasses the target's own signal disposition, so this must be caught here, not by the process itself");

    int ptrace_rc = AttackerPtraceAttach(self);
    Check(ptrace_rc == EACCES, "ptrace_attach from another process denied with EACCES (got " + std::to_string(ptrace_rc) + ")");

    // The harness process is trivially still running to observe this (a real
    // SIGKILL/SIGSTOP would have stopped it), but the real proof is the
    // errnos above, not this - kept as a sanity check that nothing upstream
    // silently reaped/froze this process another way.
    Check(kill(self, 0) == 0, "self-signal (kill(getpid(), 0)) still succeeds - the daemon's own authenticated self-shutdown path depends on this");

    // Reset - later tests in this same process must not inherit this
    // process's pid as "the protected one".
    loader.SetConfigValue(kConfigOwnPid, 0);

    // Audit-only mode: this self-defense now honors
    // CONFIG_BLOCKING_ENABLED too (kinnector_lsm_hooks_creds.h's
    // ptrace_access_check/task_kill), so a paused deployment
    // (POST /api/v1/enforcement/pause) really means "nothing enforces",
    // the daemon's own tamper resistance included - deliberate, at the
    // user's request, and a real trade against the original "unconditional
    // even against root" guarantee. Verified against a genuinely separate,
    // disposable victim process (not `self` - a real SIGKILL is exercised
    // here and must not take down this test harness).
    std::cout << "[e2e] CONFIG_OWN_PID: all three denials fall away once blocking is paused..." << std::endl;
    if (!loader.SetConfigValue(kConfigBlockingEnabled, 0)) {
        Check(false, "SetConfigValue(BLOCKING_ENABLED, 0) failed");
    } else {
        pid_t victim = fork();
        if (victim < 0) {
            Check(false, "fork (own-pid audit-only victim) failed");
        } else if (victim == 0) {
            pause();
            _exit(0);
        } else {
            usleep(50000); // let the child actually reach pause()
            if (!loader.SetConfigValue(kConfigOwnPid, static_cast<uint32_t>(victim))) {
                Check(false, "SetConfigValue(CONFIG_OWN_PID, victim) failed");
            }
            int ptrace_rc = AttackerPtraceAttach(victim);
            Check(ptrace_rc == 0, "ptrace_attach no longer denied once blocking is paused (got " + std::to_string(ptrace_rc) + ")");
            int stop_rc = AttackerKill(victim, SIGSTOP);
            Check(stop_rc == 0, "SIGSTOP no longer denied once blocking is paused (got " + std::to_string(stop_rc) + ")");
            AttackerKill(victim, SIGCONT);
            int kill_rc = AttackerKill(victim, SIGKILL);
            Check(kill_rc == 0, "SIGKILL no longer denied once blocking is paused (got " + std::to_string(kill_rc) + ")");
            int status = 0;
            waitpid(victim, &status, 0);
            loader.SetConfigValue(kConfigOwnPid, 0);
        }
        loader.SetConfigValue(kConfigBlockingEnabled, 1);
    }
}

// Agent-core tamper resistance, BPF pin-directory leg: core_pin_guard_map is
// populated by THIS SAME loader's own LoadAndAttachLsm() call in main(),
// with dir_id = /sys/fs/bpf/warden's (dev,ino) and owner_pid = this test
// harness's own getpid() (it is the process that loaded the object - see
// ebpf_loader.cpp's population code, right before LoadAndAttachLsm's final
// return). So a genuinely separate forked process must be denied removing
// an existing pin, while the harness process's own later cleanup
// (SafeShutdown -> ForceUnpinAllLinks, run from main() after every test)
// stays unaffected - proving that self-directed teardown, not just the
// external attack, is exercised by this same test run.
void TestPinDirectoryDeniesRemovalFromAnotherProcess(EbpfLoader& loader) {
    std::cout << "[e2e] core_pin_guard_map: unlink() on a live pin denied from another process..." << std::endl;
    const char* pin_path = "/sys/fs/bpf/warden/task_kill";
    struct stat st{};
    if (stat(pin_path, &st) != 0) {
        Check(false, std::string("expected pin not present, cannot run this test: ") + pin_path);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        Check(false, "fork (unlink attacker) failed");
        return;
    }
    if (pid == 0) {
        _exit(unlink(pin_path) == 0 ? 0 : errno);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    Check(rc == EPERM, "unlink() of a live pin from another process denied with EPERM (got " + std::to_string(rc) + ")");
    Check(stat(pin_path, &st) == 0, "the pin is still present after the denied unlink attempt");

    // Audit-only mode: this guard now honors
    // CONFIG_BLOCKING_ENABLED too (kinnector_container_lsm_hooks.h's
    // inode_unlink) - a paused deployment can have its own pins removed,
    // the same trade as CONFIG_OWN_PID's self-defense above. A different
    // pin than the positive case above, purely so this leaves a real file
    // behind to unlink - the guard itself is keyed on the whole pin
    // directory (core_pin_guard_map's dir_id), not on individual files, so
    // either path exercises the same check.
    const char* pin_path2 = "/sys/fs/bpf/warden/path_chmod";
    struct stat st2{};
    if (stat(pin_path2, &st2) != 0) {
        Check(false, std::string("expected pin not present, cannot run audit-only half: ") + pin_path2);
        return;
    }
    if (!loader.SetConfigValue(kConfigBlockingEnabled, 0)) {
        Check(false, "SetConfigValue(BLOCKING_ENABLED, 0) failed");
        return;
    }
    pid_t pid2 = fork();
    if (pid2 < 0) {
        Check(false, "fork (audit-only unlink attacker) failed");
    } else if (pid2 == 0) {
        _exit(unlink(pin_path2) == 0 ? 0 : errno);
    } else {
        int status2 = 0;
        waitpid(pid2, &status2, 0);
        int rc2 = WIFEXITED(status2) ? WEXITSTATUS(status2) : -1;
        Check(rc2 == 0, "unlink() of a live pin from another process succeeds once blocking is paused (got " + std::to_string(rc2) + ")");
    }
    loader.SetConfigValue(kConfigBlockingEnabled, 1);
}

// Storage-dir write/mmap protection (universal - no corpus
// data): the load-bearing case for both new mechanisms this plan adds -
// file_permission's `.so`-write gate (protected_dir_map/
// protected_dir_owner_exact via AddDirOwner) and mmap_file's widened,
// always-on untrusted-.so synchronous deny (storage_dir_verdict
// as its third trust source). Two distinct probe-binary copies stand in for
// "the app" (registered as both the storage dir's owner AND a real
// antitheft-protected owner image) and "an unrelated attacker" - the SAME
// technique TestOwnerImageChainIdentity uses above for its own owner/
// non-owner distinction.
void TestStorageDirWriteProtectionAndUntrustedSoMmapDeny(EbpfLoader& loader) {
    std::cout << "[e2e] storage-dir .so write protection + untrusted-.so mmap deny under MODE_ANTITHEFT..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) { Check(false, "SetConfigValue(MODE_ANTITHEFT) failed"); return; }
    if (!loader.SetConfigValue(kConfigBlockingEnabled, 1)) { Check(false, "SetConfigValue(BLOCKING_ENABLED) failed"); return; }

    char dir_tmpl[] = "/tmp/kinnector_e2e_storagedir_XXXXXX";
    char* dir = mkdtemp(dir_tmpl);
    if (!dir) { Check(false, "mkdtemp (storage dir) failed"); return; }
    struct stat dir_st{};
    if (stat(dir, &dir_st) != 0) { Check(false, "stat (storage dir) failed"); return; }

    std::string owner_path;
    uint64_t owner_ino_unused;
    if (!CopyProbeBinary(owner_path, owner_ino_unused)) { Check(false, "CopyProbeBinary (owner) failed"); return; }
    struct stat owner_st{};
    if (stat(owner_path.c_str(), &owner_st) != 0) { Check(false, "stat (owner probe) failed"); return; }

    std::string attacker_path;
    uint64_t attacker_ino_unused;
    if (!CopyProbeBinary(attacker_path, attacker_ino_unused)) { Check(false, "CopyProbeBinary (attacker) failed"); return; }

    if (!loader.AddDirOwner(dir_st.st_dev, dir_st.st_ino, owner_st.st_dev, owner_st.st_ino)) {
        Check(false, "AddDirOwner failed");
        return;
    }

    // --- file_permission: .so write gate. ---
    std::string evil_so = std::string(dir) + "/evil.so";
    int deny_rc = RunProbeAt(attacker_path.c_str(), "open_write_create", evil_so);
    Check(deny_rc == EACCES, "non-owner denied creating a .so file inside a protected storage dir (got " + std::to_string(deny_rc) + ")");

    std::string plain_txt = std::string(dir) + "/notes.txt";
    int plain_rc = RunProbeAt(attacker_path.c_str(), "open_write_create", plain_txt);
    Check(plain_rc == 0, "non-owner still allowed writing an ordinary (non-.so) file into the same dir (got " + std::to_string(plain_rc) + ")");

    std::string good_so = std::string(dir) + "/good.so";
    int allow_rc = RunProbeAt(owner_path.c_str(), "open_write_create", good_so);
    Check(allow_rc == 0, "recognized owner allowed creating a .so file inside its own storage dir (got " + std::to_string(allow_rc) + ")");

    // --- mmap_file: untrusted-.so synchronous deny + storage-dir allowance. ---
    // Real antitheft-protected owner image registration (mirrors
    // ownership.rs's register_link -> AddOwnerImage exactly), so
    // is_protected_owner_process() and the exec_origin_map chain-uid check
    // are both real, not simulated.
    const uint32_t kOwnerProtected = 0x1u;
    if (!loader.AddOwnerImage(owner_st.st_dev, owner_st.st_ino, kOwnerProtected)) {
        Check(false, "AddOwnerImage (mmap owner) failed");
        return;
    }

    // A user-owned (untrusted) library file OUTSIDE any storage dir - the
    // classic LD_PRELOAD=/tmp/evil.so shape.
    std::string untrusted_so;
    uint64_t untrusted_ino, untrusted_dev;
    if (!MakeTempFile(untrusted_so, untrusted_ino, untrusted_dev)) { Check(false, "MakeTempFile (untrusted .so) failed"); return; }
    DeferUnlink(untrusted_so);
    if (chown(untrusted_so.c_str(), 65534, static_cast<gid_t>(-1)) != 0) { Check(false, "chown (untrusted .so) failed"); return; }

    int mmap_deny_rc = RunProbeAt(owner_path.c_str(), "mmap_exec", untrusted_so);
    Check(mmap_deny_rc == EACCES, "an untrusted foreign .so outside any storage dir is denied at mmap(PROT_EXEC) (got " + std::to_string(mmap_deny_rc) + ")");

    // The same kind of user-owned file, but living INSIDE the app's own
    // (write-protected) storage dir, loads fine - no per-app corpus data
    // named it, the directory registration alone is what vouches for it
    // (the Widevine-CDM-style case this plan was built to fix).
    // Created via the OWNER identity's own open_write_create, not a raw
    // harness-side write - the harness's own exe is not a registered owner
    // of this dir either, so a direct write here would (correctly) be
    // denied by the very gate this test just proved above.
    std::string trusted_so = std::string(dir) + "/widevine.so";
    int fixture_rc = RunProbeAt(owner_path.c_str(), "open_write_create", trusted_so);
    if (fixture_rc != 0) { Check(false, "could not create trusted .so fixture as its owner (got " + std::to_string(fixture_rc) + ")"); return; }
    DeferUnlink(trusted_so);
    if (chown(trusted_so.c_str(), 65534, static_cast<gid_t>(-1)) != 0) { Check(false, "chown (trusted .so) failed"); return; }

    int mmap_allow_rc = RunProbeAt(owner_path.c_str(), "mmap_exec", trusted_so);
    Check(mmap_allow_rc == 0, "a user-owned .so living inside the app's own storage dir loads fine (got " + std::to_string(mmap_allow_rc) + ")");
}

// Modified-system-library deny:
// mmap_file's untrusted-.so deny trusts any ROOT-owned file (rule 1), which is
// what a package-installed system library is - so a trojaned one passed. The
// agent now fills `modified_system_libraries` with the (dev, ino) of a library
// whose content no longer matches its package manager's record, and a hit is
// refused through the same deny, ahead of all three trust rules. Cases:
//   control  - root-owned library NOT in the set loads (rule 1 still trusts it)
//   deny     - the same library, once in the set, is refused with EACCES
//   remove   - taking it out of the set restores the load
//   clear    - ClearModifiedLibraries() restores it too (the fail-open path)
//   rule 3   - a user-owned library in the app's own storage dir (trusted by
//              the storage-dir rule) is refused as well once it is in the set
//   scope    - a process that is NOT a protected owner still maps it (the
//              deny is for protected apps only)
// Every case uses the real registration path (AddOwnerImage / AddDirOwner) so
// is_protected_owner_process() and the trust rules are real, not simulated.
void TestModifiedLibraryDeny(EbpfLoader& loader) {
    std::cout << "[e2e] modified_system_libraries: a modified root-owned library is refused to a protected owner..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) { Check(false, "SetConfigValue(MODE_ANTITHEFT) failed"); return; }
    if (!loader.SetConfigValue(kConfigBlockingEnabled, 1)) { Check(false, "SetConfigValue(BLOCKING_ENABLED) failed"); return; }

    std::string owner_path;
    uint64_t owner_ino_unused;
    if (!CopyProbeBinary(owner_path, owner_ino_unused)) { Check(false, "CopyProbeBinary (owner) failed"); return; }
    struct stat owner_st{};
    if (stat(owner_path.c_str(), &owner_st) != 0) { Check(false, "stat (owner probe) failed"); return; }
    const uint32_t kOwnerProtected = 0x1u;
    if (!loader.AddOwnerImage(owner_st.st_dev, owner_st.st_ino, kOwnerProtected)) { Check(false, "AddOwnerImage failed"); return; }

    std::string bystander_path;
    uint64_t bystander_ino_unused;
    if (!CopyProbeBinary(bystander_path, bystander_ino_unused)) { Check(false, "CopyProbeBinary (bystander) failed"); return; }

    // A root-owned library: the ordinary shape of a package-installed one.
    std::string lib;
    uint64_t lib_ino, lib_dev;
    if (!MakeTempFile(lib, lib_ino, lib_dev)) { Check(false, "MakeTempFile (system library stand-in) failed"); return; }
    DeferUnlink(lib);
    if (chown(lib.c_str(), 0, 0) != 0) { Check(false, "chown (root-owned library) failed"); return; }
    struct stat lib_st{};
    if (stat(lib.c_str(), &lib_st) != 0) { Check(false, "stat (library) failed"); return; }
    // Start from a known-empty set: an earlier test in this binary must not
    // leave an entry that turns the control below into a deny.
    if (!loader.ClearModifiedLibraries()) { Check(false, "ClearModifiedLibraries (initial) failed"); return; }

    int control_rc = RunProbeAt(owner_path.c_str(), "mmap_exec", lib);
    Check(control_rc == 0, "control: a root-owned library that is not in the set loads for a protected owner (got " + std::to_string(control_rc) + ")");

    if (!loader.AddModifiedLibrary(lib_st.st_dev, lib_st.st_ino)) { Check(false, "AddModifiedLibrary failed"); return; }
    int deny_rc = RunProbeAt(owner_path.c_str(), "mmap_exec", lib);
    Check(deny_rc == EACCES, "a root-owned library in the modified set is refused to a protected owner (got " + std::to_string(deny_rc) + ")");

    int bystander_rc = RunProbeAt(bystander_path.c_str(), "mmap_exec", lib);
    Check(bystander_rc == 0, "the deny is for protected owners only: an unregistered process still maps it (got " + std::to_string(bystander_rc) + ")");

    if (!loader.RemoveModifiedLibrary(lib_st.st_dev, lib_st.st_ino)) { Check(false, "RemoveModifiedLibrary failed"); return; }
    int removed_rc = RunProbeAt(owner_path.c_str(), "mmap_exec", lib);
    Check(removed_rc == 0, "removing it from the set restores the load (got " + std::to_string(removed_rc) + ")");

    if (!loader.AddModifiedLibrary(lib_st.st_dev, lib_st.st_ino)) { Check(false, "AddModifiedLibrary (again) failed"); return; }
    if (!loader.ClearModifiedLibraries()) { Check(false, "ClearModifiedLibraries failed"); return; }
    int cleared_rc = RunProbeAt(owner_path.c_str(), "mmap_exec", lib);
    Check(cleared_rc == 0, "clearing the set restores the load (fail open) (got " + std::to_string(cleared_rc) + ")");

    // Rule 3: a user-owned library inside the app's own registered storage
    // dir is trusted by storage_dir_verdict. In the set, it is refused anyway.
    char dir_tmpl[] = "/tmp/kinnector_e2e_modlib_XXXXXX";
    char* dir = mkdtemp(dir_tmpl);
    if (!dir) { Check(false, "mkdtemp (storage dir) failed"); return; }
    struct stat dir_st{};
    if (stat(dir, &dir_st) != 0) { Check(false, "stat (storage dir) failed"); return; }
    if (!loader.AddDirOwner(dir_st.st_dev, dir_st.st_ino, owner_st.st_dev, owner_st.st_ino)) { Check(false, "AddDirOwner failed"); return; }
    std::string stored_so = std::string(dir) + "/component.so";
    int fixture_rc = RunProbeAt(owner_path.c_str(), "open_write_create", stored_so);
    if (fixture_rc != 0) { Check(false, "could not create the storage-dir library as its owner (got " + std::to_string(fixture_rc) + ")"); return; }
    DeferUnlink(stored_so);
    if (chown(stored_so.c_str(), 65534, static_cast<gid_t>(-1)) != 0) { Check(false, "chown (storage-dir library) failed"); return; }
    struct stat stored_st{};
    if (stat(stored_so.c_str(), &stored_st) != 0) { Check(false, "stat (storage-dir library) failed"); return; }

    int rule3_ok_rc = RunProbeAt(owner_path.c_str(), "mmap_exec", stored_so);
    Check(rule3_ok_rc == 0, "control: a user-owned library in the app's own storage dir loads (rule 3) (got " + std::to_string(rule3_ok_rc) + ")");
    if (!loader.AddModifiedLibrary(stored_st.st_dev, stored_st.st_ino)) { Check(false, "AddModifiedLibrary (storage-dir library) failed"); return; }
    int rule3_deny_rc = RunProbeAt(owner_path.c_str(), "mmap_exec", stored_so);
    Check(rule3_deny_rc == EACCES, "the set overrides the storage-dir trust rule too (got " + std::to_string(rule3_deny_rc) + ")");

    // Leave the set empty for whatever runs next.
    loader.ClearModifiedLibraries();
}

// errno of readlink(path) from THIS thread, 0 on success.
int ReadlinkErrno(const std::string& path) {
    char buf[PATH_MAX];
    return readlink(path.c_str(), buf, sizeof(buf)) >= 0 ? 0 : errno;
}

// The same readlink from a genuinely different process (another pid), which is
// what any non-daemon reader is.
int ReadlinkErrnoInChild(const std::string& path) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) _exit(ReadlinkErrno(path));
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// errno of ptrace(request, target) from THIS thread, 0 on success (in which
// case it detaches again so the target is left running).
int PtraceErrnoFromHere(int request, pid_t target) {
    if (ptrace(static_cast<__ptrace_request>(request), target, nullptr, nullptr) != 0) return errno;
    if (request == PTRACE_ATTACH) waitpid(target, nullptr, 0);
    ptrace(PTRACE_DETACH, target, nullptr, nullptr);
    return 0;
}

// errno of open("/proc/<pid>/mem", O_RDONLY): the memory read path, which the
// kernel gates with PTRACE_MODE_ATTACH_FSCREDS.
int ProcMemOpenErrno(pid_t target) {
    int fd = open(("/proc/" + std::to_string(target) + "/mem").c_str(), O_RDONLY);
    if (fd < 0) return errno;
    close(fd);
    return 0;
}

// Daemon-identity-read exemption,
// Updated for the decision that a non-ATTACH access to a
// protected process is allowed to everyone (see TestNonAttachAccessToProtected
// ProcessAllowedAttachStillDenied). ptrace_access_check used to deny antitheftd
// every /proc/<pid>/{exe,cwd,root} read of a protected process (a READ-mode
// access), and CONFIG_DAEMON_READS_PROTECTED_IDENTITY lets exactly one caller
// through. Now that a READ is allowed for every caller regardless, the switch
// and the daemon's registered (pid, start time) no longer decide a read at all;
// what this test still pins is that NONE of them ever opens an ATTACH-mode
// access. This harness plays the daemon: it registers its own (pid, start
// time) in CONFIG_OWN_PID / CONFIG_OWN_START_TIME_LO/HI, exactly what the
// agent writes. Cases:
//   off (default)   - the protected target's exe is readable (was: denied)
//   on, the daemon  - readable (exe, cwd, root), from the main thread AND from
//                     a worker thread (group-leader key, the thread-key gotcha)
//   attach modes    - the same caller's PTRACE_ATTACH, PTRACE_SEIZE and
//                     open(/proc/<pid>/mem) still fail with EACCES
//   other callers   - another pid, a wrong start time, a start time of 0, a
//                     different own-pid: reads are allowed too (was: denied),
//                     and ATTACH is still denied under each registration
//   off again       - still readable, ATTACH still denied
//   unprotected     - a target that is not a protected owner is unaffected
//                     (readable to the daemon and to everyone else, switch on or off)
void TestDaemonIdentityReadExemption(EbpfLoader& loader) {
    std::cout << "[e2e] daemon identity read: only the daemon, only non-ATTACH access, only protected targets..." << std::endl;
    constexpr uint32_t kConfigDaemonReads = 10; // kinnector_maps.h: CONFIG_DAEMON_READS_PROTECTED_IDENTITY
    constexpr uint32_t kConfigOwnStartLo = 11;  // CONFIG_OWN_START_TIME_LO
    constexpr uint32_t kConfigOwnStartHi = 12;  // CONFIG_OWN_START_TIME_HI
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) { Check(false, "SetConfigValue(MODE_ANTITHEFT) failed"); return; }
    if (!loader.SetConfigValue(kConfigBlockingEnabled, 1)) { Check(false, "SetConfigValue(BLOCKING_ENABLED) failed"); return; }

    std::string owner_path, bystander_path;
    uint64_t ino_unused;
    if (!CopyProbeBinary(owner_path, ino_unused)) { Check(false, "CopyProbeBinary (owner) failed"); return; }
    if (!CopyProbeBinary(bystander_path, ino_unused)) { Check(false, "CopyProbeBinary (bystander) failed"); return; }
    struct stat owner_st{};
    if (stat(owner_path.c_str(), &owner_st) != 0) { Check(false, "stat (owner probe) failed"); return; }
    if (!loader.AddOwnerImage(owner_st.st_dev, owner_st.st_ino, 0x1u)) { Check(false, "AddOwnerImage failed"); return; }

    pid_t protected_pid = StartProbeSleeping(owner_path.c_str(), 30);
    pid_t plain_pid = StartProbeSleeping(bystander_path.c_str(), 30);
    if (protected_pid <= 0 || plain_pid <= 0) { Check(false, "could not start the sleepers"); return; }
    usleep(300000); // let bprm_creds_for_exec stamp the protected one
    const std::string prot = "/proc/" + std::to_string(protected_pid);
    const std::string plain = "/proc/" + std::to_string(plain_pid);
    Check(loader.LookupOwnerStartTime(static_cast<uint32_t>(protected_pid)) != 0, "fixture: the kernel stamped protected_owner_pids for the sleeper");

    loader.RefreshTaskStartTimes();
    const uint64_t self_start = loader.GetTaskStartTime(static_cast<uint32_t>(getpid()));
    Check(self_start != 0, "fixture: the harness's own kernel start_time is known");
    auto register_daemon = [&](uint32_t pid, uint64_t start) {
        loader.SetConfigValue(kConfigOwnPid, pid);
        loader.SetConfigValue(kConfigOwnStartLo, static_cast<uint32_t>(start & 0xffffffffu));
        loader.SetConfigValue(kConfigOwnStartHi, static_cast<uint32_t>(start >> 32));
    };
    auto switch_on = [&](bool on) { loader.SetConfigValue(kConfigDaemonReads, on ? 1u : 0u); };
    if (self_start == 0) { loader.SetConfigValue(kConfigOwnPid, 0); return; }

    // Off is the default, even for a registered daemon. A read of the exe is
    // allowed regardless (only ATTACH is denied).
    register_daemon(static_cast<uint32_t>(getpid()), self_start);
    Check(ReadlinkErrno(prot + "/exe") == 0, "switch off (default): the registered daemon reads a protected process's exe (a non-ATTACH access is allowed)");
    Check(ReadlinkErrnoInChild(prot + "/exe") == 0, "switch off: any other reader reads it too");
    Check(PtraceErrnoFromHere(PTRACE_ATTACH, protected_pid) == EACCES, "switch off: the registered daemon's PTRACE_ATTACH is EACCES");

    switch_on(true);
    Check(ReadlinkErrno(prot + "/exe") == 0, "switch on: the daemon reads a protected process's /proc/<pid>/exe (got errno " + std::to_string(ReadlinkErrno(prot + "/exe")) + ")");
    Check(ReadlinkErrno(prot + "/cwd") == 0, "switch on: the daemon reads its /cwd");
    Check(ReadlinkErrno(prot + "/root") == 0, "switch on: the daemon reads its /root");
    int worker_rc = -1;
    { std::thread t([&] { worker_rc = ReadlinkErrno(prot + "/exe"); }); t.join(); }
    Check(worker_rc == 0, "switch on: a WORKER THREAD of the daemon reads it too (group-leader key) (got " + std::to_string(worker_rc) + ")");

    // Real attach modes stay denied to the very same caller.
    Check(PtraceErrnoFromHere(PTRACE_ATTACH, protected_pid) == EACCES, "switch on: the daemon's PTRACE_ATTACH of a protected process is still EACCES");
    Check(PtraceErrnoFromHere(0x4206 /* PTRACE_SEIZE */, protected_pid) == EACCES, "switch on: the daemon's PTRACE_SEIZE is still EACCES");
    Check(ProcMemOpenErrno(protected_pid) == EACCES, "switch on: open(/proc/<pid>/mem) is still EACCES (an ATTACH-mode access)");

    // Nobody is treated differently for a read any more; ATTACH is denied to
    // every one of them, whatever the daemon registration says.
    Check(ReadlinkErrnoInChild(prot + "/exe") == 0, "switch on: another pid (a forked child of the daemon) reads it too");
    register_daemon(static_cast<uint32_t>(getpid()), self_start + 1);
    Check(ReadlinkErrno(prot + "/exe") == 0, "switch on: a wrong start time (pid reuse by an impostor) reads it (allowed for everyone)");
    Check(PtraceErrnoFromHere(PTRACE_ATTACH, protected_pid) == EACCES, "switch on: a wrong start time still gets no ATTACH");
    register_daemon(static_cast<uint32_t>(getpid()), 0);
    Check(ReadlinkErrno(prot + "/exe") == 0, "switch on: a start time of 0 (never written) reads it too");
    Check(PtraceErrnoFromHere(PTRACE_ATTACH, protected_pid) == EACCES, "switch on: a start time of 0 still gets no ATTACH");
    register_daemon(static_cast<uint32_t>(getpid()) + 1, self_start);
    Check(ReadlinkErrno(prot + "/exe") == 0, "switch on: a different own-pid reads it too");
    Check(PtraceErrnoFromHere(PTRACE_ATTACH, protected_pid) == EACCES, "switch on: a different own-pid still gets no ATTACH");
    register_daemon(0, self_start);
    Check(ReadlinkErrno(prot + "/exe") == 0, "switch on: own-pid 0 (never set) reads it too");
    Check(PtraceErrnoFromHere(PTRACE_ATTACH, protected_pid) == EACCES, "switch on: own-pid 0 still gets no ATTACH");

    // A target that is not a protected owner is not this feature's business.
    register_daemon(static_cast<uint32_t>(getpid()), self_start);
    Check(ReadlinkErrno(plain + "/exe") == 0 && ReadlinkErrnoInChild(plain + "/exe") == 0, "switch on: an unprotected target is readable, as it always was");
    switch_on(false);
    Check(ReadlinkErrno(plain + "/exe") == 0 && ReadlinkErrnoInChild(plain + "/exe") == 0, "switch off: an unprotected target is readable, as it always was");

    // Off again changes nothing for a read; ATTACH stays denied.
    Check(ReadlinkErrno(prot + "/exe") == 0, "switch off again: the daemon still reads it");
    Check(ProcMemOpenErrno(protected_pid) == EACCES, "switch off again: open(/proc/<pid>/mem) is still EACCES");

    // Leave nothing behind for later tests.
    switch_on(false);
    register_daemon(0, 0);
    kill(protected_pid, SIGKILL);
    kill(plain_pid, SIGKILL);
    waitpid(protected_pid, nullptr, 0);
    waitpid(plain_pid, nullptr, 0);
    loader.RemoveOwnerImage(owner_st.st_dev, owner_st.st_ino);
}

// errno (0 = success) of `fn`, run in a genuinely separate process so the
// caller is a non-owner with a pid of its own. -1 on a harness failure.
int ErrnoInChild(const std::function<int()>& fn) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) _exit(fn() & 0xff);
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// errno of open(path, O_RDONLY) followed by one read(), 0 if both work.
int ReadFileErrno(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return errno;
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf));
    int rc = n < 0 ? errno : 0;
    close(fd);
    return rc;
}

// errno of process_vm_readv(target), which the kernel gates with
// PTRACE_MODE_ATTACH_REALCREDS. The kernel maps that EACCES to EPERM. The
// remote address is never dereferenced when the access check fails first.
int ProcessVmReadvErrno(pid_t target) {
    char local[16];
    struct iovec l = {local, sizeof(local)};
    struct iovec r = {reinterpret_cast<void*>(0x1000), sizeof(local)};
    if (process_vm_readv(target, &l, 1, &r, 1, 0) >= 0) return 0;
    return errno;
}

// Owner decision: ptrace_access_check is consulted with a
// READ-class mode (no PTRACE_MODE_ATTACH bit 0x2) for ANY access under
// /proc/<pid>/ - cmdline, status, exe, cwd, stat, environ, maps - so `ps`,
// `pgrep`, `htop` and `cat /proc/PID/cmdline` all went through the protected-
// owner deny and raised a ptrace_blocked alert on every refresh. Only real
// memory access carries the ATTACH bit (ptrace attach/seize, process_vm_*,
// /proc/<pid>/mem). Under MODE_ANTITHEFT a non-owner must now:
//   - READ /proc/<protected>/{cmdline,status,exe,cwd,environ,maps}     -> allowed
//   - PTRACE_ATTACH / PTRACE_SEIZE / open(/proc/<pid>/mem) / process_vm_readv -> EACCES (EPERM for process_vm_*)
// and, with enforcement paused (blocking off), even the attach is allowed
// (`blocking_enabled_now()` semantics unchanged). The trade-off is accepted:
// metadata (environ, maps, exe, cwd) of a protected process is readable by
// other processes; only memory stays protected. The caller is a forked child
// of the harness: not protected, not the registered daemon.
void TestNonAttachAccessToProtectedProcessAllowedAttachStillDenied(EbpfLoader& loader) {
    std::cout << "[e2e] protected process: non-ATTACH /proc access allowed to a non-owner, ATTACH modes still denied..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) { Check(false, "SetConfigValue(MODE_ANTITHEFT) failed"); return; }
    if (!loader.SetConfigValue(kConfigBlockingEnabled, 1)) { Check(false, "SetConfigValue(BLOCKING_ENABLED) failed"); return; }

    std::string owner_path, bystander_path;
    uint64_t ino_unused;
    if (!CopyProbeBinary(owner_path, ino_unused)) { Check(false, "CopyProbeBinary (owner) failed"); return; }
    if (!CopyProbeBinary(bystander_path, ino_unused)) { Check(false, "CopyProbeBinary (bystander) failed"); return; }
    struct stat owner_st{};
    if (stat(owner_path.c_str(), &owner_st) != 0) { Check(false, "stat (owner probe) failed"); return; }
    if (!loader.AddOwnerImage(owner_st.st_dev, owner_st.st_ino, 0x1u)) { Check(false, "AddOwnerImage failed"); return; }

    pid_t protected_pid = StartProbeSleeping(owner_path.c_str(), 30);
    pid_t plain_pid = StartProbeSleeping(bystander_path.c_str(), 30);
    if (protected_pid <= 0 || plain_pid <= 0) { Check(false, "could not start the sleepers"); return; }
    usleep(300000); // let bprm_creds_for_exec stamp the protected one
    const std::string prot = "/proc/" + std::to_string(protected_pid);
    Check(loader.LookupOwnerStartTime(static_cast<uint32_t>(protected_pid)) != 0,
          "fixture: the kernel stamped protected_owner_pids for the sleeper (without it every result below is meaningless)");
    int liveness = 0;
    Check(waitpid(protected_pid, &liveness, WNOHANG) == 0, "fixture: the protected process is alive");

    // Nobody is registered as the daemon, and the daemon-read switch is off:
    // this is the plain non-owner case.
    for (const char* leaf : {"cmdline", "status", "stat", "environ", "maps"}) {
        int rc = ErrnoInChild([&] { return ReadFileErrno(prot + "/" + leaf); });
        Check(rc == 0, std::string("a non-owner reads /proc/<protected>/") + leaf + " (got errno " + std::to_string(rc) + ")");
    }
    for (const char* leaf : {"exe", "cwd", "root"}) {
        int rc = ReadlinkErrnoInChild(prot + "/" + leaf);
        Check(rc == 0, std::string("a non-owner readlinks /proc/<protected>/") + leaf + " (got errno " + std::to_string(rc) + ")");
    }

    // Real memory access stays denied to the same non-owner.
    int attach_rc = AttackerPtraceAttach(protected_pid);
    Check(attach_rc == EACCES, "a non-owner's PTRACE_ATTACH is EACCES (got " + std::to_string(attach_rc) + ")");
    int seize_rc = ErrnoInChild([&] { return PtraceErrnoFromHere(0x4206 /* PTRACE_SEIZE */, protected_pid); });
    Check(seize_rc == EACCES, "a non-owner's PTRACE_SEIZE is EACCES (got " + std::to_string(seize_rc) + ")");
    int mem_rc = ErrnoInChild([&] { return ProcMemOpenErrno(protected_pid); });
    Check(mem_rc == EACCES, "a non-owner's open(/proc/<protected>/mem) is EACCES (got " + std::to_string(mem_rc) + ")");
    int vm_rc = ErrnoInChild([&] { return ProcessVmReadvErrno(protected_pid); });
    Check(vm_rc == EPERM, "a non-owner's process_vm_readv is refused (EPERM is the kernel's spelling of the hook's EACCES) (got " + std::to_string(vm_rc) + ")");

    // A target that is not protected was never affected: control.
    const std::string plain = "/proc/" + std::to_string(plain_pid);
    Check(ErrnoInChild([&] { return ReadFileErrno(plain + "/cmdline"); }) == 0, "control: an unprotected process's cmdline is readable");
    Check(AttackerPtraceAttach(plain_pid) == 0, "control: an unprotected process can be attached (this harness's attacker is root)");

    // Paused: nothing is refused, so the attach goes through too (semantics
    // unchanged by the ATTACH-only rule), and a read is still fine.
    loader.SetConfigValue(kConfigBlockingEnabled, 0);
    Check(ErrnoInChild([&] { return ReadFileErrno(prot + "/cmdline"); }) == 0, "paused: a non-owner still reads cmdline");
    Check(AttackerPtraceAttach(protected_pid) == 0, "paused: the attach is not refused (the deny honours the blocking switch)");
    loader.SetConfigValue(kConfigBlockingEnabled, 1);
    Check(AttackerPtraceAttach(protected_pid) == EACCES, "armed again: the attach is refused again");

    kill(protected_pid, SIGKILL);
    kill(plain_pid, SIGKILL);
    waitpid(protected_pid, nullptr, 0);
    waitpid(plain_pid, nullptr, 0);
    loader.RemoveOwnerImage(owner_st.st_dev, owner_st.st_ino);
}

} // namespace

// Self-injection protection is a switch, and revocation does not move it
// (replacing the JIT-allowance version of this test). Four
// cases, one fixture: with the switch off - the default - a protected
// process may build its own executable memory, and STILL may while revoked;
// with it on, the same process may not, revoked or not.
//
// Two behaviours are pinned here. First, the switch: there is no per-app JIT
// answer any more (OWNER_JIT_SELFEXEC retired), so this one config value is
// the entire difference between allowed and denied, and it must be readable
// live - every case below flips it on an already-loaded object, with no
// re-registration of the owner image.
//
// Second, revocation's non-effect on it. Withdrawing the allowance on
// revocation reads as defence in depth but was not: revoke() SIGKILLs the
// process it names, so for that process the withdrawal is redundant, while
// tracepoint_sched_process_fork propagates the revocation to children the
// kill never names - and those children then died at their next code
// generation, which to a user is a browser dropping tabs for no stated
// reason. The kill is the defence; this deny only produced casualties
// downwind of it.
//
// The fixture has to revoke a process that is already running, because the
// kernel stamps protected_owner_pids at exec and revoked_pid_map is keyed by
// the same (pid, start_time) - hence the probe's marker handshake and
// LookupOwnerStartTime(): the harness cannot invent that start_time (see
// that method's own comment).
void TestSelfInjectionProtectionSwitchGovernsSelfExec(EbpfLoader& loader) {
    std::cout << "[e2e] the self-injection switch governs self-exec under MODE_ANTITHEFT, revoked or not..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) { Check(false, "SetConfigValue(MODE_ANTITHEFT) failed"); return; }
    if (!loader.SetConfigValue(kConfigBlockingEnabled, 1)) { Check(false, "SetConfigValue(BLOCKING_ENABLED) failed"); return; }

    const uint32_t kOwnerProtected  = 0x1u;

    // Fresh probe copies so this test's owner-image registrations cannot
    // collide with the ones earlier tests left on ProbePath()'s inode.
    struct Case {
        const char* name;
        uint32_t    flags;
        uint32_t    protection; // CONFIG_SELF_INJECTION_PROTECTION
        bool        revoke;
        int         expected;   // 0 = mapping allowed, EACCES = denied
    };
    const Case cases[] = {
        { "protection off",           kOwnerProtected, 0, false, 0 },
        { "protection off, revoked",  kOwnerProtected, 0, true,  0 },
        { "protection on",            kOwnerProtected, 1, false, EACCES },
        { "protection on, revoked",   kOwnerProtected, 1, true,  EACCES },
    };

    for (const Case& c : cases) {
        if (!loader.SetConfigValue(kConfigSelfInjectionProtection, c.protection)) {
            Check(false, std::string("SetConfigValue(SELF_INJECTION_PROTECTION) failed (") + c.name + ")");
            return;
        }
        std::string app_path;
        uint64_t app_ino_unused;
        if (!CopyProbeBinary(app_path, app_ino_unused)) { Check(false, std::string("CopyProbeBinary failed (") + c.name + ")"); return; }
        struct stat app_st{};
        if (stat(app_path.c_str(), &app_st) != 0) { Check(false, std::string("stat (app probe) failed (") + c.name + ")"); return; }
        if (!loader.AddOwnerImage(app_st.st_dev, app_st.st_ino, c.flags)) {
            Check(false, std::string("AddOwnerImage failed (") + c.name + ")");
            return;
        }

        char marker_tmpl[] = "/tmp/kinnector_e2e_anonexec_XXXXXX";
        int marker_fd = mkstemp(marker_tmpl);
        if (marker_fd < 0) { Check(false, "mkstemp (marker) failed"); return; }
        close(marker_fd);
        std::string marker = marker_tmpl;
        std::string ready = marker + ".ready";
        // The probe waits for the marker to APPEAR, so it must not exist yet.
        unlink(marker.c_str());
        unlink(ready.c_str());
        DeferUnlink(marker);
        DeferUnlink(ready);

        pid_t pid = fork();
        if (pid < 0) { Check(false, "fork (anon-exec probe) failed"); return; }
        if (pid == 0) {
            execl(app_path.c_str(), app_path.c_str(), "anon_exec_on_marker", marker.c_str(), (char*)nullptr);
            _exit(127);
        }

        // Wait for the exec to have happened - only then has the kernel
        // stamped protected_owner_pids, and only then is there a start_time
        // to look up.
        bool ready_seen = false;
        for (int waited_ms = 0; waited_ms < 5000 && !ready_seen; waited_ms += 10) {
            ready_seen = (access(ready.c_str(), F_OK) == 0);
            if (!ready_seen) usleep(10000);
        }
        if (!ready_seen) {
            Check(false, std::string("anon-exec probe never signalled ready (") + c.name + ")");
            kill(pid, SIGKILL);
            waitpid(pid, nullptr, 0);
            return;
        }

        uint64_t start_time = loader.LookupOwnerStartTime(static_cast<uint32_t>(pid));
        Check(start_time != 0, std::string("the kernel stamped protected_owner_pids for the running app (") + c.name + ")");

        if (c.revoke && start_time != 0) {
            // reason_bits is opaque to the kernel; any non-zero value is a
            // revocation. 1 mirrors runtime_integrity.rs's smallest reason.
            if (!loader.UpdateMapEntry(BpfMapType::RevokedPidMap, static_cast<uint32_t>(pid), start_time, 1)) {
                Check(false, "UpdateMapEntry(RevokedPidMap) failed");
            }
        }

        // Release the probe and read its verdict.
        int go_fd = open(marker.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (go_fd < 0) { Check(false, "could not create the go marker"); kill(pid, SIGKILL); waitpid(pid, nullptr, 0); return; }
        close(go_fd);

        int status = 0;
        if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) {
            Check(false, std::string("anon-exec probe did not exit normally (") + c.name + ")");
            return;
        }
        int rc = WEXITSTATUS(status);
        Check(rc == c.expected,
              std::string("anonymous PROT_EXEC mapping [") + c.name + "]: expected " +
              std::to_string(c.expected) + ", got " + std::to_string(rc));

        if (start_time != 0) {
            loader.DeleteMapEntry(BpfMapType::RevokedPidMap, static_cast<uint32_t>(pid), start_time);
        }
        loader.RemoveOwnerImage(app_st.st_dev, app_st.st_ino);
    }

    // Back to the shipped default before any later test runs. Left on, this
    // would deny self-exec for every protected process the rest of the suite
    // registers - a failure that would look like the hooks under test rather
    // than like leftover config.
    Check(loader.SetConfigValue(kConfigSelfInjectionProtection, 0), "self-injection protection reset to its default (off)");
}

// The kernel-precision start_time lookup that startup_backfill needs
// . Correctness is checkable without any privileged trick: the
// kernel's nanosecond value must floor to exactly the USER_HZ tick that
// /proc/<pid>/stat reports, since that field IS this value put through
// nsec_to_clock_t. A quantized value would pass that check too, so the test
// also asserts the value is NOT already tick-aligned for at least one
// process - that is the whole difference the backfill was missing.
void TestTaskStartTimeIteratorMatchesProc(EbpfLoader& loader) {
    std::cout << "[e2e] iter/task start_time snapshot agrees with /proc and carries sub-tick precision..." << std::endl;
    int count = loader.RefreshTaskStartTimes();
    Check(count > 0, "iter/task walk recorded at least one process (got " + std::to_string(count) + ")");
    if (count <= 0) return;

    const long clk_tck = sysconf(_SC_CLK_TCK);
    if (clk_tck <= 0) { Check(false, "sysconf(_SC_CLK_TCK) failed"); return; }
    const uint64_t tick_ns = 1000000000ull / static_cast<uint64_t>(clk_tck);

    uint64_t self_start = loader.GetTaskStartTime(static_cast<uint32_t>(getpid()));
    Check(self_start != 0, "the walk recorded this test process itself");
    if (self_start == 0) return;

    // /proc's starttime for this process, in ticks (field 22, after the
    // parenthesised comm which may itself contain spaces).
    std::ifstream stat_file("/proc/self/stat");
    std::string stat_line;
    std::getline(stat_file, stat_line);
    size_t rparen = stat_line.rfind(')');
    if (rparen == std::string::npos) { Check(false, "could not parse /proc/self/stat"); return; }
    std::istringstream rest(stat_line.substr(rparen + 2));
    std::string field;
    uint64_t proc_ticks = 0;
    for (int i = 0; i < 20; ++i) {
        if (!(rest >> field)) { Check(false, "/proc/self/stat truncated before starttime"); return; }
    }
    proc_ticks = std::stoull(field);

    Check(self_start / tick_ns == proc_ticks,
          "the kernel's start_time floors to /proc's tick value (kernel " + std::to_string(self_start) +
          " -> " + std::to_string(self_start / tick_ns) + ", /proc " + std::to_string(proc_ticks) + ")");

    // At least one recorded process must carry sub-tick precision, which is
    // exactly what a /proc-derived value can never have. Checking only this
    // process would be flaky: one process CAN legitimately start on a tick
    // boundary.
    bool any_sub_tick = (self_start % tick_ns) != 0;
    for (uint32_t pid = 1; pid < 4096 && !any_sub_tick; ++pid) {
        uint64_t st = loader.GetTaskStartTime(pid);
        if (st != 0 && (st % tick_ns) != 0) any_sub_tick = true;
    }
    Check(any_sub_tick, "at least one recorded start_time is not tick-aligned (i.e. it is the real kernel value, not a /proc reconstruction)");
}

// "exec telemetry loss is now counted but not yet
// explained" - telemetry_stats (core 2b06019) counts ProcessCreate emitted
// vs dropped on a full ring buffer, with an idle-host baseline of 4670
// emitted / 0 dropped, but the ~1-in-8 loss measured under container
// workloads was never re-measured against this specific counter. This is
// that re-measurement: a tight burst of real execve()s, deliberately with NO
// sleeps between them (the shape most likely to pressure the ring buffer),
// checked against the SAME counter production code reads. Informational, not
// a Check() - whether a real loss here would be
// ring-buffer pressure or something else is still an open question, so a
// pass/fail assertion here would be asserting an answer this test cannot
// actually determine on its own.
void ReportExecTelemetryStatsUnderBurstLoad(EbpfLoader& loader) {
    std::cout << "[e2e] exec telemetry: emitted/dropped under a tight burst of real execs (informational)..." << std::endl;
    uint64_t before_emitted = 0, before_dropped = 0;
    loader.GetExecTelemetryStats(before_emitted, before_dropped);

    constexpr int kBurst = 2000;
    for (int i = 0; i < kBurst; ++i) {
        pid_t pid = fork();
        if (pid == 0) {
            execl("/bin/true", "/bin/true", (char*)nullptr);
            _exit(127);
        }
        if (pid > 0) {
            int status = 0;
            waitpid(pid, &status, 0);
        }
    }

    uint64_t after_emitted = 0, after_dropped = 0;
    loader.GetExecTelemetryStats(after_emitted, after_dropped);
    uint64_t delta_emitted = after_emitted - before_emitted;
    uint64_t delta_dropped = after_dropped - before_dropped;
    std::cout << "  - INFO: " << kBurst << " execs -> emitted delta=" << delta_emitted
              << " dropped delta=" << delta_dropped
              << " (before: emitted=" << before_emitted << " dropped=" << before_dropped
              << ", after: emitted=" << after_emitted << " dropped=" << after_dropped << ")" << std::endl;
    if (delta_dropped > 0) {
        std::cout << "  - INFO: non-zero drop under this burst - ring-buffer pressure is a live contributor, "
                     "not just a theoretical one (root cause still open)"
                  << std::endl;
    } else {
        std::cout << "  - INFO: zero drop under " << kBurst << " tight back-to-back execs on this machine/kernel - "
                     "the ~1-in-8 loss measured under container workloads did not reproduce from raw "
                     "exec rate alone; whatever triggers it under containers is more specific than exec volume "
                     "(e.g. concurrent multi-process fan-out, cgroup/namespace churn, or scheduling pressure this "
                     "single-process burst does not exercise)"
                  << std::endl;
    }
}

int main() {
    if (getuid() != 0) {
        std::cerr << "test_enforcement_e2e must run as root (needs BPF map writes + config_map blocking_enabled)." << std::endl;
        return 1;
    }

    EbpfLoader loader;
    if (!loader.Initialize(kinnector::test::ResolveBpfObjectPath(), false)) {
        std::cerr << "Failed to initialize EbpfLoader" << std::endl;
        return 1;
    }
    // Set before Start: the poll thread calls it unlocked.
    loader.SetEventCallback(CapturePersistence);
    if (!loader.Start()) {
        std::cerr << "Failed to start EbpfLoader" << std::endl;
        return 1;
    }

    // From here on, real LSM links may get pinned system-wide with this
    // process's test-fixture policy state -- install the crash-safety net
    // before doing anything else that could deny exec() to the whole machine.
    InstallCrashUnpinHandler();

    // Normal (non-crash) shutdown: unlike production Stop() (which
    // deliberately leaves pins alive for hot-reload), this test must fully
    // detach everything it attached before exiting -- see ForceUnpinAllLinks()
    // doc comment and linux_coverage_plan_phasing memory for why.
    auto SafeShutdown = [&]() {
        loader.SetConfigValue(kConfigBlockingEnabled, 0);
        loader.ForceUnpinAllLinks();
        loader.Stop();
    };

    if (loader.IsMockMode() || !loader.IsLsmActive()) {
        std::cerr << "test_enforcement_e2e requires real BPF LSM enforcement -- the kernel must list "
                     "\"bpf\" in /sys/kernel/security/lsm (a boot-cmdline lsm= setting, not something "
                     "this test or a reboot-less privilege change can turn on). Mock/fallback tracepoint "
                     "mode cannot satisfy it: this is the one target in the suite meant to assert actual "
                     "kernel-level deny behavior, so it fails loudly here rather than skipping quietly."
                  << std::endl;
        SafeShutdown();
        return 1;
    }

    if (!loader.SetConfigValue(kConfigBlockingEnabled, 1)) {
        std::cerr << "Failed to enable blocking_enabled" << std::endl;
        SafeShutdown();
        return 1;
    }

    TestSensitiveInodeReadDeny(loader);
    TestProtectedStaticInodeWriteDeny(loader);
    TestSensitiveInodeReadAllowForClassifiedProcess(loader);

    // owner-allowlist tests. Must run after
    // TestSensitiveInodeReadAllowForClassifiedProcess -- they depend on the
    // probe binary already being classified threshold=2 by that test, so its
    // open() attempts reach the owner-allowlist branch instead of being
    // denied earlier by the generic threshold==1 check. See that test's own
    // comment for why probe classification can't be moved earlier either.
    struct stat probe_st{};
    if (stat(ProbePath(), &probe_st) != 0) {
        Check(false, "could not stat probe binary for owner-allowlist tests");
    } else {
        uint64_t probe_ino = probe_st.st_ino;
        TestResourceOwnerMapIgnoredInWardenMode(loader, probe_ino);
        TestResourceOwnerAllowlistDenyUnrelatedProcess(loader, probe_ino);
        TestResourceOwnerAllowlistAllowConfiguredOwner(loader, probe_ino);
        TestBwrapSandboxedOwnerCanStillReadItsOwnResource(loader);
        TestResourceOwnerAllowlistWriteDeny(loader, probe_ino);
        TestGlobOwnedDirSyncProtection(loader, probe_ino);

        // Chain identity. Placed here deliberately: after
        // the probe is threshold=2 (so its open() reaches the owner branch),
        // and BEFORE TestInstallBinaryMapConfigDrivenDetection, which
        // registers probe_ino in install_binary_map permanently for the rest
        // of the process and would then deny it every secret through the
        // supply-chain rule instead.
        TestResourceOwnerExactRejectsWrongDevice(loader, probe_ino);
        TestSwappedInIdentityNeverHasAPartialOwnerSet(loader, probe_ino);
        TestFreedProtectedInodeNumberIsNotInheritedByANewFile(loader, probe_ino);
        TestFreedDaemonBinaryNumberRefusesNoNewFile(loader);
        TestPkgLifecycleLookupReadsBackWhatWasWritten(loader);
        TestOwnerImageCarriesIdentityThroughAnInterpreter(loader);
        // Both new-tier tests run here, BEFORE the protected_owner_binaries
        // test below registers ProbePath()'s inode in that map - see
        // TestBasicProtection...'s own comment on why that would mask its
        // process half.
        TestWardenAdminSessionRulesAreWardenOnly(loader);
        TestCredentialHelperExemptOnlyAtDepthTwo(loader);
        TestInstallScriptRefusedOnlyLockedStores(loader);
        TestEveryPersistenceWriteNamesItsWriter(loader);
        TestExecEventsOnlyForSuccessWithTheKernelsVerdict(loader);
        TestNoExternalInheritanceDropsStandingOutsideTheInstallDir(loader);
        TestNoExternalInheritanceSharedDirAndFlatpakLayout(loader);
        TestRenameOfProtectedResourceDeniedForNonOwner(loader, probe_ino);
        TestBasicProtectionEnforcesFilesButGrantsNoProcessPowers(loader);

        // Phase 4: also depends on probe already being threshold=2 (see comment
        // on TestInstallBinaryMapConfigDrivenDetection). Registers probe_ino in
        // install_binary_map permanently for the rest of this process.
        TestInstallBinaryMapConfigDrivenDetection(loader, probe_ino);
        TestInstallContextAppliesToWorkerThreads(loader, probe_ino);

        // Phase 2: depends on probe_ino already being both threshold=2 and
        // install_binary_map-registered by the two tests above.
        TestPidReuseInstallContextNotInherited(loader);

        // Phase 5: independent of the threshold/install-context state above,
        // but TestProtectedOwnerKillAllowedUnderWarden leaves deployment_mode
        // on MODE_WARDEN, so keep both of these last.
        // One root-owned copy, shared by both, so the MODE_WARDEN baseline
        // below really is the identical attack against the identical image.
        std::string owner_probe;
        uint64_t owner_ino = 0;
        if (!MakeRootOwnedProbeCopy(owner_probe, owner_ino)) {
            Check(false, "could not make a root-owned probe copy for the protected-owner tests");
        } else {
            DeferUnlink(owner_probe);
            TestProtectedOwnerPtraceKillDeniedUnderAntitheft(loader, owner_probe, owner_ino);
        }

        // Independent of owner_probe above (uses its own fresh, non-root-owned
        // CopyProbeBinary() identity) - must run while still MODE_ANTITHEFT,
        // same placement rule as everything else in this block.
        TestProtectedOwnerBinaryUserOwnedSurvivesStartup(loader);

        // Storage-dir write/mmap protection: independent of probe_ino's own
        // state above (uses its own fresh CopyProbeBinary() identities), but
        // must run before TestProtectedOwnerKillAllowedUnderWarden below,
        // which leaves deployment_mode on MODE_WARDEN.
        TestStorageDirWriteProtectionAndUntrustedSoMmapDeny(loader);

        // Modified-system-library deny: same placement rule (fresh probe
        // copies, MODE_ANTITHEFT, ahead of the switch to MODE_WARDEN).
        TestModifiedLibraryDeny(loader);

        // Daemon identity read: fresh probe copies, MODE_ANTITHEFT, and it
        // resets its config slots before returning.
        TestDaemonIdentityReadExemption(loader);

        // Non-ATTACH access to a protected process
        // is allowed, ATTACH modes stay denied. Same placement rule.
        TestNonAttachAccessToProtectedProcessAllowedAttachStillDenied(loader);

        // Same placement rule as the storage-dir test above: uses its own
        // fresh CopyProbeBinary() identities, and must stay ahead of
        // TestProtectedOwnerKillAllowedUnderWarden's switch to MODE_WARDEN.
        TestSelfInjectionProtectionSwitchGovernsSelfExec(loader);

        // Mode-independent (reads a snapshot map, enforces nothing).
        TestTaskStartTimeIteratorMatchesProc(loader);
        ReportExecTelemetryStatsUnderBurstLoad(loader);

        if (!owner_probe.empty()) {
            TestProtectedOwnerKillAllowedUnderWarden(loader, owner_probe);
        }
    }

    // Agent-core tamper resistance: independent of every deployment-mode/
    // probe-classification state threaded through the block above (see each
    // test's own doc comment), so deliberately run last, after all of it.
    TestOwnPidUnkillableByAnyoneButItself(loader);
    TestPinDirectoryDeniesRemovalFromAnotherProcess(loader);

    RunDeferredUnlinks();
    SafeShutdown();

    if (g_failures > 0) {
        std::cerr << "\n>>> ENFORCEMENT E2E TEST FAILED (" << g_failures << " check(s)) <<<\n";
        return 1;
    }
    std::cout << "\n>>> ENFORCEMENT E2E TEST PASSED <<<\n";
    return 0;
}
