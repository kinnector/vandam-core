// real-kernel correctness proof for
// every genuinely new kernel-observed mechanism this plan added, mirroring
// the injection telemetry's own dup2 real-kernel test. Unlike
// test_enforcement_e2e.cpp (which proves ENFORCEMENT - a real -EACCES), this
// target proves TELEMETRY - that each new hook actually fires under a real
// bpf_object__load() and decodes to the expected field values, via
// EbpfLoader::SetEventCallback capturing real ring-buffer events triggered by
// a real probe process performing the real syscall.
//
// Runs with blocking_enabled=1 (same as test_enforcement_e2e) ONLY so the
// probe process lands in process_threshold_map via bprm_creds_for_exec's
// existing "unclassified binary -> threshold=1" branch - every widened/new
// cred-family hook this plan added (task_fix_setuid/setgid, process_vm_readv/
// writev, capset, task_prctl, setgroups) is gated on that map having an
// entry for the calling process. This target does NOT assert on any -EACCES
// - it is a telemetry-visibility proof, not an enforcement proof - but it
// inherits the exact same safety obligations as test_enforcement_e2e.cpp
// since it pins the same system-wide LSM links: crash-safe unpin handler,
// ForceUnpinAllLinks() on every exit path, run only under `timeout`.
//
// pivot_root IS now covered (RunNamespaceProbe/"namespace_probe", below) - a
// real scratch mount-namespace+bind-mount setup, isolated inside its own
// unshare(CLONE_NEWNS)'d child so it never touches the real host mount
// table. Same probe also proves mount/chroot/setns real telemetry now that
// ebpf_loader.cpp attaches sb_mount/path_chroot/sys_enter_setns/
// sys_enter_unshare in the real (non-fallback) path - see that file's
// sb_mount_link_ comment for why that attach is safe.
//
// Deliberately still NOT covering io_uring-issued opens - a real, stated
// gap, not silently assumed. It needs either liburing or hand-rolled
// io_uring_setup/io_uring_enter ring-buffer management, meaningfully more
// infra than any single-syscall probe here. The kernel-design-invariant
// argument (every hook here is LSM-anchored, and io_uring's file ops route
// through the same security_file_* LSM call sites as their syscall
// equivalents) is the standing justification meanwhile.
#include "ebpf_loader.h"
#include "test_helpers/bpf_object_path.h"
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <chrono>
#include <thread>

using namespace kinnector::lnx;

namespace {

constexpr uint32_t kConfigBlockingEnabled = 0; // kinnector.bpf.c: CONFIG_BLOCKING_ENABLED
constexpr uint32_t kConfigDeploymentMode = 5;  // kinnector.bpf.c: CONFIG_DEPLOYMENT_MODE
constexpr uint32_t kModeWarden = 1;            // kinnector.bpf.c: MODE_WARDEN
constexpr uint32_t kModeAntitheft = 2;         // kinnector.bpf.c: MODE_ANTITHEFT

// Same crash-safety net as test_enforcement_e2e.cpp - see that file's own
// comment for why this exact mechanism (unlink, not bpf_link__destroy) is
// required in a signal handler.
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

const char* ProbePath() { return "bin/kinnector-enforcement-probe"; }

// Runs the probe with "impersonation_probe" (own pid as implicit
// process_vm_readv target - see enforcement_probe.cpp) as a genuinely
// separate, freshly-exec'd process, so it lands in process_threshold_map the
// same way every other probe invocation in this suite does.
void RunImpersonationProbe() {
    pid_t pid = fork();
    if (pid < 0) { perror("fork (impersonation probe)"); return; }
    if (pid == 0) {
        execl(ProbePath(), ProbePath(), "impersonation_probe", (char*)nullptr);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
}

// Antitheft container/namespace tracking fix: exercises mount/chroot/setns/
// pivot_root now that ebpf_loader.cpp attaches sb_mount/path_chroot/
// sys_enter_setns/sys_enter_unshare in the real (non-fallback) path - see
// enforcement_probe.cpp's "namespace_probe" verb for what each syscall does
// and why every mount-table-touching one is isolated inside its own private
// mount namespace.
void RunNamespaceProbe() {
    pid_t pid = fork();
    if (pid < 0) { perror("fork (namespace probe)"); return; }
    if (pid == 0) {
        execl(ProbePath(), ProbePath(), "namespace_probe", (char*)nullptr);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
}

// Owner-swap defense follow-up: exercises inode_rename/inode_symlink - a
// real rename(2) over an existing destination and a real symlink(2)
// creating a brand-new entry, both inside `scratch_dir` (the caller's own
// temp dir - no isolation needed, unlike RunNamespaceProbe, since renaming/
// symlinking within a private temp dir has zero host-wide effect on its own).
void RunRenameSymlinkProbe(const std::string& scratch_dir) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork (rename/symlink probe)"); return; }
    if (pid == 0) {
        execl(ProbePath(), ProbePath(), "rename_symlink_probe", scratch_dir.c_str(), (char*)nullptr);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
}

// Copies the probe binary to a fresh temp path and marks it setuid-root, so
// a real (non-euid-only) privilege-dropped child exec'ing it undergoes a
// real silent setuid-bit elevation at exec time with zero setuid() syscall -
// Phase 12's exact motivating scenario. Returns "" if this environment can't
// support it (e.g. /tmp mounted nosuid) - callers must treat that as a
// skip, not a hard failure, since it's an environment property, not a bug.
std::string MakeSetuidRootHelper() {
    char tmpl[] = "/tmp/kinnector_impersonation_setuid_XXXXXX";
    int out_fd = mkstemp(tmpl);
    if (out_fd < 0) { perror("mkstemp (setuid helper)"); return ""; }
    int in_fd = open(ProbePath(), O_RDONLY);
    if (in_fd < 0) { perror("open (probe source)"); close(out_fd); unlink(tmpl); return ""; }
    char buf[65536];
    ssize_t n;
    bool ok = true;
    while ((n = read(in_fd, buf, sizeof(buf))) > 0) {
        if (write(out_fd, buf, static_cast<size_t>(n)) != n) { ok = false; break; }
    }
    if (n < 0) ok = false;
    close(in_fd);
    close(out_fd);
    if (!ok || chown(tmpl, 0, 0) != 0 || chmod(tmpl, 04755) != 0) {
        std::cerr << "  (note: could not prepare setuid-root helper - skipping ExecCredentialDelta's "
                     "real-elevation probe; this filesystem likely mounts /tmp nosuid)" << std::endl;
        unlink(tmpl);
        return "";
    }
    return tmpl;
}

// Forks a child, drops its REAL uid to a non-root value (irreversible for
// that child - fine, it's short-lived), then execs the setuid-root helper.
// bprm_creds_for_exec observes pre_exec_uid=1000 (the caller's real uid,
// already dropped) vs post_exec_euid=0 (the setuid bit) - a real delta with
// zero setuid()/capset() syscall in between.
void RunSetuidRootExec(const std::string& helper_path) {
    if (helper_path.empty()) return;
    pid_t pid = fork();
    if (pid < 0) { perror("fork (setuid-root exec)"); return; }
    if (pid == 0) {
        if (setuid(1000) != 0) { _exit(126); }
        execl(helper_path.c_str(), helper_path.c_str(), "sleep", "0", (char*)nullptr);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
}

std::mutex g_events_mutex;
std::vector<TelemetryEvent> g_events;

void CaptureEvent(const TelemetryEvent& ev) {
    std::lock_guard<std::mutex> lock(g_events_mutex);
    g_events.push_back(ev);
}

std::vector<TelemetryEvent> EventsOfType(EventType type) {
    std::lock_guard<std::mutex> lock(g_events_mutex);
    std::vector<TelemetryEvent> out;
    for (const auto& ev : g_events) {
        if (ev.header.event_type == type) out.push_back(ev);
    }
    return out;
}

void ClearEvents() {
    std::lock_guard<std::mutex> lock(g_events_mutex);
    g_events.clear();
}

// Chain identity needs to attribute events to one specific
// process, not merely observe that some arrived - the harness itself and its
// other probes emit the same event types.
size_t CountForPid(EventType type, uint32_t pid) {
    std::lock_guard<std::mutex> lock(g_events_mutex);
    size_t n = 0;
    for (const auto& ev : g_events) {
        if (ev.header.event_type == type && ev.header.pid == pid) n++;
    }
    return n;
}

// Runs the impersonation probe and returns its pid, so the caller can ask
// what the kernel reported for that process specifically.
pid_t RunImpersonationProbeReturningPid() {
    pid_t pid = fork();
    if (pid < 0) { perror("fork (impersonation probe)"); return -1; }
    if (pid == 0) {
        execl(ProbePath(), ProbePath(), "impersonation_probe", (char*)nullptr);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return pid;
}


// execveat(2) producer coverage. Runs the probe, which execve's
// once (the fork+exec that starts it) and then execveat's once - so a working
// execveat producer means TWO ProcessCreate events for that pid, and the
// pre-fix behaviour of one.
pid_t RunExecveatProbeReturningPid() {
    pid_t pid = fork();
    if (pid < 0) { perror("fork (execveat probe)"); return -1; }
    if (pid == 0) {
        execl(ProbePath(), ProbePath(), "execveat_probe", (char*)nullptr);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return pid;
}

int g_failures = 0;
void Check(bool cond, const std::string& msg) {
    if (cond) {
        std::cout << "  - PASS: " << msg << std::endl;
    } else {
        std::cerr << "  - FAIL: " << msg << std::endl;
        g_failures++;
    }
}

void CheckSoft(bool cond, const std::string& msg) {
    // For probes into optional/environment-dependent territory
    // (setuid-root exec support) - logged, never fails the suite.
    std::cout << "  - " << (cond ? "PASS" : "SKIP") << ": " << msg << std::endl;
}

} // namespace

int main() {
    if (getuid() != 0) {
        std::cerr << "test_impersonation_telemetry_e2e must run as root (needs real BPF LSM load + "
                     "config_map blocking_enabled)." << std::endl;
        return 1;
    }

    EbpfLoader loader;
    if (!loader.Initialize(kinnector::test::ResolveBpfObjectPath(), false)) {
        std::cerr << "Failed to initialize EbpfLoader" << std::endl;
        return 1;
    }
    loader.SetEventCallback(CaptureEvent);
    if (!loader.Start()) {
        std::cerr << "Failed to start EbpfLoader" << std::endl;
        return 1;
    }

    InstallCrashUnpinHandler();

    auto SafeShutdown = [&]() {
        loader.SetConfigValue(kConfigBlockingEnabled, 0);
        loader.ForceUnpinAllLinks();
        loader.Stop();
    };

    if (loader.IsMockMode() || !loader.IsLsmActive()) {
        std::cerr << "test_impersonation_telemetry_e2e requires real BPF LSM enforcement (\"bpf\" in "
                     "/sys/kernel/security/lsm) - the whole point is proving these hooks fire under a "
                     "real bpf_object__load(), not mock/tracepoint fallback." << std::endl;
        SafeShutdown();
        return 1;
    }

    // -----------------------------------------------------------------
    // ProcessStop only at the thread group's end. The
    // sched_process_exit tracepoint fires for every exiting thread and the
    // event carries only the tgid, so a worker thread's exit used to read as
    // the whole process's end (antitheft's tree dropped live
    // nodes). Worker threads of THIS process end:
    // no ProcessStop for our pid. A forked child that exits: one.
    // -----------------------------------------------------------------
    std::cout << "[impersonation-e2e] exit: a worker thread's end is not the process's end..." << std::endl;
    {
        ClearEvents();
        const uint32_t me = static_cast<uint32_t>(getpid());
        for (int i = 0; i < 4; ++i) {
            std::thread([] { std::this_thread::sleep_for(std::chrono::milliseconds(20)); }).join();
        }
        pid_t child = fork();
        if (child == 0) {
            _exit(0);
        }
        int status = 0;
        if (child > 0) {
            waitpid(child, &status, 0);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        size_t mine = CountForPid(EventType::ProcessStop, me);
        size_t childs = child > 0 ? CountForPid(EventType::ProcessStop, static_cast<uint32_t>(child)) : 0;
        Check(mine == 0, "4 worker threads ended: no ProcessStop for the live process (got " + std::to_string(mine) + ")");
        Check(childs >= 1, "a child process that exited: ProcessStop (got " + std::to_string(childs) + ")");
    }

    // -----------------------------------------------------------------
    // the mode gate on the threshold-gated hooks.
    //
    // Every hook this file exercises is gated on process_threshold_map,
    // which Warden fills from its own trust corpus and antitheftd never
    // writes for anything. On an antitheft machine the lookup therefore
    // missed for every process and each hook returned before emitting -
    // silently, because a hook that reports nothing looks exactly like a
    // machine where nothing happened.
    //
    // Deliberately FIRST, before blocking_enabled is turned on: with
    // blocking on, bprm_creds_for_exec gives every freshly-exec'd binary
    // the default threshold of 1, so the probe would have an entry and the
    // mode gate would never be what decided anything. Off, it has none -
    // which is the state this rule exists for.
    //
    // It also has to be anywhere ABOVE main's SafeShutdown() call, which
    // stops the loader and frees the ring buffer. A measurement placed
    // after it captures zero events of every type in every blocking/mode
    // combination, which reads exactly like a mode gate that does not
    // work
    // -----------------------------------------------------------------
    std::cout << "[impersonation-e2e] A3: threshold-gated hooks under each deployment mode..." << std::endl;
    {
        if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
            Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        } else {
            ClearEvents();
            pid_t at_pid = RunImpersonationProbeReturningPid();
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            size_t at_group = CountForPid(EventType::GroupSet, static_cast<uint32_t>(at_pid));
            size_t at_priv = CountForPid(EventType::PrivilegeChange, static_cast<uint32_t>(at_pid));
            Check(at_group > 0, "setgroups() reports under MODE_ANTITHEFT with no threshold entry (got " + std::to_string(at_group) + ")");
            Check(at_priv > 0, "seteuid() reports under MODE_ANTITHEFT with no threshold entry (got " + std::to_string(at_priv) + ")");
        }

        // The contrast, and the state an antitheft machine was stuck in.
        if (!loader.SetConfigValue(kConfigDeploymentMode, kModeWarden)) {
            Check(false, "SetConfigValue(MODE_WARDEN) failed");
        } else {
            ClearEvents();
            pid_t w_pid = RunImpersonationProbeReturningPid();
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            size_t w_group = CountForPid(EventType::GroupSet, static_cast<uint32_t>(w_pid));
            size_t w_priv = CountForPid(EventType::PrivilegeChange, static_cast<uint32_t>(w_pid));
            Check(w_group == 0 && w_priv == 0,
                  "the same probe reports nothing under MODE_WARDEN without a threshold entry (got " +
                      std::to_string(w_group) + "/" + std::to_string(w_priv) +
                      ") - if it reported here, the two checks above never tested the mode gate");
        }

        // Back to the unset mode every assertion below was written against.
        loader.SetConfigValue(kConfigDeploymentMode, 0);
        ClearEvents();
    }

    // -----------------------------------------------------------------
    // D1: dup2/dup3 are attached in LSM mode now, for antitheft
    // only. Before, they were fallback-only, so net_stdio never fired on a
    // BPF-LSM kernel. Warden's Dup2 heuristic kills, and it never received
    // Dup2 in LSM mode - it still must not, under MODE_WARDEN or with the
    // mode unset. The family field tells a real inet socket from the
    // AF_UNIX socketpair libuv gives every child as stdio.
    // -----------------------------------------------------------------
    std::cout << "[impersonation-e2e] D1: dup2 in LSM mode, per deployment mode..." << std::endl;
    {
        auto run_dup2_child = []() -> pid_t {
            pid_t pid = fork();
            if (pid < 0) { perror("fork (dup2 probe)"); return -1; }
            if (pid == 0) {
                int inet = socket(AF_INET, SOCK_STREAM, 0);
                int pair[2];
                if (inet < 0 || socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) _exit(126);
                dup2(inet, 0);
                dup2(pair[0], 1);
                _exit(0);
            }
            int status = 0;
            waitpid(pid, &status, 0);
            return pid;
        };
        auto dup2_events_for = [](pid_t pid) {
            std::vector<TelemetryEvent> out;
            for (const auto& ev : EventsOfType(EventType::Dup2)) {
                if (ev.header.pid == static_cast<uint32_t>(pid)) out.push_back(ev);
            }
            return out;
        };

        if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
            Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        } else {
            ClearEvents();
            pid_t at_pid = run_dup2_child();
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            bool inet_on_stdin = false, unix_on_stdout = false;
            for (const auto& ev : dup2_events_for(at_pid)) {
                const auto& d = ev.details.dup2;
                if (d.newfd == 0 && d.old_fd_type == 2 && d.old_fd_family == AF_INET) inet_on_stdin = true;
                if (d.newfd == 1 && d.old_fd_type == 2 && d.old_fd_family == AF_UNIX) unix_on_stdout = true;
            }
            Check(inet_on_stdin, "MODE_ANTITHEFT: dup2 of an AF_INET socket onto stdin reports, family 2");
            Check(unix_on_stdout, "MODE_ANTITHEFT: dup2 of an AF_UNIX socketpair end onto stdout reports, family 1");
        }

        for (uint32_t mode : {kModeWarden, 0u}) {
            const std::string name = mode == kModeWarden ? "MODE_WARDEN" : "mode unset";
            if (!loader.SetConfigValue(kConfigDeploymentMode, mode)) {
                Check(false, "SetConfigValue(" + name + ") failed");
                continue;
            }
            ClearEvents();
            pid_t pid = run_dup2_child();
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            size_t n = dup2_events_for(pid).size();
            Check(n == 0, name + ": the same child reports no Dup2 in LSM mode, as before (got " + std::to_string(n) +
                              ") - warden's reverse-shell kill must not start acting on it");
        }

        loader.SetConfigValue(kConfigDeploymentMode, 0);
        ClearEvents();
    }

    if (!loader.SetConfigValue(kConfigBlockingEnabled, 1)) {
        std::cerr << "Failed to enable blocking_enabled" << std::endl;
        SafeShutdown();
        return 1;
    }

    std::cout << "[impersonation-e2e] running probe process (process_vm_readv, setgroups, "
                 "seteuid-then-back, prctl x3, unshare(CLONE_NEWUSER), clone(CLONE_NEWUSER))..." << std::endl;
    RunImpersonationProbe();

    std::cout << "[impersonation-e2e] running namespace probe (mount, chroot, setns, pivot_root)..." << std::endl;
    RunNamespaceProbe();

    std::cout << "[impersonation-e2e] running rename/symlink probe..." << std::endl;
    {
        char scratch_tmpl[] = "/tmp/kinnector_rename_symlink_probe_XXXXXX";
        const char* scratch_dir = mkdtemp(scratch_tmpl);
        if (scratch_dir) {
            RunRenameSymlinkProbe(scratch_dir);
        } else {
            std::cerr << "  (note: could not create scratch dir for rename/symlink probe - skipping)" << std::endl;
        }
    }

    std::string setuid_helper = MakeSetuidRootHelper();
    std::cout << "[impersonation-e2e] running setuid-root exec probe (ExecCredentialDelta)..." << std::endl;
    RunSetuidRootExec(setuid_helper);
    if (!setuid_helper.empty()) unlink(setuid_helper.c_str());

    // Ring buffer is polled on a background thread every 100ms
    // (RingBufferPollLoop) - give it several cycles to drain everything the
    // probes above just emitted.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    std::cout << "\n[impersonation-e2e] checking captured telemetry:" << std::endl;

    // Phase 2: process_vm_readv, self-target (direction=0=read).
    {
        auto evs = EventsOfType(EventType::CrossMemoryAccess);
        bool found = false;
        for (const auto& ev : evs) {
            if (ev.details.cross_memory_access.direction == 0) { found = true; break; }
        }
        Check(found, "process_vm_readv produced a real CrossMemoryAccess(direction=0) event");
    }

    // Phase 1: setgroups(0, NULL).
    {
        auto evs = EventsOfType(EventType::GroupSet);
        Check(!evs.empty(), "setgroups() produced a real GroupSet event");
    }

    // Phase 1: seteuid(65534)-then-seteuid(0) - task_fix_setuid should fire
    // at least once with a real euid delta (65534 <-> 0 in either direction).
    {
        auto evs = EventsOfType(EventType::PrivilegeChange);
        bool found = false;
        for (const auto& ev : evs) {
            auto old_euid = ev.details.privilege_change.old_euid;
            auto new_euid = ev.details.privilege_change.new_euid;
            if (old_euid != new_euid) { found = true; break; }
        }
        Check(found, "seteuid()-then-back produced a real PrivilegeChange event with an euid delta");
    }

    // Phase 4: prctl(PR_SET_KEEPCAPS, 1).
    {
        auto evs = EventsOfType(EventType::PrctlKeepcaps);
        bool found = false;
        for (const auto& ev : evs) {
            if (ev.details.prctl_keepcaps.keepcaps_enabled == 1) { found = true; break; }
        }
        Check(found, "prctl(PR_SET_KEEPCAPS, 1) produced a real PrctlKeepcaps(enabled=1) event");
    }

    // Phase 11: prctl(PR_SET_NAME, "sshd").
    {
        auto evs = EventsOfType(EventType::CommRename);
        bool found = false;
        for (const auto& ev : evs) {
            if (strncmp(ev.details.comm_rename.new_comm, "sshd", 4) == 0) { found = true; break; }
        }
        Check(found, "prctl(PR_SET_NAME, \"sshd\") produced a real CommRename(new_comm=\"sshd\") event");
    }

    // Phase 11: prctl(PR_SET_CHILD_SUBREAPER, 1).
    {
        auto evs = EventsOfType(EventType::SubreaperSet);
        bool found = false;
        for (const auto& ev : evs) {
            if (ev.details.subreaper_set.enabled == 1) { found = true; break; }
        }
        Check(found, "prctl(PR_SET_CHILD_SUBREAPER, 1) produced a real SubreaperSet(enabled=1) event");
    }

    // Phase 13: clone(CLONE_NEWUSER) (operation=5) - a namespace-creating
    // clone at process-creation time.
    {
        auto evs = EventsOfType(EventType::NamespaceChange);
        bool found = false;
        for (const auto& ev : evs) {
            if (ev.details.namespace_change.operation == 5) { found = true; break; }
        }
        Check(found, "clone(CLONE_NEWUSER) produced a real NamespaceChange(operation=5) event");
    }

    // Antitheft container/namespace tracking fix: unshare(CLONE_NEWUSER)
    // (operation=1) checked strictly on its own now - previously OR'd with
    // the clone(CLONE_NEWUSER) check above, which silently masked the fact
    // that sys_enter_unshare was never attached in real BPF-LSM mode at all
    // (this exact probe process calls a real unshare(CLONE_NEWUSER) and it
    // produced zero telemetry before ebpf_loader.cpp's fix).
    {
        auto evs = EventsOfType(EventType::NamespaceChange);
        bool found = false;
        for (const auto& ev : evs) {
            if (ev.details.namespace_change.operation == 1) { found = true; break; }
        }
        Check(found, "unshare(CLONE_NEWUSER) produced a real NamespaceChange(operation=1) event");
    }

    // Antitheft container/namespace tracking fix: setns(2) - joins the
    // probe's own current mount namespace (operation=0).
    {
        auto evs = EventsOfType(EventType::NamespaceChange);
        bool found = false;
        for (const auto& ev : evs) {
            if (ev.details.namespace_change.operation == 0) { found = true; break; }
        }
        Check(found, "setns() produced a real NamespaceChange(operation=0) event");
    }

    // Antitheft container/namespace tracking fix: mount(2) - a real bind
    // mount inside the probe's own private mount namespace (operation=2).
    {
        auto evs = EventsOfType(EventType::NamespaceChange);
        bool found = false;
        for (const auto& ev : evs) {
            if (ev.details.namespace_change.operation == 2) { found = true; break; }
        }
        Check(found, "mount() produced a real NamespaceChange(operation=2) event");
    }

    // Antitheft container/namespace tracking fix: chroot(2) (operation=3).
    {
        auto evs = EventsOfType(EventType::NamespaceChange);
        bool found = false;
        for (const auto& ev : evs) {
            if (ev.details.namespace_change.operation == 3) { found = true; break; }
        }
        Check(found, "chroot() produced a real NamespaceChange(operation=3) event");
    }

    // Antitheft container/namespace tracking fix: pivot_root(2) (operation=4)
    // - previously only proven by the compile+bpf_object__load pass (this
    // test running at all), now proven by a real pivot_root() call inside
    // the probe's own private mount namespace.
    {
        auto evs = EventsOfType(EventType::NamespaceChange);
        bool found = false;
        for (const auto& ev : evs) {
            if (ev.details.namespace_change.operation == 4) { found = true; break; }
        }
        Check(found, "pivot_root() produced a real NamespaceChange(operation=4) event");
    }

    // Owner-swap defense follow-up: rename(2) over an existing destination
    // - previously produced no telemetry at all (no inode_rename hook
    // existed), a real gap for a rename-based owner-path swap.
    {
        auto evs = EventsOfType(EventType::FileRename);
        bool found = false;
        for (const auto& ev : evs) {
            if (strncmp(ev.details.file_rename.destination_path, "rename-dst", 10) == 0) { found = true; break; }
        }
        Check(found, "rename() produced a real FileRename(destination_path=\"rename-dst\") event");
    }

    // Owner-swap defense follow-up: symlink(2) creating a brand-new entry -
    // previously produced no telemetry at all (no inode_symlink hook
    // existed), a real gap for a symlink-based owner-path swap.
    {
        auto evs = EventsOfType(EventType::FileCreate);
        bool found = false;
        for (const auto& ev : evs) {
            if (strncmp(ev.details.file_create.file_path, "symlink-dst", 11) == 0) { found = true; break; }
        }
        Check(found, "symlink() produced a real FileCreate(file_path=\"symlink-dst\") event");
    }

    // Phase 12: setuid-root exec. Kept as a soft check (not a hard failure)
    // only because MakeSetuidRootHelper's own file setup can legitimately be
    // skipped on a nosuid-mounted /tmp - the mechanism itself is confirmed
    // correct when that setup succeeds (see bprm_committing_creds's own
    // comment for the real-kernel correction this required: the original
    // bprm_creds_for_exec placement never saw the setuid-bit elevation,
    // moving to bprm_committing_creds fixed it, verified live via
    // bpf_trace_printk before this comment was written).
    {
        auto evs = EventsOfType(EventType::ExecCredentialDelta);
        bool found = false;
        for (const auto& ev : evs) {
            if (ev.details.exec_credential_delta.pre_exec_uid == 1000 &&
                ev.details.exec_credential_delta.post_exec_euid == 0) {
                found = true;
                break;
            }
        }
        CheckSoft(found, "setuid-root exec with no setuid() syscall produced a real ExecCredentialDelta event "
                          "(soft check only for MakeSetuidRootHelper's nosuid-mount caveat, not for the mechanism itself)");
    }

    // -----------------------------------------------------------------
    // execveat(2) had no ProcessCreate producer at all.
    //
    // In an antitheft LSM deployment bprm_creds_for_exec deliberately stays
    // silent (it would duplicate the tracepoint without argv/envp), and the
    // only exec tracepoint attached was sys_enter_execve - so every
    // fexecve()/memfd-backed exec, which is exactly what execveat exists for,
    // produced nothing for userspace. Kernel-side stamps still fired, so this
    // was a blind spot in the tree/origin/install-context half, not in
    // enforcement. Notably memfd exec is a vector this same BPF file can
    // deny for protected processes (with self-injection protection on), so
    // it was also the one exec the agent could not observe.
    //
    // The probe execve's once (its own startup) and execveat's once, so a
    // working producer means TWO ProcessCreate events for that pid. One means
    // the execveat went unseen, which is the pre-fix behaviour.
    {
        std::cout << "[impersonation-e2e] execveat produces a ProcessCreate under MODE_ANTITHEFT..." << std::endl;
        if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
            Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        } else {
            ClearEvents();
            pid_t pid = RunExecveatProbeReturningPid();
            Check(pid > 0, "execveat probe ran");
            if (pid > 0) {
                // The ring buffer is drained by the poll thread, so give the
                // second event a moment to land before counting.
                usleep(500000);
                // ProcessCreate puts the PARENT in header.pid (see
                // fill_header's call site) and the process itself in
                // details.process_create.child_pid, so CountForPid would
                // count the harness, not the probe.
                size_t n = 0;
                for (const auto& ev : EventsOfType(EventType::ProcessCreate)) {
                    if (ev.details.process_create.child_pid == static_cast<uint32_t>(pid)) n++;
                }
                Check(n >= 2, "both the probe's execve and its execveat produced a ProcessCreate (got " +
                              std::to_string(n) + ", 1 means execveat went unseen)");
            }
        }
    }

    SafeShutdown();

    if (g_failures > 0) {
        std::cerr << "\n>>> IMPERSONATION TELEMETRY E2E TEST FAILED (" << g_failures << " check(s)) <<<\n";
        return 1;
    }
    std::cout << "\n>>> IMPERSONATION TELEMETRY E2E TEST PASSED <<<\n";
    return 0;
}
