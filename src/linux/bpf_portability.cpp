#include "bpf_portability.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>

namespace kinnector {
namespace bpf_portability {
namespace {

// Minimal instruction builders. libbpf ships no bpf_insn.h in the distro
// package, and the probes below only ever need "return 0".
constexpr struct bpf_insn MovImm(int dst, int imm) {
    return {static_cast<__u8>(BPF_ALU64 | BPF_MOV | BPF_K), static_cast<__u8>(dst),
            0, 0, imm};
}
constexpr struct bpf_insn ExitInsn() {
    return {static_cast<__u8>(BPF_JMP | BPF_EXIT), 0, 0, 0, 0};
}

bool EnvFlag(const char* name) {
    const char* v = std::getenv(name);
    if (!v || !*v) return false;
    return !(std::strcmp(v, "0") == 0 || std::strcmp(v, "false") == 0);
}

// Loads a trivial program of `type` and reports whether the kernel took it.
bool ProbeTrivialProgram(enum bpf_prog_type type, const char* name,
                         enum bpf_attach_type expected_attach,
                         int attach_btf_id, int* out_fd) {
    struct bpf_insn insns[] = {MovImm(BPF_REG_0, 0), ExitInsn()};
    LIBBPF_OPTS(bpf_prog_load_opts, opts);
    if (expected_attach) opts.expected_attach_type = expected_attach;
    if (attach_btf_id > 0) opts.attach_btf_id = attach_btf_id;
    int fd = bpf_prog_load(type, name, "Dual BSD/GPL", insns,
                           sizeof(insns) / sizeof(insns[0]), &opts);
    if (fd < 0) return false;
    if (out_fd) {
        *out_fd = fd;
    } else {
        close(fd);
    }
    return true;
}

// --- feature cache ---------------------------------------------------------

struct CachedFlag {
    std::once_flag once;
    bool value = false;
};

CachedFlag g_lsm, g_fentry, g_large, g_ringbuf, g_btf, g_getfuncret;
std::mutex g_reset_mu;

bool DetectKernelBtf() {
    struct btf* btf = btf__load_vmlinux_btf();
    if (!btf) return false;
    btf__free(btf);
    return true;
}

// Ported from Tetragon's detectLSM(). The layer our old CheckLsmSupport()
// lacked is the securityfs one: on a host where /sys/kernel/security is not
// mounted, reading /sys/kernel/security/lsm fails and the old code reported
// "no BPF LSM" - indistinguishable from a kernel genuinely built without it.
bool DetectLsm() {
    if (libbpf_probe_bpf_prog_type(BPF_PROG_TYPE_LSM, nullptr) != 1) return false;

    bool mounted_here = false;
    bool securityfs_empty = true;
    if (DIR* d = opendir("/sys/kernel/security")) {
        while (struct dirent* e = readdir(d)) {
            if (std::strcmp(e->d_name, ".") != 0 && std::strcmp(e->d_name, "..") != 0) {
                securityfs_empty = false;
                break;
            }
        }
        closedir(d);
    }
    if (securityfs_empty) {
        if (mount("securityfs", "/sys/kernel/security", "securityfs", MS_RDONLY, nullptr) != 0) {
            return false;
        }
        mounted_here = true;
    }

    bool has_bpf = false;
    {
        std::ifstream lsm_file("/sys/kernel/security/lsm");
        std::string list;
        if (lsm_file.is_open() && std::getline(lsm_file, list)) {
            has_bpf = list.find("bpf") != std::string::npos;
        }
    }
    if (mounted_here) umount("/sys/kernel/security");
    if (!has_bpf) return false;

    // Final layer: a real lsm/file_open program, loaded AND attached. Loading
    // alone is not proof - attach is where a missing trampoline shows up.
    int btf_id = libbpf_find_vmlinux_btf_id("file_open", BPF_LSM_MAC);
    if (btf_id < 0) return false;
    int prog_fd = -1;
    if (!ProbeTrivialProgram(BPF_PROG_TYPE_LSM, "kinn_probe_lsm", BPF_LSM_MAC, btf_id, &prog_fd)) {
        return false;
    }
    int link_fd = bpf_link_create(prog_fd, 0, BPF_LSM_MAC, nullptr);
    close(prog_fd);
    if (link_fd < 0) return false;
    close(link_fd);
    return true;
}

// Tetragon's detectFentry(): on amd64 the program-type check is sufficient
// because BPF trampolines landed together with the type in 5.5. On arm64 they
// did not (6.0), so there the probe has to actually attach or it reports a
// false positive. This is the concrete reason these are probes and not a
// version table.
bool DetectFentry() {
    if (libbpf_probe_bpf_prog_type(BPF_PROG_TYPE_TRACING, nullptr) != 1) return false;
#if defined(__x86_64__)
    return true;
#else
    int btf_id = libbpf_find_vmlinux_btf_id("security_task_prctl", BPF_TRACE_FENTRY);
    if (btf_id < 0) return false;
    int prog_fd = -1;
    if (!ProbeTrivialProgram(BPF_PROG_TYPE_TRACING, "kinn_probe_fentry",
                             BPF_TRACE_FENTRY, btf_id, &prog_fd)) {
        return false;
    }
    int link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_FENTRY, nullptr);
    close(prog_fd);
    if (link_fd < 0) return false;
    close(link_fd);
    return true;
#endif
}

// Loads a program longer than the historical 4096-instruction cap. A kernel
// that still enforces the old cap rejects it; one with the 5.2+ 1M complexity
// limit takes it.
bool DetectLargeProgs() {
    constexpr int kInsns = 4096 + 16;
    std::vector<struct bpf_insn> insns;
    insns.reserve(kInsns);
    for (int i = 0; i < kInsns - 1; ++i) insns.push_back(MovImm(BPF_REG_0, 0));
    insns.push_back(ExitInsn());
    LIBBPF_OPTS(bpf_prog_load_opts, opts);
    int fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, "kinn_probe_large", "Dual BSD/GPL",
                           insns.data(), insns.size(), &opts);
    if (fd < 0) return false;
    close(fd);
    return true;
}

bool DetectRingbuf() {
    return libbpf_probe_bpf_map_type(BPF_MAP_TYPE_RINGBUF, nullptr) == 1;
}

// Ported from Tetragon's detectGetFuncRetHelper(): load a real fexit program
// that calls bpf_get_func_ret. Attached to sys_getcpu, which exists everywhere
// and is cheap, exactly as they do.
bool DetectGetFuncRet() {
    if (libbpf_probe_bpf_prog_type(BPF_PROG_TYPE_TRACING, nullptr) != 1) return false;
    int btf_id = libbpf_find_vmlinux_btf_id("__x64_sys_getcpu", BPF_TRACE_FEXIT);
    if (btf_id < 0) btf_id = libbpf_find_vmlinux_btf_id("sys_getcpu", BPF_TRACE_FEXIT);
    if (btf_id < 0) return false;

    // r2 = fp - 8; call bpf_get_func_ret; r0 = 0; exit
    struct bpf_insn insns[] = {
        {static_cast<__u8>(BPF_ALU64 | BPF_MOV | BPF_X), BPF_REG_2, BPF_REG_10, 0, 0},
        {static_cast<__u8>(BPF_ALU64 | BPF_ADD | BPF_K), BPF_REG_2, 0, 0, -8},
        {static_cast<__u8>(BPF_JMP | BPF_CALL), 0, 0, 0, 184 /* bpf_get_func_ret */},
        MovImm(BPF_REG_0, 0),
        ExitInsn(),
    };
    LIBBPF_OPTS(bpf_prog_load_opts, opts);
    opts.expected_attach_type = BPF_TRACE_FEXIT;
    opts.attach_btf_id = btf_id;
    int fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, "kinn_probe_gfr", "GPL", insns,
                           sizeof(insns) / sizeof(insns[0]), &opts);
    if (fd < 0) return false;
    close(fd);
    return true;
}

bool Cached(CachedFlag& slot, bool (*detect)()) {
    std::call_once(slot.once, [&slot, detect]() { slot.value = detect(); });
    return slot.value;
}

}  // namespace

bool Features::HasLsm() { return Cached(g_lsm, DetectLsm); }
bool Features::HasFentry() { return Cached(g_fentry, DetectFentry); }
bool Features::HasRingbuf() { return Cached(g_ringbuf, DetectRingbuf); }
bool Features::HasKernelBtf() { return Cached(g_btf, DetectKernelBtf); }
bool Features::HasGetFuncRet() { return Cached(g_getfuncret, DetectGetFuncRet); }

bool Features::HasLargeProgs() {
    if (ForceSmallProgs()) return false;
    if (ForceLargeProgs()) return true;
    return Cached(g_large, DetectLargeProgs);
}

bool Features::ForceSmallProgs() { return EnvFlag("KINNECTOR_FORCE_SMALL_PROGS"); }
bool Features::ForceLargeProgs() {
    // Small wins when both are set, so a operator escaping a broken kernel is
    // never overridden by a stale "force large" left in a unit file.
    return !ForceSmallProgs() && EnvFlag("KINNECTOR_FORCE_LARGE_PROGS");
}

std::string Features::Summary() {
    std::ostringstream os;
    os << "[BPF Features] lsm=" << (HasLsm() ? "yes" : "no")
       << " fentry=" << (HasFentry() ? "yes" : "no")
       << " large_progs=" << (HasLargeProgs() ? "yes" : "no")
       << " ringbuf=" << (HasRingbuf() ? "yes" : "no")
       << " kernel_btf=" << (HasKernelBtf() ? "yes" : "no")
       << " get_func_ret=" << (HasGetFuncRet() ? "yes" : "no")
       << " tier=" << (SelectTier() == Tier::kSmall ? "small" : "full");
    if (ForceSmallProgs()) os << " (forced small)";
    if (ForceLargeProgs()) os << " (forced large)";
    return os.str();
}

void Features::ResetCacheForTesting() {
    std::lock_guard<std::mutex> lk(g_reset_mu);
    g_lsm.~CachedFlag();  new (&g_lsm) CachedFlag();
    g_fentry.~CachedFlag(); new (&g_fentry) CachedFlag();
    g_large.~CachedFlag(); new (&g_large) CachedFlag();
    g_ringbuf.~CachedFlag(); new (&g_ringbuf) CachedFlag();
    g_btf.~CachedFlag(); new (&g_btf) CachedFlag();
    g_getfuncret.~CachedFlag(); new (&g_getfuncret) CachedFlag();
}

// ---------------------------------------------------------------------------
// (1) Variant tiers
// ---------------------------------------------------------------------------

Tier SelectTier() {
    return Features::HasLargeProgs() ? Tier::kFull : Tier::kSmall;
}

std::string SmallTierPath(const std::string& requested) {
    const std::string suffix = ".o";
    if (requested.size() <= suffix.size() ||
        requested.compare(requested.size() - suffix.size(), suffix.size(), suffix) != 0) {
        return {};
    }
    std::string small = requested.substr(0, requested.size() - suffix.size()) + ".small.o";
    if (small == requested) return {};
    if (access(small.c_str(), R_OK) != 0) return {};
    return small;
}

// Same shape as SmallTierPath, for the tier built with KINN_D_PATH's calls
// compiled out (see kinnector_helpers.h). Reactive, like the small tier:
// bpf_d_path's availability in an LSM context can only be observed by a
// real load failure (confirmed: 5.10.268 rejects it, "helper call is not
// allowed in probe"), never predicted from a version number.
std::string NoDpathTierPath(const std::string& requested) {
    const std::string suffix = ".o";
    if (requested.size() <= suffix.size() ||
        requested.compare(requested.size() - suffix.size(), suffix.size(), suffix) != 0) {
        return {};
    }
    std::string base = requested.substr(0, requested.size() - suffix.size());
    // Strip a ".small" suffix first, if present, so this always resolves to
    // "kinnector.bpf.nodpath.o" regardless of which tier failed - there is
    // no separate "small+nodpath" object, and bpf_d_path's availability is
    // independent of program-size tolerance.
    const std::string small_suffix = ".small";
    if (base.size() > small_suffix.size() &&
        base.compare(base.size() - small_suffix.size(), small_suffix.size(), small_suffix) == 0) {
        base = base.substr(0, base.size() - small_suffix.size());
    }
    std::string nodpath = base + ".nodpath.o";
    if (nodpath == requested) return {};
    if (access(nodpath.c_str(), R_OK) != 0) return {};
    return nodpath;
}

std::string SelectObjectPath(const std::string& requested) {
    if (SelectTier() != Tier::kSmall) return requested;

    // kinnector.bpf.o -> kinnector.bpf.small.o
    const std::string suffix = ".o";
    if (requested.size() <= suffix.size() ||
        requested.compare(requested.size() - suffix.size(), suffix.size(), suffix) != 0) {
        return requested;
    }
    std::string small = requested.substr(0, requested.size() - suffix.size()) + ".small.o";
    if (access(small.c_str(), R_OK) == 0) {
        std::cout << "[BPF Tier] kernel cannot take large programs; using " << small << std::endl;
        return small;
    }
    // A deployment that ships only the full object keeps its previous
    // behaviour rather than failing to find a file that was never installed.
    std::cerr << "[BPF Tier] small tier selected but " << small
              << " is not installed; falling back to " << requested << std::endl;
    return requested;
}

// ---------------------------------------------------------------------------
// (4) BTF function-prototype validation
// ---------------------------------------------------------------------------

namespace {
// BTF name of a parameter's type. For a pointer, the pointee's name, which is
// what identifies `struct inode *` vs `struct dentry *` - the distinction that
// matters if an upstream change reorders arguments under us.
std::string ParamTypeName(const struct btf* btf, __u32 type_id) {
    const struct btf_type* t = btf__type_by_id(btf, type_id);
    // Peel qualifiers, then one pointer level.
    for (int guard = 0; t && guard < 8; ++guard) {
        if (btf_is_const(t) || btf_is_volatile(t) || btf_is_restrict(t) || btf_is_typedef(t)) {
            t = btf__type_by_id(btf, t->type);
            continue;
        }
        break;
    }
    if (!t) return "";
    if (btf_is_ptr(t)) {
        const struct btf_type* pointee = btf__type_by_id(btf, t->type);
        for (int guard = 0; pointee && guard < 8; ++guard) {
            if (btf_is_const(pointee) || btf_is_volatile(pointee) ||
                btf_is_restrict(pointee) || btf_is_typedef(pointee)) {
                pointee = btf__type_by_id(btf, pointee->type);
                continue;
            }
            break;
        }
        if (!pointee) return "";
        const char* n = btf__name_by_offset(btf, pointee->name_off);
        return n ? n : "";
    }
    const char* n = btf__name_by_offset(btf, t->name_off);
    return n ? n : "";
}
}  // namespace

Validation ValidateTracingTarget(const std::string& kernel_func,
                                 const std::vector<TracingArg>& args,
                                 std::string* detail) {
    struct btf* btf = btf__load_vmlinux_btf();
    if (!btf) {
        if (detail) *detail = "kernel BTF unavailable; cannot validate " + kernel_func;
        return Validation::kWarn;
    }
    struct BtfGuard {
        struct btf* p;
        ~BtfGuard() { btf__free(p); }
    } guard{btf};

    __s32 id = btf__find_by_name_kind(btf, kernel_func.c_str(), BTF_KIND_FUNC);
    if (id < 0) {
        if (detail) *detail = "no BTF FUNC named " + kernel_func;
        return Validation::kWarn;
    }
    const struct btf_type* fn = btf__type_by_id(btf, id);
    if (!fn) {
        if (detail) *detail = "BTF FUNC " + kernel_func + " has no type";
        return Validation::kWarn;
    }
    const struct btf_type* proto = btf__type_by_id(btf, fn->type);
    if (!proto || !btf_is_func_proto(proto)) {
        if (detail) *detail = "BTF FUNC " + kernel_func + " has no FUNC_PROTO";
        return Validation::kWarn;
    }

    const int actual = btf_vlen(proto);
    const struct btf_param* params = btf_params(proto);

    for (const auto& want : args) {
        if (want.index < 0 || want.index >= actual) {
            if (detail) {
                std::ostringstream os;
                os << kernel_func << " takes " << actual
                   << " args in this kernel's BTF; we read index " << want.index;
                *detail = os.str();
            }
            return Validation::kFailed;
        }
        if (!want.type_name || !*want.type_name) continue;

        const std::string got = ParamTypeName(btf, params[want.index].type);
        if (got != want.type_name) {
            if (detail) {
                const char* pname = btf__name_by_offset(btf, params[want.index].name_off);
                std::ostringstream os;
                os << kernel_func << " arg " << want.index << " ("
                   << (pname && *pname ? pname : "anon") << ") is '" << got
                   << "' in this kernel's BTF, we read it as '" << want.type_name << "'";
                *detail = os.str();
            }
            return Validation::kFailed;
        }
    }
    return Validation::kOk;
}

// ---------------------------------------------------------------------------
// (3) Per-program load tolerance
// ---------------------------------------------------------------------------

const std::vector<ProgramPolicy>& PolicyTable() {
    // Requirement rationale, program by program, is deliberately explicit:
    // marking something kOptional is a decision to let enforcement degrade
    // silently on a kernel that rejects it, so it needs a reason.
    static const std::vector<ProgramPolicy> table = {
        // --- Required: the enforcement core. Without these the daemon is not
        // protecting anything and must not pretend otherwise. ---
        {"file_open",              Requirement::kRequired, "", {}},
        {"file_permission",        Requirement::kRequired, "", {}},
        {"bprm_creds_for_exec",    Requirement::kRequired, "", {}},
        {"bprm_check_security",    Requirement::kRequired, "", {}},
        {"mmap_file",              Requirement::kRequired, "", {}},
        {"file_mprotect",          Requirement::kRequired, "", {}},
        {"ptrace_access_check",    Requirement::kRequired, "", {}},
        {"task_kill",              Requirement::kRequired, "", {}},
        // sched_process_exit is the ONLY site that reclaims per-process map
        // entries. Losing it does not merely lose telemetry: twelve maps grow
        // to max_entries and enforcement then fails OPEN (fixed in d1b'e1).
        {"tracepoint_sched_process_exit", Requirement::kRequired, "", {}},
        // Lineage propagation - chain identity depends on it.
        {"tracepoint_sched_process_fork", Requirement::kRequired, "", {}},
        // The two exec producers. execveat was a real blind spot once already.
        {"tracepoint_sys_enter_execve",   Requirement::kRequired, "", {}},
        {"tracepoint_sys_enter_execveat", Requirement::kRequired, "", {}},
        // Emits a held exec's events once it succeeded. Optional:
        // unloaded, CONFIG_EXEC_AT_SUCCESS stays 0 and the syscall emits.
        {"tracepoint_sched_process_exec", Requirement::kOptional, "", {}},
        // Backfill of pre-existing processes; without it every already-running
        // app is unprotected. The program's C name is iter_task_start_times,
        // not its SEC() name "iter/task" - bpf_object__find_program_by_name
        // looks up the former, and the test cross-checks the table against the
        // object's real names precisely because getting this wrong turns a
        // classified entry into dead code.
        {"iter_task_start_times",  Requirement::kRequired, "", {}},

        // --- Optional: enforcement with a backstop elsewhere. ---
        // O_CREAT through inode_create is denied by file_open anyway.
        {"inode_create",           Requirement::kOptional, "", {}},
        {"inode_mkdir",            Requirement::kOptional, "", {}},
        {"inode_unlink",           Requirement::kOptional, "", {}},
        // Residual-gap close #1: verified attachable on every kernel in the
        // LVH matrix (5.10-7.2 bpf-next) via progload before this was
        // written, but it's the first program in this codebase attached to
        // `security_bpf` at all - no Tetragon precedent, no in-tree history
        // to lean on. Optional for the same reason as inode_unlink just
        // above (its sibling in the same self-defense pair, also Optional):
        // losing it degrades tamper resistance against a raw-BPF-admin
        // attacker, but every other enforcement hook keeps working, which is
        // a strictly better failure mode than the whole object refusing to
        // load on some untested kernel (arm64, a 4.19 no-BTF build, etc.).
        {"bpf_syscall_guard",      Requirement::kOptional, "", {}},
        {"path_chmod",             Requirement::kOptional, "", {}},
        {"socket_connect",         Requirement::kOptional, "", {}},
        // AUDIT ONLY (never a deny path) - see this
        // program's own doc comment in kinnector.bpf.c. Optional for the same
        // reason as every other Optional entry near it: losing it on some
        // untested kernel costs visibility, not enforcement, which is a
        // strictly better failure mode than the whole object refusing to load.
        {"unix_stream_connect",    Requirement::kOptional, "", {}},
        {"socket_listen",          Requirement::kOptional, "", {}},
        {"socket_accept",          Requirement::kOptional, "", {}},
        {"socket_sendmsg",         Requirement::kOptional, "", {}},
        {"task_fix_setuid",        Requirement::kOptional, "", {}},
        {"shm_shmat",              Requirement::kOptional, "", {}},

        // --- Optional: resource-swap closure. The pre-operation LSM hooks
        // (inode_rename/symlink/link) and lsm_d_instantiate's post-operation
        // closure (see kinnector_container_lsm_hooks.h) cover the same gap
        // from two sides, so losing either side degrades but does not
        // disable the defence. Used to be six programs here (an fexit pair
        // gated on bpf_get_func_ret plus a kprobe/kretprobe-with-side-map
        // fallback for kernels without it) - removed along with
        // that whole HelperGate dance once lsm_d_instantiate was confirmed
        // to cover symlink(2)/link(2) directly, no kernel-feature tiering
        // needed at all. ---
        {"inode_rename",           Requirement::kOptional, "", {}},
        {"inode_symlink",          Requirement::kOptional, "", {}},
        {"inode_link",             Requirement::kOptional, "", {}},
        // A freed protected inode's number stops being protected. Losing it brings back the
        // inherited-protection false denies, not an opening.
        {"inode_free_security",    Requirement::kOptional, "", {}},

        // --- Optional: monitoring-only hooks. These never return non-zero;
        // by construction nothing is enforced by them, so skipping one loses
        // visibility and nothing else. (See the impersonation-telemetry work:
        // "monitoring only, no new enforcement".) ---
        {"task_fix_setgid",        Requirement::kOptional, "", {}},
        {"capset",                 Requirement::kOptional, "", {}},
        {"task_prctl",             Requirement::kOptional, "", {}},
        {"sb_pivotroot",           Requirement::kOptional, "", {}},
        {"bprm_committing_creds",  Requirement::kOptional, "", {}},
        {"warden_sb_mount",        Requirement::kOptional, "", {}},
        {"warden_path_chroot",     Requirement::kOptional, "", {}},

        // --- Optional: pure telemetry tracepoints and kprobes. ---
        {"tracepoint_sys_enter_connect",          Requirement::kOptional, "", {}},
        {"tracepoint_sys_enter_openat",           Requirement::kOptional, "", {}},
        {"tracepoint_sys_enter_mmap",             Requirement::kOptional, "", {}},
        {"tracepoint_sys_enter_mprotect",         Requirement::kOptional, "", {}},
        {"tracepoint_sys_enter_dup2",             Requirement::kOptional, "", {}},
        {"tracepoint_sys_enter_dup3",             Requirement::kOptional, "", {}},
        {"tracepoint_sys_enter_listen",           Requirement::kOptional, "", {}},
        {"tracepoint_sys_enter_process_vm_readv", Requirement::kOptional, "", {}},
        {"tracepoint_sys_enter_process_vm_writev",Requirement::kOptional, "", {}},
        {"tracepoint_sys_enter_setns",            Requirement::kOptional, "", {}},
        {"tracepoint_sys_enter_unshare",          Requirement::kOptional, "", {}},
        {"tracepoint_sys_enter_clone",            Requirement::kOptional, "", {}},
        {"tracepoint_sys_enter_clone3",           Requirement::kOptional, "", {}},
        {"tracepoint_sys_enter_setgroups",        Requirement::kOptional, "", {}},
        // PTY capture. tty_write/tty_read are file_operations
        // .write_iter/.read_iter callbacks on every kernel we support:
        //     tty_write(struct kiocb *iocb, struct iov_iter *from)
        //     tty_read (struct kiocb *iocb, struct iov_iter *to)
        // These programs used to DECLARE the classic
        // `(struct file *, char *, size_t)` shape. A kprobe has no
        // verifier-enforced signature - it just gets pt_regs - so that loaded
        // cleanly everywhere while is_pty_file() dereferenced a kiocb as a
        // file, matched nothing, and PTY capture silently captured NOTHING.
        // The programs now read the real prototype; these entries are what
        // stops a future rename or reorder from making it silent again, which
        // is why a kprobe target is worth a policy entry even though its arity
        // cannot break the load the way an fexit's can.
        {"kprobe_tty_write",       Requirement::kOptional, "tty_write",
             {{0, "kiocb"}, {1, "iov_iter"}}},
        // count (index 2) is declared but never read in kprobe_tty_read's
        // body, unlike kprobe_tty_write's - so it is deliberately absent here,
        // matching the "must equal what the source actually reads" rule
        // TestPolicyTableArityMatchesSource enforces for these two kprobes.
        {"kprobe_tty_read",        Requirement::kOptional, "tty_read",
             {{0, "kiocb"}, {1, "iov_iter"}}},
        // NOT given a kernel_func, on purpose. BPF_KRETPROBE binds its sole
        // parameter to the synthesized return value (PT_REGS_RC), not to any
        // index in the kernel function's real argument list - there is no
        // "index we read" for ValidateTracingTarget's per-argument check to
        // compare against, so a kernel_func entry here would validate nothing
        // and just look like coverage that isn't there. The one thing that
        // COULD drift for a kretprobe - the target function disappearing or
        // being renamed - is already covered for free: kretprobe_tty_read
        // attaches to the identical symbol name ("tty_read") that
        // kprobe_tty_read's own entry above validates, and if that kprobe gets
        // gated off for a failed/absent symbol this kretprobe's own map entry
        // in pending_tty_reads is simply never populated, so it silently
        // no-ops on every return (see its `if (!req) return 0;` guard) instead
        // of misreading anything.
        {"kretprobe_tty_read",     Requirement::kOptional, "", {}},
        // Glob-owned-directory closure (kinnector_container_lsm_hooks.h): a
        // file created inside a protected directory inherits its protection.
        // Was a kprobe pair on `d_instantiate`/`d_instantiate_new` (kOptional
        // for the same reason as the telemetry kprobes above - a Required
        // program that cannot attach rejects the ENTIRE object, and
        // `d_instantiate_new` in particular does not exist on every kernel),
        // replaced with a single real LSM hook,
        // `lsm/d_instantiate` (`security_d_instantiate`), after the kprobe
        // pair turned out not to fire at all for a real tmpfs create on
        // kernel 7.2 - see kinnector_container_lsm_hooks.h's own comment for
        // the full history. No kernel-symbol/arg-type entry needed, same as
        // every other `lsm/` program in this table (`file_open`/`mmap_file`
        // above): LSM-type programs get their argument types checked
        // automatically by the verifier via BTF, unlike a kprobe's raw
        // register reads. Kept Optional, same reasoning as before - losing
        // this hook loses coverage of newly created files in a protected
        // directory and nothing else, and this product's minimum supported
        // kernel for `security_d_instantiate`'s BPF-LSM exposure has not
        // been surveyed as thoroughly as `d_instantiate`'s was.
        {"lsm_d_instantiate", Requirement::kOptional, "", {}},
    };
    return table;
}

Requirement RequirementFor(const std::string& prog_name) {
    for (const auto& p : PolicyTable()) {
        if (prog_name == p.prog_name) return p.requirement;
    }
    // Unknown programs are Required on purpose: a program added to
    // kinnector.bpf.c without a policy entry must not be silently droppable.
    return Requirement::kRequired;
}

std::map<std::string, std::string> GateByBtfValidation(struct bpf_object* obj) {
    return GateByBtfValidation(obj, PolicyTable());
}

std::map<std::string, std::string> GateByBtfValidation(
    struct bpf_object* obj, const std::vector<ProgramPolicy>& policy_table) {
    std::map<std::string, std::string> disabled;
    if (!obj) return disabled;

    for (const auto& policy : policy_table) {
        // NOTE: no "skip programs without a kernel_func" early-out here. The
        // helper gate below must see every program, because a program can be
        // helper-gated without having a tracing target to validate - the
        // kretprobe halves of the path-closure fallback are exactly that, and
        // an early-out let them load on a kernel where their fexit
        // counterparts were already doing the same work.
        //
        // Helper availability is checked before the BTF prototype, because a
        // missing helper is a certainty while a prototype mismatch is a
        // judgement. bpf_get_func_ret() is 5.17+, and the fexit programs read
        // their return value through it precisely so they do not depend on the
        // target's arity - which means on 5.15 they cannot load at all
        // ("invalid func unknown#184"). Skipping them here costs one wasted
        // load-and-reopen cycle less than letting the tolerant loader discover
        // it, and says why in the log instead of just "rejected by the kernel".
        const bool have_gfr = Features::HasGetFuncRet();
        const bool gated_off =
            (policy.helper_gate == ProgramPolicy::HelperGate::kNeedsGetFuncRet && !have_gfr) ||
            (policy.helper_gate == ProgramPolicy::HelperGate::kNeedsNoGetFuncRet && have_gfr);
        if (gated_off) {
            struct bpf_program* prog =
                bpf_object__find_program_by_name(obj, policy.prog_name);
            if (prog) {
                bpf_program__set_autoload(prog, false);
                disabled[policy.prog_name] =
                    have_gfr
                        ? "kernel has bpf_get_func_ret, so the fexit implementation of this "
                          "work runs instead - only one of the two may be attached"
                        : "kernel lacks bpf_get_func_ret (5.17+), so the kprobe/kretprobe "
                          "implementation of this work runs instead";
                std::cerr << "[BPF Portability] skipping optional program "
                          << policy.prog_name << ": " << disabled[policy.prog_name]
                          << std::endl;
            }
            continue;
        }

        // Nothing further to validate for a program with no tracing target.
        if (!policy.kernel_func || !*policy.kernel_func) continue;

        std::string detail;
        Validation v = ValidateTracingTarget(policy.kernel_func, policy.args, &detail);
        if (v == Validation::kOk) continue;

        if (v == Validation::kWarn) {
            std::cerr << "[BPF Portability] " << policy.prog_name << ": " << detail
                      << " (loading anyway)" << std::endl;
            continue;
        }

        // kFailed. A Required program with a drifted prototype is a real
        // outage either way - report it and let the load fail loudly rather
        // than disabling enforcement behind the operator's back.
        if (policy.requirement == Requirement::kRequired) {
            std::cerr << "[BPF Portability] FATAL " << policy.prog_name << ": " << detail
                      << std::endl;
            continue;
        }

        struct bpf_program* prog =
            bpf_object__find_program_by_name(obj, policy.prog_name);
        if (!prog) continue;
        bpf_program__set_autoload(prog, false);
        disabled[policy.prog_name] = detail;
        std::cerr << "[BPF Portability] skipping optional program " << policy.prog_name
                  << ": " << detail << std::endl;
    }
    return disabled;
}

namespace {

// libbpf reports a rejected program as
//   libbpf: prog 'NAME': BPF program load failed: <errno text>
// so the name is recoverable from its log even though bpf_object__load()
// itself only returns an errno. This is how a complexity rejection - which no
// amount of BTF inspection can predict - gets attributed to one program
// instead of taking the whole object down.
std::mutex g_capture_mu;
std::string g_failed_prog;
libbpf_print_fn_t g_prev_print = nullptr;

int CapturePrint(enum libbpf_print_level level, const char* fmt, va_list args) {
    char buf[1024];
    va_list copy;
    va_copy(copy, args);
    int n = vsnprintf(buf, sizeof(buf), fmt, copy);
    va_end(copy);

    if (n > 0) {
        const char* p = std::strstr(buf, "prog '");
        if (p && std::strstr(buf, "BPF program load failed")) {
            p += 6;
            const char* end = std::strchr(p, '\'');
            if (end && end > p) {
                std::lock_guard<std::mutex> lk(g_capture_mu);
                g_failed_prog.assign(p, static_cast<size_t>(end - p));
            }
        }
    }
    if (g_prev_print) return g_prev_print(level, fmt, args);
    return 0;
}

}  // namespace

LoadReport LoadTolerantly(struct bpf_object** obj, ReopenFn reopen, void* user) {
    LoadReport report;
    if (!obj || !*obj) {
        report.fatal_error = "no bpf object";
        return report;
    }

    // Bounded: each attempt can only ever disable one more program, and the
    // table is finite, but an unbounded loop against a kernel that keeps
    // failing for an unattributable reason would spin forever.
    const int kMaxAttempts = 12;
    std::vector<std::string> disabled_so_far;

    // The BTF pre-flight is run here rather than by the caller because every
    // reopen below produces a fresh object with every autoload flag back at
    // its default - so gating done once, outside this function, would be
    // silently undone by the first retry.
    for (auto& kv : GateByBtfValidation(*obj)) report.skipped[kv.first] = kv.second;

    g_prev_print = libbpf_set_print(CapturePrint);

    for (report.attempts = 1; report.attempts <= kMaxAttempts; ++report.attempts) {
        {
            std::lock_guard<std::mutex> lk(g_capture_mu);
            g_failed_prog.clear();
        }

        if (bpf_object__load(*obj) == 0) {
            report.loaded = true;
            break;
        }

        std::string failed;
        {
            std::lock_guard<std::mutex> lk(g_capture_mu);
            failed = g_failed_prog;
        }

        if (failed.empty()) {
            report.fatal_error = "bpf_object__load failed and libbpf named no program";
            break;
        }
        if (RequirementFor(failed) == Requirement::kRequired) {
            report.fatal_error = "required program '" + failed + "' failed to load";
            break;
        }

        // Reopen: a bpf_object that failed to load cannot be loaded again.
        bpf_object__close(*obj);
        *obj = reopen ? reopen(user) : nullptr;
        if (!*obj) {
            report.fatal_error = "could not reopen object after skipping '" + failed + "'";
            break;
        }

        disabled_so_far.push_back(failed);
        report.skipped[failed] = "rejected by the verifier or kernel; skipped as optional";
        for (auto& kv : GateByBtfValidation(*obj)) report.skipped[kv.first] = kv.second;
        for (const auto& name : disabled_so_far) {
            if (struct bpf_program* p = bpf_object__find_program_by_name(*obj, name.c_str())) {
                bpf_program__set_autoload(p, false);
            }
        }
        std::cerr << "[BPF Portability] optional program '" << failed
                  << "' was rejected; retrying without it" << std::endl;
    }

    libbpf_set_print(g_prev_print);
    g_prev_print = nullptr;

    if (!report.loaded && report.fatal_error.empty()) {
        report.fatal_error = "gave up after " + std::to_string(kMaxAttempts) + " attempts";
    }
    if (!report.loaded && *obj) {
        bpf_object__close(*obj);
        *obj = nullptr;
    }
    return report;
}

// ---------------------------------------------------------------------------
// (5) Verifier complexity budget
// ---------------------------------------------------------------------------

namespace {
// libbpf logs a paragraph per rejected program, and MeasureComplexity
// deliberately loads every program one at a time - so on a host that cannot
// load any of them (no CAP_BPF) the useful output drowns in 52 copies of the
// same message. The counts and errors are captured in the returned entries
// either way.
int SilentPrint(enum libbpf_print_level, const char*, va_list) { return 0; }
}  // namespace

std::vector<ComplexityEntry> MeasureComplexity(const std::string& object_path) {
    std::vector<ComplexityEntry> out;
    libbpf_print_fn_t prev = libbpf_set_print(SilentPrint);
    struct PrintRestore {
        libbpf_print_fn_t p;
        ~PrintRestore() { libbpf_set_print(p); }
    } restore{prev};

    // Each program is loaded on its own, so one rejection does not hide the
    // numbers for everything after it - the exact failure mode this whole
    // module exists to remove.
    struct bpf_object* probe = bpf_object__open_file(object_path.c_str(), nullptr);
    if (!probe) return out;

    std::vector<std::string> names;
    struct bpf_program* p;
    bpf_object__for_each_program(p, probe) {
        names.push_back(bpf_program__name(p));
    }
    bpf_object__close(probe);

    for (const auto& name : names) {
        ComplexityEntry entry;
        entry.prog_name = name;

        struct bpf_object* obj = bpf_object__open_file(object_path.c_str(), nullptr);
        if (!obj) {
            entry.error = "open failed";
            out.push_back(entry);
            continue;
        }

        struct bpf_program* target = nullptr;
        bpf_object__for_each_program(p, obj) {
            const char* n = bpf_program__name(p);
            const bool is_target = (name == n);
            bpf_program__set_autoload(p, is_target);
            if (is_target) target = p;
        }
        if (!target) {
            bpf_object__close(obj);
            entry.error = "program vanished between passes";
            out.push_back(entry);
            continue;
        }

        // lsm/ programs need their type set the same way the real loader sets
        // it, or they are measured as the wrong program type (or not at all).
        const char* sec = bpf_program__section_name(target);
        if (sec && std::strncmp(sec, "lsm/", 4) == 0) {
            bpf_program__set_type(target, BPF_PROG_TYPE_LSM);
            bpf_program__set_expected_attach_type(target, BPF_LSM_MAC);
        }

        // -ENOSPC from the load means OUR LOG BUFFER was too small, not that
        // the program was rejected. The heaviest program here processes
        // ~206k insns and its log_level=1 output does not fit in 1 MB, so a
        // fixed buffer reports the two busiest (and therefore most interesting)
        // programs as failures. Grow and retry instead.
        int rc = -ENOSPC;
        for (size_t log_size = (1u << 20); ; log_size *= 8) {
            std::vector<char> log(log_size);
            log[0] = '\0';
            bpf_program__set_log_buf(target, log.data(), log.size());
            bpf_program__set_log_level(target, 1);

            rc = bpf_object__load(obj);

            // The verifier's final line is "processed N insns (limit ...)".
            const char* pos = std::strstr(log.data(), "processed ");
            if (pos) entry.insns = std::strtol(pos + 10, nullptr, 10);

            if (rc != -ENOSPC || log_size >= (1u << 29)) break;

            // A bpf_object cannot be loaded twice, so retrying means reopening
            // and re-selecting the one program under measurement.
            bpf_object__close(obj);
            obj = bpf_object__open_file(object_path.c_str(), nullptr);
            if (!obj) { target = nullptr; break; }
            target = nullptr;
            bpf_object__for_each_program(p, obj) {
                const char* n = bpf_program__name(p);
                const bool is_target = (name == n);
                bpf_program__set_autoload(p, is_target);
                if (is_target) target = p;
            }
            if (!target) break;
            const char* sec2 = bpf_program__section_name(target);
            if (sec2 && std::strncmp(sec2, "lsm/", 4) == 0) {
                bpf_program__set_type(target, BPF_PROG_TYPE_LSM);
                bpf_program__set_expected_attach_type(target, BPF_LSM_MAC);
            }
        }

        // A genuine rejection discards the count. CRITICAL: the verifier emits
        // "processed N insns" even when it REJECTS a program - a rejected
        // fexit_vfs_symlink on 7.2 reports "processed 2 insns". Keeping that
        // would make a broken program indistinguishable from a cheap one: it
        // counts as verified, and DiffComplexity sees a large DECREASE, which
        // is not growth and so passes the gate silently. A program that stops
        // verifying is exactly what this gate exists to catch.
        if (rc != 0) {
            entry.error = (rc == -ENOSPC) ? "verifier log too large to capture"
                                          : std::strerror(-rc);
            if (entry.error.empty()) entry.error = "load failed";
            entry.insns = -1;
        }
        if (obj) bpf_object__close(obj);
        out.push_back(entry);
    }
    return out;
}

bool WriteBaseline(const std::string& path, const std::vector<ComplexityEntry>& entries) {
    std::ofstream f(path, std::ios::trunc);
    if (!f.is_open()) return false;
    f << "# kinnector BPF verifier complexity baseline\n";
    f << "# <program> <insns>   (-1 = did not verify on the machine that wrote this)\n";
    for (const auto& e : entries) {
        f << e.prog_name << ' ' << e.insns << '\n';
    }
    return f.good();
}

bool ReadBaseline(const std::string& path, std::vector<ComplexityEntry>* entries) {
    if (!entries) return false;
    std::ifstream f(path);
    if (!f.is_open()) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream is(line);
        ComplexityEntry e;
        if (!(is >> e.prog_name >> e.insns)) continue;
        entries->push_back(e);
    }
    return true;
}

std::vector<ComplexityDiff> DiffComplexity(const std::vector<ComplexityEntry>& baseline,
                                           const std::vector<ComplexityEntry>& current,
                                           double allowed_growth_fraction) {
    std::map<std::string, long> base;
    for (const auto& e : baseline) base[e.prog_name] = e.insns;

    std::vector<ComplexityDiff> out;
    for (const auto& e : current) {
        ComplexityDiff d;
        d.prog_name = e.prog_name;
        d.current_insns = e.insns;
        auto it = base.find(e.prog_name);
        d.baseline_insns = (it == base.end()) ? -1 : it->second;

        if (d.baseline_insns > 0 && d.current_insns > 0) {
            d.delta = d.current_insns - d.baseline_insns;
            const double allowed = static_cast<double>(d.baseline_insns) * allowed_growth_fraction;
            d.regressed = static_cast<double>(d.delta) > allowed;
        } else if (d.baseline_insns > 0 && d.current_insns <= 0) {
            // It verified when the baseline was taken and does not now. That
            // is the most severe outcome this diff can report - strictly worse
            // than any amount of growth - so it must never be silently folded
            // into "no usable baseline".
            d.failed_to_verify = true;
        }
        if (d.current_insns > 0) {
            d.near_limit = static_cast<double>(d.current_insns) >
                           static_cast<double>(kVerifierInsnLimit) * kNearLimitFraction;
        }
        out.push_back(d);
    }
    return out;
}

}  // namespace bpf_portability
}  // namespace kinnector
