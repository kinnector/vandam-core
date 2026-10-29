#ifndef KINNECTOR_BPF_PORTABILITY_H
#define KINNECTOR_BPF_PORTABILITY_H

// Kernel-portability layer for the eBPF object, ported from cilium/tetragon's
// design (studied at 9793c80).
//
// The problem this exists to solve: `kinnector.bpf.c` compiles to ONE object
// holding 52 programs, and libbpf fails the ENTIRE object if any single
// program is rejected. Twice in one session that turned a single-program
// problem into total loss of enforcement, silently:
//
//   * `bprm_creds_for_exec` went -E2BIG on 6.18 by one instruction, so the
//     daemon came up enforcing nothing.
//   * `fexit/vfs_symlink` has a BPF_PROG signature declaring 4 kernel args;
//     upstream vfs_symlink gained a parameter, so on 7.2 the whole object is
//     rejected. CO-RE relocates struct field offsets - it does NOT check
//     function prototypes, so nothing caught this at compile time.
//
// Tetragon's answers, ported here:
//
//   1. Variant tiers        - SelectObjectPath(): one source compiled to
//                             several objects, chosen at runtime.
//   2. Functional probes    - Features(): load a real (tiny) program to decide
//                             what the kernel supports, never a version table.
//   3. Per-program tolerance- ProgramPolicy/LoadTolerantly(): a program that
//                             fails to load is skipped, not fatal, unless it
//                             is declared Required.
//   4. BTF proto validation - ValidateTracingTarget(): compare our declared
//                             arg count against the running kernel's BTF
//                             FUNC_PROTO before load.
//   5. Complexity budget    - MeasureComplexity(): per-program verifier
//                             instruction counts, diffable against a baseline.

#include <cstdint>
#include <map>
#include <string>
#include <vector>

struct bpf_object;

namespace kinnector {
namespace bpf_portability {

// ---------------------------------------------------------------------------
// (2) Functional feature probes
// ---------------------------------------------------------------------------

// Every probe here loads (and where necessary attaches) a real, minimal BPF
// program rather than comparing kernel versions. Tetragon's detectFentry() is
// the cautionary tale for why: on amd64 the program-type check is sufficient
// because trampolines landed with the type in 5.5, but on arm64 trampolines
// came later, so the type check alone reports a false positive there. A
// version table cannot express that; a probe just answers it.
//
// Results are computed once and cached for process lifetime.
class Features {
public:
    // bpf_get_func_ret() (5.17+). Reading an fexit return value through the
    // helper instead of a typed BPF_PROG signature is what makes those
    // programs independent of the target's arity, so a kernel without it
    // cannot run them.
    static bool HasGetFuncRet();

    // BPF LSM programs can be loaded AND attached. Four layers, matching
    // Tetragon's detectLSM(): program type present, securityfs mounted (this
    // mounts it read-only itself if /sys/kernel/security is empty, then
    // unmounts - an unmounted securityfs used to read to us as "no BPF LSM"),
    // "bpf" present in the active LSM list, and finally a real lsm/file_open
    // stub loaded and attached.
    static bool HasLsm();

    // fentry/fexit (BPF trampoline) programs can be loaded and attached.
    static bool HasFentry();

    // The kernel allows programs above the historical 4096-instruction cap
    // (raised to 1M complexity in 5.2). Probed by loading a program larger
    // than the old cap, not by version.
    static bool HasLargeProgs();

    // BPF ring buffer map type (5.8+).
    static bool HasRingbuf();

    // Kernel BTF is present and parseable, which (4) requires.
    static bool HasKernelBtf();

    // Escape hatches, mirroring Tetragon's ForceSmallProgs/ForceLargeProgs, so
    // an operator on a kernel we misjudge can override without a rebuild.
    // KINNECTOR_FORCE_SMALL_PROGS=1 forces the small tier; _LARGE_ forces the
    // full tier. Small wins if both are set.
    static bool ForceSmallProgs();
    static bool ForceLargeProgs();

    // Human-readable one-line summary of every probe, for startup logging.
    static std::string Summary();

    // Test seam: drop cached probe results so a test can re-probe.
    static void ResetCacheForTesting();
};

// ---------------------------------------------------------------------------
// (1) Variant tiers
// ---------------------------------------------------------------------------

enum class Tier {
    kFull,   // kinnector.bpf.o        - every program
    kSmall,  // kinnector.bpf.small.o  - monitoring-only programs compiled out
};

// Which tier this kernel should get. kSmall when the kernel cannot take large
// programs, or when KINNECTOR_FORCE_SMALL_PROGS is set.
Tier SelectTier();

// Resolves the object to load. `requested` is whatever the caller was
// configured with (e.g. /usr/lib/kinnector/kinnector.bpf.o). If SelectTier()
// picks kSmall and a sibling `.small.o` exists, that path is returned;
// otherwise `requested` is returned unchanged, so a deployment that ships only
// one object keeps working exactly as before.
std::string SelectObjectPath(const std::string& requested);

// The small-tier sibling of `requested` if one is installed, else an empty
// string. Lets a caller fall back to the small object AFTER a full-tier load
// has actually failed, which is strictly better evidence than any up-front
// guess: whether a kernel's verifier will accept our heaviest program is not
// something a generic probe can answer, and a version table only encodes
// someone's guess about where the boundary is.
std::string SmallTierPath(const std::string& requested);

// Same idea, for the tier with every bpf_d_path() call compiled out (see
// kinnector_helpers.h's KINN_D_PATH). Resolves to "<base>.nodpath.o"
// regardless of whether `requested` names the full or small tier - there is
// no separate small+nodpath object.
std::string NoDpathTierPath(const std::string& requested);

// ---------------------------------------------------------------------------
// (4) BTF function-prototype validation
// ---------------------------------------------------------------------------

enum class Validation {
    kOk,      // prototype matches what we declared
    kWarn,    // could not tell (no BTF, or function absent from BTF) - load anyway
    kFailed,  // prototype definitively disagrees - do not load this program
};

// One kernel-function argument a tracing program actually reads.
struct TracingArg {
    int index;              // position in the kernel function's parameter list
    const char* type_name;  // expected type (pointee name for pointers); "" skips
};

// Validates, against the RUNNING kernel's BTF, that every argument a program
// reads is present at the index it reads it from and still has the type it
// expects.
//
// This is deliberately NOT a total-arity check any more. Arity was the obvious
// thing to compare and it was the wrong thing: when vfs_symlink gained
// `delegated_inode` upstream it was APPENDED at index [4], so `dir` [1] and
// `dentry` [2] - the only arguments we read - did not move, and the program
// was still perfectly correct. Only the typed BPF_PROG signature's dependence
// on the total count made it fail. Checking the indices we use answers the
// question that actually matters and stops flagging harmless additions.
//
// Severities:
//   kWarn   - no BTF, or the symbol is absent. Cannot tell; a missing symbol is
//             a legitimate reason for attach to fail later, and failing here
//             would regress kernels where the program always worked.
//   kFailed - an index we read does not exist, or its type changed.
//
// NOTE this treats a type mismatch as kFailed where Tetragon's
// ValidateKprobeSpec returns a warning. Their argument types come from
// user-supplied policy, so a mismatch is often just an imprecise spec. Ours
// are compiled-in reads: a changed type at an index we read means we would
// cast a pointer to the wrong struct and walk it, which is a silent
// memory-safety and correctness failure, not a cosmetic one.
Validation ValidateTracingTarget(const std::string& kernel_func,
                                 const std::vector<TracingArg>& args,
                                 std::string* detail);

// ---------------------------------------------------------------------------
// (3) Per-program load tolerance
// ---------------------------------------------------------------------------

// Required: enforcement would be meaningfully broken without it, so a failure
// to load is fatal and the caller should fall back (or refuse to start)
// instead of pretending to enforce.
//
// Optional: telemetry, monitoring-only hooks, and hooks with a working
// backstop elsewhere. These are skipped with a loud log line and the rest of
// the object still loads. This is the whole point of the layer - see the file
// header.
enum class Requirement { kRequired, kOptional };

struct ProgramPolicy {
    const char* prog_name;     // bpf_object__find_program_by_name() name
    Requirement requirement;
    // Non-empty for tracing programs (fentry/fexit/kprobe) whose attach target
    // is a kernel function whose prototype can drift. Validated by (4) before
    // load; empty for LSM hooks and tracepoints, whose contexts are stable
    // ABI.
    const char* kernel_func;
    // The arguments the program actually reads. Must match the
    // KINN_FEXIT_ARG(ctx, N) calls in kinnector.bpf.c - a test parses the
    // source and fails if these two disagree, because this table is otherwise
    // a hand-maintained mirror that can silently validate the wrong thing.
    std::vector<TracingArg> args;
    // Which side of the bpf_get_func_ret() (5.17+) divide this program is for.
    // Checked before the BTF prototype: a missing helper is a certainty, not a
    // judgement.
    //
    // Some post-operation work exists twice, once as an fexit program and once
    // as a kprobe/kretprobe pair, because an fexit return value can only be
    // read arity-independently through that helper - ctx[nargs] needs a
    // CONSTANT offset and the verifier rejects a statically-present
    // out-of-bounds ctx access even on an unreachable path. Exactly one of the
    // two implementations must run on any given kernel, or the work happens
    // twice.
    enum class HelperGate {
        kNone,               // no dependency either way
        kNeedsGetFuncRet,    // load only where the helper exists
        kNeedsNoGetFuncRet,  // load only where it does not (the fallback path)
    };
    HelperGate helper_gate = HelperGate::kNone;
};

// The policy table for every program in kinnector.bpf.c.
const std::vector<ProgramPolicy>& PolicyTable();

// Requirement for `prog_name`. Programs absent from the table default to
// kRequired: a new program is treated as load-bearing until someone has
// actually decided it is not, so this layer can never silently downgrade
// enforcement that nobody classified.
Requirement RequirementFor(const std::string& prog_name);

// Report of what a tolerant load actually did.
struct LoadReport {
    bool loaded = false;
    // prog name -> why it was skipped.
    std::map<std::string, std::string> skipped;
    // Set when the load failed outright (a Required program was rejected).
    std::string fatal_error;
    int attempts = 0;
};

// Disables autoload for optional programs whose BTF prototype validation
// fails, before the object is loaded. Returns the programs it disabled. This
// is the cheap pre-flight pass; LoadTolerantly() below handles everything BTF
// cannot predict (verifier complexity, missing helpers, ...).
//
// Callers do not normally need this: LoadTolerantly() runs it on the initial
// object and again after every reopen, because a reopened object comes back
// with every autoload flag at its default and gating applied only once would
// be silently undone by the first retry. Exposed for tests.
std::map<std::string, std::string> GateByBtfValidation(struct bpf_object* obj);

// Same, against an explicit policy. Test seam: the shipped PolicyTable() is
// const, so this is the only way to exercise the gate's behaviour on a policy
// that DOES disagree with the running kernel - a BPF-side fault cannot reach
// this layer, because the gate reads the policy, not the object.
std::map<std::string, std::string> GateByBtfValidation(
    struct bpf_object* obj, const std::vector<ProgramPolicy>& policy);

// Loads `*obj` with per-program tolerance.
//
// On a load failure the offending program is identified from libbpf's own log
// output (libbpf prints `prog 'NAME': BPF program load failed`). If that
// program is kOptional it is disabled and the object is reopened and retried;
// if it is kRequired, or the program cannot be identified, the failure stands.
//
// `reopen` must return a freshly opened, freshly configured object - the
// caller's own open path (map scaling, program type fixups, ...) - because a
// bpf_object that failed to load cannot be reused. On return `*obj` points at
// the loaded object, or nullptr on failure (the old one is always closed).
using ReopenFn = struct bpf_object* (*)(void* user);
LoadReport LoadTolerantly(struct bpf_object** obj, ReopenFn reopen, void* user);

// ---------------------------------------------------------------------------
// (5) Verifier complexity budget
// ---------------------------------------------------------------------------

struct ComplexityEntry {
    std::string prog_name;
    // Verifier's "processed N insns". Forced to -1 whenever the program did
    // not load, because the verifier prints that line on rejection too and a
    // rejected program's count is meaningless (typically 1-2).
    long insns = -1;
    std::string error;      // non-empty when the program did not verify
};

// Loads each program in `object_path` on its own with a verifier log and
// records the instruction count the verifier reports. This is our own
// veristat: Tetragon runs veristat in CI on every PR touching bpf/ and diffs
// against the base ref, which is how they never discover a complexity
// regression by having a kernel reject the object in production.
std::vector<ComplexityEntry> MeasureComplexity(const std::string& object_path);

// Serialises/parses the baseline file that MeasureComplexity() output is
// diffed against. Plain "name insns" lines, one per program.
bool WriteBaseline(const std::string& path, const std::vector<ComplexityEntry>& entries);
bool ReadBaseline(const std::string& path, std::vector<ComplexityEntry>* entries);

struct ComplexityDiff {
    std::string prog_name;
    long baseline_insns = -1;
    long current_insns = -1;
    long delta = 0;
    bool regressed = false;      // grew past the allowed tolerance
    bool near_limit = false;     // within kNearLimitFraction of the 1M ceiling
    // Verified when the baseline was taken, does not verify now. Worse than
    // any growth: the program is simply gone from this kernel. Tracked
    // separately because a rejected program reports a TINY insn count (the
    // verifier prints "processed N insns" even on rejection), which reads as a
    // decrease and would otherwise pass a growth-only check.
    bool failed_to_verify = false;
};

// The verifier's complexity ceiling. bprm_creds_for_exec was rejected at this
// limit by ONE instruction, so "how close are we" is a number worth printing.
constexpr long kVerifierInsnLimit = 1000000;
// Warn once a program is using this much of the ceiling.
constexpr double kNearLimitFraction = 0.75;

std::vector<ComplexityDiff> DiffComplexity(const std::vector<ComplexityEntry>& baseline,
                                           const std::vector<ComplexityEntry>& current,
                                           double allowed_growth_fraction);

}  // namespace bpf_portability
}  // namespace kinnector

#endif  // KINNECTOR_BPF_PORTABILITY_H
