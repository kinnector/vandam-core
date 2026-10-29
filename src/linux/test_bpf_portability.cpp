// Tests for the kernel-portability layer (src/linux/bpf_portability.h).
//
// Deliberate scope note, in the spirit of "don't headline N/N passing when
// most tests can't reach the real mechanism": the interesting half of this
// module only does anything against a real kernel that actually rejects a
// program. These tests are split accordingly:
//
//   * The policy table, BTF validation, tier selection, baseline I/O and diff
//     logic are pure logic and are tested unconditionally.
//   * The probes and the tolerant-load retry loop need a kernel (and root, to
//     load programs). Those are run when the environment allows it and
//     REPORTED AS SKIPPED, loudly, when it does not - never silently counted
//     as passes.

#include "bpf_portability.h"
#include "test_helpers/bpf_object_path.h"

#include <bpf/libbpf.h>
#include <unistd.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace kinnector::bpf_portability;

namespace {

// NOT CHECK(). This repo builds with CMAKE_BUILD_TYPE=Release, which defines
// NDEBUG, and under NDEBUG CHECK() expands to nothing at all - the condition
// is not merely unchecked, it is never evaluated. A test written with CHECK()
// therefore runs none of the calls inside its assertions and still reports
// success, which is exactly how this test first "passed" while silently
// skipping most of its own body.
#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << ": "      \
                      << #cond << std::endl;                                 \
            std::exit(1);                                                    \
        }                                                                    \
    } while (0)

int g_skipped = 0;

void Skip(const std::string& what, const std::string& why) {
    ++g_skipped;
    std::cout << "  SKIP  " << what << " (" << why << ")" << std::endl;
}

std::string ObjectPath() {
    return kinnector::test::ResolveBpfObjectPath();
}

bool HaveObject(const std::string& p) { return access(p.c_str(), R_OK) == 0; }

// ---------------------------------------------------------------------------
// (3) policy table
// ---------------------------------------------------------------------------

void TestPolicyTableWellFormed() {
    std::cout << "[Portability] policy table is well formed..." << std::endl;
    const auto& table = PolicyTable();
    CHECK(!table.empty());

    std::set<std::string> seen;
    for (const auto& p : table) {
        CHECK(p.prog_name && *p.prog_name);
        // A duplicate entry means one of the two requirement decisions is
        // dead code, and which one wins depends on table order.
        CHECK(seen.insert(p.prog_name).second && "duplicate program in policy table");
        if (p.kernel_func && *p.kernel_func) {
            // A tracing target that declares no arguments cannot be validated,
            // which would make its entry a silent no-op.
            CHECK(!p.args.empty() && "tracing target needs argument indices");
            for (const auto& a : p.args) CHECK(a.index >= 0);
        } else {
            CHECK(p.args.empty());
        }
    }
    std::cout << "  " << table.size() << " programs classified" << std::endl;
}

void TestUnknownProgramsAreRequired() {
    std::cout << "[Portability] unknown programs default to Required..." << std::endl;
    // The safety property: adding a program to kinnector.bpf.c without
    // classifying it must not make it silently droppable.
    CHECK(RequirementFor("a_program_that_does_not_exist") == Requirement::kRequired);
    CHECK(RequirementFor("") == Requirement::kRequired);
    // And the enforcement core stays Required.
    CHECK(RequirementFor("file_open") == Requirement::kRequired);
    CHECK(RequirementFor("bprm_creds_for_exec") == Requirement::kRequired);
    CHECK(RequirementFor("mmap_file") == Requirement::kRequired);
    // sched_process_exit is Required because losing it leaks twelve maps to
    // max_entries and enforcement then fails OPEN - not merely telemetry.
    CHECK(RequirementFor("tracepoint_sched_process_exit") == Requirement::kRequired);
    // ... and the drift-prone tracing hooks stay Optional, which is the whole
    // point: a kernel function's prototype changing must not take the object
    // down.
    CHECK(RequirementFor("lsm_d_instantiate") == Requirement::kOptional);
    CHECK(RequirementFor("kprobe_tty_write") == Requirement::kOptional);
}

// Every program named in the policy table must actually exist in the compiled
// object, and vice versa. Without this, a rename in kinnector.bpf.c silently
// turns a classified Optional program back into an unclassified Required one.
void TestPolicyTableMatchesObject() {
    std::cout << "[Portability] policy table matches the compiled object..." << std::endl;
    const std::string obj_path = ObjectPath();
    if (!HaveObject(obj_path)) {
        Skip("policy/object cross-check", "no " + obj_path);
        return;
    }
    struct bpf_object* obj = bpf_object__open_file(obj_path.c_str(), nullptr);
    if (!obj) {
        Skip("policy/object cross-check", "could not open object");
        return;
    }

    std::set<std::string> in_object;
    struct bpf_program* p;
    bpf_object__for_each_program(p, obj) { in_object.insert(bpf_program__name(p)); }
    bpf_object__close(obj);

    std::set<std::string> in_table;
    for (const auto& e : PolicyTable()) in_table.insert(e.prog_name);

    int missing = 0;
    for (const auto& name : in_table) {
        if (!in_object.count(name)) {
            std::cerr << "  policy names '" << name << "' but the object has no such program"
                      << std::endl;
            ++missing;
        }
    }
    int unclassified = 0;
    for (const auto& name : in_object) {
        if (!in_table.count(name)) {
            std::cerr << "  object has '" << name
                      << "' with no policy entry (defaults to Required)" << std::endl;
            ++unclassified;
        }
    }
    std::cout << "  object=" << in_object.size() << " table=" << in_table.size()
              << " missing=" << missing << " unclassified=" << unclassified << std::endl;
    CHECK(missing == 0 && "policy table names a program the object does not have");
    CHECK(unclassified == 0 && "object has an unclassified program");
}

// ---------------------------------------------------------------------------
// (4) BTF prototype validation
// ---------------------------------------------------------------------------

void TestBtfValidation() {
    std::cout << "[Portability] BTF prototype validation..." << std::endl;
    if (!Features::HasKernelBtf()) {
        Skip("BTF validation", "no kernel BTF on this host");
        return;
    }

    std::string detail;

    // A function that certainly does not exist must be kWarn, not kFailed:
    // we cannot distinguish "renamed upstream" from "not built into this
    // kernel", and failing the program here would be a regression on kernels
    // where it never existed in the first place.
    detail.clear();
    CHECK(ValidateTracingTarget("kinnector_no_such_kernel_function",
                                {{0, "inode"}}, &detail) == Validation::kWarn);
    CHECK(!detail.empty());
    std::cout << "  absent symbol -> Warn: " << detail << std::endl;

    // vfs_symlink/vfs_link are no longer hooked (see
    // kinnector_container_lsm_hooks.h's apply_post_op_path_closure doc
    // comment) - kept here purely as real-kernel-function test
    // vehicles for ValidateTracingTarget() itself, a standalone BTF query
    // that needs no compiled object or policy entry to exercise. The
    // indices we once read must validate on kernels where the signature has
    // 4-5 args in the idmap-bearing form (7.2 grew a 5th arg, dir[1]/
    // dentry[2] untouched). Found live on 5.10 (kind_5.10): the
    // pre-idmap 3-arg form (dir[0], dentry[1], symname[2]) shifts BOTH
    // indices, which this same check correctly reports kFailed for. When
    // this was still a real hook, GateByBtfValidation (bpf_portability.cpp)
    // treated that as expected for an Optional program and disabled its
    // autoload rather than attaching it with the wrong registers - so
    // kFailed here was never a test bug to chase, and still isn't: Skip
    // exactly like the kWarn (absent-symbol) case above.
    detail.clear();
    Validation v = ValidateTracingTarget("vfs_symlink", {{1, "inode"}, {2, "dentry"}}, &detail);
    if (v == Validation::kWarn || v == Validation::kFailed) {
        Skip("vfs_symlink indices", detail);
    } else {
        CHECK(v == Validation::kOk);
        std::cout << "  vfs_symlink dir[1]/dentry[2] -> Ok (idmap-bearing kernels)" << std::endl;
    }

    // Same shift hits vfs_link on 5.10: old_dentry[0], dir[1], new_dentry[2],
    // delegated_inode[3] (pre-idmap) vs. the idmap-bearing dir[2]/new_dentry[3]
    // this policy expects - same tolerated kFailed, same reasoning as above.
    detail.clear();
    Validation vl = ValidateTracingTarget("vfs_link", {{2, "inode"}, {3, "dentry"}}, &detail);
    if (vl == Validation::kWarn || vl == Validation::kFailed) {
        Skip("vfs_link indices", detail);
    } else {
        CHECK(vl == Validation::kOk);
        std::cout << "  vfs_link dir[2]/new_dentry[3] -> Ok" << std::endl;
    }

    // An index the function does not have must fail - the read would be out of
    // bounds of the context.
    detail.clear();
    CHECK(ValidateTracingTarget("vfs_symlink", {{99, ""}}, &detail) == Validation::kFailed);
    CHECK(detail.find("99") != std::string::npos);
    std::cout << "  index 99 -> Failed: " << detail << std::endl;

    // A type that disagrees must fail too. This is the dangerous case the
    // arity check could never see: if arguments were REORDERED without the
    // count changing, we would cast a pointer to the wrong struct and walk it.
    //
    // Uses vfs_link's arg[0] (old_dentry), not vfs_symlink's arg[1] like the
    // rest of this function - found live on 5.10 that vfs_symlink[1]'s real
    // type (inode vs. dentry) depends on which of the two ABI shapes above
    // is present, so it cannot anchor a fixed-type assertion across kernels.
    // old_dentry is dentry-typed at index 0 in vfs_link on both the pre-idmap
    // 4-arg form and the idmap-bearing one (idmap is inserted at [1],
    // shifting dir/new_dentry, never [0]) - a genuinely stable invariant.
    detail.clear();
    CHECK(ValidateTracingTarget("vfs_link", {{0, "inode"}}, &detail) ==
          Validation::kFailed);
    CHECK(detail.find("dentry") != std::string::npos);
    std::cout << "  wrong type at a valid index -> Failed: " << detail << std::endl;

    // Reading an index without asserting a type is allowed and must not fail.
    detail.clear();
    CHECK(ValidateTracingTarget("vfs_link", {{0, ""}}, &detail) == Validation::kOk);
}

// kprobe_tty_write/kprobe_tty_read declare the classic
// `(struct file *, char *, size_t)` shape (see their policy-table entries'
// comment for how that was confirmed, not guessed, via bpftrace/BTF dump).
// Whether that still matches THIS kernel is exactly what this test reports -
// unlike the vfs_symlink/vfs_link checks above, it deliberately does not
// assert one outcome, because the real answer varies kernel to kernel and
// that variance is the entire reason this validation layer exists:
//
//   * On a kernel where tty_write/tty_read are still classic file_operations
//     .write/.read callbacks, this reports Ok.
//   * On a kernel where they were converted to .write_iter/.read_iter
//     (confirmed true for kernel 6.17.0-40-generic, this environment, at the
//     time this test was written: tty_write/tty_read there are
//     `(struct kiocb *, struct iov_iter *)`), this reports Failed at index 0
//     ("file" vs the real "kiocb") - which is the whole point: a kprobe has
//     no verifier-enforced signature, so without this check that mismatch
//     would load fine and silently misread PTY traffic forever.
//
// Either branch is a PASS for this test; the only failure mode that matters
// is the validation call itself crashing, hanging, or returning kWarn when
// BTF plainly has an answer.
void TestTtyKprobeBtfValidation() {
    std::cout << "[Portability] tty kprobes match the real kernel prototype..." << std::endl;
    if (!Features::HasKernelBtf()) {
        Skip("tty kprobe BTF validation", "no kernel BTF on this host");
        return;
    }

    // The programs now declare the iter form, which is what every kernel we
    // support actually has:
    //     tty_write(struct kiocb *iocb, struct iov_iter *from)
    //     tty_read (struct kiocb *iocb, struct iov_iter *to)
    // They previously declared (struct file *, char *, size_t). A kprobe has no
    // verifier-enforced signature, so that mismatch never failed a load - it
    // just made is_pty_file() read a kiocb as a file and capture nothing, for
    // as long as nobody checked. This test is the thing that would catch a
    // regression back to that state.
    for (const char* fn : {"tty_write", "tty_read"}) {
        std::string detail;
        Validation v = ValidateTracingTarget(fn, {{0, "kiocb"}, {1, "iov_iter"}}, &detail);
        if (v == Validation::kWarn) {
            Skip(std::string(fn) + " validation", detail);
            continue;
        }
        if (v == Validation::kFailed) {
            // Legitimate on a kernel older than the iter conversion. Say so
            // loudly rather than asserting one kernel's answer - but the
            // programs must then be gated off, which the policy check below
            // covers.
            std::cout << "  " << fn << ": iter prototype does NOT hold here -> " << detail
                      << " (programs will be gated off)" << std::endl;
            continue;
        }
        CHECK(v == Validation::kOk);
        std::cout << "  " << fn << "(kiocb, iov_iter) -> Ok" << std::endl;
    }

    // The declared shape must be exactly what the policy table asserts, or the
    // validation is checking something the programs do not do.
    for (const auto& e : PolicyTable()) {
        const std::string n = e.prog_name;
        if (n != "kprobe_tty_write" && n != "kprobe_tty_read") continue;
        CHECK(e.args.size() == 2);
        CHECK(std::string(e.args[0].type_name) == "kiocb");
        CHECK(std::string(e.args[1].type_name) == "iov_iter");
    }

    // kretprobe_tty_read stays unvalidated on purpose: BPF_KRETPROBE's only
    // parameter is the synthesized return value, not an index into the target's
    // argument list, so there is nothing for a per-index check to compare.
    for (const auto& e : PolicyTable()) {
        if (std::string(e.prog_name) == "kretprobe_tty_read") {
            CHECK(!e.kernel_func || !*e.kernel_func);
            CHECK(e.args.empty());
        }
    }
}

// The pre-flight gate must disable exactly the optional programs whose
// prototype disagrees, and leave everything else loadable.
void TestGateByBtfValidation() {
    std::cout << "[Portability] BTF gate disables only the drifted program..." << std::endl;
    const std::string obj_path = ObjectPath();
    if (!HaveObject(obj_path) || !Features::HasKernelBtf()) {
        Skip("BTF gate", "no object or no kernel BTF");
        return;
    }
    struct bpf_object* obj = bpf_object__open_file(obj_path.c_str(), nullptr);
    if (!obj) {
        Skip("BTF gate", "could not open object");
        return;
    }

    auto disabled = GateByBtfValidation(obj);
    // Whatever it disabled must (a) be Optional and (b) actually be turned off.
    for (const auto& kv : disabled) {
        CHECK(RequirementFor(kv.first) == Requirement::kOptional);
        struct bpf_program* p = bpf_object__find_program_by_name(obj, kv.first.c_str());
        CHECK(p && !bpf_program__autoload(p));
        std::cout << "  disabled " << kv.first << ": " << kv.second << std::endl;
    }
    // Nothing outside the tracing set may be touched.
    struct bpf_program* file_open = bpf_object__find_program_by_name(obj, "file_open");
    if (file_open) CHECK(bpf_program__autoload(file_open));
    std::cout << "  " << disabled.size() << " program(s) gated off by BTF" << std::endl;
    bpf_object__close(obj);
}

// The gate reads the POLICY, not the object, so no BPF-side fault can reach it.
// This drives it with a policy that deliberately disagrees with the running
// kernel - the only way to prove it disables the right program for the right
// reason, and leaves Required ones alone.
void TestGateHonoursPolicyDisagreement() {
    std::cout << "[Portability] BTF gate on a policy that disagrees with the kernel..."
              << std::endl;
    const std::string obj_path = ObjectPath();
    if (!HaveObject(obj_path) || !Features::HasKernelBtf()) {
        Skip("BTF gate disagreement", "no object or no kernel BTF");
        return;
    }
    struct bpf_object* obj = bpf_object__open_file(obj_path.c_str(), nullptr);
    if (!obj) { Skip("BTF gate disagreement", "could not open object"); return; }

    // Used to use fexit_vfs_symlink/fexit_vfs_link - removed along
    // with the last `fexit/`-type program in the object (see
    // kinnector_container_lsm_hooks.h's apply_post_op_path_closure doc
    // comment). kprobe_tty_write/kprobe_tty_read are real, still-hooked
    // kprobes with kernel-func policies, equally valid test vehicles for
    // this generic mechanism.
    std::vector<ProgramPolicy> policy = {
        // Optional, reads an index no kernel has -> must be disabled.
        {"kprobe_tty_write", Requirement::kOptional, "tty_write", {{99, ""}}},
        // Optional, wrong TYPE at a real index -> must be disabled. This is
        // the reordering case a total-arity check could never see.
        //
        // tty_read(struct kiocb *iocb, struct iov_iter *to) - index 0 is
        // genuinely kiocb-typed on every kernel this runs on, so asserting
        // "iov_iter" there is wrong everywhere, the same durability property
        // the original vfs_link fixture's comment cared about.
        {"kprobe_tty_read", Requirement::kOptional, "tty_read", {{0, "iov_iter"}}},
    };
    auto disabled = GateByBtfValidation(obj, policy);
    CHECK(disabled.count("kprobe_tty_write") == 1);
    CHECK(disabled["kprobe_tty_write"].find("99") != std::string::npos);
    CHECK(disabled.count("kprobe_tty_read") == 1);
    CHECK(disabled["kprobe_tty_read"].find("kiocb") != std::string::npos);
    for (const auto& kv : disabled) {
        struct bpf_program* p = bpf_object__find_program_by_name(obj, kv.first.c_str());
        CHECK(p && !bpf_program__autoload(p));
    }
    std::cout << "  disabled both on disagreement" << std::endl;
    bpf_object__close(obj);

    // A REQUIRED program that disagrees must NOT be quietly disabled - that
    // would be the gate silently downgrading enforcement, which is the one
    // thing it must never do. It is reported and left enabled so the load
    // fails loudly instead.
    obj = bpf_object__open_file(obj_path.c_str(), nullptr);
    CHECK(obj != nullptr);
    std::vector<ProgramPolicy> required_bad = {
        {"kprobe_tty_write", Requirement::kRequired, "tty_write", {{99, ""}}},
    };
    auto none = GateByBtfValidation(obj, required_bad);
    CHECK(none.empty());
    struct bpf_program* still_on =
        bpf_object__find_program_by_name(obj, "kprobe_tty_write");
    CHECK(still_on && bpf_program__autoload(still_on));
    std::cout << "  a Required disagreement is reported, never silently dropped" << std::endl;
    bpf_object__close(obj);
}

// The policy table's argument indices are a hand-written mirror of the real
// reads in kinnector.bpf.c: KINN_FEXIT_ARG(ctx, N) for fexit programs, and
// "does the body use the Nth declared BPF_KPROBE/BPF_KRETPROBE parameter's
// name" for kprobes. If the source starts reading a different index and the
// table is not updated, ValidateTracingTarget() cheerfully validates an index
// the program never touches and reports Ok - the check silently stops
// checking the thing it exists to check. Parsing the real reads out of the
// source is what makes that impossible to do quietly.
void TestPolicyTableArityMatchesSource() {
    std::cout << "[Portability] policy indices match the BPF source reads..." << std::endl;
    const char* src_env = std::getenv("KINNECTOR_BPF_SRC");
    const std::string src_path = src_env ? src_env : "../src/linux/ebpf/kinnector.bpf.c";

    // kinnector.bpf.c used to hold all 52 programs inline; it is now a thin
    // shell that #includes the real logic from headers in the same directory
    // (see that file's own header comment). The fexit/kprobe programs this
    // check cross-checks now live in those headers, not in kinnector.bpf.c
    // itself, so this must follow the #include chain and scan the headers
    // too - reading only kinnector.bpf.c would make `from_source` empty and
    // the CHECK(!from_source.empty()) below would (correctly) fail, but the
    // point is to keep checking the real thing, not merely fail loudly.
    //
    // This is line-oriented, same spirit as the token scan below it: it looks
    // for local, quoted `#include "foo.h"` lines in kinnector.bpf.c (system
    // includes use angle brackets and are not local headers) and reads each
    // resolved file, in the order the .c file includes them, right after the
    // .c file's own lines. None of the split headers themselves include one
    // another, so one level of expansion is enough; if that ever changes,
    // the loop below still only recurses one level and a stale mirror here
    // would need extending, not just this comment.
    const size_t slash = src_path.find_last_of('/');
    const std::string src_dir = (slash == std::string::npos) ? "." : src_path.substr(0, slash);

    std::vector<std::string> all_lines;
    {
        std::ifstream src(src_path);
        if (!src.is_open()) {
            Skip("policy index cross-check", "cannot read " + src_path);
            return;
        }
        std::vector<std::string> included_headers;
        std::string line;
        while (std::getline(src, line)) {
            all_lines.push_back(line);
            const size_t inc = line.find("#include \"");
            if (inc != std::string::npos) {
                const size_t name_start = inc + std::strlen("#include \"");
                const size_t name_end = line.find('"', name_start);
                if (name_end != std::string::npos) {
                    included_headers.push_back(line.substr(name_start, name_end - name_start));
                }
            }
        }
        for (const std::string& header : included_headers) {
            // vmlinux.h is a build-generated BTF dump (see CMakeLists.txt),
            // never checked into the source tree - not finding it next to
            // kinnector.bpf.c is normal, not a sign the split is broken.
            // "kinnector_*.h" is this split's own naming convention (see the
            // #include chain in kinnector.bpf.c); those are exactly the files
            // this check exists to follow, so a missing one there is real.
            const bool is_split_header = header.rfind("kinnector_", 0) == 0;
            const std::string header_path = src_dir + "/" + header;
            std::ifstream hdr(header_path);
            if (!hdr.is_open()) {
                if (!is_split_header) continue;
                // The .c file is readable and explicitly names this header as
                // part of the build - failing to find it means the split
                // itself is broken, not merely that the source tree is
                // unavailable in this environment. Fail loudly rather than
                // silently checking fewer programs than the policy table
                // expects.
                std::cerr << "  " << src_path << " includes \"" << header
                          << "\" but " << header_path << " could not be opened" << std::endl;
                CHECK(false);
                continue;
            }
            std::string hline;
            while (std::getline(hdr, hline)) all_lines.push_back(hline);
        }
    }

    // prog name -> set of kernel-function argument indices it reads.
    std::map<std::string, std::set<int>> from_source;
    // kprobe/kretprobe program -> its declared parameter names in positional
    // order (index 0 = first argument of the kernel function it attaches to).
    // fexit programs don't need this: KINN_FEXIT_ARG(ctx, N) already names the
    // index directly. BPF_KPROBE instead binds arguments to NAMED locals
    // positionally (PT_REGS_PARMn under the macro), so the only way to tell
    // "does this program read index N" from the source is "does the body use
    // the Nth declared parameter's name" - a heuristic whole-word scan, same
    // spirit as the KINN_FEXIT_ARG token search below, not a real C parser.
    std::map<std::string, std::vector<std::string>> kprobe_param_names;
    auto trim = [](const std::string& s) -> std::string {
        const size_t a = s.find_first_not_of(" \t");
        if (a == std::string::npos) return "";
        const size_t b = s.find_last_not_of(" \t");
        return s.substr(a, b - a + 1);
    };
    auto is_ident_char = [](char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; };

    std::string current;
    bool in_break_block = false;
    for (const std::string& line : all_lines) {
        // The fault-injection variant reads a deliberately invalid index; it is
        // not part of the shipped program's contract.
        if (line.find("#ifdef __KINN_TEST_BREAK_OPTIONAL") != std::string::npos) in_break_block = true;
        else if (in_break_block && line.find("#endif") != std::string::npos) in_break_block = false;

        // Track which fexit program we are inside.
        const size_t sec = line.find("SEC(\"fexit/");
        if (sec != std::string::npos) { current.clear(); continue; }
        const size_t fn = line.find("int fexit_");
        if (fn != std::string::npos && line.find("(void *ctx)") != std::string::npos) {
            const size_t b = line.find("int ") + 4;
            const size_t e = line.find('(', b);
            current = line.substr(b, e - b);
            from_source[current];  // ensure present even with zero reads
            continue;
        }

        // Track which kprobe/kretprobe program we are inside.
        const size_t kprobe_macro = line.find("BPF_KPROBE(");
        const size_t kretprobe_macro = line.find("BPF_KRETPROBE(");
        if (kprobe_macro != std::string::npos || kretprobe_macro != std::string::npos) {
            const bool is_kret = kretprobe_macro != std::string::npos;
            const size_t open = (is_kret ? kretprobe_macro + std::strlen("BPF_KRETPROBE(")
                                          : kprobe_macro + std::strlen("BPF_KPROBE("));
            const size_t close = line.find(')', open);
            current.clear();
            if (close != std::string::npos && close > open) {
                std::vector<std::string> parts;
                size_t start = open;
                while (true) {
                    const size_t comma = line.find(',', start);
                    const size_t end = (comma == std::string::npos || comma > close) ? close : comma;
                    parts.push_back(trim(line.substr(start, end - start)));
                    if (comma == std::string::npos || comma > close) break;
                    start = comma + 1;
                }
                if (!parts.empty() && !parts[0].empty()) {
                    if (is_kret) {
                        // A kretprobe's sole "parameter" is the synthesized
                        // return value (PT_REGS_RC), not an index into the
                        // kernel function's real argument list - see
                        // kretprobe_tty_read's policy-table comment. Leaving
                        // `current` empty means it is never added to
                        // from_source, so the "every program found must be
                        // classified" check below correctly does not demand a
                        // kernel_func entry for it.
                    } else {
                        current = parts[0];
                        std::vector<std::string> names;
                        for (size_t i = 1; i < parts.size(); ++i) {
                            // The declared parameter's name is its last
                            // identifier token: "struct file *file" -> "file".
                            const std::string& decl = parts[i];
                            size_t p = decl.size();
                            while (p > 0 && is_ident_char(decl[p - 1])) --p;
                            names.push_back(decl.substr(p));
                        }
                        kprobe_param_names[current] = names;
                        from_source[current];  // ensure present even with zero reads
                    }
                }
            }
            continue;
        }

        if (line.find("SEC(\"") != std::string::npos) { current.clear(); continue; }
        if (current.empty() || in_break_block) continue;

        const auto kp = kprobe_param_names.find(current);
        if (kp != kprobe_param_names.end()) {
            for (size_t i = 0; i < kp->second.size(); ++i) {
                const std::string& pname = kp->second[i];
                if (pname.empty()) continue;
                size_t pos = 0;
                while ((pos = line.find(pname, pos)) != std::string::npos) {
                    const bool left_ok = pos == 0 || !is_ident_char(line[pos - 1]);
                    const size_t endp = pos + pname.size();
                    const bool right_ok = endp >= line.size() || !is_ident_char(line[endp]);
                    if (left_ok && right_ok) {
                        from_source[current].insert(static_cast<int>(i));
                        break;
                    }
                    pos = endp;
                }
            }
            continue;
        }

        size_t pos = 0;
        const std::string tok = "KINN_FEXIT_ARG(ctx, ";
        while ((pos = line.find(tok, pos)) != std::string::npos) {
            pos += tok.size();
            from_source[current].insert(std::atoi(line.c_str() + pos));
        }
    }
    // The macro definition itself lives outside any program, so a completely
    // empty result means the parser broke, not that nothing reads arguments.
    CHECK(!from_source.empty());

    int checked = 0;
    for (const auto& e : PolicyTable()) {
        if (!e.kernel_func || !*e.kernel_func) continue;
        auto it = from_source.find(e.prog_name);
        if (it == from_source.end()) {
            std::cerr << "  policy entry " << e.prog_name
                      << " has a kernel_func but no fexit/kprobe program in the source" << std::endl;
            CHECK(false);
        }
        std::set<int> in_table;
        for (const auto& a : e.args) in_table.insert(a.index);
        if (in_table != it->second) {
            std::cerr << "  " << e.prog_name << ": source reads {";
            for (int i : it->second) std::cerr << i << " ";
            std::cerr << "}, policy table declares {";
            for (int i : in_table) std::cerr << i << " ";
            std::cerr << "}" << std::endl;
            CHECK(false);
        }
        ++checked;
    }
    // Every fexit/kprobe program in the source must be classified, or one of
    // them is going through with no prototype validation at all. (Kretprobes
    // are deliberately excluded from from_source in the first place - see the
    // parsing loop above and kretprobe_tty_read's policy-table comment - so
    // this does not wrongly demand a kernel_func for those.)
    for (const auto& kv : from_source) {
        bool found = false;
        for (const auto& e : PolicyTable()) {
            if (kv.first == e.prog_name && e.kernel_func && *e.kernel_func) { found = true; break; }
        }
        if (!found) {
            std::cerr << "  source has fexit/kprobe program " << kv.first
                      << " with no kernel_func in the policy table" << std::endl;
            CHECK(false);
        }
    }
    std::cout << "  " << checked << " fexit/kprobe program(s) agree with the source" << std::endl;
}

// ---------------------------------------------------------------------------
// (1) tier selection
// ---------------------------------------------------------------------------

void TestTierSelection() {
    std::cout << "[Portability] tier selection and force overrides..." << std::endl;

    // Force-small must win over force-large, so an operator escaping a broken
    // kernel is never overridden by a stale force-large in a unit file.
    setenv("KINNECTOR_FORCE_SMALL_PROGS", "1", 1);
    setenv("KINNECTOR_FORCE_LARGE_PROGS", "1", 1);
    CHECK(Features::ForceSmallProgs());
    CHECK(!Features::ForceLargeProgs());
    CHECK(!Features::HasLargeProgs());
    CHECK(SelectTier() == Tier::kSmall);

    unsetenv("KINNECTOR_FORCE_SMALL_PROGS");
    CHECK(Features::ForceLargeProgs());
    CHECK(Features::HasLargeProgs());
    CHECK(SelectTier() == Tier::kFull);
    unsetenv("KINNECTOR_FORCE_LARGE_PROGS");

    // "0" and "false" must not read as set - otherwise KINNECTOR_FORCE_SMALL_PROGS=0
    // would force the small tier, which is the opposite of what it says.
    setenv("KINNECTOR_FORCE_SMALL_PROGS", "0", 1);
    CHECK(!Features::ForceSmallProgs());
    setenv("KINNECTOR_FORCE_SMALL_PROGS", "false", 1);
    CHECK(!Features::ForceSmallProgs());
    unsetenv("KINNECTOR_FORCE_SMALL_PROGS");
    std::cout << "  overrides behave" << std::endl;
}

void TestSelectObjectPath() {
    std::cout << "[Portability] small-tier object path resolution..." << std::endl;

    setenv("KINNECTOR_FORCE_LARGE_PROGS", "1", 1);
    unsetenv("KINNECTOR_FORCE_SMALL_PROGS");
    CHECK(SelectObjectPath("/opt/x/kinnector.bpf.o") == "/opt/x/kinnector.bpf.o");
    unsetenv("KINNECTOR_FORCE_LARGE_PROGS");

    setenv("KINNECTOR_FORCE_SMALL_PROGS", "1", 1);

    // A deployment that ships only the full object must keep working rather
    // than resolving to a file nobody installed.
    CHECK(SelectObjectPath("/nonexistent/dir/kinnector.bpf.o") ==
           "/nonexistent/dir/kinnector.bpf.o");

    // A path that is not an .o is returned untouched.
    CHECK(SelectObjectPath("/opt/x/kinnector.bpf") == "/opt/x/kinnector.bpf");

    // When the small object does exist next to the full one, it is chosen.
    const std::string full = ObjectPath();
    const std::string small = full.substr(0, full.size() - 2) + ".small.o";
    if (HaveObject(small)) {
        CHECK(SelectObjectPath(full) == small);
        std::cout << "  small tier resolves to " << small << std::endl;
    } else {
        Skip("small-object selection", "no " + small + " built");
    }
    unsetenv("KINNECTOR_FORCE_SMALL_PROGS");
}

// ---------------------------------------------------------------------------
// (5) complexity baseline I/O and diffing
// ---------------------------------------------------------------------------

void TestBaselineRoundTrip() {
    std::cout << "[Portability] complexity baseline round-trip..." << std::endl;
    const std::string path = "/tmp/kinnector_baseline_test.txt";

    std::vector<ComplexityEntry> written = {
        {"file_open", 12000, ""},
        {"mmap_file", 4000, ""},
        {"broken_prog", -1, "did not verify"},
    };
    CHECK(WriteBaseline(path, written));

    std::vector<ComplexityEntry> read;
    CHECK(ReadBaseline(path, &read));
    CHECK(read.size() == 3);
    CHECK(read[0].prog_name == "file_open" && read[0].insns == 12000);
    CHECK(read[2].insns == -1);

    CHECK(!ReadBaseline("/tmp/kinnector_baseline_does_not_exist.txt", &read));
    std::remove(path.c_str());
    std::cout << "  round-trip preserves names, counts and the -1 sentinel" << std::endl;
}

void TestComplexityDiff() {
    std::cout << "[Portability] complexity diff flags growth and the ceiling..." << std::endl;
    std::vector<ComplexityEntry> baseline = {
        {"steady", 10000, ""},
        {"grower", 10000, ""},
        {"unverifiable", -1, ""},
    };
    std::vector<ComplexityEntry> current = {
        {"steady", 10500, ""},        // +5%, inside a 10% tolerance
        {"grower", 13000, ""},        // +30%, a regression
        {"unverifiable", 500, ""},    // no usable baseline
        {"brand_new", 800000, ""},    // 80% of the ceiling
    };

    // The severe case: verified at 9000 when the baseline was taken, does not
    // verify at all now. A rejected program still reports a tiny count from
    // the verifier's own log, so before MeasureComplexity started discarding
    // those, this looked like a large DECREASE and sailed through a
    // growth-only check - which is how a completely broken program could pass
    // the gate.
    baseline.push_back({"stopped_verifying", 9000, ""});
    current.push_back({"stopped_verifying", -1, "Permission denied"});

    auto diffs = DiffComplexity(baseline, current, 0.10);
    CHECK(diffs.size() == 5);
    CHECK(diffs[4].prog_name == "stopped_verifying");
    CHECK(diffs[4].failed_to_verify);
    CHECK(!diffs[4].regressed);
    // ... and none of the healthy ones may be mislabelled that way.
    CHECK(!diffs[0].failed_to_verify);
    CHECK(!diffs[1].failed_to_verify);

    CHECK(diffs[0].delta == 500 && !diffs[0].regressed);
    CHECK(diffs[1].delta == 3000 && diffs[1].regressed);
    // A baseline of -1 cannot be compared against, and must not be reported as
    // a regression just because the current run produced a number.
    CHECK(!diffs[2].regressed);
    // A brand-new program has no baseline, but the absolute ceiling check must
    // still fire - this is the bprm_creds_for_exec case, which was rejected at
    // the limit without ever having "grown" relative to anything.
    CHECK(diffs[3].baseline_insns == -1);
    CHECK(diffs[3].near_limit);
    CHECK(!diffs[0].near_limit);
    std::cout << "  growth, missing-baseline and near-limit all handled" << std::endl;
}

// ---------------------------------------------------------------------------
// (2) functional probes + (3) tolerant load, both needing a real kernel
// ---------------------------------------------------------------------------

void TestFeatureProbes() {
    std::cout << "[Portability] functional feature probes..." << std::endl;
    // These must never crash or hang, whatever the kernel says, and must be
    // stable across calls (they are cached).
    const bool lsm = Features::HasLsm();
    const bool fentry = Features::HasFentry();
    const bool ringbuf = Features::HasRingbuf();
    const bool btf = Features::HasKernelBtf();
    CHECK(Features::HasLsm() == lsm);
    CHECK(Features::HasFentry() == fentry);
    CHECK(Features::HasRingbuf() == ringbuf);
    CHECK(Features::HasKernelBtf() == btf);
    std::cout << "  " << Features::Summary() << std::endl;

    if (geteuid() != 0) {
        // Without CAP_BPF every probe that must load a program answers "no".
        // That is the correct answer for this process, but it is not evidence
        // about the kernel, so say so instead of asserting anything.
        Skip("probe agreement with kernel capability", "not root; probes cannot load programs");
        return;
    }
    // As root, BTF and LSM should agree with what the kernel advertises.
    if (access("/sys/kernel/btf/vmlinux", R_OK) == 0) {
        CHECK(btf && "kernel BTF is readable but the probe says no");
    }
}

struct ReopenCtx {
    std::string path;
    int opens = 0;
};

struct bpf_object* ReopenForTest(void* user) {
    auto* ctx = static_cast<ReopenCtx*>(user);
    ++ctx->opens;
    struct bpf_object* obj = bpf_object__open_file(ctx->path.c_str(), nullptr);
    if (!obj) return nullptr;
    struct bpf_program* p;
    bpf_object__for_each_program(p, obj) {
        const char* sec = bpf_program__section_name(p);
        if (sec && std::strncmp(sec, "lsm/", 4) == 0) {
            bpf_program__set_type(p, BPF_PROG_TYPE_LSM);
            bpf_program__set_expected_attach_type(p, BPF_LSM_MAC);
        }
    }
    return obj;
}

void TestLoadTolerantly() {
    std::cout << "[Portability] tolerant load against the real object..." << std::endl;
    const std::string obj_path = ObjectPath();
    if (!HaveObject(obj_path)) {
        Skip("tolerant load", "no " + obj_path);
        return;
    }
    if (geteuid() != 0) {
        // The retry loop only does anything when a program is actually
        // rejected, and nothing can be loaded at all without CAP_BPF. Running
        // it here would exercise only the "load failed, no program named"
        // path, which is not the behaviour under test.
        Skip("tolerant load", "not root; cannot load BPF programs");
        return;
    }

    ReopenCtx ctx{obj_path, 0};
    struct bpf_object* obj = ReopenForTest(&ctx);
    CHECK(obj != nullptr);

    LoadReport report = LoadTolerantly(&obj, &ReopenForTest, &ctx);
    std::cout << "  loaded=" << report.loaded << " attempts=" << report.attempts
              << " skipped=" << report.skipped.size();
    if (!report.fatal_error.empty()) std::cout << " fatal=\"" << report.fatal_error << "\"";
    std::cout << std::endl;
    for (const auto& kv : report.skipped) {
        std::cout << "    - " << kv.first << ": " << kv.second << std::endl;
        // Anything it chose to skip must have been Optional. Skipping a
        // Required program is the failure mode this layer must never have.
        CHECK(RequirementFor(kv.first) == Requirement::kOptional);
    }
    // Whether the object loads on this kernel is not the assertion - the
    // invariant is that it never returns "loaded" while holding a null object,
    // and never returns "not loaded" without saying why.
    if (report.loaded) {
        CHECK(obj != nullptr);
        bpf_object__close(obj);
    } else {
        CHECK(obj == nullptr);
        CHECK(!report.fatal_error.empty());
    }
}

// The tolerance mechanism only does anything when a program is actually
// rejected. On a healthy kernel nothing is - so these two tests run against
// objects built with a deliberately broken program (see the fault-injection
// block at the top of kinnector.bpf.c). Without them, the retry loop that
// exists to keep one bad program from disabling all enforcement would be
// shipped having never once done its job.
void TestTolerantLoadSkipsBrokenOptional() {
    std::cout << "[Portability] a broken OPTIONAL program is skipped, object still loads..."
              << std::endl;
    const std::string obj_path = "kinnector.bpf.break_optional.o";
    if (!HaveObject(obj_path)) {
        Skip("broken-optional load", "no " + obj_path);
        return;
    }
    if (geteuid() != 0) {
        Skip("broken-optional load", "not root; cannot load BPF programs");
        return;
    }

    ReopenCtx ctx{obj_path, 0};
    struct bpf_object* obj = ReopenForTest(&ctx);
    CHECK(obj != nullptr);

    LoadReport report = LoadTolerantly(&obj, &ReopenForTest, &ctx);
    std::cout << "  loaded=" << report.loaded << " attempts=" << report.attempts
              << " skipped=" << report.skipped.size() << " reopens=" << ctx.opens << std::endl;
    for (const auto& kv : report.skipped) {
        std::cout << "    - " << kv.first << ": " << kv.second << std::endl;
    }

    // The whole point: the object loads despite a broken program. Used to be
    // two (fexit_vfs_symlink was also fault-injected here, with a direct
    // out-of-range CONTEXT access - what a drifted prototype actually looks
    // like to the verifier, "func 'vfs_symlink' doesn't have 12-th
    // argument") - removed along with the program itself (see
    // kinnector_container_lsm_hooks.h's apply_post_op_path_closure doc
    // comment). No `fexit/`-type program exists anywhere in the object
    // anymore, so that specific fault shape (a TRACING program whose
    // prototype drifted, caught only by the load-fail-attribute-retry loop
    // since BTF pre-flight reads the policy, not the object, and the policy
    // was correct) currently has no real vehicle to test against - not a
    // gap in the retry loop itself (still generic, still exercised below by
    // kprobe_tty_write), just untested by a real fexit program until one
    // exists again.
    CHECK(report.loaded);
    CHECK(obj != nullptr);
    CHECK(report.fatal_error.empty());

    // kprobe_tty_write is broken in a way BTF could never predict (an
    // unchecked map-value deref), so only the load-fail-attribute-retry loop
    // can find it. This is the half that a BTF check alone would miss.
    CHECK(report.skipped.count("kprobe_tty_write") == 1);

    // Nothing Required may ever be among the casualties.
    for (const auto& kv : report.skipped) {
        CHECK(RequirementFor(kv.first) == Requirement::kOptional);
    }

    // And the enforcement core must actually be loaded, not merely "not skipped".
    for (const char* name : {"file_open", "bprm_creds_for_exec", "mmap_file"}) {
        struct bpf_program* p = bpf_object__find_program_by_name(obj, name);
        CHECK(p != nullptr);
        CHECK(bpf_program__fd(p) >= 0);
    }
    std::cout << "  enforcement core loaded; " << report.skipped.size()
              << " optional program(s) dropped" << std::endl;
    bpf_object__close(obj);
}

void TestTolerantLoadFailsOnBrokenRequired() {
    std::cout << "[Portability] a broken REQUIRED program is still fatal..." << std::endl;
    const std::string obj_path = "kinnector.bpf.break_required.o";
    if (!HaveObject(obj_path)) {
        Skip("broken-required load", "no " + obj_path);
        return;
    }
    if (geteuid() != 0) {
        Skip("broken-required load", "not root; cannot load BPF programs");
        return;
    }

    ReopenCtx ctx{obj_path, 0};
    struct bpf_object* obj = ReopenForTest(&ctx);
    CHECK(obj != nullptr);

    LoadReport report = LoadTolerantly(&obj, &ReopenForTest, &ctx);
    std::cout << "  loaded=" << report.loaded << " fatal=\"" << report.fatal_error << "\""
              << std::endl;

    // Degrading gracefully must NOT extend to the enforcement core. A daemon
    // that comes up "successfully" without file_open reports protection it is
    // not providing - the exact silent-no-enforcement failure this layer was
    // built to end, not to institutionalise.
    CHECK(!report.loaded);
    CHECK(obj == nullptr);
    CHECK(report.fatal_error.find("file_open") != std::string::npos);
    CHECK(report.fatal_error.find("required") != std::string::npos);

    // It must also give up immediately rather than thrashing through retries
    // on a program it can never drop.
    CHECK(report.attempts == 1);
    std::cout << "  refused to start, naming file_open, after 1 attempt" << std::endl;
}

void TestMeasureComplexity() {
    std::cout << "[Portability] per-program complexity measurement..." << std::endl;
    const std::string obj_path = ObjectPath();
    if (!HaveObject(obj_path)) {
        Skip("complexity measurement", "no " + obj_path);
        return;
    }
    auto entries = MeasureComplexity(obj_path);
    CHECK(!entries.empty() && "object has programs but measurement returned none");

    // Every program in the object must appear exactly once, whether or not it
    // verified - a silently dropped program is how a complexity regression
    // hides from the baseline.
    std::set<std::string> names;
    for (const auto& e : entries) {
        CHECK(!e.prog_name.empty());
        CHECK(names.insert(e.prog_name).second);
        CHECK(e.insns == -1 || e.insns > 0);
        // An insn count and a load error are mutually exclusive: the verifier
        // prints "processed N insns" even when it rejects a program, so a
        // failed entry that kept its count would be counted as verified and
        // would read as a decrease rather than a breakage.
        if (!e.error.empty()) CHECK(e.insns == -1);
    }
    std::cout << "  " << entries.size() << " programs measured" << std::endl;

    if (geteuid() != 0) {
        Skip("complexity counts", "not root; every count is the -1 sentinel");
        for (const auto& e : entries) CHECK(e.insns == -1);
        return;
    }

    long worst = 0;
    std::string worst_name;
    int verified = 0;
    for (const auto& e : entries) {
        if (e.insns > worst) { worst = e.insns; worst_name = e.prog_name; }
        if (e.insns > 0) ++verified;
    }
    std::cout << "  verified " << verified << "/" << entries.size() << ", worst is "
              << worst_name << " at " << worst << " insns ("
              << (100.0 * worst / kVerifierInsnLimit) << "% of the ceiling)" << std::endl;
}

}  // namespace

int main() {
    std::cout << "=== BPF portability layer tests ===" << std::endl;

    TestPolicyTableWellFormed();
    TestUnknownProgramsAreRequired();
    TestPolicyTableMatchesObject();
    TestBtfValidation();
    TestTtyKprobeBtfValidation();
    TestGateByBtfValidation();
    TestGateHonoursPolicyDisagreement();
    TestPolicyTableArityMatchesSource();
    TestTierSelection();
    TestSelectObjectPath();
    TestBaselineRoundTrip();
    TestComplexityDiff();
    TestFeatureProbes();
    TestLoadTolerantly();
    TestTolerantLoadSkipsBrokenOptional();
    TestTolerantLoadFailsOnBrokenRequired();
    TestMeasureComplexity();

    std::cout << "\n=== all assertions passed";
    if (g_skipped) {
        std::cout << "; " << g_skipped
                  << " check(s) SKIPPED for lack of root/kernel support - see SKIP lines above";
    }
    std::cout << " ===" << std::endl;
    return 0;
}
