// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// The build must NAME the target architecture; this file must never assume
// one. `clang -target bpf` defines only __bpf__, so bpf_tracing.h has nothing
// to infer from and BPF_KPROBE's PT_REGS_PARMn expand to whichever register
// mapping we hand it. This used to be an unconditional `#define
// __TARGET_ARCH_x86` right here, which on arm64 would have compiled, loaded
// and attached an object that reads x86 registers - garbage arguments in
// kprobe_tty_write/kprobe_tty_read/kprobe_vfs_symlink/kprobe_vfs_link, with no
// error at any stage. CMake derives it from CMAKE_SYSTEM_PROCESSOR; fail here
// rather than guess if it did not.
#if !defined(__TARGET_ARCH_x86) && !defined(__TARGET_ARCH_arm64) && \
    !defined(__TARGET_ARCH_s390) && !defined(__TARGET_ARCH_powerpc) && \
    !defined(__TARGET_ARCH_riscv) && !defined(__TARGET_ARCH_loongarch)
#error "no __TARGET_ARCH_* defined - compile via CMake, which derives it from the host arch"
#endif

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// ---------------------------------------------------------------------------
// Kernel-portability tiers (see src/linux/bpf_portability.h)
// ---------------------------------------------------------------------------
//
// This file is compiled twice from one source, the way cilium/tetragon builds
// its v53/v511/v61 variants: the full tier (kinnector.bpf.o) and a small tier
// (kinnector.bpf.small.o, -D__SMALL_BPF_PROG) for kernels that still enforce
// the pre-5.2 4096-instruction cap. bpf_portability::SelectObjectPath() picks
// between them at runtime from a functional probe, never a version compare,
// and KINNECTOR_FORCE_SMALL_PROGS / _FORCE_LARGE_PROGS override that.
//
// Rules for anything put behind __SMALL_BPF_PROG:
//   * It may reduce REACH (how far a walk climbs, how many entries a scan
//     inspects). It must never change a VERDICT the code would reach - a small
//     build that allows what the full build denies is a security regression
//     shipped to exactly the oldest, least defensible kernels.
//   * It must never change a value userspace also computes. fnv1a_hash_name()'s
//     128-byte bound is the standing example: shortening it would silently
//     change hashes for long names and break every protected_path_names_map
//     lookup, which is a correctness bug, not a smaller program.
#ifdef __SMALL_BPF_PROG
#define KINN_ENV_SCAN_ENTRIES 24
#else
#define KINN_ENV_SCAN_ENTRIES 64
#endif

// ---------------------------------------------------------------------------
// Test-only fault injection (never defined in a shipped build)
// ---------------------------------------------------------------------------
//
// The per-program tolerance in bpf_portability.cpp only does anything when a
// program is actually rejected, and on a healthy kernel nothing is - so
// without a way to break a program on purpose, the retry loop that exists to
// keep one bad program from disabling all enforcement would ship untested.
//
// CMake builds two extra objects nobody installs:
//   -D__KINN_TEST_BREAK_OPTIONAL  breaks fexit_vfs_symlink (prototype drift,
//                                 caught by BTF validation) and kprobe_tty_write
//                                 (verifier rejection, which BTF cannot predict)
//   -D__KINN_TEST_BREAK_REQUIRED  breaks file_open the same way, to prove a
//                                 Required program's failure is still fatal
//
// KINN_TEST_VERIFIER_FAULT is an unconditional deref of a map lookup result,
// which the verifier rejects as "invalid mem access 'map_value_or_null'".
//
// The key must be UNKNOWN to the verifier. A constant, in-bounds key into an
// ARRAY map is provably present, so the verifier returns a plain
// PTR_TO_MAP_VALUE and the unchecked deref is accepted - which is exactly what
// happened on the first attempt at this, and it made the fault injection a
// no-op that quietly turned the test into a pass. Deriving the key from
// bpf_get_current_pid_tgid() leaves it unknown, so the lookup is
// _OR_NULL-typed and the rejection is deterministic.
// ---------------------------------------------------------------------------
// Arity-independent fexit argument access (ported from cilium/tetragon)
// ---------------------------------------------------------------------------
//
// A typed `BPF_PROG(name, a, b, c, int ret)` makes the WHOLE program depend on
// the target's total argument count, because BPF_PROG computes the return
// value's slot as ctx[nargs]. When vfs_symlink gained a fifth parameter
// upstream, that read became ctx[5] on a 5-arg function and the verifier
// rejected the program ("func 'vfs_symlink' doesn't have 6-th argument") -
// which, before per-program tolerance, took the entire object down and left
// the daemon enforcing nothing on 7.2.
//
// Tetragon never declares the arity at all (`bpf/process/bpf_generic_fexit.c`
// takes a bare `void *ctx`): arguments are read positionally out of the
// context, and the return value comes from the bpf_get_func_ret() HELPER,
// which does not care how many arguments there are. Ported here.
//
// Why positional reads are safe for these two: measured on 6.18.46 and
// 7.2.0-bpf-next, `vfs_symlink`'s new `delegated_inode` was APPENDED at index
// [4] - `dir` [1] and `dentry` [2], the only arguments we read, did not move.
// `vfs_link` is identical on both. The indices are asserted against the
// running kernel's BTF before load (bpf_portability.cpp's PolicyTable /
// ValidateTracingTarget), so an upstream change that DOES reorder arguments
// disables the program instead of silently reading the wrong pointer.
#define KINN_FEXIT_ARG(ctx, idx) \
    BPF_CORE_READ((struct bpf_raw_tracepoint_args *)(ctx), args[(idx)])

#if defined(__KINN_TEST_BREAK_OPTIONAL) || defined(__KINN_TEST_BREAK_REQUIRED)
#define KINN_TEST_VERIFIER_FAULT()                                   \
    do {                                                             \
        uint32_t __k = (uint32_t)bpf_get_current_pid_tgid();         \
        uint32_t *__v = bpf_map_lookup_elem(&config_map, &__k);      \
        *__v = 1;                                                    \
    } while (0)
#else
#define KINN_TEST_VERIFIER_FAULT() do { } while (0)
#endif


// ---------------------------------------------------------------------------
// Source split (readability only). This file used to hold all 52
// programs inline; it is now a thin shell that #includes the real logic from
// headers in this same directory, one #include per translation unit, exactly like
// cilium/tetragon's bpf/process/*.c shells. Still ONE object file - see the
// CMakeLists.txt eBPF compile rules, unchanged by this split.
//
// Include order matters: many helpers are `static __always_inline` and must
// be defined before their first use, so this chain preserves the exact
// top-to-bottom order the monolithic file used to have. Do not reorder.
// ---------------------------------------------------------------------------
#include "kinnector_types.h"
#include "kinnector_maps.h"
#include "kinnector_helpers.h"
#include "kinnector_lsm_hooks_exec.h"
#include "kinnector_lsm_hooks_creds.h"
#include "kinnector_tracepoints.h"
#include "kinnector_container_lsm_hooks.h"
