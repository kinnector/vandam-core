#!/usr/bin/env bash
# Verifier-complexity regression gate - our stand-in for the veristat diff
# cilium/tetragon runs on every PR that touches bpf/.
#
# Why this exists: bprm_creds_for_exec went -E2BIG on 6.18 by ONE instruction,
# and the way we found out was a daemon that came up enforcing nothing. A
# number that is tracked cannot surprise you like that.
#
# Needs root (loading BPF programs) and a built tree. Exits non-zero on a
# regression beyond the tolerance, or on any program within 75% of the ceiling.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build="${BUILD_DIR:-$here/build}"
tool="$build/bin/kinnector-bpf-complexity"
obj="${BPF_OBJECT:-$build/kinnector.bpf.o}"
baseline="${BASELINE:-$here/src/linux/ebpf/complexity_baseline.txt}"
tolerance="${TOLERANCE:-0.10}"

[ -x "$tool" ] || { echo "not built: $tool (make kinnector-bpf-complexity)" >&2; exit 2; }
[ -r "$obj" ]  || { echo "no BPF object: $obj" >&2; exit 2; }
[ -r "$baseline" ] || { echo "no baseline: $baseline" >&2; exit 2; }

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root: loading BPF programs is how the counts are obtained" >&2
    exit 2
fi

echo "kernel $(uname -r)"
echo "baseline recorded on: $(sed -n 's/^#   \(.*\), [0-9-]*$/\1/p' "$baseline" | head -1)"
echo "(a diff across two different kernels is noise, not a regression)"
echo
exec "$tool" check "$obj" --baseline "$baseline" --tolerance "$tolerance"
