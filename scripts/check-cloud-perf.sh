#!/usr/bin/env bash
# Per-hook cost gate for the cloud-tier collectors (kinnector_cloud.bpf.c), the
# counterpart of check-bpf-complexity.sh: that one guards "will it load", this one
# guards "what does it cost the machine".
#
# It reads the kernel's own per-program run counters, never wall-clock time (the
# LVH VMs drift by 2x, the counters do not). Budgets live in cloud_perf_tool.cpp.
#
# Needs root and a built tree. DO NOT run this on a machine you depend on: it drives
# 200k file opens and thousands of connections. Run it in a VM:
#
#   KINN_VM_MEM=1536M KINN_VM_CPU=2 ~/lvh/kinn-vm.sh start 6.18
#   scp -P 2222 build/bin/kinnector-cloud-perf build/kinnector_cloud.bpf.o root@127.0.0.1:/root/
#   ~/lvh/kinn-vm.sh ssh 6.18 /root/kinnector-cloud-perf /root/kinnector_cloud.bpf.o
#   ~/lvh/kinn-vm.sh stop 6.18
#
# Or, from inside a machine that is allowed to run it, just run this script.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build="${BUILD_DIR:-$here/build}"
tool="$build/bin/kinnector-cloud-perf"
obj="${BPF_OBJECT:-$build/kinnector_cloud.bpf.o}"

[ -x "$tool" ] || { echo "not built: $tool (cmake --build build --target kinnector-cloud-perf)" >&2; exit 2; }
[ -r "$obj" ]  || { echo "no BPF object: $obj" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 2; }

avail=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
if [ "$avail" -lt 400 ]; then
    echo "only ${avail} MB available: refusing to run, this workload needs headroom" >&2
    exit 2
fi

echo "kernel $(uname -r)"
echo "(budgets are per program, ns per call, from the kernel's run counters)"
echo
exec "$tool" "$obj" "$@"
