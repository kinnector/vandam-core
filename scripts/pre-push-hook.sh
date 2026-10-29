#!/usr/bin/env bash
# Optional local pre-push gate: the BPF verifier-complexity check, run
# before code leaves this machine.
#
# There is no hosted CI: GitHub's runners boot without the BPF LSM, so a hosted
# gate could never exercise enforcement. This hook and multi-kernel VM runs are
# the checks. A hook is opt-in per clone and bypassed with `git push
# --no-verify`. What it adds:
#   - Feedback in seconds, before the push.
#   - It's the only place multi-kernel VM tests (Cilium's little-vm-helper)
#     can plug in at all - those need machine-local QEMU VMs and cannot run
#     in hosted GitHub Actions. This hook does NOT run them by default
#     (they take minutes, and most pushes shouldn't pay that cost every
#     time) - opt in with KINN_PREPUSH_VMTEST=1 if ~/lvh is set up.
#
# What this hook deliberately does NOT do: build the project. A pre-push
# hook that silently kicks off a multi-minute Release+BPF build on every
# `git push` is a worse developer experience than the check it's trying to
# add, and a build failure for an unrelated reason (missing bpftool, no BTF
# on this machine right now) would block pushes with a confusing error at
# the worst possible time. If build/ isn't there yet, or the complexity
# tool wasn't built, this hook says so and gets out of the way - it never
# reports success for a check that didn't actually run (same principle as
# check-bpf-complexity.sh's own exit-2 handling).
#
# Install (opt-in, per clone - this repo does not install it automatically):
#   ln -sf ../../scripts/pre-push-hook.sh .git/hooks/pre-push
#   chmod +x .git/hooks/pre-push
#
# Uninstall:
#   rm .git/hooks/pre-push

set -u

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build="${BUILD_DIR:-$here/build}"

echo "[pre-push] BPF verifier-complexity gate"

if [ ! -x "$build/bin/kinnector-bpf-complexity" ] || [ ! -r "$build/kinnector.bpf.o" ]; then
    echo "[pre-push] SKIPPED: no build at $build (or kinnector-bpf-complexity/kinnector.bpf.o missing)."
    echo "[pre-push]          Run 'cmake -B build && cmake --build build --config Release' first"
    echo "[pre-push]          if you want this check."
    exit 0
fi

if ! sudo -n true 2>/dev/null; then
    echo "[pre-push] SKIPPED: loading BPF programs needs root and this shell has no passwordless sudo."
    exit 0
fi

if ! timeout 300 sudo "$here/scripts/check-bpf-complexity.sh"; then
    echo
    echo "[pre-push] BLOCKED: the BPF complexity gate failed (see output above)."
    echo "[pre-push]          Bypass (not recommended) with: git push --no-verify"
    exit 1
fi

echo "[pre-push] complexity gate OK"

if [ "${KINN_PREPUSH_VMTEST:-0}" = "1" ]; then
    if [ -x "$HOME/lvh/kinn-vm.sh" ]; then
        echo "[pre-push] KINN_PREPUSH_VMTEST=1: running multi-kernel VM tests (~/lvh/kinn-vm.sh test all)"
        echo "[pre-push]                        this is the one check hosted CI genuinely cannot run."
        if ! "$HOME/lvh/kinn-vm.sh" test all; then
            echo "[pre-push] BLOCKED: multi-kernel VM test run failed."
            echo "[pre-push]          Bypass (not recommended) with: git push --no-verify"
            exit 1
        fi
    else
        echo "[pre-push] KINN_PREPUSH_VMTEST=1 but ~/lvh/kinn-vm.sh not found - skipping, nothing to run."
    fi
fi

exit 0
