# vandam-core - agent instructions

vandam-core is the Linux kernel telemetry and enforcement engine (eBPF, BPF LSM, fanotify) under
the vandam server agent. See `README.md` for architecture, hook inventory, FFI usage and
performance design; this file is operational guidance for anyone (human or agent) working in the
source.

## Safety-critical: kernel-blocking mechanisms

**Never pair a mount-wide fanotify mark (`FAN_MARK_MOUNT`) with a `*_PERM` (blocking) event type.**
`FAN_MARK_MOUNT` + `FAN_OPEN_PERM` on `/` blocks every `open()` on the filesystem, including
anything you would use to intervene, and hangs the machine. Mount-wide marks are fine for
notify-only events; a blocking mark must be scoped to a specific path.

**Anything that can arm blocking behaviour (fanotify `*_PERM`, a new BPF LSM deny path) must
default to off**, and the default init path (`initialize_telemetry_engine`, called by every
product and test) must never opt in implicitly.

**Wrap any root-level kernel/BPF/fanotify test in `timeout <N>s` the first time you run it**, and
reason through the blast radius first. Never attach enforcement hooks on a machine you depend on:
a wrong `bprm_creds_for_exec` or `path_chmod` deny refuses exec or chmod system-wide. Use a VM.

This build is `-DNDEBUG`, so `assert()` with a required side effect is silently elided: assign the
result to a variable, then `assert()` the variable. (Test targets undefine `NDEBUG`, see
`CMakeLists.txt`.)

If everything needing root starts failing with `Permission denied` after loading BPF LSM hooks,
suspect leftover pinned links (`/sys/fs/bpf/warden/`) from an earlier run, not a lockout: unpin
them. bpffs is not disk-backed, so a reboot clears them as a last resort.

## BPF verifier and LSM gotchas (kinnector.bpf.c)

1. **A NULL check does not carry over to a re-read of the same field.** The verifier tracks the
   value of one read, not the expression. Null-check the exact variable you dereference:

   ```c
   // wrong: the second read is unchecked
   if (!newsock || !newsock->sk) return 0;
   struct sock *sk = newsock->sk;
   // right
   struct sock *sk = newsock->sk;
   if (!sk) return 0;
   ```

   This only surfaces at a real `bpf_object__load()`, never in a compile or a mock-mode test.

2. **A NULL check on a hook's own pointer argument is deleted.** LSM/fentry context pointers are
   typed trusted and non-NULL, so `if (!file)` in `lsm/mmap_file` is compiled out, although the
   kernel does pass NULL for anonymous mappings. Derive the condition from a scalar (`flags &
   MAP_ANONYMOUS`) or from a `BPF_CORE_READ` result. Check with `bpftool prog dump xlated name
   <prog>` while attached.

3. **A `BPF_PROG` with more parameters than the real hook reads garbage.** Nothing checks the
   declared arguments against the kernel's signature. Check the arity in
   `include/linux/lsm_hook_defs.h` of the kernel you target, and prefer deriving what you need
   from the objects the hook passes (write intent from `file->f_mode & FMODE_WRITE`).

4. **A new `lsm/` program is not attached by writing it.** `EbpfLoader::Start()` only sets the
   program type in its loop; attachment is an explicit list of `AttachOrUpdatePinnedLink(...)`
   calls. Adding a program means three edits: the attach call, a `struct bpf_link*` member with
   its `CleanPinnedLink()` in the destructor, and an entry in `kWardenPinnedLinkPaths` (what the
   test-only and signal-safe unpin paths iterate; a pin missing from it survives a crash and keeps
   enforcing). Check what is attached with `ls /sys/fs/bpf/warden/`.

5. **`get_current_process_key()` is per thread; fork-propagated maps are keyed per process.**
   `process_key` is `(tgid, start_time)` and that call fills the calling thread's start time, so a
   lookup against a map written at fork or registered from userspace matches only from the main
   thread. Use `get_current_group_leader_key()` for current-process lookups against those maps.

6. **"The hook fires" is not "the hook sees the new state".** `security_d_instantiate()` runs
   before the inode is attached, so `dentry->d_inode` is NULL in `lsm/d_instantiate`: use the
   hook's `inode` argument. When moving logic between hooks, test the effect (a deny), not the
   firing.

## kinnector.bpf.c serves more than one product

One BPF object and one `EbpfLoader` singleton (`src/ffi.cpp`) serve every product built on this
engine; a `deployment_mode` config value (`MODE_WARDEN` for vandam) gates product-specific logic.
For any change to a shared hook (`file_open`, `file_permission`, `ptrace_access_check`,
`task_kill`, ...):

- gate a new product-specific branch behind `deployment_mode`, after the existing checks, not
  interleaved with them;
- never reuse a map or config index another mode reads: new state goes in new maps;
- run `test_enforcement_e2e` (real syscalls, real errno against protected resources) before
  merging.

## A protected identity is an inode number, and the number outlives the file

Protection maps are keyed by `(dev, ino)`, and filesystems such as ext4 hand a freed number to the
next file created nearby (an atomic save frees one every time). `lsm/inode_free_security` drops
the protection of an inode that is really gone (`i_nlink == 0`; a plain cache eviction must not
unprotect a live file), and registration discards a previous life's state. A swapped-in identity's
owner set is written in one step (`add_resource_owners_exact_batch`), never one owner at a time.
Tests of inode reuse must create files on a disk filesystem (`/var/tmp`), not tmpfs, which never
reuses numbers.

## Observe-only collectors are a separate object

`kinnector_cloud.bpf.c` (network accounting, DNS names, file-open folding) is its own observe-only
object with its own loader (`src/linux/cloud_collectors.*`), nothing pinned and no map shared with
the enforcement object. Keep it that way: a crash leaves nothing attached, and a rejected program
cannot take enforcement down.

## Build & test

```bash
cmake -B build
cmake --build build --config Release
```

The test list and the root-requiring targets are in `README.md`'s Build section.
`test_enforcement_e2e` and `test_lsm` need root and a BPF-LSM-capable kernel (`bpf` in
`/sys/kernel/security/lsm`); without them they fall back to mock-mode assertions that prove
nothing, so confirm you hit the real-kernel branch. `TestWardenAdminSessionRulesAreWardenOnly`
also needs a real audit loginuid: over SSH that means sshd running PAM's session stack
(`UsePAM yes`); check `sshd -T | grep -i usepam` before treating a failure there as a regression.
Changes to `kinnector.bpf.c` or the loader should be run on more than one kernel: argument counts
and verifier limits differ between versions. `scripts/check-bpf-complexity.sh` gates verifier
complexity against `src/linux/ebpf/complexity_baseline.txt`.
