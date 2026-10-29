// Minimal, deliberately-unclassified probe process for test_enforcement_e2e.cpp.
// Not linked against kinnector-core -- it must be a genuinely separate binary
// so its exec-time trust level is whatever the harness configures via
// AddTrustedExecInode/AddSensitiveInode, never inherited from the test
// runner's own (already-exec'd) image. The LSM hooks key off the calling
// task, so fork() alone from the harness would not exercise the same code
// path a real untrusted process takes -- this binary is exec'd into that
// forked child.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sched.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <grp.h>
#include <string>
#include <pthread.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <open_read|open_write> <path>\n", argv[0]);
        fprintf(stderr, "       %s sleep <seconds>\n", argv[0]);
        fprintf(stderr, "       %s impersonation_probe <target_pid>\n", argv[0]);
        fprintf(stderr, "       %s namespace_probe\n", argv[0]);
        fprintf(stderr, "       %s rename_symlink_probe <scratch_dir>\n", argv[0]);
        fprintf(stderr, "       %s anon_exec_on_marker <marker_path>\n", argv[0]);
        fprintf(stderr, "       %s execveat_probe\n", argv[0]);
        fprintf(stderr, "       %s thread_open_read <path> <result_path>\n", argv[0]);
        return 2;
    }
    const char* op = argv[1];

    // Regression probe for the thread-key bug in is_admin_session()/
    // is_install_session() (fixed 6449762, first flagged by 92c2f26). Opens the
    // same path twice - once from the main thread, once from a worker thread -
    // and reports both errnos. Every map the fork handler propagates is keyed
    // on the GROUP LEADER's start_time, so a lookup made with the calling
    // THREAD's key matched from the main thread only: the two numbers this
    // writes were 0 and EACCES before the fix and must now be equal.
    //
    // The result goes to a file rather than an exit status because the only
    // process the kernel will stamp TREE_ADMIN_SESSION is the orphaned
    // grandchild of StartProbeInAdminSession's double fork, which by
    // construction the harness cannot waitpid(). Written to a temporary and
    // rename()d so a reader polling for it never sees a half-written line.
    if (strcmp(op, "thread_open_read") == 0) {
        if (argc < 4) {
            fprintf(stderr, "usage: %s thread_open_read <path> <result_path>\n", argv[0]);
            return 2;
        }
        const char* target = argv[2];
        const char* result_path = argv[3];

        auto open_once = [](const char* p) -> int {
            int fd = open(p, O_RDONLY);
            if (fd < 0) return errno;
            close(fd);
            return 0;
        };

        int main_errno = open_once(target);

        // A real pthread, not a fork: the bug is specifically that a task
        // sharing its thread group's maps has a start_time of its own, which a
        // forked child would not reproduce.
        struct ThreadArg { const char* path; int result; int (*fn)(const char*); };
        ThreadArg arg{target, -1, open_once};
        pthread_t th;
        int worker_errno = -1;
        if (pthread_create(&th, nullptr, [](void* a) -> void* {
                ThreadArg* ta = static_cast<ThreadArg*>(a);
                ta->result = ta->fn(ta->path);
                return nullptr;
            }, &arg) == 0) {
            pthread_join(th, nullptr);
            worker_errno = arg.result;
        }

        char tmp[512];
        snprintf(tmp, sizeof(tmp), "%s.part", result_path);
        FILE* f = fopen(tmp, "w");
        if (!f) return 3;
        fprintf(f, "main=%d worker=%d\n", main_errno, worker_errno);
        fclose(f);
        if (rename(tmp, result_path) != 0) return 3;
        return 0;
    }

    // stand-in for a long-lived "owner" process
    // (e.g. a password manager) that test_enforcement_e2e's ptrace/kill tests
    // target from a separate, unrelated process while this one is still alive.
    if (strcmp(op, "sleep") == 0) {
        if (argc < 3) {
            fprintf(stderr, "usage: %s sleep <seconds>\n", argv[0]);
            return 2;
        }
        sleep(static_cast<unsigned int>(atoi(argv[2])));
        return 0;
    }

    // real-kernel correctness proof.
    // Runs as an exec'd, freshly-unclassified process (same fork+exec
    // discipline as every other op here) so it lands in process_threshold_map
    // under blocking_enabled=1 - the gate every widened/new cred-family hook
    // this plan added requires. Exercises each mechanism once, in a fixed
    // order, and exits 0 unconditionally (success/failure of each individual
    // syscall is not asserted here - the harness's ring-buffer callback is
    // the actual proof; a syscall failing for an unrelated environment
    // reason, e.g. CLONE_NEWUSER disabled by sysctl, must not make the whole
    // probe process look like a harness bug).
    if (strcmp(op, "impersonation_probe") == 0) {
        pid_t target_pid = argc >= 3 ? static_cast<pid_t>(atoi(argv[2])) : getpid();

        // Phase 2: process_vm_readv against `target_pid` (defaults to self -
        // reading your own memory is a legal, always-succeeds special case of
        // the same syscall, sufficient to prove the tracepoint fires with the
        // real target pid).
        char local_buf[16];
        struct iovec local_iov{local_buf, sizeof(local_buf)};
        struct iovec remote_iov{local_buf, sizeof(local_buf)};
        process_vm_readv(target_pid, &local_iov, 1, &remote_iov, 1, 0);

        // Phase 1: a real setgroups() call.
        setgroups(0, nullptr);

        // Phase 1: seteuid(nonroot)-then-back - the standard temporary-
        // elevation shape. Only meaningful if this process's real uid is 0
        // (the harness runs as root); silently a no-op sequence of harmless
        // calls otherwise.
        seteuid(65534); // nobody
        seteuid(0);

        // Phase 4: prctl(PR_SET_KEEPCAPS, 1).
        prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

        // Phase 11: prctl(PR_SET_NAME, "sshd") - deliberately spoofing comm.
        prctl(PR_SET_NAME, "sshd", 0, 0, 0);

        // Phase 11: prctl(PR_SET_CHILD_SUBREAPER, 1).
        prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

        // Phase 5/13: unshare(CLONE_NEWUSER) - only affects a *new* child, so
        // fork immediately after to actually exercise the namespace, then
        // have the child exit right away.
        if (unshare(CLONE_NEWUSER) == 0) {
            pid_t p = fork();
            if (p == 0) _exit(0);
            if (p > 0) { int st; waitpid(p, &st, 0); }
        }

        // Phase 13: clone(CLONE_NEWUSER) directly at process-creation time,
        // without a prior unshare() - raw syscall (glibc's clone() wrapper
        // needs a callback+stack; SYS_clone with a null stack duplicates the
        // calling stack via COW, safe for an immediate-exit child on x86_64).
        pid_t cpid = static_cast<pid_t>(syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, nullptr, nullptr, nullptr, nullptr));
        if (cpid == 0) {
            _exit(0);
        } else if (cpid > 0) {
            int st;
            waitpid(cpid, &st, 0);
        }

        return 0;
    }

    // Antitheft container/namespace tracking fix: proves mount/chroot/setns/
    // pivot_root actually produce NamespaceChange telemetry now that
    // ebpf_loader.cpp attaches sb_mount/path_chroot/sys_enter_setns/
    // sys_enter_unshare in the real (non-fallback) path. Deliberately
    // isolated from impersonation_probe above - every mount-table-touching
    // operation here runs inside its own freshly unshare(CLONE_NEWNS)'d
    // child so nothing ever touches the real host mount table, and each
    // syscall gets its own short-lived forked child so one failing (e.g. an
    // environment without unprivileged user/mount namespaces) can't prevent
    // the others from running - same non-assertive "exercise it, let the
    // ring-buffer callback be the real proof" discipline as impersonation_probe.
    if (strcmp(op, "namespace_probe") == 0) {
        // mount + chroot: both need their own mount namespace so bind-
        // mounting/chrooting never affects the real host root.
        //
        // src/dst are created here, in the PARENT, deliberately - the child
        // below calls chroot(dst), which changes what an ABSOLUTE path like
        // "/tmp/kinnector_ns_probe_src_..." even resolves to for the rest of
        // that process's life (it now means dst's own former self, an empty
        // directory with no /tmp under it). rmdir() on either path from
        // inside the chrooted child therefore failed with ENOENT, silently,
        // every single run - the child's exit status is never checked, so
        // this had gone unnoticed. The parent never chroots, so it keeps a
        // stable path to clean up once the child is gone.
        {
            char src_tmpl[] = "/tmp/kinnector_ns_probe_src_XXXXXX";
            char dst_tmpl[] = "/tmp/kinnector_ns_probe_dst_XXXXXX";
            char* src = mkdtemp(src_tmpl);
            char* dst = src ? mkdtemp(dst_tmpl) : nullptr;
            if (src && dst) {
                pid_t p = fork();
                if (p == 0) {
                    // unshare(CLONE_NEWNS) alone is not isolation: it clones
                    // the mount TABLE, but every mount it inherited keeps
                    // whatever propagation type it already had, and systemd
                    // makes "/" (and therefore /tmp) MS_SHARED by default. A
                    // mount() this child makes under /tmp propagates straight
                    // back out to the real host namespace as an independent
                    // copy - the child's own later umount2()/exit never
                    // touches that copy, which is exactly how
                    // /tmp/kinnector_ns_probe_*/kinnector_pivot_probe_*
                    // mounts were leaking onto the real machine.
                    // Recursively
                    // re-marking MS_PRIVATE right after unshare (the same
                    // idiom `unshare --propagation private` uses) confines
                    // every mount below to this process's own private copy -
                    // nothing it does from here can reach the real host
                    // mount table.
                    if (unshare(CLONE_NEWNS) == 0 && mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) == 0) {
                        // Phase: real mount(2) - bind mount, confined to this
                        // private namespace above.
                        if (mount(src, dst, nullptr, MS_BIND, nullptr) == 0) {
                            umount2(dst, MNT_DETACH);
                        }
                        // Phase: real chroot(2) - harmless, this child exits
                        // immediately after.
                        chroot(dst);
                    }
                    _exit(0);
                }
                if (p > 0) { int st; waitpid(p, &st, 0); }
                // The child's private namespace is torn down with it; these
                // are now just two plain, unmounted directory entries again.
                rmdir(dst);
                rmdir(src);
            }
        }

        // Phase: real setns(2) - joins this process's OWN current mount
        // namespace, a legal degenerate no-op that still exercises the real
        // syscall entry (and hence the tracepoint) without changing anything.
        {
            int fd = open("/proc/self/ns/mnt", O_RDONLY);
            if (fd >= 0) {
                setns(fd, CLONE_NEWNS);
                close(fd);
            }
        }

        // Phase: real pivot_root(2). Needs its own mount namespace plus a
        // new_root that IS itself a mount point (the standard way to make an
        // arbitrary directory qualify is bind-mounting it onto itself) and an
        // old_root subdirectory inside it.
        //
        // new_root is created here, in the PARENT, deliberately - once the
        // child below calls pivot_root(2) its own idea of "/" becomes that
        // directory, so it cannot reliably name or rmdir() it again
        // afterward. The parent never pivots, so it keeps a stable path to
        // clean up once the child (and, since it was the sole user, its
        // private mount namespace) is gone.
        {
            char root_tmpl[] = "/tmp/kinnector_pivot_probe_XXXXXX";
            char* new_root = mkdtemp(root_tmpl);
            if (new_root) {
                pid_t p = fork();
                if (p == 0) {
                    // unshare(CLONE_NEWNS) alone clones the mount TABLE, not
                    // propagation - "/" is MS_SHARED by default under
                    // systemd, so the self-bind below would otherwise
                    // propagate straight back out to the real host
                    // namespace, permanently, independent of anything this
                    // child does afterward. This is exactly how
                    // /tmp/kinnector_pivot_probe_* mounts were leaking onto
                    // the real machine. MS_REC|MS_PRIVATE right after unshare (the
                    // `unshare --propagation private` idiom) confines
                    // everything below to this process's own private view.
                    if (unshare(CLONE_NEWNS) == 0 && mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) == 0) {
                        if (mount(new_root, new_root, nullptr, MS_BIND, nullptr) == 0) {
                            char old_root[300];
                            snprintf(old_root, sizeof(old_root), "%s/old_root", new_root);
                            mkdir(old_root, 0700);
                            if (chdir(new_root) == 0) {
                                syscall(SYS_pivot_root, ".", "old_root");
                                chdir("/");
                                umount2("/old_root", MNT_DETACH);
                            }
                        }
                    }
                    _exit(0);
                }
                if (p > 0) { int st; waitpid(p, &st, 0); }
                // The child's private namespace (bind mount included) is
                // torn down by the kernel now that its sole user has exited
                // - nothing left to unmount here, just two plain directory
                // entries on the real filesystem (old_root never got
                // rmdir'd inside the child either, since after pivot_root
                // its own idea of "/" no longer resolves that path).
                char old_root[300];
                snprintf(old_root, sizeof(old_root), "%s/old_root", new_root);
                rmdir(old_root);
                rmdir(new_root);
            }
        }

        return 0;
    }

    // Owner-swap defense follow-up: proves inode_rename/inode_symlink
    // telemetry fires for real. Takes a scratch directory (already created
    // by the caller) so this stays a plain, unprivileged probe - no
    // isolation needed, unlike namespace_probe above, since renaming/
    // symlinking within a private temp dir the caller owns has zero host-
    // wide effect on its own.
    if (strcmp(op, "rename_symlink_probe") == 0) {
        if (argc < 3) {
            fprintf(stderr, "usage: %s rename_symlink_probe <scratch_dir>\n", argv[0]);
            return 2;
        }
        std::string dir = argv[2];

        // Phase: real rename(2) - a source file renamed OVER an existing
        // destination, the exact shape a rename-based path swap takes.
        std::string rename_src = dir + "/rename-src";
        std::string rename_dst = dir + "/rename-dst";
        FILE* f1 = fopen(rename_src.c_str(), "w");
        if (f1) fclose(f1);
        FILE* f2 = fopen(rename_dst.c_str(), "w");
        if (f2) fclose(f2);
        rename(rename_src.c_str(), rename_dst.c_str());

        // Phase: real symlink(2) - a brand-new symlink entry, the shape a
        // symlink-based path swap takes.
        std::string symlink_target = dir + "/symlink-does-not-need-to-exist";
        std::string symlink_path = dir + "/symlink-dst";
        symlink(symlink_target.c_str(), symlink_path.c_str());

        return 0;
    }

    // Storage-dir write protection: creates a brand-new file
    // (O_CREAT) and writes to it - unlike open_write below, which requires
    // the target to already exist. A `.so`-named path here is exactly the
    // shape of a non-owner planting a library inside a protected storage
    // dir; a non-`.so` path is the "ordinary write, unaffected" control
    // case.
    if (strcmp(op, "open_write_create") == 0) {
        if (argc < 3) {
            fprintf(stderr, "usage: %s open_write_create <path>\n", argv[0]);
            return 2;
        }
        int fd = open(argv[2], O_WRONLY | O_CREAT, 0644);
        if (fd < 0) {
            return errno;
        }
        // Same rw_verify_area() reasoning as open_write below - the deny
        // fires on the actual write, not the open().
        if (write(fd, "x", 1) < 0) {
            int err = errno;
            close(fd);
            return err;
        }
        close(fd);
        return 0;
    }

    // execveat(2) producer coverage. Re-execs via execveat with
    // AT_EMPTY_PATH - the fexecve/memfd shape - so the harness can prove the
    // new tracepoint fires. Deliberately not a plain execve on
    // /proc/self/fd/N, which would go through the execve tracepoint that was
    // already covered and prove nothing.
    if (strcmp(op, "execveat_probe") == 0) {
        int fd = open("/bin/true", O_RDONLY | O_PATH);
        if (fd < 0) {
            return errno;
        }
        char* const child_argv[] = { (char*)"true", nullptr };
        char* const child_envp[] = { nullptr };
        syscall(SYS_execveat, fd, "", child_argv, child_envp, AT_EMPTY_PATH);
        return errno; // only reached if the exec itself failed
    }

    // Self-injection policy: the anonymous-executable-memory
    // shape a code-generating runtime makes constantly, held until the
    // harness says go.
    // Two phases because the thing under test is a map entry written to a
    // process that is ALREADY running and already stamped
    // protected_owner_pids at exec - the harness cannot revoke a process
    // that has exited, and cannot know the kernel's exact start_time key
    // until the exec has happened. So: exec, announce liveness by creating
    // <marker>.ready, wait for <marker> to appear, then make the mapping and
    // exit with its verdict (0 allowed, errno denied). One-step
    // mmap(PROT_EXEC|MAP_ANONYMOUS) rather than mmap+mprotect because
    // anon_exec_policy() mediates both and the one-step form is the one that
    // was silently missing until it was closed.
    if (strcmp(op, "anon_exec_on_marker") == 0) {
        if (argc < 3) {
            fprintf(stderr, "usage: %s anon_exec_on_marker <marker_path>\n", argv[0]);
            return 2;
        }
        char ready[4096];
        snprintf(ready, sizeof(ready), "%s.ready", argv[2]);
        int ready_fd = open(ready, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (ready_fd < 0) {
            return errno;
        }
        close(ready_fd);
        // Bounded wait: a harness that dies must not leave this process
        // pinned forever (the whole suite runs under a live daemon).
        for (int waited_ms = 0; waited_ms < 30000; waited_ms += 10) {
            if (access(argv[2], F_OK) == 0) {
                void* mapped = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (mapped == MAP_FAILED) {
                    return errno;
                }
                munmap(mapped, 4096);
                return 0;
            }
            usleep(10000);
        }
        return ETIMEDOUT;
    }

    // Untrusted-.so synchronous kernel deny: opens `path`
    // read-only and mmaps it PROT_EXEC - the real shape mmap_file's new
    // gate mediates (the dynamic linker/dlopen path). Content doesn't need
    // to be a real ELF for this to exercise the LSM hook; a plain byte is
    // enough to prove the mapping itself was allowed or denied.
    if (strcmp(op, "mmap_exec") == 0) {
        if (argc < 3) {
            fprintf(stderr, "usage: %s mmap_exec <path>\n", argv[0]);
            return 2;
        }
        int fd = open(argv[2], O_RDONLY);
        if (fd < 0) {
            return errno;
        }
        void* mapped = mmap(nullptr, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
        if (mapped == MAP_FAILED) {
            int err = errno;
            close(fd);
            return err;
        }
        munmap(mapped, 4096);
        close(fd);
        return 0;
    }

    // Destructive-ops gate: a plain rename(2) of
    // the SOURCE path to the given DESTINATION - the real syscall shape
    // inode_rename's new resource-owner gate mediates, as opposed to
    // rename_symlink_probe above which exercises the resource-SWAP-defense
    // path (rename onto an existing destination) and isn't classification-
    // controlled the way this probe needs to be.
    if (strcmp(op, "rename") == 0) {
        if (argc < 4) {
            fprintf(stderr, "usage: %s rename <source> <destination>\n", argv[0]);
            return 2;
        }
        if (rename(argv[2], argv[3]) != 0) {
            return errno; // caller (test_enforcement_e2e) asserts against the exact errno
        }
        return 0;
    }

    if (argc < 3) {
        fprintf(stderr, "usage: %s <open_read|open_write> <path>\n", argv[0]);
        return 2;
    }
    const char* path = argv[2];

    int flags;
    if (strcmp(op, "open_read") == 0) {
        flags = O_RDONLY;
    } else if (strcmp(op, "open_write") == 0) {
        flags = O_WRONLY;
    } else {
        fprintf(stderr, "unknown op: %s\n", op);
        return 2;
    }

    int fd = open(path, flags);
    if (fd < 0) {
        return errno; // caller (test_enforcement_e2e) asserts against the exact errno
    }
    if (flags == O_WRONLY) {
        // security_file_permission() (where protected_static_inodes and the
        // resource-owner allowlist are enforced) is invoked from
        // rw_verify_area() on an actual read/write syscall -- open() alone
        // with O_WRONLY never reaches it, so a "write deny" probe must
        // actually attempt a write for that check to run at all.
        if (write(fd, "x", 1) < 0) {
            int err = errno;
            close(fd);
            return err;
        }
    }
    close(fd);
    return 0;
}
