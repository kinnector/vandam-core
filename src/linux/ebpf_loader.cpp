#include "ebpf_loader.h"
#include "bpf_portability.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstring>

// Custom matching key matching ebpf structure
struct process_key {
    uint32_t pid;
    uint64_t start_time;
};

// mirrors kinnector.bpf.c's struct resource_id
// exactly -- the canonical (dev, ino) key for the sensitive/protected-*file*-
// identity maps. See that file's declaration comment for the scoping rationale.
struct resource_id {
    uint64_t dev;
    uint64_t ino;
};

// Every caller of the Add*/Remove* functions below obtains `dev` from
// stat()/fstat()/symlink_metadata() -- glibc's POSIX dev_t encoding (what
// major()/minor() decode). The kernel's own internal dev_t -- what
// kinnector.bpf.c reads via inode->i_sb->s_dev, which is what these maps
// must actually match against at file_open/file_permission time -- uses a
// completely different bit layout ((major << 20) | minor). These are NOT
// numerically interchangeable except when major == 0: empirically on this
// machine, stat()'s raw st_dev for a real filesystem (66306) and the
// kernel-internal encoding for that identical device (271581186) differ
// completely. Left unconverted, every (dev, ino) key registered from
// userspace silently never matches the kernel side, and file_open's
// "category not found -> allow" default (kinnector.bpf.c's sensitive_inodes_map
// lookup) means sensitive-file/protected-static-file/owner-allowlist
// protection is not merely mis-scoped but entirely inert. Convert once, here,
// at every boundary function -- not in each of the many Rust/C++ callers.
static inline uint64_t ToKernelDevEncoding(uint64_t posix_dev) {
    dev_t d = static_cast<dev_t>(posix_dev);
    return (static_cast<uint64_t>(major(d)) << 20) | static_cast<uint64_t>(minor(d));
}

// Resource-swap-defense synchronous-closure follow-up: mirrors
// kinnector.bpf.c's struct path_name_id/path_protection exactly - see that
// file's declaration comment for the full rationale.
struct path_name_id {
    uint64_t parent_dev;
    uint64_t parent_ino;
    uint64_t name_hash;
};

struct path_protection {
    uint32_t category;
    uint64_t owner_mask;
    uint64_t origin_dev;
    uint64_t origin_ino;
};

// Mirrors kinnector.bpf.c's struct owner_link - the exact owner-set
// membership key that replaced the 64-slot mask as the authority on who owns
// a resource. All members are 8 bytes, so there is no padding to leave
// uninitialised here.
struct owner_link {
    uint64_t dev;
    uint64_t ino;
    uint64_t owner_dev; // 0 = wildcard (legacy bare-inode registration)
    uint64_t owner_ino;
};

// Mirrors kinnector.bpf.c's struct exec_origin (chain identity).
// 40 bytes, no padding.
// dir_dev/dir_ino are the origin image's own directory, used by
// OWNER_NO_EXTERNAL_INHERIT. SetExecOrigin below leaves them zero: a chain
// stamped from userspace has no bprm to read a parent dentry from, and the
// kernel treats zero as "unknown" and never drops a chain on it.
struct exec_origin {
    uint64_t dev;
    uint64_t ino;
    uint32_t flags;
    uint32_t uid;
    uint64_t dir_dev;
    uint64_t dir_ino;
};

// FNV-1a, matched byte-for-byte by kinnector.bpf.c's fnv1a_hash_name and
// antitheft-agent's Rust implementation - all three hash exactly the
// basename's bytes with no padding, so as long as none of them hash past
// the string's natural end, the result is identical across all three.
static inline uint64_t Fnv1aHashName(const std::string& name) {
    uint64_t hash = 0xcbf29ce484222325ULL; // FNV-1a 64-bit offset basis
    for (unsigned char c : name) {
        hash ^= c;
        hash *= 0x100000001b3ULL; // FNV-1a 64-bit prime
    }
    return hash;
}

// Mirrors kinnector.bpf.c's fw_key4/fw_key6/fw_value exactly (packed,
// field-for-field) — see that file's Firewall section for the rationale.
struct fw_key4 {
    uint32_t prefixlen;
    uint8_t  addr[4];
} __attribute__((packed));

struct fw_key6 {
    uint32_t prefixlen;
    uint8_t  addr[16];
} __attribute__((packed));

struct fw_value {
    uint32_t rule_id;
    uint16_t port;
    uint8_t  proto;
    uint8_t  direction;
    uint8_t  action;
    uint8_t  _pad[3];
} __attribute__((packed));

namespace kinnector::lnx {

const char* const kWardenPinnedLinkPaths[] = {
    "/sys/fs/bpf/warden/kprobe_tty_write",
    "/sys/fs/bpf/warden/kprobe_tty_read",
    "/sys/fs/bpf/warden/kretprobe_tty_read",
    "/sys/fs/bpf/warden/file_open",
    "/sys/fs/bpf/warden/socket_connect",
    "/sys/fs/bpf/warden/unix_stream_connect",
    "/sys/fs/bpf/warden/socket_listen",
    "/sys/fs/bpf/warden/bprm_creds_for_exec",
    "/sys/fs/bpf/warden/bprm_check_security",
    "/sys/fs/bpf/warden/ptrace_access_check",
    "/sys/fs/bpf/warden/file_mprotect",
    "/sys/fs/bpf/warden/task_kill",
    "/sys/fs/bpf/warden/path_chmod",
    "/sys/fs/bpf/warden/mmap_file",
    "/sys/fs/bpf/warden/tracepoint_sched_process_fork",
    "/sys/fs/bpf/warden/file_permission",
    "/sys/fs/bpf/warden/socket_accept",
    "/sys/fs/bpf/warden/socket_sendmsg",
    "/sys/fs/bpf/warden/inode_unlink",
    "/sys/fs/bpf/warden/inode_create",
    "/sys/fs/bpf/warden/inode_mkdir",
    "/sys/fs/bpf/warden/task_fix_setuid",
    "/sys/fs/bpf/warden/shm_shmat",
    "/sys/fs/bpf/warden/task_fix_setgid",
    "/sys/fs/bpf/warden/capset",
    "/sys/fs/bpf/warden/task_prctl",
    "/sys/fs/bpf/warden/sb_pivotroot",
    "/sys/fs/bpf/warden/bprm_committing_creds",
    "/sys/fs/bpf/warden/sb_mount",
    "/sys/fs/bpf/warden/path_chroot",
    "/sys/fs/bpf/warden/inode_rename",
    "/sys/fs/bpf/warden/inode_symlink",
    "/sys/fs/bpf/warden/inode_link",
    "/sys/fs/bpf/warden/lsm_d_instantiate",
    "/sys/fs/bpf/warden/inode_free_security",
    "/sys/fs/bpf/warden/bpf_syscall_guard",
};
const size_t kWardenPinnedLinkPathsCount = sizeof(kWardenPinnedLinkPaths) / sizeof(kWardenPinnedLinkPaths[0]);

// must match kinnector.bpf.c's
// resource_owner_hash() exactly, bit-for-bit — this is the userspace side of
// resource_owner_map's 64-slot bitmask representation.
static uint32_t ResourceOwnerHash(uint64_t exec_ino) {
    return static_cast<uint32_t>((exec_ino * 2654435761ULL) & 0x3FULL);
}

// A program that fails to ATTACH is not a degraded feature, it is a rule that
// silently does not exist. Every failure path here used to be mute:
// `bpf_program__attach()` returning NULL printed nothing at all, and the only
// "DEGRADED" banner the loader emits covers programs the portability layer
// deliberately declines to LOAD. So a load-clean, attach-failed program left
// the daemon reporting a healthy startup while enforcing nothing.
//
// Measured: a container has its own sysfs with no tracefs, so
// `tracepoint_sys_enter_execve` and `tracepoint_sched_process_fork` could not
// attach. Those two are the only path by which a command-line-gated package
// manager (dnf, pacman, zypper, apk, pip, composer, snap, flatpak - every
// manager the kernel's image map deliberately excludes because it cannot see
// a command line) is ever marked as an install. Supply-chain scoping enforced
// nothing for that entire half of the corpus, with no diagnostic anywhere.
// The same check for the telemetry-only programs, which are attached without
// a bpffs pin on purpose (their links die with the process rather than
// outliving it). They were the mute case that mattered most: the two execve
// tracepoints and the fork tracepoint are what produce ProcessCreate.
static struct bpf_link* AttachUnpinned(struct bpf_object* bpf_obj, const char* prog_name) {
    struct bpf_program* prog = bpf_object__find_program_by_name(bpf_obj, prog_name);
    if (!prog) {
        std::cerr << "[BPF Link] program not present in the object: " << prog_name << std::endl;
        return nullptr;
    }
    struct bpf_link* link = bpf_program__attach(prog);
    if (!link) {
        std::cerr << "[BPF Link] FAILED TO ATTACH " << prog_name << ": " << std::strerror(errno)
                  << " - loaded but never runs; if this is a tracepoint, check that tracefs is mounted "
                     "at /sys/kernel/tracing" << std::endl;
    }
    return link;
}

static struct bpf_link* AttachOrUpdatePinnedLink(struct bpf_object* bpf_obj, const char* prog_name, const char* pin_path) {
    struct bpf_program* prog = bpf_object__find_program_by_name(bpf_obj, prog_name);
    if (!prog) {
        std::cerr << "[BPF Link] program not present in the object: " << prog_name
                  << " - nothing will enforce or report whatever it implements" << std::endl;
        return nullptr;
    }

    struct bpf_link* link = nullptr;
    if (access(pin_path, F_OK) == 0) {
        link = bpf_link__open(pin_path);
        if (link) {
            int ret = bpf_link_update(bpf_link__fd(link), bpf_program__fd(prog), nullptr);
            if (ret == 0) {
                std::cout << "[BPF Link] Successfully updated pinned link in-place: " << pin_path << std::endl;
                return link;
            }
            std::cerr << "[BPF Link] Failed to update pinned link in-place: " << pin_path << ". Re-creating." << std::endl;
            bpf_link__destroy(link);
            unlink(pin_path);
        }
    }

    link = bpf_program__attach(prog);
    if (!link) {
        // errno is what libbpf leaves behind here. ENOENT on a tracepoint
        // almost always means tracefs is not mounted
        // (`mount -t tracefs tracefs /sys/kernel/tracing`), which is the
        // container case; on a kprobe it means the symbol does not exist on
        // this kernel.
        std::cerr << "[BPF Link] FAILED TO ATTACH " << prog_name << ": " << std::strerror(errno)
                  << " - this program is loaded but will never run, so whatever it enforces or "
                     "reports is silently absent" << std::endl;
        return nullptr;
    }
    int ret = bpf_link__pin(link, pin_path);
    if (ret == 0) {
        std::cout << "[BPF Link] Successfully attached and pinned: " << pin_path << std::endl;
    } else {
        // Pinning is a convenience (it survives a daemon restart); the link
        // itself is already live, so this is not an enforcement gap.
        std::cerr << "[BPF Link] attached " << prog_name << " but could not pin it to " << pin_path << ": "
                  << std::strerror(-ret) << " - enforcement is active, it just will not survive a restart"
                  << std::endl;
    }
    return link;
}

EbpfLoader::EbpfLoader() = default;

EbpfLoader::~EbpfLoader() {
    Stop();
}

// Was: open /sys/kernel/security/lsm and substring-match "bpf". That could not
// distinguish "securityfs is not mounted" from "this kernel has no BPF LSM",
// and it never checked that an LSM program can actually be loaded and
// attached - only that the kernel advertised the module. Both gaps now live in
// bpf_portability's four-layer probe (which mounts securityfs itself if it has
// to, and finishes by attaching a real lsm/file_open stub).
bool EbpfLoader::CheckLsmSupport() {
    return kinnector::bpf_portability::Features::HasLsm();
}

bool EbpfLoader::Initialize(const std::string& bpf_obj_path, bool force_fallback) {
    if (initialized_) {
        return false;
    }
    // Variant tiers: a kernel that cannot take large programs gets the small
    // object if one is installed alongside. Resolved once, here, so every
    // later reference (including the reopen path in LoadObjectTolerantly)
    // uses the same file.
    bpf_obj_path_ = kinnector::bpf_portability::SelectObjectPath(bpf_obj_path);
    std::cout << kinnector::bpf_portability::Features::Summary() << std::endl;

    // Check if the eBPF object file exists
    if (access(bpf_obj_path_.c_str(), F_OK) == -1) {
        std::cerr << "eBPF object file not found at: " << bpf_obj_path_ << ". Bypassing to mock mode." << std::endl;
        mock_mode_ = true;
        lsm_active_ = false;
        initialized_ = true;
        return true;
    }

    if (force_fallback) {
        std::cout << "Force fallback mode requested." << std::endl;
        lsm_active_ = false;
    } else {
        lsm_active_ = CheckLsmSupport();
        if (!lsm_active_) {
            std::cout << "BPF LSM not active in kernel. Configuring fallback tracepoint mode." << std::endl;
        }
    }

    initialized_ = true;
    return true;
}

bool EbpfLoader::Start() {
    if (!initialized_ || running_) {
        return false;
    }

    if (mock_mode_) {
        std::cout << "Running in mock telemetry mode (offline/user-space verification)." << std::endl;
        running_ = true;
        return true;
    }

    running_ = true;

    if (lsm_active_) {
        if (!LoadAndAttachLsm()) {
            std::cerr << "Failed to load/attach BPF LSM. Falling back to tracepoint mode." << std::endl;
            lsm_active_ = false;
            if (!LoadAndAttachFallback()) {
                std::cerr << "Fallback tracepoint attachment failed." << std::endl;
                running_ = false;
                return false;
            }
        }
    } else {
        if (!LoadAndAttachFallback()) {
            std::cerr << "Fallback tracepoint attachment failed." << std::endl;
            running_ = false;
            return false;
        }
    }

    // exe_name_class_map is no longer seeded here - it is config-driven now
    // (see AddExeNameClass's doc), populated by the Rust caller after Start()
    // returns, same ordering rule Phase 4's install_binary_map registration
    // already follows (FFI calls need g_running).

    // Set up ring buffer polling loop if the bpf object has been loaded
    if (bpf_obj_) {
        ring_buf_ = ring_buffer__new(bpf_map__fd(bpf_object__find_map_by_name(bpf_obj_, "telemetry_ringbuf")),
                                     HandleRingBufferEvent, this, nullptr);
        if (!ring_buf_) {
            std::cerr << "Failed to initialize telemetry ring buffer." << std::endl;
            Stop();
            return false;
        }

        // Add tty_ringbuf to the same manager (P8-pty)
        struct bpf_map* tty_map = bpf_object__find_map_by_name(bpf_obj_, "tty_ringbuf");
        if (tty_map) {
            int tty_fd = bpf_map__fd(tty_map);
            if (ring_buffer__add(ring_buf_, tty_fd, HandleTtyRingBufferEvent, this) != 0) {
                std::cerr << "Warning: Failed to add tty_ringbuf to ring buffer manager." << std::endl;
            }
        }

        // Attach TTY/PTY hooks with pinning for zero-downtime hot-reloading
        mkdir("/sys/fs/bpf", 0755);
        mkdir("/sys/fs/bpf/warden", 0755);

        kprobe_tty_write_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "kprobe_tty_write", "/sys/fs/bpf/warden/kprobe_tty_write");
        kprobe_tty_read_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "kprobe_tty_read", "/sys/fs/bpf/warden/kprobe_tty_read");
        kretprobe_tty_read_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "kretprobe_tty_read", "/sys/fs/bpf/warden/kretprobe_tty_read");

        ring_buffer_thread_ = std::thread(&EbpfLoader::RingBufferPollLoop, this);
    }

    return true;
}

void EbpfLoader::Stop() {
    running_ = false;
    
    if (ring_buffer_thread_.joinable()) {
        ring_buffer_thread_.join();
    }
    
    if (ring_buf_) {
        ring_buffer__free(ring_buf_);
        ring_buf_ = nullptr;
    }
    
    // For pinned links: disconnect them so they persist in the kernel, then destroy the structure
    auto CleanPinnedLink = [](struct bpf_link*& link) {
        if (link) {
            bpf_link__disconnect(link);
            bpf_link__destroy(link);
            link = nullptr;
        }
    };

    CleanPinnedLink(file_open_link_);
    CleanPinnedLink(socket_connect_link_);
    CleanPinnedLink(unix_stream_connect_link_);
    CleanPinnedLink(socket_listen_link_);
    CleanPinnedLink(exec_link_);
    CleanPinnedLink(bprm_check_security_link_);
    CleanPinnedLink(ptrace_link_);
    CleanPinnedLink(kprobe_tty_write_link_);
    CleanPinnedLink(kprobe_tty_read_link_);
    CleanPinnedLink(kretprobe_tty_read_link_);
    CleanPinnedLink(mprotect_link_);
    CleanPinnedLink(task_kill_link_);
    CleanPinnedLink(path_chmod_link_);
    CleanPinnedLink(mmap_file_link_);
    CleanPinnedLink(fork_link_);
    CleanPinnedLink(task_fix_setgid_link_);
    CleanPinnedLink(capset_link_);
    CleanPinnedLink(task_prctl_link_);
    CleanPinnedLink(sb_pivotroot_link_);
    CleanPinnedLink(bprm_committing_creds_link_);
    CleanPinnedLink(sb_mount_link_);
    CleanPinnedLink(path_chroot_link_);
    CleanPinnedLink(inode_create_link_);
    CleanPinnedLink(inode_mkdir_link_);
    CleanPinnedLink(inode_rename_link_);
    CleanPinnedLink(inode_symlink_link_);
    CleanPinnedLink(inode_link_link_);
    CleanPinnedLink(lsm_d_instantiate_link_);
    CleanPinnedLink(inode_free_security_link_);

    // Fallback tracepoints are not pinned, so we can destroy them normally
    if (tp_exec_link_)         { bpf_link__destroy(tp_exec_link_); tp_exec_link_ = nullptr; }
    if (tp_execat_link_)       { bpf_link__destroy(tp_execat_link_); tp_execat_link_ = nullptr; }
    if (tp_sched_exec_link_)   { bpf_link__destroy(tp_sched_exec_link_); tp_sched_exec_link_ = nullptr; }
    if (tp_connect_link_)      { bpf_link__destroy(tp_connect_link_); tp_connect_link_ = nullptr; }
    if (tp_exit_link_)         { bpf_link__destroy(tp_exit_link_); tp_exit_link_ = nullptr; }
    if (tp_openat_link_)       { bpf_link__destroy(tp_openat_link_); tp_openat_link_ = nullptr; }
    if (tp_mmap_link_)         { bpf_link__destroy(tp_mmap_link_); tp_mmap_link_ = nullptr; }
    if (tp_mprotect_link_)     { bpf_link__destroy(tp_mprotect_link_); tp_mprotect_link_ = nullptr; }
    if (tp_dup2_link_)         { bpf_link__destroy(tp_dup2_link_); tp_dup2_link_ = nullptr; }
    if (tp_dup3_link_)         { bpf_link__destroy(tp_dup3_link_); tp_dup3_link_ = nullptr; }
    if (tp_listen_link_)       { bpf_link__destroy(tp_listen_link_); tp_listen_link_ = nullptr; }
    if (tp_fork_link_)         { bpf_link__destroy(tp_fork_link_); tp_fork_link_ = nullptr; }
    if (tp_setgroups_link_)          { bpf_link__destroy(tp_setgroups_link_); tp_setgroups_link_ = nullptr; }
    if (tp_process_vm_readv_link_)   { bpf_link__destroy(tp_process_vm_readv_link_); tp_process_vm_readv_link_ = nullptr; }
    if (tp_process_vm_writev_link_)  { bpf_link__destroy(tp_process_vm_writev_link_); tp_process_vm_writev_link_ = nullptr; }
    if (tp_clone_link_)              { bpf_link__destroy(tp_clone_link_); tp_clone_link_ = nullptr; }
    if (tp_clone3_link_)             { bpf_link__destroy(tp_clone3_link_); tp_clone3_link_ = nullptr; }
    if (tp_setns_link_)              { bpf_link__destroy(tp_setns_link_); tp_setns_link_ = nullptr; }
    if (tp_unshare_link_)            { bpf_link__destroy(tp_unshare_link_); tp_unshare_link_ = nullptr; }


    file_open_link_      = nullptr;
    socket_connect_link_ = nullptr;
    unix_stream_connect_link_ = nullptr;
    socket_listen_link_  = nullptr;
    exec_link_           = nullptr;
    bprm_check_security_link_ = nullptr;
    ptrace_link_         = nullptr;
    kprobe_tty_write_link_ = nullptr;
    kprobe_tty_read_link_  = nullptr;
    kretprobe_tty_read_link_ = nullptr;
    mprotect_link_       = nullptr;
    task_kill_link_      = nullptr;
    path_chmod_link_     = nullptr;
    mmap_file_link_      = nullptr;
    fork_link_           = nullptr;
    tp_exec_link_        = nullptr;
    tp_execat_link_      = nullptr;
    tp_sched_exec_link_  = nullptr;
    tp_connect_link_     = nullptr;
    tp_exit_link_        = nullptr;
    tp_openat_link_      = nullptr;
    tp_mmap_link_        = nullptr;
    tp_mprotect_link_    = nullptr;
    tp_dup2_link_        = nullptr;
    tp_dup3_link_        = nullptr;
    tp_listen_link_      = nullptr;
    tp_fork_link_        = nullptr;

    if (bpf_obj_) {
        bpf_object__close(bpf_obj_);
        bpf_obj_ = nullptr;
    }

    initialized_ = false;
}

void EbpfLoader::ForceUnpinAllLinks() {
    // Unconditional: unlink every known pin path regardless of whether this
    // process's own bpf_link handle for it is still live. bpf_link__open()
    // re-derives a handle from the pin itself, so this also cleans up a pin
    // left behind by a previous crashed/killed process, not just this one's.
    for (size_t i = 0; i < kWardenPinnedLinkPathsCount; ++i) {
        const char* path = kWardenPinnedLinkPaths[i];
        struct bpf_link* link = bpf_link__open(path);
        if (link) {
            bpf_link__destroy(link);
        }
        unlink(path);
    }
}

static void ApplyRamBasedMapScaling(struct bpf_object* bpf_obj) {
    if (!bpf_obj) return;

    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    uint64_t total_ram_bytes = (uint64_t)pages * (uint64_t)page_size;

    uint32_t auto_max_entries = 65536;
    if (total_ram_bytes < 4ULL * 1024 * 1024 * 1024) {          // < 4 GB
        auto_max_entries = 16384;
    } else if (total_ram_bytes < 8ULL * 1024 * 1024 * 1024) {   // 4 GB - 8 GB
        auto_max_entries = 32768;
    } else if (total_ram_bytes < 16ULL * 1024 * 1024 * 1024) {  // 8 GB - 16 GB
        auto_max_entries = 65536;
    } else if (total_ram_bytes < 24ULL * 1024 * 1024 * 1024) {  // 16 GB - 24 GB
        auto_max_entries = 131072;
    } else if (total_ram_bytes < 32ULL * 1024 * 1024 * 1024) {  // 24 GB - 32 GB
        auto_max_entries = 196608;
    } else if (total_ram_bytes < 48ULL * 1024 * 1024 * 1024) {  // 32 GB - 48 GB
        auto_max_entries = 262144;
    } else if (total_ram_bytes < 64ULL * 1024 * 1024 * 1024) {  // 48 GB - 64 GB
        auto_max_entries = 524288;
    } else {                                                     // >= 64 GB
        auto_max_entries = 1048576;
    }

    const char* maps_to_scale[] = {
        "process_threshold_map",
        "category_flags_map",
        "pending_network_connect",
        "sensitive_inodes_map",
        "trusted_exec_inodes",
        "exec_allowlist_map",
        "tainted_process_map",
        "pid_tree_type_map",
        "db_outbound_allowlist",
        "infra_outbound_allowlist",
        "fw_rules_v4",
        "fw_rules_v6"
    };

    for (const char* map_name : maps_to_scale) {
        struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj, map_name);
        if (map) {
            bpf_map__set_max_entries(map, auto_max_entries);
        }
    }
}

// Pins a map at `pin_path` so its content is inspectable by path (bpftool,
// or a future stat/open-based check) independent of this process holding an
// fd — the anti-tamper precedent this codebase already has for *links*
// (AttachOrUpdatePinnedLink above) never extended to *maps*, so a root user
// could previously empty fw_rules_v4/v6 via bpftool without tripping
// anything (ebpf_health.rs only checks link presence). This doesn't by
// itself detect tampering — see ebpf_health.rs's periodic
// CountFirewallEntries() comparison for that — but it's the prerequisite:
// an unpinned map has no stable path for that check to inspect.
//
// Any stale pin from a previous process is unlinked and replaced rather
// than reused — firewall reconcile (warden/src/firewall/reconcile.rs)
// unconditionally rebuilds desired state from the rule store on every
// wardend startup, so discarding a prior map's contents on restart is
// correct, not a loss.
static bool PinMapReplacing(struct bpf_map* map, const char* pin_path) {
    if (!map) return false;
    if (access(pin_path, F_OK) == 0) {
        unlink(pin_path);
    }
    int ret = bpf_map__pin(map, pin_path);
    if (ret != 0) {
        std::cerr << "[BPF Map] Failed to pin " << pin_path << ": " << std::strerror(-ret) << std::endl;
        return false;
    }
    return true;
}

// Opens the object and applies every pre-load configuration step, in one
// place, so that bpf_portability::LoadTolerantly() can reopen it identically
// after skipping a rejected program. A bpf_object that failed to load cannot
// be loaded a second time, so "reopen" has to mean "redo all of this", and
// having two copies of the configuration would guarantee they drift.
struct ObjOpenCtx {
    std::string path;
    bool lsm_mode;
};

static struct bpf_object* OpenAndConfigureObject(void* user) {
    auto* ctx = static_cast<ObjOpenCtx*>(user);
    struct bpf_object* obj = bpf_object__open_file(ctx->path.c_str(), nullptr);
    if (!obj) return nullptr;

    ApplyRamBasedMapScaling(obj);

    struct bpf_program* prog;
    bpf_object__for_each_program(prog, obj) {
        const char* sec_name = bpf_program__section_name(prog);
        if (sec_name && std::strncmp(sec_name, "lsm/", 4) == 0) {
            if (ctx->lsm_mode) {
                bpf_program__set_type(prog, BPF_PROG_TYPE_LSM);
                bpf_program__set_expected_attach_type(prog, BPF_LSM_MAC);
            } else {
                // Fallback mode: the LSM programs would fail to load anyway.
                bpf_program__set_autoload(prog, false);
            }
        }
    }
    return obj;
}

// Runs the tolerant load and records what it had to skip. Returns false only
// when a Required program was rejected - the case where continuing would mean
// reporting "protected" while enforcing nothing.
bool EbpfLoader::LoadObjectTolerantly(bool lsm_mode) {
    ObjOpenCtx ctx{bpf_obj_path_, lsm_mode};
    bpf_obj_ = OpenAndConfigureObject(&ctx);
    if (!bpf_obj_) return false;

    auto report = kinnector::bpf_portability::LoadTolerantly(
        &bpf_obj_, &OpenAndConfigureObject, &ctx);

    {
        std::lock_guard<std::mutex> lk(skipped_programs_mu_);
        skipped_programs_ = report.skipped;
    }

    if (!report.loaded) {
        // Last resort before giving up: the small tier. Whether a kernel's
        // verifier will accept our heaviest program cannot be probed generically
        // - 5.15 has the 1M instruction limit and still rejects the ~206k-insn
        // execve tracepoints with -E2BIG, while passing the pre-5.2 4096-insn
        // probe that HasLargeProgs() uses. cilium/tetragon solves this with
        // kernel-version thresholds; falling back only after a real failure is
        // better evidence than any version table, which just encodes someone's
        // guess about where the boundary sits.
        const std::string small = kinnector::bpf_portability::SmallTierPath(bpf_obj_path_);
        if (!small.empty() && small != bpf_obj_path_) {
            std::cerr << "[BPF Loader] full tier failed (" << report.fatal_error
                      << "); retrying with the small tier: " << small << std::endl;
            ObjOpenCtx small_ctx{small, lsm_mode};
            bpf_obj_ = OpenAndConfigureObject(&small_ctx);
            if (bpf_obj_) {
                auto small_report = kinnector::bpf_portability::LoadTolerantly(
                    &bpf_obj_, &OpenAndConfigureObject, &small_ctx);
                if (small_report.loaded) {
                    bpf_obj_path_ = small;
                    {
                        std::lock_guard<std::mutex> lk(skipped_programs_mu_);
                        skipped_programs_ = small_report.skipped;
                    }
                    std::cerr << "[BPF Loader] DEGRADED: running the small tier, "
                              << "which trades walk depth and env-scan reach for a "
                              << "program this kernel's verifier will accept"
                              << std::endl;
                    report = small_report;
                } else {
                    std::cerr << "[BPF Loader] small tier also failed: "
                              << small_report.fatal_error << std::endl;
                    bpf_obj_ = nullptr;
                }
            }
        }
    }

    if (!report.loaded) {
        // Last resort: bpf_d_path() is rejected by the verifier in an LSM
        // context on some kernels (confirmed: 5.10.268, "helper call is not
        // allowed in probe"), which fails file_open's (Required) load
        // regardless of program-size tier - the small tier above cannot help,
        // since it still calls the same helper. Same reactive-fallback shape:
        // whether the helper is usable here cannot be probed generically, and
        // trying only after a real failure is stronger evidence than a guess.
        const std::string nodpath = kinnector::bpf_portability::NoDpathTierPath(bpf_obj_path_);
        if (!nodpath.empty() && nodpath != bpf_obj_path_) {
            std::cerr << "[BPF Loader] tier(s) failed (" << report.fatal_error
                      << "); retrying without bpf_d_path(): " << nodpath << std::endl;
            ObjOpenCtx nodpath_ctx{nodpath, lsm_mode};
            bpf_obj_ = OpenAndConfigureObject(&nodpath_ctx);
            if (bpf_obj_) {
                auto nodpath_report = kinnector::bpf_portability::LoadTolerantly(
                    &bpf_obj_, &OpenAndConfigureObject, &nodpath_ctx);
                if (nodpath_report.loaded) {
                    bpf_obj_path_ = nodpath;
                    {
                        std::lock_guard<std::mutex> lk(skipped_programs_mu_);
                        skipped_programs_ = nodpath_report.skipped;
                    }
                    std::cerr << "[BPF Loader] DEGRADED: running the no-dpath tier - "
                              << "telemetry events that would carry a resolved file "
                              << "path carry an empty one instead; no enforcement "
                              << "decision depends on that string" << std::endl;
                    report = nodpath_report;
                } else {
                    std::cerr << "[BPF Loader] no-dpath tier also failed: "
                              << nodpath_report.fatal_error << std::endl;
                    bpf_obj_ = nullptr;
                }
            }
        }
    }

    if (!report.loaded) {
        std::cerr << "[BPF Loader] load failed: " << report.fatal_error << std::endl;
        bpf_obj_ = nullptr;
        return false;
    }
    if (!report.skipped.empty()) {
        // Loud on purpose. Degraded-but-running is the outcome this whole
        // layer exists to produce, but it must never look like a clean start:
        // a silently missing hook is how "the daemon is up" came to mean
        // "nothing is enforced" twice already.
        std::cerr << "[BPF Loader] DEGRADED: loaded without " << report.skipped.size()
                  << " program(s):" << std::endl;
        for (const auto& kv : report.skipped) {
            std::cerr << "[BPF Loader]   - " << kv.first << ": " << kv.second << std::endl;
        }
    }
    return true;
}

std::map<std::string, std::string> EbpfLoader::SkippedPrograms() const {
    std::lock_guard<std::mutex> lk(skipped_programs_mu_);
    return skipped_programs_;
}

bool EbpfLoader::LoadAndAttachLsm() {
    if (!LoadObjectTolerantly(/*lsm_mode=*/true)) {
        return false;
    }

    // Attach LSM hooks with pinning for zero-downtime hot-reloading
    mkdir("/sys/fs/bpf", 0755);
    mkdir("/sys/fs/bpf/warden", 0755);

    // Pin the firewall maps so their content is path-inspectable — see
    // PinMapReplacing's comment for why this is a real anti-tamper gap fix,
    // not routine bookkeeping.
    PinMapReplacing(bpf_object__find_map_by_name(bpf_obj_, "fw_rules_v4"), "/sys/fs/bpf/warden/fw_rules_v4");
    PinMapReplacing(bpf_object__find_map_by_name(bpf_obj_, "fw_rules_v6"), "/sys/fs/bpf/warden/fw_rules_v6");

    file_open_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "file_open", "/sys/fs/bpf/warden/file_open");
    socket_connect_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "socket_connect", "/sys/fs/bpf/warden/socket_connect");
    // audit-only, not in IsFullyAttached()'s
    // critical set on purpose: a failure here loses visibility, not
    // enforcement.
    unix_stream_connect_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "unix_stream_connect", "/sys/fs/bpf/warden/unix_stream_connect");
    socket_listen_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "socket_listen", "/sys/fs/bpf/warden/socket_listen");
    exec_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "bprm_creds_for_exec", "/sys/fs/bpf/warden/bprm_creds_for_exec");
    bprm_check_security_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "bprm_check_security", "/sys/fs/bpf/warden/bprm_check_security");
    ptrace_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "ptrace_access_check", "/sys/fs/bpf/warden/ptrace_access_check");
    mprotect_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "file_mprotect", "/sys/fs/bpf/warden/file_mprotect");
    task_kill_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "task_kill", "/sys/fs/bpf/warden/task_kill");
    path_chmod_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "path_chmod", "/sys/fs/bpf/warden/path_chmod");

    // activate the two LSM-relevant
    // programs that were compiled but never attached. mmap_file is LSM-only
    // (no fallback equivalent — image-load telemetry + W^X enforcement need
    // the LSM hook's synchronous context). tracepoint_sched_process_fork is
    // attached here too (in addition to LoadAndAttachFallback below) because
    // §4's lineage-marker propagation must run regardless of which mode
    // Start() picked for the LSM-gated deny hooks.
    mmap_file_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "mmap_file", "/sys/fs/bpf/warden/mmap_file");
    fork_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "tracepoint_sched_process_fork", "/sys/fs/bpf/warden/tracepoint_sched_process_fork");

    // sched_process_exit is the ONLY site that deletes a per-process entry
    // from any of the twelve maps its handler cleans up - category_flags_map,
    // pending_network_connect, trusted_ancestor_roots, process_threshold_map,
    // tainted_process_map, pid_tree_type_map, jvm_exception_pids,
    // admin_session_pids, protected_owner_pids, revoked_pid_map,
    // pkg_lifecycle_pids and exec_origin_map - and it used to be attached in
    // LoadAndAttachFallback() only. In an LSM deployment, which is the only
    // mode that enforces anything, nothing ever reclaimed an entry, so every
    // one of those maps grew monotonically until it hit max_entries and its
    // feature silently stopped working: no more install-context marks, no
    // more owner protection for a newly started app, no more chain identity.
    // Measured: about 30 minutes of package-manager testing
    // filled pkg_lifecycle_pids (max_entries 4096), after which the agent
    // logged `failed to mark a package-manager process for supply-chain
    // scoping` and an invocation that had been denied 20 minutes earlier was
    // allowed on three consecutive runs.
    //
    // Unpinned, like the execve tracepoint below and for the same reason: it
    // is telemetry plus bookkeeping, not an enforcement hook whose link must
    // outlive the process. Attaching it here also starts delivering
    // EVT_PROCESS_STOP in LSM mode, which the agent's ingestion loop already
    // handles (it is the ProcessStop arm that untracks remote-access tools).
    {
        tp_exit_link_ = AttachUnpinned(bpf_obj_, "tracepoint_sched_process_exit");
    }

    // P2-8: Attach file_permission for FileWrite events
    AttachOrUpdatePinnedLink(bpf_obj_, "file_permission", "/sys/fs/bpf/warden/file_permission");

    // Attach new Dimension 5 telemetry hooks
    AttachOrUpdatePinnedLink(bpf_obj_, "socket_accept", "/sys/fs/bpf/warden/socket_accept");
    AttachOrUpdatePinnedLink(bpf_obj_, "socket_sendmsg", "/sys/fs/bpf/warden/socket_sendmsg");
    AttachOrUpdatePinnedLink(bpf_obj_, "inode_unlink", "/sys/fs/bpf/warden/inode_unlink");
    // Residual-gap close #1: see bpf_syscall_guard's own doc in
    // kinnector_container_lsm_hooks.h. Same "attach call, no dedicated
    // member" shape as inode_unlink just above - this program has no
    // hot-reload continuity to preserve either.
    AttachOrUpdatePinnedLink(bpf_obj_, "bpf_syscall_guard", "/sys/fs/bpf/warden/bpf_syscall_guard");
    // Supply-chain persistence deny. LSM programs are attached
    // by these explicit per-hook calls, NOT by the `lsm/`-prefix loop in
    // Start() - that loop only sets each program's TYPE. A new lsm/ program
    // with no line here loads, verifies, and never runs: exactly what
    // happened to these two, and it was invisible for inode_create (whose
    // O_CREAT case file_open denies anyway) until inode_mkdir - which has no
    // such backstop - let a descendant mkdir a drop-in directory under a
    // persistence dir in a live test.
    inode_create_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "inode_create", "/sys/fs/bpf/warden/inode_create");
    inode_mkdir_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "inode_mkdir", "/sys/fs/bpf/warden/inode_mkdir");
    AttachOrUpdatePinnedLink(bpf_obj_, "task_fix_setuid", "/sys/fs/bpf/warden/task_fix_setuid");
    AttachOrUpdatePinnedLink(bpf_obj_, "shm_shmat", "/sys/fs/bpf/warden/shm_shmat");

    // new LSM hooks, all
    // zero-enforcement (never return non-zero) for a deployment that hasn't
    // opted into Warden's container-restriction feature.
    task_fix_setgid_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "task_fix_setgid", "/sys/fs/bpf/warden/task_fix_setgid");
    capset_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "capset", "/sys/fs/bpf/warden/capset");
    task_prctl_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "task_prctl", "/sys/fs/bpf/warden/task_prctl");
    sb_pivotroot_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "sb_pivotroot", "/sys/fs/bpf/warden/sb_pivotroot");
    bprm_committing_creds_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "bprm_committing_creds", "/sys/fs/bpf/warden/bprm_committing_creds");

    // Antitheft container/namespace tracking fix: sb_mount/path_chroot were
    // written (with working is_container_restricted() deny logic) but never
    // attached anywhere, ever - see ebpf_loader.h's member comment for the
    // full rationale on why attaching them here is safe (is_container_
    // restricted() stays a no-op unless CONFIG_HOST_MNT_NS is explicitly
    // configured, a Warden-only opt-in antitheft deployments won't set).
    // Program names are "warden_sb_mount"/"warden_path_chroot" (the
    // BPF_PROG-generated C function names in kinnector.bpf.c), not
    // "sb_mount"/"path_chroot" - those are the LSM hook/SEC() names, a
    // different namespace bpf_object__find_program_by_name doesn't look up
    // by. The pin paths are unaffected (just filesystem locations chosen to
    // match every other hook's naming convention).
    sb_mount_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "warden_sb_mount", "/sys/fs/bpf/warden/sb_mount");
    path_chroot_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "warden_path_chroot", "/sys/fs/bpf/warden/path_chroot");

    // Owner-swap defense follow-up: activates the previously-dormant
    // EVT_FILE_RENAME/EVT_FILE_CREATE ABI slots (telemetry.h/telemetry.rs
    // had carried these for a long time with no producer). Closes a real
    // gap: a rename(2) over an existing path, or a symlink(2) creating a
    // brand-new one, swaps what a configured owner path resolves to without
    // ever triggering inode_unlink or a fanotify write-notify event.
    inode_rename_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "inode_rename", "/sys/fs/bpf/warden/inode_rename");
    inode_symlink_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "inode_symlink", "/sys/fs/bpf/warden/inode_symlink");

    // Resource-swap-defense follow-up: link(2) (hardlink) into a previously-
    // unlinked resource/owner path was completely unobserved before - same
    // gap class as the rename/symlink hooks just above.
    inode_link_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "inode_link", "/sys/fs/bpf/warden/inode_link");

    // Resource-swap-defense synchronous-closure follow-up: the real fix for
    // the gap inode_symlink/inode_link's own doc comments describe (their
    // destination dentry has no inode yet at their pre-operation hook
    // point) is `lsm_d_instantiate` below - it fires once the new dentry's
    // inode actually exists, for symlink/hardlink creation just as much as
    // a regular file create (confirmed live). Was a
    // kernel-feature-tiered choice between an fexit pair (bpf_get_func_ret,
    // 5.17+) and a kprobe/kretprobe-with-side-map fallback attached here;
    // both are gone now that the LSM hook covers it directly - see
    // apply_post_op_path_closure's own doc comment in
    // kinnector_container_lsm_hooks.h for the full history.

    // Directory-keyed synchronous protection: a brand-new file
    // inside a corpus-flagged "glob root" directory (see glob_owned_dirs_map's
    // own doc) is protected the instant it is created, not up to 60s later
    // via periodic discovery. Was a pair of kprobes on `d_instantiate`/
    // `d_instantiate_new` (see apply_glob_dir_closure's own comment in
    // kinnector_container_lsm_hooks.h for the full history: a `vfs_create()`
    // fexit tried first never fired on tmpfs/ext4's `atomic_open` path, and
    // the kprobe pair that replaced it then failed the same way on kernel
    // 7.2, whose tmpfs create path doesn't call either kprobed symbol).
    // Replaced with a single real LSM hook, `lsm/d_instantiate`
    // (`security_d_instantiate` - every dentry-instantiation path is
    // contractually required to call it, the property both kprobe attempts
    // were hoping for and didn't get), proven to fire on both 6.18 and a
    // real 7.2.5 kernel.
    lsm_d_instantiate_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "lsm_d_instantiate", "/sys/fs/bpf/warden/lsm_d_instantiate");

    // A freed protected inode's number stops being protected, so the next file the filesystem gives
    // that number does not inherit it (see the program's own comment).
    inode_free_security_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "inode_free_security", "/sys/fs/bpf/warden/inode_free_security");

    // the execve tracepoint used to be attached in
    // LoadAndAttachFallback only, so its EnvironmentMarkers event (and now
    // its argv capture) never fired in any LSM deployment. Attached here
    // too, unpinned like the other telemetry tracepoints. The kernel side
    // gates on CONFIG_LSM_ACTIVE + deployment mode so a Warden LSM
    // deployment still gets exactly one ProcessCreate per exec, from
    // bprm_check_security, as before.
    {
        tp_exec_link_ = AttachUnpinned(bpf_obj_, "tracepoint_sys_enter_execve");
        // execveat(2) had no producer at all, so fexecve and
        // every memfd-backed exec were invisible to userspace. Attached in
        // both modes, right next to its execve sibling - a program that is
        // compiled into the object but never attached silently does nothing,
        // which is how sched_process_exit leaked twelve maps (d1b'e1).
        tp_execat_link_ = AttachUnpinned(bpf_obj_, "tracepoint_sys_enter_execveat");
        // an antitheft exec's events are held at the syscall and
        // emitted here once the exec succeeded, with the kernel's verdict for it
        // (see exec_stash_map). Optional: without it the syscall emits, as before.
        tp_sched_exec_link_ = AttachUnpinned(bpf_obj_, "tracepoint_sched_process_exec");
        struct bpf_map* cfg = bpf_object__find_map_by_name(bpf_obj_, "config_map");
        if (cfg) {
            uint32_t lsm_active_idx = 6; // CONFIG_LSM_ACTIVE
            uint32_t one = 1;
            bpf_map_update_elem(bpf_map__fd(cfg), &lsm_active_idx, &one, BPF_ANY);
            if (tp_sched_exec_link_) {
                uint32_t exec_at_success_idx = 13; // CONFIG_EXEC_AT_SUCCESS
                bpf_map_update_elem(bpf_map__fd(cfg), &exec_at_success_idx, &one, BPF_ANY);
            }
        }
        // dup2/dup3 used to be fallback-only, so antitheft's net_stdio never
        // fired on a BPF-LSM kernel. Attached only after CONFIG_LSM_ACTIVE is
        // set: both programs return early in an LSM deployment that is not
        // antitheft, so warden (whose Dup2 heuristic kills) still gets none.
        tp_dup2_link_ = AttachUnpinned(bpf_obj_, "tracepoint_sys_enter_dup2");
        tp_dup3_link_ = AttachUnpinned(bpf_obj_, "tracepoint_sys_enter_dup3");
    }

    // New tracepoints (unpinned, telemetry-only - same discipline as the
    // pre-existing tp_listen_link_, which is ALSO only attached in
    // LoadAndAttachFallback today, not here (dup2/dup3 are attached above,
    // gated to antitheft) - a real,
    // pre-existing gap this plan's own real-kernel test surfaced but does
    // not fix (out of scope: fixing it changes which telemetry fires in
    // every existing real-LSM-mode production deployment, not just this
    // plan's own new events - needs its own dedicated, reviewed pass).
    // sys_enter_process_vm_readv/writev, sys_enter_setgroups, and
    // sys_enter_clone/clone3 are all BRAND NEW tracepoints with no prior
    // attachment history and zero enforcement, so attaching them here has
    // no such risk.
    {
        struct bpf_program* p = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_setgroups");
        if (p) tp_setgroups_link_ = bpf_program__attach(p);
        p = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_process_vm_readv");
        if (p) tp_process_vm_readv_link_ = bpf_program__attach(p);
        p = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_process_vm_writev");
        if (p) tp_process_vm_writev_link_ = bpf_program__attach(p);
        p = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_clone");
        if (p) tp_clone_link_ = bpf_program__attach(p);
        p = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_clone3");
        if (p) tp_clone3_link_ = bpf_program__attach(p);

        // Runtime-revocation plan: a scoped, deliberate exception to the
        // "out of scope" note above, not a reversal of it - sys_enter_mmap
        // is the ONLY source of EVT_MEMORY_MAP for anonymous PROT_EXEC
        // mappings (mmap_file's LSM hook enforces on them via
        // anon_exec_policy() but deliberately emits no telemetry there, to
        // avoid duplicating this event), and that signal is load-bearing
        // for antitheft's runtime-tamper-revocation check - real JIT
        // engines and real shellcode/injection payloads both overwhelmingly
        // use anonymous memory, not file-backed. Zero enforcement risk in
        // the attached program itself (always returns 0/allow, pure
        // telemetry) - the only real effect is more MemoryMap events
        // system-wide, same discipline as the other programs in this block.
        // sys_enter_listen and the rest of that still-dormant family remain
        // untouched, per the note above - this is not a blanket fix for all
        // of them.
        p = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_mmap");
        if (p) tp_mmap_link_ = bpf_program__attach(p);

        // Antitheft container/namespace tracking fix (see ebpf_loader.h's
        // sb_mount_link_ comment): sys_enter_setns/sys_enter_unshare were
        // attached only in LoadAndAttachFallback, never here. Same
        // is_container_restricted() safety argument applies - these
        // tracepoints' own bpf_send_signal(9) path is gated on
        // is_container_process(), a no-op without CONFIG_HOST_MNT_NS set.
        p = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_setns");
        if (p) tp_setns_link_ = bpf_program__attach(p);
        p = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_unshare");
        if (p) tp_unshare_link_ = bpf_program__attach(p);
    }

    // Agent-core tamper resistance: tell the BPF side which
    // (dev,ino) is our own pin directory and which pid loaded us, so
    // inode_unlink (kinnector_container_lsm_hooks.h) can deny anyone else
    // removing a pin from under us. Uses stat(), not the fd AttachOrUpdate-
    // PinnedLink() already opened per-pin, because this is the DIRECTORY's
    // identity, not any one pin's - deliberately done last, after every pin
    // above, so a load that fails partway through never marks a
    // half-populated directory as self-protected. Best-effort: if stat()
    // fails (directory somehow missing despite the mkdir above) this stays
    // zeroed, which core_pin_guard_map's own doc establishes as a safe
    // no-op, not a silent "deny everything".
    {
        struct stat st;
        if (stat("/sys/fs/bpf/warden", &st) == 0) {
            struct bpf_map* guard_map = bpf_object__find_map_by_name(bpf_obj_, "core_pin_guard_map");
            if (guard_map) {
                uint32_t idx = 0;
                // MUST go through ToKernelDevEncoding - see its own comment
                // just above in this file. stat()'s raw st_dev does not
                // numerically match kinnector.bpf.c's make_resource_id(),
                // which reads inode->i_sb->s_dev directly; left unconverted
                // this guard would silently never match and deny nothing.
                struct {
                    struct resource_id dir_id;
                    uint32_t owner_pid;
                } guard = {{ToKernelDevEncoding(static_cast<uint64_t>(st.st_dev)),
                            static_cast<uint64_t>(st.st_ino)},
                           static_cast<uint32_t>(getpid())};
                bpf_map_update_elem(bpf_map__fd(guard_map), &idx, &guard, BPF_ANY);
            }
        }
    }

    // Residual-gap close #2: populate core_self_integrity_map -
    // see its own doc in kinnector_maps.h. stat() (not lstat) on
    // /proc/self/exe follows the symlink to the real binary's (dev,ino);
    // bpf_obj_path_ already reflects whichever tier (full/small/nodpath)
    // LoadObjectTolerantly settled on, so this protects the object actually
    // running, not just the originally-requested path. Best-effort per slot,
    // same reasoning as the pin-guard block above: a stat() failure leaves
    // that slot zeroed, which file_open's check must treat as "matches
    // nothing real", never "deny everything".
    {
        struct bpf_map* self_map = bpf_object__find_map_by_name(bpf_obj_, "core_self_integrity_map");
        if (self_map) {
            int self_map_fd = bpf_map__fd(self_map);
            struct stat st;
            if (stat("/proc/self/exe", &st) == 0) {
                struct resource_id exe_id = {ToKernelDevEncoding(static_cast<uint64_t>(st.st_dev)),
                                              static_cast<uint64_t>(st.st_ino)};
                uint32_t idx0 = 0;
                bpf_map_update_elem(self_map_fd, &idx0, &exe_id, BPF_ANY);
            }
            if (stat(bpf_obj_path_.c_str(), &st) == 0) {
                struct resource_id obj_id = {ToKernelDevEncoding(static_cast<uint64_t>(st.st_dev)),
                                              static_cast<uint64_t>(st.st_ino)};
                uint32_t idx1 = 1;
                bpf_map_update_elem(self_map_fd, &idx1, &obj_id, BPF_ANY);
            }
        }
    }

    // Q-06 fix: validate exec_link_ is attached before reporting success
    return file_open_link_ && socket_connect_link_ && exec_link_ && bprm_check_security_link_;
}

bool EbpfLoader::LoadAndAttachFallback() {
    if (!LoadObjectTolerantly(/*lsm_mode=*/false)) {
        return false;
    }

    // P2-13: Attach all new tracepoint programs for fallback mode
    struct bpf_program* prog =
        bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_execve");
    if (prog) tp_exec_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_execveat");
    if (prog) tp_execat_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_connect");
    if (prog) tp_connect_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sched_process_exit");
    if (prog) tp_exit_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_openat");
    if (prog) tp_openat_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_mmap");
    if (prog) tp_mmap_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_mprotect");
    if (prog) tp_mprotect_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_dup2");
    if (prog) tp_dup2_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_dup3");
    if (prog) tp_dup3_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_listen");
    if (prog) tp_listen_link_ = bpf_program__attach(prog);

    // fork-time lineage propagation must
    // run in fallback mode too, not just when the LSM hooks are active.
    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sched_process_fork");
    if (prog) tp_fork_link_ = bpf_program__attach(prog);

    return tp_exec_link_ != nullptr;

}

// Read one process's pkg_lifecycle_pids value, or -1 when the process is not
// inside an install at all. Exists so the agent's own re-root decision can
// see PKG_LIFECYCLE_RAN_OTHER_CODE, which only the kernel can set: it is
// stamped at exec, and the agent's exec event arrives afterwards. Without
// this the agent would happily re-root a lifecycle script that the kernel
// had already refused to re-root, reopening the `exec` escape from the other
// side.
int EbpfLoader::LookupPkgLifecycle(uint32_t pid, uint64_t start_time) {
    if (mock_mode_ || !bpf_obj_) {
        return -1;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "pkg_lifecycle_pids");
    if (!map) return -1;
    // Zeroed, then assigned: a positional initializer leaves the padding after `pid` as whatever
    // was on the stack, and the hash compares it, so this lookup matched nothing (see
    // UpdateMapEntry). The agent read every process as absent from the map: a
    // package manager's own earlier stamp, and the kernel's RAN_OTHER_CODE taint its re-root
    // check relies on.
    struct process_key key;
    memset(&key, 0, sizeof(key));
    key.pid = pid;
    key.start_time = start_time;
    uint8_t value = 0;
    if (bpf_map_lookup_elem(bpf_map__fd(map), &key, &value) != 0) return -1;
    return static_cast<int>(value);
}

uint64_t EbpfLoader::LookupOwnerStartTime(uint32_t pid) {
    if (mock_mode_ || !bpf_obj_) {
        return 0;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "protected_owner_pids");
    if (!map) return 0;
    int fd = bpf_map__fd(map);
    struct process_key key = {};
    struct process_key next = {};
    // First call takes a NULL "previous key" to start the walk; passing the
    // zeroed key would skip whatever entry legitimately follows it.
    bool have_key = (bpf_map_get_next_key(fd, nullptr, &next) == 0);
    while (have_key) {
        if (next.pid == pid) {
            return next.start_time;
        }
        key = next;
        have_key = (bpf_map_get_next_key(fd, &key, &next) == 0);
    }
    return 0;
}

void EbpfLoader::GetExecTelemetryStats(uint64_t& emitted, uint64_t& dropped) {
    emitted = 0;
    dropped = 0;
    if (mock_mode_ || !bpf_obj_) return;
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "telemetry_stats");
    if (!map) return;
    int fd = bpf_map__fd(map);
    // PER-CPU array: one value per possible CPU, so the read buffer must be
    // sized by libbpf_num_possible_cpus() and not by the online count -
    // undersizing it is a buffer overrun, not a short read.
    int ncpu = libbpf_num_possible_cpus();
    if (ncpu <= 0) return;
    std::vector<uint64_t> values(static_cast<size_t>(ncpu), 0);
    for (uint32_t idx = 0; idx < 2; ++idx) {
        if (bpf_map_lookup_elem(fd, &idx, values.data()) != 0) continue;
        uint64_t sum = 0;
        for (int cpu = 0; cpu < ncpu; ++cpu) sum += values[static_cast<size_t>(cpu)];
        if (idx == 0) emitted = sum; else dropped = sum;
    }
}

// Drives the iter/task program. An iterator produces nothing until its fd is
// read, so the read loop below IS the walk - the program runs once per task
// as the kernel streams it. The program writes into task_start_times and
// emits no seq output, so the reads return 0 bytes and simply terminate.
//
// Attached and torn down per call rather than kept live: this runs at daemon
// startup (and any later re-registration pass), the map it fills is a
// snapshot by nature, and a permanently attached iterator would be one more
// link to leak on shutdown for no benefit.
int EbpfLoader::RefreshTaskStartTimes() {
    if (mock_mode_ || !bpf_obj_) return -1;
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_program* prog = bpf_object__find_program_by_name(bpf_obj_, "iter_task_start_times");
    if (!prog) return -1;
    struct bpf_link* link = bpf_program__attach_iter(prog, nullptr);
    if (!link) return -1;
    int iter_fd = bpf_iter_create(bpf_link__fd(link));
    if (iter_fd < 0) {
        bpf_link__destroy(link);
        return -1;
    }
    char buf[4096];
    ssize_t n;
    while ((n = read(iter_fd, buf, sizeof(buf))) > 0) {
        // No seq output is emitted; the read is only here to drive the walk.
    }
    bool read_ok = (n == 0);
    close(iter_fd);
    bpf_link__destroy(link);
    if (!read_ok) return -1;

    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "task_start_times");
    if (!map) return -1;
    int fd = bpf_map__fd(map);
    int count = 0;
    uint32_t key = 0, next = 0;
    bool have_key = (bpf_map_get_next_key(fd, nullptr, &next) == 0);
    while (have_key) {
        count++;
        key = next;
        have_key = (bpf_map_get_next_key(fd, &key, &next) == 0);
    }
    return count;
}

uint64_t EbpfLoader::GetTaskStartTime(uint32_t pid) {
    if (mock_mode_ || !bpf_obj_) return 0;
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "task_start_times");
    if (!map) return 0;
    uint64_t value = 0;
    if (bpf_map_lookup_elem(bpf_map__fd(map), &pid, &value) != 0) return 0;
    return value;
}

bool EbpfLoader::UpdateMapEntry(BpfMapType map_type, uint32_t pid, uint64_t start_time, uint32_t value) {
    // Validate map_type before the mock-mode short-circuit below -- an invalid
    // enum value is a caller bug regardless of mode, but mock_mode_'s old
    // early `return true` skipped this switch entirely, silently treating
    // garbage map_type values as success in mock mode.
    const char* map_name = nullptr;
    switch (map_type) {
        case BpfMapType::CategoryFlags: map_name = "category_flags_map"; break;
        case BpfMapType::PendingNetwork: map_name = "pending_network_connect"; break;
        case BpfMapType::TrustedRoots: map_name = "trusted_ancestor_roots"; break;
        case BpfMapType::TaintedProcess: map_name = "tainted_process_map"; break;
        case BpfMapType::ProcessThreshold: map_name = "process_threshold_map"; break;
        case BpfMapType::PidTreeType: map_name = "pid_tree_type_map"; break;
        case BpfMapType::JvmExceptionPids: map_name = "jvm_exception_pids"; break;
        case BpfMapType::DbOutboundAllowlist: map_name = "db_outbound_allowlist"; break;
        case BpfMapType::InfraOutboundAllowlist: map_name = "infra_outbound_allowlist"; break;
        case BpfMapType::ExecAllowlistMap: map_name = "exec_allowlist_map"; break;
        case BpfMapType::AdminSessionPids: map_name = "admin_session_pids"; break;
        case BpfMapType::TrustedAdminBinaries: map_name = "trusted_admin_binaries"; break;
        case BpfMapType::InstallBinaryMap: map_name = "install_binary_map"; break;
        case BpfMapType::ProtectedOwnerBinaries: map_name = "protected_owner_binaries"; break;
        case BpfMapType::ProtectedOwnerPids: map_name = "protected_owner_pids"; break;
        case BpfMapType::RevokedPidMap: map_name = "revoked_pid_map"; break;
        case BpfMapType::PkgLifecyclePids: map_name = "pkg_lifecycle_pids"; break;
        default: return false;
    }

    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, map_name);
    if (!map) return false;

    int fd = bpf_map__fd(map);

    // For maps that key on pid (uint32_t) rather than process_key
    if (map_type == BpfMapType::JvmExceptionPids || map_type == BpfMapType::AdminSessionPids) {
        uint8_t val8 = static_cast<uint8_t>(value);
        return bpf_map_update_elem(fd, &pid, &val8, BPF_ANY) == 0;
    } else if (map_type == BpfMapType::DbOutboundAllowlist || map_type == BpfMapType::InfraOutboundAllowlist) {
        struct {
            uint32_t pid;
            uint32_t ip;
        } __attribute__((packed)) key = { pid, static_cast<uint32_t>(start_time) };
        uint8_t val8 = static_cast<uint8_t>(value);
        return bpf_map_update_elem(fd, &key, &val8, BPF_ANY) == 0;
    } else if (map_type == BpfMapType::ExecAllowlistMap || map_type == BpfMapType::TrustedAdminBinaries ||
               map_type == BpfMapType::InstallBinaryMap || map_type == BpfMapType::ProtectedOwnerBinaries) {
        uint64_t key = start_time;
        uint8_t val8 = static_cast<uint8_t>(value);
        return bpf_map_update_elem(fd, &key, &val8, BPF_ANY) == 0;
    }

    // Zero first, then field-assign - same discipline as kinnector.bpf.c's
    // get_current_process_key() and its own doc comment on tracee_key: a
    // positional {a, b} initializer is not guaranteed to zero the 4-byte
    // alignment gap between `pid` (4 bytes) and the 8-byte-aligned
    // `start_time`, and BPF hash-map keys compare the full byte-for-byte
    // struct including that padding. Garbage padding here made a
    // userspace-populated process_key never match the kernel's own
    // zero-padded lookups - a real, previously-undiscovered instance of the
    // exact same bug class already fixed once for tracee_key in this
    // codebase, found while live-testing revoked_pid_map (its only
    // population path goes through this exact function).
    struct process_key key = {0};
    key.pid = pid;
    key.start_time = start_time;

    // For TrustedRoots/ProtectedOwnerPids, map holds uint8_t, others hold uint32_t
    if (map_type == BpfMapType::TrustedRoots || map_type == BpfMapType::ProtectedOwnerPids || map_type == BpfMapType::PkgLifecyclePids) {
        uint8_t val8 = static_cast<uint8_t>(value);
        return bpf_map_update_elem(fd, &key, &val8, BPF_ANY) == 0;
    } else {
        return bpf_map_update_elem(fd, &key, &value, BPF_ANY) == 0;
    }
}

bool EbpfLoader::DeleteMapEntry(BpfMapType map_type, uint32_t pid, uint64_t start_time) {
    // See the identical fix/comment in UpdateMapEntry -- validate map_type
    // before the mock-mode short-circuit, not after.
    const char* map_name = nullptr;
    switch (map_type) {
        case BpfMapType::CategoryFlags: map_name = "category_flags_map"; break;
        case BpfMapType::PendingNetwork: map_name = "pending_network_connect"; break;
        case BpfMapType::TrustedRoots: map_name = "trusted_ancestor_roots"; break;
        case BpfMapType::TaintedProcess: map_name = "tainted_process_map"; break;
        case BpfMapType::ProcessThreshold: map_name = "process_threshold_map"; break;
        case BpfMapType::PidTreeType: map_name = "pid_tree_type_map"; break;
        case BpfMapType::JvmExceptionPids: map_name = "jvm_exception_pids"; break;
        case BpfMapType::DbOutboundAllowlist: map_name = "db_outbound_allowlist"; break;
        case BpfMapType::InfraOutboundAllowlist: map_name = "infra_outbound_allowlist"; break;
        case BpfMapType::ExecAllowlistMap: map_name = "exec_allowlist_map"; break;
        case BpfMapType::AdminSessionPids: map_name = "admin_session_pids"; break;
        case BpfMapType::TrustedAdminBinaries: map_name = "trusted_admin_binaries"; break;
        case BpfMapType::InstallBinaryMap: map_name = "install_binary_map"; break;
        case BpfMapType::ProtectedOwnerBinaries: map_name = "protected_owner_binaries"; break;
        case BpfMapType::ProtectedOwnerPids: map_name = "protected_owner_pids"; break;
        case BpfMapType::RevokedPidMap: map_name = "revoked_pid_map"; break;
        case BpfMapType::PkgLifecyclePids: map_name = "pkg_lifecycle_pids"; break;
        default: return false;
    }

    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, map_name);
    if (!map) return false;

    int fd = bpf_map__fd(map);
    if (map_type == BpfMapType::JvmExceptionPids || map_type == BpfMapType::AdminSessionPids) {
        return bpf_map_delete_elem(fd, &pid) == 0;
    } else if (map_type == BpfMapType::DbOutboundAllowlist || map_type == BpfMapType::InfraOutboundAllowlist) {
        struct {
            uint32_t pid;
            uint32_t ip;
        } __attribute__((packed)) key = { pid, static_cast<uint32_t>(start_time) };
        return bpf_map_delete_elem(fd, &key) == 0;
    } else if (map_type == BpfMapType::ExecAllowlistMap || map_type == BpfMapType::TrustedAdminBinaries ||
               map_type == BpfMapType::InstallBinaryMap || map_type == BpfMapType::ProtectedOwnerBinaries) {
        uint64_t key = start_time;
        return bpf_map_delete_elem(fd, &key) == 0;
    } else {
        // See UpdateMapEntry's identical comment above - same zero-then-assign fix.
        struct process_key key = {0};
        key.pid = pid;
        key.start_time = start_time;
        return bpf_map_delete_elem(fd, &key) == 0;
    }
}

bool EbpfLoader::AddSensitiveInode(uint64_t dev, uint64_t inode, uint32_t category) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "sensitive_inodes_map");
    if (!map) return false;

    struct resource_id key = { ToKernelDevEncoding(dev), inode };
    uint32_t existing = 0;
    if (bpf_map_lookup_elem(bpf_map__fd(map), &key, &existing) != 0) {
        DiscardPreviousLifeLocked(key, /*sensitive_absent=*/true);
    }
    return bpf_map_update_elem(bpf_map__fd(map), &key, &category, BPF_ANY) == 0;
}

bool EbpfLoader::AddSecretBrokerSocket(uint64_t dev, uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "secret_broker_sockets_map");
    if (!map) return false;

    struct resource_id key = { ToKernelDevEncoding(dev), inode };
    uint8_t val = 1;
    return bpf_map_update_elem(bpf_map__fd(map), &key, &val, BPF_ANY) == 0;
}

bool EbpfLoader::AddProtectedStaticInode(uint64_t dev, uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "protected_static_inodes");
    if (!map) return false;

    struct resource_id key = { ToKernelDevEncoding(dev), inode };
    uint8_t val = 1;
    return bpf_map_update_elem(bpf_map__fd(map), &key, &val, BPF_ANY) == 0;
}

bool EbpfLoader::RemoveProtectedStaticInode(uint64_t dev, uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "protected_static_inodes");
    if (!map) return false;

    struct resource_id key = { ToKernelDevEncoding(dev), inode };
    return bpf_map_delete_elem(bpf_map__fd(map), &key) == 0;
}

bool EbpfLoader::AddTrustedExecInode(uint64_t inode, uint32_t trust_level) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "trusted_exec_inodes");
    if (!map) return false;

    return bpf_map_update_elem(bpf_map__fd(map), &inode, &trust_level, BPF_ANY) == 0;
}

bool EbpfLoader::LookupTrustedExecInode(uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        // In mock mode, treat everything as trusted to avoid false positives
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "trusted_exec_inodes");
    if (!map) return false;

    uint32_t trust_level = 0;
    return bpf_map_lookup_elem(bpf_map__fd(map), &inode, &trust_level) == 0;
}


// Registers one name in exe_name_class_map (EXE_CLASS_* bits from
// kinnector_maps.h). Used to be a hardcoded kEntries[] table populated
// automatically from Start() - the list is config-driven now
// (protect-community/configs/warden/exec_control_lists.json via
// kinnector-config); see this method's header doc for the caller's
// obligation to set CONFIG_EXE_CLASSES_READY once done.
bool EbpfLoader::AddExeNameClass(const char* name, uint32_t classes) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    if (!name) return false;

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "exe_name_class_map");
    if (!map) return false;

    // The key is the same 32-byte buffer shape the BPF side reads into,
    // zero-padded, so a name and its key are byte-identical. A name that
    // does not fit is a programming error rather than a silent truncation
    // that would match the wrong thing.
    struct { char name[32]; } key{};
    const size_t len = std::strlen(name);
    if (len >= sizeof(key.name)) {
        std::cerr << "exe_name_class_map: name too long, skipped: " << name << std::endl;
        return false;
    }
    std::memcpy(key.name, name, len);
    if (bpf_map_update_elem(bpf_map__fd(map), &key, &classes, BPF_ANY) != 0) {
        std::cerr << "exe_name_class_map: failed to add " << name << std::endl;
        return false;
    }
    return true;
}

bool EbpfLoader::AddUntrustedDirName(const char* name) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    if (!name) return false;

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "untrusted_dir_names_map");
    if (!map) return false;

    struct { char name[32]; } key{};
    const size_t len = std::strlen(name);
    if (len >= sizeof(key.name)) {
        std::cerr << "untrusted_dir_names_map: name too long, skipped: " << name << std::endl;
        return false;
    }
    std::memcpy(key.name, name, len);
    uint8_t marker = 1;
    if (bpf_map_update_elem(bpf_map__fd(map), &key, &marker, BPF_ANY) != 0) {
        std::cerr << "untrusted_dir_names_map: failed to add " << name << std::endl;
        return false;
    }
    return true;
}

bool EbpfLoader::SetConfigValue(uint32_t index, uint32_t value) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "config_map");
    if (!map) return false;

    return bpf_map_update_elem(bpf_map__fd(map), &index, &value, BPF_ANY) == 0;
}

bool EbpfLoader::SelfIntegrityIdentityTestOnly(uint32_t slot, uint64_t& kernel_dev, uint64_t& inode) {
    if (mock_mode_ || !bpf_obj_) return false;
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "core_self_integrity_map");
    if (!map) return false;
    struct resource_id id = {0, 0};
    if (bpf_map_lookup_elem(bpf_map__fd(map), &slot, &id) != 0) return false;
    kernel_dev = id.dev;
    inode = id.ino;
    return true;
}

bool EbpfLoader::SetSelfIntegrityIdentityTestOnly(uint32_t slot, uint64_t dev, uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) return false;
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "core_self_integrity_map");
    if (!map) return false;
    struct resource_id id = {dev ? ToKernelDevEncoding(dev) : 0, inode};
    return bpf_map_update_elem(bpf_map__fd(map), &slot, &id, BPF_ANY) == 0;
}

bool EbpfLoader::AddBypassedDirectoryInode(uint64_t dev, uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "bypassed_directories");
    if (!map) return false;

    struct resource_id key = { ToKernelDevEncoding(dev), inode };
    uint8_t val = 1;
    return bpf_map_update_elem(bpf_map__fd(map), &key, &val, BPF_ANY) == 0;
}

bool EbpfLoader::RemoveBypassedDirectoryInode(uint64_t dev, uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "bypassed_directories");
    if (!map) return false;

    struct resource_id key = { ToKernelDevEncoding(dev), inode };
    return bpf_map_delete_elem(bpf_map__fd(map), &key) == 0;
}

// --- Exact resource-owner set -------------------------------------------
//
// kinnector.bpf.c's resource_owner_map folds an owner's executable inode
// into a 6-bit slot, which means one binary in 64 is accepted as any given
// owner - reachable on purpose, not just by luck, since an attacker can stat
// the owner binary and then create files until one of their own lands in the
// same slot. The mask survives as a cheap negative pre-filter; membership is
// now decided by resource_owner_exact, and these three helpers are the only
// writers.
//
// The loader keeps its own copy of each resource's owner set because a BPF
// program cannot enumerate a map, so "forget every owner of this resource"
// (ResetResourceOwnerToSingle, the fail-closed path used when a swap is held
// for review) has no in-kernel expression. Guarded by map_mutex_, which every
// caller already holds.

bool EbpfLoader::WriteExactOwnerLocked(const struct resource_id& key, uint64_t owner_dev, uint64_t owner_exec_inode, bool present, bool mark_known) {
    struct bpf_map* exact = bpf_object__find_map_by_name(bpf_obj_, "resource_owner_exact");
    struct bpf_map* known = bpf_object__find_map_by_name(bpf_obj_, "resource_exact_known");
    if (!exact || !known) return false;

    struct owner_link link = {};
    link.dev = key.dev;
    link.ino = key.ino;
    link.owner_dev = owner_dev;
    link.owner_ino = owner_exec_inode;

    auto& owners = resource_owners_[{key.dev, key.ino}];
    if (present) {
        uint8_t one = 1;
        if (bpf_map_update_elem(bpf_map__fd(exact), &link, &one, BPF_ANY) != 0) return false;
        owners.insert({owner_dev, owner_exec_inode});
    } else {
        bpf_map_delete_elem(bpf_map__fd(exact), &link); // absent is success
        owners.erase({owner_dev, owner_exec_inode});
    }

    if (!mark_known) return true;

    // Mark the set authoritative even when it just became empty: "no owner
    // may open this" is a real, intended state (that is what holding a
    // swapped identity for review means), and must not read as "no exact
    // information, fall back to the mask".
    uint8_t one = 1;
    return bpf_map_update_elem(bpf_map__fd(known), &key, &one, BPF_ANY) == 0;
}

void EbpfLoader::ClearExactOwnersLocked(const struct resource_id& key) {
    struct bpf_map* exact = bpf_object__find_map_by_name(bpf_obj_, "resource_owner_exact");
    if (!exact) return;
    auto it = resource_owners_.find({key.dev, key.ino});
    if (it == resource_owners_.end()) return;
    for (const auto& owner : it->second) {
        struct owner_link link = {};
        link.dev = key.dev;
        link.ino = key.ino;
        link.owner_dev = owner.first;
        link.owner_ino = owner.second;
        bpf_map_delete_elem(bpf_map__fd(exact), &link);
    }
    it->second.clear();
}

// The kernel stops protecting an inode number once its file is freed (inode_free_security) and a
// swap onto such a number drops its authoritative flag (apply_resource_protection); the owner set
// is left in resource_owner_exact on purpose, for the files still aliased to it. So an owner set
// recorded here for a key the kernel no longer protects (`sensitive_absent`), or no longer marks
// authoritative, belonged to a file that is gone. Registering the new file on top of it would hand
// the old file's owners (another app's, or only the daemon for a retired identity) to the new one.
void EbpfLoader::DiscardPreviousLifeLocked(const struct resource_id& key, bool sensitive_absent) {
    auto it = resource_owners_.find({key.dev, key.ino});
    if (it == resource_owners_.end() || it->second.empty()) return;
    struct bpf_map* known = bpf_object__find_map_by_name(bpf_obj_, "resource_exact_known");
    if (!known) return;
    uint8_t flag = 0;
    const bool is_known = bpf_map_lookup_elem(bpf_map__fd(known), &key, &flag) == 0;
    if (!sensitive_absent && is_known) return;
    ClearExactOwnersLocked(key);
    bpf_map_delete_elem(bpf_map__fd(known), &key);
    if (sensitive_absent) {
        if (struct bpf_map* mask = bpf_object__find_map_by_name(bpf_obj_, "resource_owner_map")) {
            bpf_map_delete_elem(bpf_map__fd(mask), &key);
        }
    }
}

bool EbpfLoader::OtherOwnerSharesSlotLocked(const struct resource_id& key, uint64_t owner_dev, uint64_t owner_exec_inode) {
    auto it = resource_owners_.find({key.dev, key.ino});
    if (it == resource_owners_.end()) return false;
    const uint32_t slot = ResourceOwnerHash(owner_exec_inode);
    for (const auto& other : it->second) {
        if (other == std::make_pair(owner_dev, owner_exec_inode)) continue;
        if (ResourceOwnerHash(other.second) == slot) return true;
    }
    return false;
}

// Chain identity (B1): the three owner-set operations, keyed on the
// composite (kernel-encoded owner_dev, owner_ino). owner_dev 0 is the legacy
// wildcard the bare-inode entry points below pass through.
bool EbpfLoader::AddResourceOwnerLocked(const struct resource_id& key, uint64_t owner_dev, uint64_t owner_exec_inode) {
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "resource_owner_map");
    if (!map) return false;
    DiscardPreviousLifeLocked(key, /*sensitive_absent=*/false);

    int fd = bpf_map__fd(map);
    uint64_t bit = 1ULL << ResourceOwnerHash(owner_exec_inode);
    uint64_t existing_mask = 0;
    bpf_map_lookup_elem(fd, &key, &existing_mask); // 0 on miss — fine, OR still correct
    uint64_t new_mask = existing_mask | bit;
    if (bpf_map_update_elem(fd, &key, &new_mask, BPF_ANY) != 0) return false;
    return WriteExactOwnerLocked(key, owner_dev, owner_exec_inode, /*present=*/true);
}

bool EbpfLoader::ResetResourceOwnerToSingleLocked(const struct resource_id& key, uint64_t owner_dev, uint64_t owner_exec_inode) {
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "resource_owner_map");
    if (!map) return false;

    int fd = bpf_map__fd(map);
    uint64_t bit = 1ULL << ResourceOwnerHash(owner_exec_inode);
    if (bpf_map_update_elem(fd, &key, &bit, BPF_ANY) != 0) return false;
    // Reset means "this one owner and nobody else", so the exact set has to
    // be emptied too - otherwise a previously registered owner would keep
    // reading a resource that has just been locked down. BPF programs cannot
    // enumerate a map, which is why the loader keeps the authoritative set.
    ClearExactOwnersLocked(key);
    return WriteExactOwnerLocked(key, owner_dev, owner_exec_inode, /*present=*/true);
}

bool EbpfLoader::RemoveResourceOwnerLocked(const struct resource_id& key, uint64_t owner_dev, uint64_t owner_exec_inode) {
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "resource_owner_map");
    if (!map) return false;

    int fd = bpf_map__fd(map);
    uint64_t existing_mask = 0;
    if (bpf_map_lookup_elem(fd, &key, &existing_mask) != 0) {
        return true; // Nothing to remove.
    }
    uint64_t bit = 1ULL << ResourceOwnerHash(owner_exec_inode);
    // The mask bit can only be cleared if no OTHER remaining owner hashes to
    // the same slot; clearing it blindly would make the pre-filter reject a
    // legitimate owner that is still registered.
    uint64_t new_mask = existing_mask;
    if (!OtherOwnerSharesSlotLocked(key, owner_dev, owner_exec_inode)) {
        new_mask &= ~bit;
    }
    if (bpf_map_update_elem(fd, &key, &new_mask, BPF_ANY) != 0) return false;
    return WriteExactOwnerLocked(key, owner_dev, owner_exec_inode, /*present=*/false);
}

bool EbpfLoader::AddResourceOwnerExact(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_dev, uint64_t owner_exec_inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct resource_id key = { ToKernelDevEncoding(resource_dev), resource_inode };
    return AddResourceOwnerLocked(key, owner_dev ? ToKernelDevEncoding(owner_dev) : 0, owner_exec_inode);
}

bool EbpfLoader::AddResourceOwnersExactBatch(uint64_t resource_dev, uint64_t resource_inode, const std::vector<std::pair<uint64_t, uint64_t>>& owners) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    if (owners.empty()) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct resource_id key = { ToKernelDevEncoding(resource_dev), resource_inode };
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "resource_owner_map");
    if (!map) return false;
    DiscardPreviousLifeLocked(key, /*sensitive_absent=*/false);

    // The mask is only a pre-filter (a clear bit is conclusive), so every
    // owner's bit goes in before any exact entry: an owner must never be
    // rejected by the pre-filter while its exact entry is already there.
    int fd = bpf_map__fd(map);
    uint64_t mask = 0;
    bpf_map_lookup_elem(fd, &key, &mask); // 0 on miss - fine, OR still correct
    for (const auto& owner : owners) {
        mask |= 1ULL << ResourceOwnerHash(owner.second);
    }
    if (bpf_map_update_elem(fd, &key, &mask, BPF_ANY) != 0) return false;

    // Only the last write marks the set authoritative. If one fails the set
    // stays non-authoritative, so the kernel keeps following the alias to the
    // complete set (or the mask-only fallback) rather than a partial one.
    for (size_t i = 0; i < owners.size(); ++i) {
        const auto& owner = owners[i];
        const uint64_t owner_dev = owner.first ? ToKernelDevEncoding(owner.first) : 0;
        if (!WriteExactOwnerLocked(key, owner_dev, owner.second, /*present=*/true, /*mark_known=*/i + 1 == owners.size())) return false;
    }
    return true;
}

bool EbpfLoader::ResetResourceOwnerToSingleExact(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_dev, uint64_t owner_exec_inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct resource_id key = { ToKernelDevEncoding(resource_dev), resource_inode };
    return ResetResourceOwnerToSingleLocked(key, owner_dev ? ToKernelDevEncoding(owner_dev) : 0, owner_exec_inode);
}

bool EbpfLoader::RemoveResourceOwnerExact(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_dev, uint64_t owner_exec_inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct resource_id key = { ToKernelDevEncoding(resource_dev), resource_inode };
    return RemoveResourceOwnerLocked(key, owner_dev ? ToKernelDevEncoding(owner_dev) : 0, owner_exec_inode);
}

bool EbpfLoader::AddOwnerImage(uint64_t dev, uint64_t inode, uint32_t flags) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "owner_images");
    if (!map) return false;
    struct resource_id key = { ToKernelDevEncoding(dev), inode };
    return bpf_map_update_elem(bpf_map__fd(map), &key, &flags, BPF_ANY) == 0;
}

bool EbpfLoader::RemoveOwnerImage(uint64_t dev, uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "owner_images");
    if (!map) return false;
    struct resource_id key = { ToKernelDevEncoding(dev), inode };
    bpf_map_delete_elem(bpf_map__fd(map), &key); // absent is success
    return true;
}

bool EbpfLoader::AddCredentialHelperImage(uint64_t dev, uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "credential_helper_images");
    if (!map) return false;
    struct resource_id key = { ToKernelDevEncoding(dev), inode };
    uint8_t val = 1;
    return bpf_map_update_elem(bpf_map__fd(map), &key, &val, BPF_ANY) == 0;
}

bool EbpfLoader::RemoveCredentialHelperImage(uint64_t dev, uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "credential_helper_images");
    if (!map) return false;
    struct resource_id key = { ToKernelDevEncoding(dev), inode };
    bpf_map_delete_elem(bpf_map__fd(map), &key); // absent is success
    return true;
}

bool EbpfLoader::AddModifiedLibrary(uint64_t dev, uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "modified_system_libraries");
    if (!map) return false;
    struct resource_id key = { ToKernelDevEncoding(dev), inode };
    uint8_t val = 1;
    return bpf_map_update_elem(bpf_map__fd(map), &key, &val, BPF_ANY) == 0;
}

bool EbpfLoader::RemoveModifiedLibrary(uint64_t dev, uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "modified_system_libraries");
    if (!map) return false;
    struct resource_id key = { ToKernelDevEncoding(dev), inode };
    bpf_map_delete_elem(bpf_map__fd(map), &key); // absent is success
    return true;
}

bool EbpfLoader::ClearModifiedLibraries() {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "modified_system_libraries");
    if (!map) return false;
    int fd = bpf_map__fd(map);
    // Collect first, delete second: deleting the key a get_next_key walk is
    // standing on restarts the walk, which is fine for a small map but not
    // something to reason about while it is being mutated.
    std::vector<struct resource_id> keys;
    struct resource_id next = {};
    bool have_key = (bpf_map_get_next_key(fd, nullptr, &next) == 0);
    while (have_key) {
        keys.push_back(next);
        struct resource_id cur = next;
        have_key = (bpf_map_get_next_key(fd, &cur, &next) == 0);
    }
    bool ok = true;
    for (const auto& key : keys) {
        if (bpf_map_delete_elem(fd, &key) != 0 && errno != ENOENT) ok = false;
    }
    return ok;
}

bool EbpfLoader::SetExecOrigin(uint32_t pid, uint64_t start_time, uint64_t dev, uint64_t inode, uint32_t flags, uint32_t uid) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "exec_origin_map");
    if (!map) return false;
    // Zero first, then field-assign - see UpdateMapEntry's padding note.
    struct process_key key = {0};
    key.pid = pid;
    key.start_time = start_time;
    struct exec_origin origin = {};
    origin.dev = ToKernelDevEncoding(dev);
    origin.ino = inode;
    origin.flags = flags;
    origin.uid = uid;
    return bpf_map_update_elem(bpf_map__fd(map), &key, &origin, BPF_ANY) == 0;
}

bool EbpfLoader::AddResourceOwner(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct resource_id key = { ToKernelDevEncoding(resource_dev), resource_inode };
    return AddResourceOwnerLocked(key, /*owner_dev=*/0, owner_exec_inode);
}

// Resource-swap-defense fail-closed follow-up: `AddResourceOwner` above is
// deliberately OR-only (read-modify-write onto whatever mask is already
// there) everywhere else it's used - correct for incrementally registering
// more legitimate owners. It is WRONG for this one caller
// (`deny_all_for_new_resource_identity` in ownership.rs): once the new
// synchronous carry-forward (`lsm_d_instantiate`'s `apply_post_op_path_closure`
// call, `inode_rename`'s in-kernel copy) has already set a swapped identity's mask
// to the OLD owner's bits (closing the race window - a real, separate,
// deliberate feature), an OR-based "deny everyone" call can only ever ADD
// the daemon's own bit on top - it can never CLEAR the old owner's
// already-set bit. Found live: a held/untrusted swap ended up still
// allowing the real owner, silently defeating the fail-closed guarantee
// this function exists for. This is a genuine hard RESET, not an add -
// exactly one bit (the daemon's own), nothing else survives.
bool EbpfLoader::ResetResourceOwnerToSingle(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct resource_id key = { ToKernelDevEncoding(resource_dev), resource_inode };
    return ResetResourceOwnerToSingleLocked(key, /*owner_dev=*/0, owner_exec_inode);
}

bool EbpfLoader::RemoveResourceOwner(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct resource_id key = { ToKernelDevEncoding(resource_dev), resource_inode };
    return RemoveResourceOwnerLocked(key, /*owner_dev=*/0, owner_exec_inode);
}

// Storage-dir write/mmap protection: the same mask + exact-
// membership write pattern AddResourceOwnerLocked/RemoveResourceOwnerLocked
// use, against protected_dir_map/protected_dir_owner_exact and the separate
// dir_owners_ cache instead - see this class's header declaration for why
// these stay separate from the resource-owner maps. No "exact_known"
// counterpart: dir_owner_verdict() in the BPF program never consults one
// (directories aren't yet subject to rename/hardlink swap-defense).
bool EbpfLoader::AddDirOwner(uint64_t dir_dev, uint64_t dir_inode, uint64_t owner_dev, uint64_t owner_exec_inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* mask_map = bpf_object__find_map_by_name(bpf_obj_, "protected_dir_map");
    struct bpf_map* exact_map = bpf_object__find_map_by_name(bpf_obj_, "protected_dir_owner_exact");
    if (!mask_map || !exact_map) return false;

    struct resource_id key = { ToKernelDevEncoding(dir_dev), dir_inode };
    uint64_t kernel_owner_dev = owner_dev ? ToKernelDevEncoding(owner_dev) : 0;

    int mask_fd = bpf_map__fd(mask_map);
    uint64_t bit = 1ULL << ResourceOwnerHash(owner_exec_inode);
    uint64_t existing_mask = 0;
    bpf_map_lookup_elem(mask_fd, &key, &existing_mask); // 0 on miss - fine, OR still correct
    uint64_t new_mask = existing_mask | bit;
    if (bpf_map_update_elem(mask_fd, &key, &new_mask, BPF_ANY) != 0) return false;

    struct owner_link link = {};
    link.dev = key.dev;
    link.ino = key.ino;
    link.owner_dev = kernel_owner_dev;
    link.owner_ino = owner_exec_inode;
    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(exact_map), &link, &one, BPF_ANY) != 0) return false;

    dir_owners_[{key.dev, key.ino}].insert({kernel_owner_dev, owner_exec_inode});
    return true;
}

bool EbpfLoader::RemoveDirOwner(uint64_t dir_dev, uint64_t dir_inode, uint64_t owner_dev, uint64_t owner_exec_inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* mask_map = bpf_object__find_map_by_name(bpf_obj_, "protected_dir_map");
    struct bpf_map* exact_map = bpf_object__find_map_by_name(bpf_obj_, "protected_dir_owner_exact");
    if (!mask_map || !exact_map) return false;

    struct resource_id key = { ToKernelDevEncoding(dir_dev), dir_inode };
    uint64_t kernel_owner_dev = owner_dev ? ToKernelDevEncoding(owner_dev) : 0;

    struct owner_link link = {};
    link.dev = key.dev;
    link.ino = key.ino;
    link.owner_dev = kernel_owner_dev;
    link.owner_ino = owner_exec_inode;
    bpf_map_delete_elem(bpf_map__fd(exact_map), &link); // absent is success

    auto it = dir_owners_.find({key.dev, key.ino});
    if (it != dir_owners_.end()) {
        it->second.erase({kernel_owner_dev, owner_exec_inode});

        if (it->second.empty()) {
            // No owners left at all - this dir is no longer a registered
            // storage dir, full stop. Delete the mask entry outright rather
            // than leaving a stale zero-value one behind: dir_owner_verdict()
            // treats ANY present protected_dir_map entry as "this IS a
            // registered storage dir" regardless of its mask value (that's
            // what distinguishes its -1 "not registered, keep walking"
            // return from its 0 "registered, but not an owner - deny"
            // return) - so a lingering mask=0 entry would deny every future
            // write into this directory forever, including the original
            // owner's own, instead of correctly falling through to "not
            // registered" the way an always-unregistered dir would. Found
            // live: reproduced by a full register -> approve -> revoke ->
            // re-approve cycle in test_unmanaged_owner_protection.rs, which
            // is exactly this shape (the last/only owner being removed).
            bpf_map_delete_elem(bpf_map__fd(mask_map), &key);
            dir_owners_.erase(it);
        } else {
            // The mask bit can only be cleared if no OTHER remaining owner
            // hashes to the same slot - same collision-safety reasoning as
            // RemoveResourceOwnerLocked/OtherOwnerSharesSlotLocked.
            const uint32_t slot = ResourceOwnerHash(owner_exec_inode);
            bool other_shares_slot = false;
            for (const auto& other : it->second) {
                if (ResourceOwnerHash(other.second) == slot) { other_shares_slot = true; break; }
            }
            if (!other_shares_slot) {
                int mask_fd = bpf_map__fd(mask_map);
                uint64_t existing_mask = 0;
                if (bpf_map_lookup_elem(mask_fd, &key, &existing_mask) == 0) {
                    uint64_t bit = 1ULL << slot;
                    uint64_t new_mask = existing_mask & ~bit;
                    bpf_map_update_elem(mask_fd, &key, &new_mask, BPF_ANY);
                }
            }
        }
    }
    return true;
}

bool EbpfLoader::AddPersistenceDir(uint64_t dev, uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "persistence_dirs_map");
    if (!map) return false;
    struct resource_id key = { ToKernelDevEncoding(dev), inode };
    uint8_t one = 1;
    return bpf_map_update_elem(bpf_map__fd(map), &key, &one, BPF_ANY) == 0;
}

bool EbpfLoader::AddPersistenceName(uint64_t parent_dev, uint64_t parent_inode, const std::string& name) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    if (name.empty()) {
        return false;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "persistence_names_map");
    if (!map) return false;
    struct path_name_id key = { ToKernelDevEncoding(parent_dev), parent_inode, Fnv1aHashName(name) };
    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(map), &key, &one, BPF_ANY) != 0) return false;
    // The parent is marked as a directory holding a registered name (value 2), so
    // is_persistence_target hashes a name only there. BPF_NOEXIST keeps a drop dir's 1.
    struct bpf_map* dirs = bpf_object__find_map_by_name(bpf_obj_, "persistence_dirs_map");
    if (!dirs) return false;
    struct resource_id dir_key = { ToKernelDevEncoding(parent_dev), parent_inode };
    uint8_t two = 2;
    int rc = bpf_map_update_elem(bpf_map__fd(dirs), &dir_key, &two, BPF_NOEXIST);
    return rc == 0 || errno == EEXIST;
}

bool EbpfLoader::AddPackageManagerImage(uint64_t dev, uint64_t inode, uint32_t flags) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "pkg_manager_images");
    if (!map) return false;
    struct resource_id key = { ToKernelDevEncoding(dev), inode };
    // kinnector.bpf.c's pkg_lifecycle value layout: depth 1 in the low bits,
    // PKG_LIFECYCLE_DISTRO (0x80) when the corpus says this manager's
    // scripts legitimately manage persistence. Only that flag is taken from
    // `flags`; the depth is always the root's.
    uint8_t value = static_cast<uint8_t>(1 | (flags & 0x80));
    return bpf_map_update_elem(bpf_map__fd(map), &key, &value, BPF_ANY) == 0;
}

bool EbpfLoader::RemovePackageManagerImage(uint64_t dev, uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "pkg_manager_images");
    if (!map) return false;
    struct resource_id key = { ToKernelDevEncoding(dev), inode };
    bpf_map_delete_elem(bpf_map__fd(map), &key); // absent is success
    return true;
}

bool EbpfLoader::AddProtectedPathName(uint64_t parent_dev, uint64_t parent_inode, const std::string& name, uint32_t category, uint64_t owner_mask,
                                      uint64_t origin_dev, uint64_t origin_inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    if (name.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "protected_path_names_map");
    if (!map) return false;

    struct path_name_id key = { ToKernelDevEncoding(parent_dev), parent_inode, Fnv1aHashName(name) };
    struct path_protection value = {};
    value.category = category;
    value.owner_mask = owner_mask;
    value.origin_dev = ToKernelDevEncoding(origin_dev);
    value.origin_ino = origin_inode;
    return bpf_map_update_elem(bpf_map__fd(map), &key, &value, BPF_ANY) == 0;
}

// Directory-keyed synchronous protection - see
// glob_owned_dirs_map's own declaration comment. Keyed on the directory's
// own identity, not a (parent, name) pair like AddProtectedPathName - the
// whole point is to cover a name that hasn't been chosen yet.
bool EbpfLoader::AddGlobOwnedDir(uint64_t dir_dev, uint64_t dir_inode, uint32_t category, uint64_t owner_mask,
                                  uint64_t origin_dev, uint64_t origin_inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "glob_owned_dirs_map");
    if (!map) return false;

    struct resource_id key = { ToKernelDevEncoding(dir_dev), dir_inode };
    struct path_protection value = {};
    value.category = category;
    value.owner_mask = owner_mask;
    value.origin_dev = ToKernelDevEncoding(origin_dev);
    value.origin_ino = origin_inode;
    return bpf_map_update_elem(bpf_map__fd(map), &key, &value, BPF_ANY) == 0;
}

uint64_t EbpfLoader::GetResourceOwnerMask(uint64_t resource_dev, uint64_t resource_inode) {
    if (mock_mode_ || !bpf_obj_) {
        return 0;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "resource_owner_map");
    if (!map) return 0;

    struct resource_id key = { ToKernelDevEncoding(resource_dev), resource_inode };
    uint64_t mask = 0;
    bpf_map_lookup_elem(bpf_map__fd(map), &key, &mask); // 0 on miss - fine, "no owners yet" is a valid answer
    return mask;
}

bool EbpfLoader::AddFirewallCidr(bool is_v6, const uint8_t* addr, uint32_t prefixlen,
                                  uint32_t rule_id, uint16_t port, uint8_t proto,
                                  uint8_t direction, uint8_t action) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    if (!addr) return false;

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct fw_value value = {};
    value.rule_id = rule_id;
    value.port = port;
    value.proto = proto;
    value.direction = direction;
    value.action = action;

    if (is_v6) {
        struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "fw_rules_v6");
        if (!map) return false;
        struct fw_key6 key = {};
        key.prefixlen = prefixlen;
        std::memcpy(key.addr, addr, 16);
        return bpf_map_update_elem(bpf_map__fd(map), &key, &value, BPF_ANY) == 0;
    } else {
        struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "fw_rules_v4");
        if (!map) return false;
        struct fw_key4 key = {};
        key.prefixlen = prefixlen;
        std::memcpy(key.addr, addr, 4);
        return bpf_map_update_elem(bpf_map__fd(map), &key, &value, BPF_ANY) == 0;
    }
}

bool EbpfLoader::RemoveFirewallCidr(bool is_v6, const uint8_t* addr, uint32_t prefixlen) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }
    if (!addr) return false;

    std::lock_guard<std::mutex> lock(map_mutex_);
    if (is_v6) {
        struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "fw_rules_v6");
        if (!map) return false;
        struct fw_key6 key = {};
        key.prefixlen = prefixlen;
        std::memcpy(key.addr, addr, 16);
        return bpf_map_delete_elem(bpf_map__fd(map), &key) == 0;
    } else {
        struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "fw_rules_v4");
        if (!map) return false;
        struct fw_key4 key = {};
        key.prefixlen = prefixlen;
        std::memcpy(key.addr, addr, 4);
        return bpf_map_delete_elem(bpf_map__fd(map), &key) == 0;
    }
}

int64_t EbpfLoader::CountFirewallEntries() {
    if (mock_mode_ || !bpf_obj_) {
        return -1;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    int64_t total = 0;

    struct bpf_map* map_v4 = bpf_object__find_map_by_name(bpf_obj_, "fw_rules_v4");
    if (!map_v4) return -1;
    int fd_v4 = bpf_map__fd(map_v4);
    struct fw_key4 key4 = {}, next_key4 = {};
    bool has_key4 = false;
    while (bpf_map_get_next_key(fd_v4, has_key4 ? &key4 : nullptr, &next_key4) == 0) {
        total++;
        key4 = next_key4;
        has_key4 = true;
    }

    struct bpf_map* map_v6 = bpf_object__find_map_by_name(bpf_obj_, "fw_rules_v6");
    if (!map_v6) return -1;
    int fd_v6 = bpf_map__fd(map_v6);
    struct fw_key6 key6 = {}, next_key6 = {};
    bool has_key6 = false;
    while (bpf_map_get_next_key(fd_v6, has_key6 ? &key6 : nullptr, &next_key6) == 0) {
        total++;
        key6 = next_key6;
        has_key6 = true;
    }

    return total;
}


void EbpfLoader::SetTtyEventCallback(TtyEventCallback cb) {
    tty_event_callback_ = cb;
}

void EbpfLoader::SetEventCallback(EventCallback cb) {
    event_callback_ = cb;
}

void EbpfLoader::RingBufferPollLoop() {
    while (running_) {
        int err = ring_buffer__poll(ring_buf_, 100);
        if (err < 0 && err != -EINTR) {
            std::cerr << "Error polling eBPF ring buffer" << std::endl;
            break;
        }
    }
}

int EbpfLoader::HandleRingBufferEvent(void *ctx, void *data, size_t data_sz) {
    auto* loader = static_cast<EbpfLoader*>(ctx);
    if (loader->event_callback_ && data && data_sz == sizeof(TelemetryEvent)) {
        loader->event_callback_(*static_cast<TelemetryEvent*>(data));
    }
    return 0;
}

int EbpfLoader::HandleTtyRingBufferEvent(void *ctx, void *data, size_t data_sz) {
    auto* loader = static_cast<EbpfLoader*>(ctx);
    if (loader->tty_event_callback_ && data && data_sz == sizeof(TtyEvent)) {
        loader->tty_event_callback_(*static_cast<TtyEvent*>(data));
    }
    return 0;
}

} // namespace kinnector::lnx
