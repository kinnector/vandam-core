#define _GNU_SOURCE
#include "fanotify.h"
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <chrono>

namespace kinnector::lnx {

FanotifyMonitor::FanotifyMonitor() = default;

FanotifyMonitor::~FanotifyMonitor() {
    Stop();
}

bool FanotifyMonitor::Initialize(const std::string& mount_path, bool enable_blocking) {
    if (initialized_) {
        return false;
    }

    mount_path_ = mount_path;

    // , post-incident revision: FAN_CLASS_CONTENT
    // (permission-event-capable) is only ever attempted when the caller
    // explicitly opts in via enable_blocking=true -- see this method's
    // declaration comment in fanotify.h for why. Marking a real mount
    // (especially "/") with FAN_MARK_MOUNT + FAN_OPEN_PERM makes every open()
    // by every process on that mount block on this object's one monitor
    // thread; this took the whole dev machine down the first time it actually
    // ran, because it had only ever run non-root before (fanotify_init(
    // FAN_CLASS_CONTENT) silently requires CAP_SYS_ADMIN, so this path was
    // previously untested, not merely untaken). Default is notify-only
    // (FAN_CLASS_NOTIF), matching this class's pre-Phase-8 behavior.
    if (enable_blocking) {
        fanotify_fd_ = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, O_RDWR | O_LARGEFILE);
        if (fanotify_fd_ >= 0) {
            permission_capable_ = true;
        } else {
            std::cerr << "[Fanotify] FAN_CLASS_CONTENT unavailable (" << std::strerror(errno)
                      << "), falling back to notify-only mode." << std::endl;
            fanotify_fd_ = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, O_RDONLY | O_LARGEFILE);
            permission_capable_ = false;
        }
    } else {
        fanotify_fd_ = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, O_RDONLY | O_LARGEFILE);
        permission_capable_ = false;
    }
    if (fanotify_fd_ < 0) {
        std::cerr << "[Fanotify] Failed to initialize fanotify: " << std::strerror(errno) << std::endl;
        return false;
    }

    // Mark the mount point to monitor file modification and write completion.
    // Deliberately notify-only (FAN_MODIFY | FAN_CLOSE_WRITE), never
    // FAN_OPEN_PERM -- this mount-wide mark must never carry a permission bit,
    // since that would block every open() on the mount by every process. When
    // permission_capable_, FAN_OPEN_PERM is added per-path only, via
    // AddProtectedResource() below, so blocking is scoped to resources this
    // object was actually asked to protect.
    size_t extra_marks = 0;
    {
        std::lock_guard<std::mutex> lock(marks_mutex_);
        if (!MarkMountLocked(mount_path_)) {
            std::cerr << "[Fanotify] Failed to add fanotify mark on " << mount_path_
                      << ": " << std::strerror(errno) << std::endl;
            close(fanotify_fd_);
            fanotify_fd_ = -1;
            return false;
        }
        // every other real filesystem
        // mount too, so a separate /home or a data partition gets the same
        // write-notify coverage as the root mount.
        extra_marks = MarkAllRealMountsLocked();
    }

    initialized_ = true;
    std::cout << "[Fanotify] File Integrity Monitor initialized on mount: " << mount_path_
              << " (+" << extra_marks << " other real mounts)"
              << (permission_capable_ ? " (permission-capable; FAN_OPEN_PERM available per-path via AddProtectedResource)" : " (notify-only)")
              << std::endl;
    return true;
}

bool FanotifyMonitor::MarkMountLocked(const std::string& mount_point) {
    if (marked_mounts_.count(mount_point) > 0) {
        return true;
    }
    uint64_t mask = FAN_MODIFY | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD;
    int ret = fanotify_mark(fanotify_fd_, FAN_MARK_ADD | FAN_MARK_MOUNT, mask, AT_FDCWD, mount_point.c_str());
    if (ret < 0) {
        return false;
    }
    marked_mounts_.insert(mount_point);
    return true;
}

namespace {
// Filesystem types where a notify-only mount mark buys nothing: kernel
// pseudo filesystems, read-only images (snaps, Flatpak runtimes, AppImage
// squashfs mounts), and desktop FUSE portals whose backing files live on a
// real mount that is already marked.
bool IsPseudoOrImageFs(const std::string& fstype) {
    static const char* const kSkip[] = {
        "proc", "sysfs", "devtmpfs", "devpts", "mqueue", "debugfs", "tracefs", "securityfs",
        "pstore", "bpf", "configfs", "hugetlbfs", "fusectl", "binfmt_misc", "autofs", "nsfs",
        "efivarfs", "rpc_pipefs", "cgroup", "cgroup2", "squashfs", "iso9660", "erofs",
        "fuse.portal", "fuse.gvfsd-fuse", "fuse.appimagelauncherfs", "selinuxfs", "ramfs",
        // tmpfs (/run, /dev/shm, per-user runtime dirs) never hosts an owner
        // binary or a registered secret and churns constantly; the monitor
        // loop's path filter would drop every event anyway. vfat is the EFI
        // system partition on a desktop.
        "tmpfs", "vfat",
        // Container image/layer filesystems. A FAN_MARK_MOUNT holds a
        // vfsmount reference, so marking one of these makes the runtime's
        // own unmount fail with EBUSY - see kContainerRuntimeMountPrefixes
        // below for the incident this comes from. Container rootfs is also
        // out of product scope: nothing we protect lives there.
        "overlay", "overlay2", "fuse-overlayfs",
    };
    for (const char* s : kSkip) {
        if (fstype == s) return true;
    }
    return false;
}

// Mount points a container runtime creates and destroys constantly while
// pulling or running images. Marking any of them pins the mount and breaks
// the runtime; none of them can host a resource this monitor protects.
const char* const kContainerRuntimeMountPrefixes[] = {
    "/var/lib/containerd/",
    "/run/containerd/",
    "/var/lib/docker/",
    "/run/docker/",
    "/var/lib/containers/",
    "/run/containers/",
    "/var/lib/podman/",
    "/run/user/",
};

// /proc/self/mountinfo escapes spaces in paths as "\040".
std::string UnescapeMountPath(const std::string& raw) {
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); ++i) {
        if (raw[i] == '\\' && i + 3 < raw.size() && raw[i + 1] == '0' && raw[i + 2] == '4' && raw[i + 3] == '0') {
            out.push_back(' ');
            i += 3;
        } else {
            out.push_back(raw[i]);
        }
    }
    return out;
}
} // namespace

size_t FanotifyMonitor::MarkAllRealMountsLocked() {
    FILE* f = std::fopen("/proc/self/mountinfo", "r");
    if (!f) {
        return 0;
    }
    size_t added = 0;
    char line[4096];
    while (std::fgets(line, sizeof(line), f)) {
        // Fields: id parent major:minor root mount_point options [optional...] - fstype source superopts
        std::string s(line);
        size_t sep = s.find(" - ");
        if (sep == std::string::npos) continue;
        std::string before = s.substr(0, sep);
        std::string after = s.substr(sep + 3);
        // mount point is the 5th whitespace-separated field of `before`
        size_t pos = 0;
        std::string mount_point;
        for (int field = 0; field < 5; ++field) {
            size_t next = before.find(' ', pos);
            std::string tok = before.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
            if (field == 4) mount_point = tok;
            if (next == std::string::npos) break;
            pos = next + 1;
        }
        size_t sp = after.find(' ');
        std::string fstype = after.substr(0, sp);
        if (mount_point.empty() || IsPseudoOrImageFs(fstype)) continue;
        mount_point = UnescapeMountPath(mount_point);
        if (mount_point == mount_path_) continue;
        // Skip mounts under the private-tmp/pivot probe locations and other
        // ephemeral test mounts - they come and go and nothing protected
        // lives there.
        if (mount_point.rfind("/tmp/", 0) == 0) continue;
        // Container runtime scratch. A container runtime bind-mounts each
        // image layer somewhere under these while extracting it, then
        // unmounts it. A FAN_MARK_MOUNT pins the vfsmount, so our mark made
        // that unmount fail with EBUSY and broke the extract - i.e. every
        // multi-layer `docker pull` on the host failed with "failed to
        // unmount /var/lib/containerd/tmpmounts/containerd-mount...: device
        // or resource busy". It is self-sustaining, because the mount we
        // pinned can never go away to drop the mark. Confirmed by matching
        // the leaked mount ids against the mnt_id entries in the daemon's
        // own /proc/<pid>/fdinfo for the fanotify fd.
        bool container_scratch = false;
        for (const char* prefix : kContainerRuntimeMountPrefixes) {
            if (mount_point.rfind(prefix, 0) == 0) { container_scratch = true; break; }
        }
        if (container_scratch) continue;
        if (marked_mounts_.count(mount_point) > 0) continue;
        if (MarkMountLocked(mount_point)) {
            ++added;
        }
    }
    std::fclose(f);
    return added;
}

size_t FanotifyMonitor::RescanMounts() {
    if (fanotify_fd_ < 0) {
        return 0;
    }
    std::lock_guard<std::mutex> lock(marks_mutex_);
    return MarkAllRealMountsLocked();
}

bool FanotifyMonitor::AddProtectedResource(const std::string& path, uint64_t dev, uint64_t ino) {
    std::lock_guard<std::mutex> lock(protected_resources_mutex_);
    protected_resources_.insert(ResourceId{dev, ino});
    if (!permission_capable_) {
        return true; // Tracked for future use; nothing to mark without a permission-capable group.
    }
    if (path.empty()) {
        std::cerr << "[Fanotify] AddProtectedResource: no path given, cannot establish a live "
                     "FAN_OPEN_PERM mark for (dev=" << dev << ", ino=" << ino << ") -- tracked "
                     "in-memory only." << std::endl;
        return true;
    }
    // Per-path mark, deliberately NOT FAN_MARK_MOUNT -- only this specific
    // path's opens block, not the whole mount. See this method's declaration
    // comment in fanotify.h.
    int ret = fanotify_mark(fanotify_fd_, FAN_MARK_ADD, FAN_OPEN_PERM, AT_FDCWD, path.c_str());
    if (ret < 0) {
        std::cerr << "[Fanotify] Failed to add FAN_OPEN_PERM mark on " << path
                  << ": " << std::strerror(errno) << std::endl;
        return false;
    }
    return true;
}

bool FanotifyMonitor::RemoveProtectedResource(const std::string& path, uint64_t dev, uint64_t ino) {
    std::lock_guard<std::mutex> lock(protected_resources_mutex_);
    protected_resources_.erase(ResourceId{dev, ino});
    if (permission_capable_ && !path.empty()) {
        fanotify_mark(fanotify_fd_, FAN_MARK_REMOVE, FAN_OPEN_PERM, AT_FDCWD, path.c_str());
    }
    return true;
}

bool FanotifyMonitor::IsProtectedResource(uint64_t dev, uint64_t ino) {
    std::lock_guard<std::mutex> lock(protected_resources_mutex_);
    return protected_resources_.count(ResourceId{dev, ino}) > 0;
}

bool FanotifyMonitor::Start() {
    if (!initialized_ || running_) {
        return false;
    }

    running_ = true;
    monitor_thread_ = std::thread(&FanotifyMonitor::MonitorLoop, this);
    std::cout << "[Fanotify] File Integrity Monitor thread started." << std::endl;
    return true;
}

void FanotifyMonitor::Stop() {
    if (!running_) {
        return;
    }

    running_ = false;

    if (fanotify_fd_ != -1) {
        // Closing the fd will unblock any blocking read() in the monitor loop
        close(fanotify_fd_);
        fanotify_fd_ = -1;
    }

    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }

    initialized_ = false;
    std::cout << "[Fanotify] File Integrity Monitor stopped." << std::endl;
}

void FanotifyMonitor::SetEventCallback(EventCallback cb) {
    event_callback_ = cb;
}

void FanotifyMonitor::MonitorLoop() {
    alignas(struct fanotify_event_metadata) char buf[8192];
    static uint64_t seq = 0;

    while (running_) {
        ssize_t len = read(fanotify_fd_, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR) {
                continue;
            }
            // If the socket was closed, break the loop
            if (errno == EBADF || !running_) {
                break;
            }
            std::cerr << "[Fanotify] Error reading fanotify event: " << std::strerror(errno) << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        auto* metadata = reinterpret_cast<struct fanotify_event_metadata*>(buf);
        while (FAN_EVENT_OK(metadata, len)) {
            if (metadata->metadata_len < FAN_EVENT_METADATA_LEN) {
                break;
            }

            if (metadata->fd >= 0) {
                // permission event -- must
                // write an allow/deny response before this fd is closed, or
                // the waiting process's open() hangs. Handled separately from
                // the notify-only telemetry path below; deliberately skips
                // telemetry for this event (the FAN_MODIFY/FAN_CLOSE_WRITE
                // path already covers write telemetry).
                if (metadata->mask & FAN_OPEN_PERM) {
                    struct stat st{};
                    uint32_t decision = FAN_ALLOW;
                    if (fstat(metadata->fd, &st) == 0 &&
                        IsProtectedResource(static_cast<uint64_t>(st.st_dev), static_cast<uint64_t>(st.st_ino))) {
                        decision = FAN_DENY;
                    }
                    struct fanotify_response resp{};
                    resp.fd = metadata->fd;
                    resp.response = decision;
                    ssize_t wret = write(fanotify_fd_, &resp, sizeof(resp));
                    if (wret != sizeof(resp)) {
                        std::cerr << "[Fanotify] Failed to write permission response: "
                                  << std::strerror(errno) << std::endl;
                    }
                    close(metadata->fd);
                    metadata = FAN_EVENT_NEXT(metadata, len);
                    continue;
                }

                // Resolve path using /proc/self/fd/
                char path[PATH_MAX];
                char proc_path[64];
                std::snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", metadata->fd);
                ssize_t path_len = readlink(proc_path, path, sizeof(path) - 1);
                
                if (path_len > 0) {
                    path[path_len] = '\0';
                    
                    std::string path_str(path);

                    // Filter out noisy paths to prevent feedback loops and system noise
                    bool should_filter = path_str.empty() ||
                                         path_str.find(mount_path_) != 0 ||
                                         path_str.find("/proc/") == 0 ||
                                         path_str.find("/sys/") == 0 ||
                                         path_str.find("/dev/") == 0 ||
                                         path_str.find("/run/") != std::string::npos ||
                                         path_str.find("/var/run/") != std::string::npos ||
                                         path_str.find("/var/log/") != std::string::npos ||
                                         path_str.find("/tmp/") == 0 ||
                                         path_str.find(".gemini") != std::string::npos ||
                                         path_str.find("kinnector.bpf.o") != std::string::npos;

                    if (!should_filter && event_callback_) {
                        TelemetryEvent event{};
                        event.header.sequence_number = ++seq;
                        event.header.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()
                        ).count();
                        event.header.pid = metadata->pid;
                        event.header.event_type = EventType::FileWrite;
                        event.header.source = TelemetrySource::fanotify;

                        std::strncpy(event.details.file_write.file_path, path, sizeof(event.details.file_write.file_path) - 1);
                        event.details.file_write.bytes_written = 0; // Close write event

                        event_callback_(event);
                    }
                }

                close(metadata->fd);
            }

            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}

} // namespace kinnector::lnx
