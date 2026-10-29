#include "platform.h"
#include "kinnector/ffi.h"
#include "kinnector/ipc.h"

#include <chrono>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "linux/ebpf_loader.h"
#include "linux/fanotify.h"
#include "linux/cloud_collectors.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <atomic>

class LinuxTtyTelemetrySender {
public:
    LinuxTtyTelemetrySender() = default;
    ~LinuxTtyTelemetrySender() { Stop(); }

    bool Start(const std::string& path) {
        if (running_) return false;
        socket_path_ = path;
        running_ = true;
        connection_thread_ = std::thread(&LinuxTtyTelemetrySender::ConnectionLoop, this);
        return true;
    }

    void Stop() {
        running_ = false;
        connected_ = false;
        int fd = socket_fd_.exchange(-1);
        if (fd != -1) close(fd);
        if (connection_thread_.joinable()) connection_thread_.join();
    }

    bool SendTtyEvent(const kinnector::lnx::EbpfLoader::TtyEvent& event) {
        if (!connected_) return false;
        std::lock_guard<std::mutex> lock(send_mutex_);
        int fd = socket_fd_.load();
        if (fd == -1) return false;
        ssize_t written = write(fd, &event, sizeof(event));
        if (written != sizeof(event)) {
            connected_ = false;
            close(fd);
            socket_fd_ = -1;
            return false;
        }
        return true;
    }

private:
    void ConnectionLoop() {
        while (running_) {
            if (connected_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            int fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (fd < 0) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
            struct sockaddr_un addr;
            std::memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);
            if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                close(fd);
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
            socket_fd_ = fd;
            connected_ = true;
        }
    }

    std::string socket_path_;
    std::atomic<bool> running_{false};
    std::atomic<bool> connected_{false};
    std::atomic<int> socket_fd_{-1};
    std::thread connection_thread_;
    std::mutex send_mutex_;
};

static LinuxTtyTelemetrySender g_tty_sender;

#include <memory>
#include <mutex>
#include <set>
#include <iostream>

static std::unique_ptr<kinnector::ipc::ITelemetrySender> g_sender = nullptr;
static kinnector::ipc::IPCConfig g_config;

static std::unique_ptr<kinnector::lnx::EbpfLoader> g_loader = nullptr;
static std::unique_ptr<kinnector::lnx::FanotifyMonitor> g_fanotify = nullptr;

static std::mutex g_ffi_mutex;
static bool g_initialized = false;
static bool g_running = false;


extern "C" {

bool initialize_telemetry_engine(const char* bpf_obj_path, const char* socket_path, const char* auth_token) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_initialized) {
        return false;
    }

    g_config.socket_path = socket_path ? socket_path : "";
    g_config.pipe_name = socket_path ? socket_path : "";
    g_config.auth_token = auth_token ? auth_token : "";

    g_sender = kinnector::ipc::CreateTelemetrySender();
    if (!g_sender) {
        return false;
    }

    g_loader = std::make_unique<kinnector::lnx::EbpfLoader>();
    if (!g_loader || !g_loader->Initialize(bpf_obj_path ? bpf_obj_path : "", false)) {
        g_sender.reset();
        g_loader.reset();
        return false;
    }

    g_fanotify = std::make_unique<kinnector::lnx::FanotifyMonitor>();
    // enable_blocking intentionally omitted (defaults false): this Initialize()
    // call marks the ROOT filesystem. Passing true here would arm FAN_OPEN_PERM
    // mount-wide, blocking every open() on the whole machine on this one
    // monitor thread -- see fanotify.h's Initialize() comment. Never flip this
    // without the per-path-mark follow-up documented there.
    if (!g_fanotify || !g_fanotify->Initialize("/")) {
        std::cerr << "[FFI] Warning: Fanotify FIM failed to initialize. Continuing with eBPF only." << std::endl;
        g_fanotify.reset();
    }

    g_initialized = true;
    std::cout << "[FFI] Telemetry Engine initialized successfully." << std::endl;
    return true;
}

bool start_telemetry_engine() {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (!g_initialized || g_running) {
        return false;
    }

    // Start the IPC sender
    if (!g_sender->Start(g_config)) {
        std::cerr << "[FFI] Failed to start IPC sender" << std::endl;
        return false;
    }

    // Start TTY/PTY IPC sender
    g_tty_sender.Start("/var/run/kinnector/tty_telemetry.sock");

    // Forward eBPF events from the ring buffer directly to the agent over the IPC socket
    g_loader->SetEventCallback([](const TelemetryEvent& event) {
        if (g_sender) {
            g_sender->SendEvent(event);
        }
    });

    g_loader->SetTtyEventCallback([](const kinnector::lnx::EbpfLoader::TtyEvent& event) {
        g_tty_sender.SendTtyEvent(event);
    });

    if (!g_loader->Start()) {
        std::cerr << "[FFI] Failed to start EbpfLoader" << std::endl;
        g_tty_sender.Stop();
        g_sender->Stop();
        return false;
    }

    if (g_fanotify) {
        g_fanotify->SetEventCallback([](const TelemetryEvent& event) {
            if (g_sender) {
                g_sender->SendEvent(event);
            }
        });
        if (!g_fanotify->Start()) {
            std::cerr << "[FFI] Warning: Failed to start Fanotify monitor" << std::endl;
        }
    }

    g_running = true;
    std::cout << "[FFI] Telemetry Engine started." << std::endl;
    return true;
}

void stop_telemetry_engine() {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (!g_running) {
        return;
    }

    g_tty_sender.Stop();
    if (g_loader) {
        g_loader->Stop();
    }
    if (g_fanotify) {
        g_fanotify->Stop();
    }

    if (g_sender) {
        g_sender->Stop();
    }

    g_running = false;
    std::cout << "[FFI] Telemetry Engine stopped." << std::endl;
}

bool add_secret_broker_socket(uint64_t dev, uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->AddSecretBrokerSocket(dev, inode);
    }
    return false;
}

bool add_sensitive_inode(uint64_t dev, uint64_t inode, uint32_t category) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        bool ok = g_loader->AddSensitiveInode(dev, inode, category);
        // belt-and-suspenders -- also register
        // with the fanotify fallback so the resource stays protected even on a
        // kernel without BPF LSM support. Best-effort: the BPF-side result above
        // is authoritative, this doesn't affect the return value. No path
        // available at this call site (Rust passes dev+inode only), so this is
        // tracked in-memory only -- no live FAN_OPEN_PERM mark -- and is a
        // no-op either way while g_fanotify's Initialize() call keeps
        // enable_blocking at its default false (see that call site).
        if (g_fanotify) {
            g_fanotify->AddProtectedResource("", dev, inode);
        }
        return ok;
    }
    return false;
}

bool add_protected_static_inode(uint64_t dev, uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        bool ok = g_loader->AddProtectedStaticInode(dev, inode);
        if (g_fanotify) {
            g_fanotify->AddProtectedResource("", dev, inode);
        }
        return ok;
    }
    return false;
}

bool remove_protected_static_inode(uint64_t dev, uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        bool ok = g_loader->RemoveProtectedStaticInode(dev, inode);
        if (g_fanotify) {
            g_fanotify->RemoveProtectedResource("", dev, inode);
        }
        return ok;
    }
    return false;
}

bool add_bypassed_directory_inode(uint64_t dev, uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->AddBypassedDirectoryInode(dev, inode);
    }
    return false;
}

bool remove_bypassed_directory_inode(uint64_t dev, uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->RemoveBypassedDirectoryInode(dev, inode);
    }
    return false;
}


uint64_t fanotify_rescan_mounts(void) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_fanotify && g_running) {
        return static_cast<uint64_t>(g_fanotify->RescanMounts());
    }
    return 0;
}

bool add_persistence_dir(uint64_t dev, uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->AddPersistenceDir(dev, inode);
    }
    return false;
}

bool add_persistence_name(uint64_t parent_dev, uint64_t parent_inode, const char* name) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running && name) {
        return g_loader->AddPersistenceName(parent_dev, parent_inode, name);
    }
    return false;
}

bool add_package_manager_image(uint64_t dev, uint64_t inode, uint32_t flags) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->AddPackageManagerImage(dev, inode, flags);
    }
    return false;
}

bool remove_package_manager_image(uint64_t dev, uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->RemovePackageManagerImage(dev, inode);
    }
    return false;
}

bool add_resource_owner(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->AddResourceOwner(resource_dev, resource_inode, owner_exec_inode);
    }
    return false;
}

bool add_exe_name_class(const char* name, uint32_t classes) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->AddExeNameClass(name, classes);
    }
    return false;
}

bool add_untrusted_dir_name(const char* name) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->AddUntrustedDirName(name);
    }
    return false;
}

bool reset_resource_owner_to_single(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->ResetResourceOwnerToSingle(resource_dev, resource_inode, owner_exec_inode);
    }
    return false;
}

bool remove_resource_owner(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->RemoveResourceOwner(resource_dev, resource_inode, owner_exec_inode);
    }
    return false;
}

bool add_resource_owners_exact_batch(uint64_t resource_dev, uint64_t resource_inode, const uint64_t* owner_devs, const uint64_t* owner_inodes, uint32_t count) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running && (count == 0 || (owner_devs && owner_inodes))) {
        std::vector<std::pair<uint64_t, uint64_t>> owners;
        owners.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            owners.emplace_back(owner_devs[i], owner_inodes[i]);
        }
        return g_loader->AddResourceOwnersExactBatch(resource_dev, resource_inode, owners);
    }
    return false;
}

bool add_resource_owner_exact(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_dev, uint64_t owner_exec_inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->AddResourceOwnerExact(resource_dev, resource_inode, owner_dev, owner_exec_inode);
    }
    return false;
}

bool reset_resource_owner_to_single_exact(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_dev, uint64_t owner_exec_inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->ResetResourceOwnerToSingleExact(resource_dev, resource_inode, owner_dev, owner_exec_inode);
    }
    return false;
}

bool remove_resource_owner_exact(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_dev, uint64_t owner_exec_inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->RemoveResourceOwnerExact(resource_dev, resource_inode, owner_dev, owner_exec_inode);
    }
    return false;
}

bool add_dir_owner(uint64_t dir_dev, uint64_t dir_inode, uint64_t owner_dev, uint64_t owner_exec_inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->AddDirOwner(dir_dev, dir_inode, owner_dev, owner_exec_inode);
    }
    return false;
}

bool remove_dir_owner(uint64_t dir_dev, uint64_t dir_inode, uint64_t owner_dev, uint64_t owner_exec_inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->RemoveDirOwner(dir_dev, dir_inode, owner_dev, owner_exec_inode);
    }
    return false;
}

bool add_owner_image(uint64_t dev, uint64_t inode, uint32_t flags) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->AddOwnerImage(dev, inode, flags);
    }
    return false;
}

bool add_credential_helper_image(uint64_t dev, uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->AddCredentialHelperImage(dev, inode);
    }
    return false;
}

bool remove_credential_helper_image(uint64_t dev, uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->RemoveCredentialHelperImage(dev, inode);
    }
    return false;
}

bool add_modified_library(uint64_t dev, uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->AddModifiedLibrary(dev, inode);
    }
    return false;
}

bool remove_modified_library(uint64_t dev, uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->RemoveModifiedLibrary(dev, inode);
    }
    return false;
}

bool clear_modified_libraries(void) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->ClearModifiedLibraries();
    }
    return false;
}

bool remove_owner_image(uint64_t dev, uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->RemoveOwnerImage(dev, inode);
    }
    return false;
}

bool set_exec_origin(uint32_t pid, uint64_t start_time, uint64_t dev, uint64_t inode, uint32_t flags, uint32_t uid) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->SetExecOrigin(pid, start_time, dev, inode, flags, uid);
    }
    return false;
}

bool add_protected_path_name(uint64_t parent_dev, uint64_t parent_inode, const char* name, uint32_t category, uint64_t owner_mask,
                             uint64_t origin_dev, uint64_t origin_inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running && name) {
        return g_loader->AddProtectedPathName(parent_dev, parent_inode, name, category, owner_mask, origin_dev, origin_inode);
    }
    return false;
}

bool add_glob_owned_dir(uint64_t dir_dev, uint64_t dir_inode, uint32_t category, uint64_t owner_mask,
                         uint64_t origin_dev, uint64_t origin_inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->AddGlobOwnedDir(dir_dev, dir_inode, category, owner_mask, origin_dev, origin_inode);
    }
    return false;
}

uint64_t get_resource_owner_mask(uint64_t resource_dev, uint64_t resource_inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->GetResourceOwnerMask(resource_dev, resource_inode);
    }
    return 0;
}

bool add_trusted_exec_inode(uint64_t inode, uint32_t trust_level) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->AddTrustedExecInode(inode, trust_level);
    }
    return false;
}

// Fix 10: query whether an inode is registered in the trusted_exec_inodes BPF map.
// Used by the image_load() heuristic to detect SO side-loading into trusted processes.
bool is_trusted_exec_inode(uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->LookupTrustedExecInode(inode);
    }
    return false;
}

bool set_config_value(uint32_t index, uint32_t value) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->SetConfigValue(index, value);
    }
    return false;
}

bool update_process_threshold(uint32_t pid, uint64_t start_time, uint32_t threshold) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->UpdateMapEntry(kinnector::lnx::BpfMapType::ProcessThreshold, pid, start_time, threshold);
    }
    return false;
}

bool update_map_entry(int map_type, uint32_t pid, uint64_t start_time, uint32_t value) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->UpdateMapEntry(static_cast<kinnector::lnx::BpfMapType>(map_type), pid, start_time, value);
    }
    return false;
}

void get_exec_telemetry_stats(uint64_t* emitted, uint64_t* dropped) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    uint64_t e = 0, d = 0;
    if (g_loader && g_running) {
        g_loader->GetExecTelemetryStats(e, d);
    }
    if (emitted) *emitted = e;
    if (dropped) *dropped = d;
}

int refresh_task_start_times(void) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->RefreshTaskStartTimes();
    }
    return -1;
}

uint64_t get_task_start_time(uint32_t pid) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->GetTaskStartTime(pid);
    }
    return 0;
}

int lookup_pkg_lifecycle(uint32_t pid, uint64_t start_time) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->LookupPkgLifecycle(pid, start_time);
    }
    return -1;
}

bool delete_map_entry(int map_type, uint32_t pid, uint64_t start_time) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->DeleteMapEntry(static_cast<kinnector::lnx::BpfMapType>(map_type), pid, start_time);
    }
    return false;
}

bool is_lsm_active() {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader) {
        return g_loader->IsLsmActive();
    }
    return false;
}

bool force_unpin_all_links_test_only() {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader) {
        g_loader->ForceUnpinAllLinks();
        return true;
    }
    return false;
}

void raw_unpin_all_links_signal_safe() {
    // Deliberately no lock, no g_loader dereference, no libbpf calls - see
    // ffi.h's doc comment. Only touches the fixed, statically-known path
    // array, exactly like test_enforcement_e2e.cpp's own crash handler.
    for (size_t i = 0; i < kinnector::lnx::kWardenPinnedLinkPathsCount; ++i) {
        unlink(kinnector::lnx::kWardenPinnedLinkPaths[i]);
    }
}

// Firewall (warden/src/firewall) — see ebpf_loader.h's AddFirewallCidr for
// the addr/prefixlen contract. `is_v6` selects fw_rules_v4 vs fw_rules_v6.
bool add_firewall_cidr(bool is_v6, const uint8_t* addr, uint32_t prefixlen,
                        uint32_t rule_id, uint16_t port, uint8_t proto,
                        uint8_t direction, uint8_t action) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->AddFirewallCidr(is_v6, addr, prefixlen, rule_id, port, proto, direction, action);
    }
    return false;
}

bool remove_firewall_cidr(bool is_v6, const uint8_t* addr, uint32_t prefixlen) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->RemoveFirewallCidr(is_v6, addr, prefixlen);
    }
    return false;
}

// Anti-tamper: -1 if unavailable (mock mode / not loaded), so the caller
// (warden/src/ebpf_health.rs) can distinguish "can't check" from "zero
// entries is correct."
int64_t count_firewall_entries() {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_loader && g_running) {
        return g_loader->CountFirewallEntries();
    }
    return -1;
}

// No in-core kill-on-access response on Linux: the BPF LSM deny already refuses the open.
bool set_resource_kill_on_access(uint64_t dev, uint64_t inode, bool enabled) {
    (void)dev; (void)inode; (void)enabled;
    return false;
}

bool send_telemetry_event(const TelemetryEvent* event) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_sender && g_running && event) {
        return g_sender->SendEvent(*event);
    }
    return false;
}

// ---------------------------------------------------------------------------
// Cloud-tier collectors. Deliberately outside g_ffi_mutex and g_running: they do
// not depend on the telemetry engine and must not contend with it.
// ---------------------------------------------------------------------------
using kinnector::lnx::CloudCollectors;

bool cloud_collectors_start(const char* bpf_object_path, uint32_t features, int32_t scan_secs) {
    if (!bpf_object_path) return false;
    return CloudCollectors::Instance().Start(bpf_object_path, features, scan_secs);
}
void cloud_collectors_stop(void) { CloudCollectors::Instance().Stop(); }
bool cloud_collectors_running(void) { return CloudCollectors::Instance().Running(); }

size_t cloud_collectors_program_status(char* buf, size_t cap) {
    std::string s;
    for (const auto& p : CloudCollectors::Instance().Status()) {
        s += p.name + (p.loaded ? " 1" : " 0") + (p.attached ? " 1" : " 0") + "\n";
    }
    if (buf && cap > 0) {
        size_t n = s.size() < cap - 1 ? s.size() : cap - 1;
        std::memcpy(buf, s.data(), n);
        buf[n] = 0;
    }
    return s.size();
}

bool cloud_scope_add_root(uint64_t dev, uint64_t inode, uint32_t kind) {
    return CloudCollectors::Instance().AddScopeRoot(dev, inode, kind);
}
bool cloud_scope_remove_root(uint64_t dev, uint64_t inode) {
    return CloudCollectors::Instance().RemoveScopeRoot(dev, inode);
}
bool cloud_scope_add_skip(uint64_t dev, uint64_t inode) {
    return CloudCollectors::Instance().AddSkipDir(dev, inode);
}
bool cloud_scope_remove_skip(uint64_t dev, uint64_t inode) {
    return CloudCollectors::Instance().RemoveSkipDir(dev, inode);
}
void cloud_scope_clear(void) { CloudCollectors::Instance().ClearScope(); }
void cloud_scope_commit(void) { CloudCollectors::Instance().CommitScope(); }

size_t cloud_drain_net(struct cloud_net_rec* out, size_t cap) {
    return out ? CloudCollectors::Instance().DrainNet(out, cap) : 0;
}
size_t cloud_drain_dns(struct cloud_dns_name* out, size_t cap) {
    return out ? CloudCollectors::Instance().DrainDns(out, cap) : 0;
}
size_t cloud_drain_udp(struct cloud_udp_row* out, size_t cap) {
    return out ? CloudCollectors::Instance().DrainUdp(out, cap) : 0;
}
size_t cloud_drain_files(struct cloud_file_row* out, size_t cap) {
    return out ? CloudCollectors::Instance().DrainFiles(out, cap) : 0;
}
size_t cloud_drain_projects(struct cloud_proj_row* out, size_t cap) {
    return out ? CloudCollectors::Instance().DrainProjects(out, cap) : 0;
}
void cloud_collectors_stats(uint64_t* out, size_t n) {
    if (out) CloudCollectors::Instance().Stats(out, n);
}
size_t cloud_drain_life(uint8_t* out, size_t cap_bytes, size_t* nrecs) {
    if (nrecs) *nrecs = 0;
    return out ? CloudCollectors::Instance().DrainLife(out, cap_bytes, nrecs) : 0;
}
void cloud_life_stats(uint64_t* out, size_t n) {
    if (out) CloudCollectors::Instance().LifeStats(out, n);
}
void cloud_set_dir_rows_on(bool on) { CloudCollectors::Instance().SetDirRowsOn(on); }
void cloud_set_name_policy(const uint64_t* exts, size_t n_exts, const char* const* names, size_t n_names,
                           const char* const* prefixes, size_t n_prefixes) {
    std::vector<uint64_t> e(exts, exts + (exts ? n_exts : 0));
    std::vector<std::string> n, p;
    for (size_t i = 0; names && i < n_names; i++) {
        if (names[i]) n.emplace_back(names[i]);
    }
    for (size_t i = 0; prefixes && i < n_prefixes; i++) {
        if (prefixes[i]) p.emplace_back(prefixes[i]);
    }
    CloudCollectors::Instance().SetNamePolicy(std::move(e), std::move(n), std::move(p));
}
void cloud_set_dir_prefix_policy(const char* const* prefixes, size_t n_prefixes) {
    std::vector<std::string> p;
    for (size_t i = 0; prefixes && i < n_prefixes; i++) {
        if (prefixes[i]) p.emplace_back(prefixes[i]);
    }
    CloudCollectors::Instance().SetDirPrefixPolicy(std::move(p));
}
void cloud_set_dir_limits(uint32_t proc_max) { CloudCollectors::Instance().SetDirProcMax(proc_max); }
size_t cloud_drain_dirs(struct cloud_dir_row* out, size_t cap) {
    return out ? CloudCollectors::Instance().DrainDirs(out, cap) : 0;
}
size_t cloud_drain_dir_drops(struct cloud_dir_drop_row* out, size_t cap) {
    return out ? CloudCollectors::Instance().DrainDirDrops(out, cap) : 0;
}
size_t cloud_drain_names(struct cloud_name_rec* out, size_t cap) {
    return out ? CloudCollectors::Instance().DrainNames(out, cap) : 0;
}
size_t cloud_drain_dir_ext_fold(struct cloud_dir_ext_row* out, size_t cap) {
    return out ? CloudCollectors::Instance().DrainDirExtFold(out, cap) : 0;
}
size_t cloud_drain_dir_prefix_fold(struct cloud_dir_prefix_row* out, size_t cap) {
    return out ? CloudCollectors::Instance().DrainDirPrefixFold(out, cap) : 0;
}
size_t cloud_drain_dir_hll(struct cloud_dir_hll_row* out, size_t cap) {
    return out ? CloudCollectors::Instance().DrainDirHll(out, cap) : 0;
}
void cloud_name_stats(uint64_t* out, size_t n) {
    if (out) CloudCollectors::Instance().NameStats(out, n);
}
void cloud_policy_stats(uint64_t* out, size_t n) {
    if (out) CloudCollectors::Instance().PolicyStats(out, n);
}
size_t cloud_drain_moves(struct cloud_move_rec* out, size_t cap) {
    return out ? CloudCollectors::Instance().DrainMoves(out, cap) : 0;
}
void cloud_move_stats(uint64_t* out, size_t n) {
    if (out) CloudCollectors::Instance().MoveStats(out, n);
}

} // extern "C"
