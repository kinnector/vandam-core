#ifndef KINNECTOR_TELEMETRY_H
#define KINNECTOR_TELEMETRY_H

#include <cstdint>

#pragma pack(push, 1)

enum class EventType : uint8_t {
    ProcessCreate = 1,
    ProcessStop = 2,
    FileRead = 3,
    FileCreate = 4,
    FileWrite = 5,
    FileRename = 6,
    NetworkConnect = 7,
    ImageLoad = 8,
    RegistryWrite = 9,
    ClipboardWrite = 10,
    CallStackFrame = 11,
    MemoryProtect = 12,
    PtraceAttach = 13,
    SSHAuth = 14,
    TerminalCommand = 15,
    FileOpen = 16,
    MemoryMap = 17,
    Dup2 = 18,
    Listen = 19,
    NetworkAccept = 20,
    DNSQuery = 21,
    FileDelete = 22,
    SignalDelivery = 23,
    PrivilegeChange = 24,
    IPCAccess = 25,
    TaskRegistered = 26,
    CrossProcessMemoryAccess = 27,
    ThreadContextAccess = 28,
    ImpersonationChange = 29,
    DpapiOperation = 30,
    // LD_PRELOAD/LD_LIBRARY_PATH
    // presence capture at exec time.
    EnvironmentMarkers = 31,
    // monitoring-only identity/capability/
    // namespace/cross-memory signals. See each Details struct's own comment
    // below for the phase that added it.
    CrossMemoryAccess = 32,
    CapabilityChange = 33,
    PrctlKeepcaps = 34,
    CommRename = 35,
    SubreaperSet = 36,
    ExecCredentialDelta = 37,
    GroupChange = 38,
    GroupSet = 39,
    NamespaceChange = 40,
    // Antitheft resource-swap-defense follow-up: link(2) (hardlink) into a
    // previously-unlinked resource/owner path - no LSM hook anywhere in this
    // codebase observed this syscall before, same class of gap as
    // FileRename/FileCreate's own additions.
    FileLink = 41,
    // Linux-only coalesced filesystem-activity burst - kinnector.bpf.c's
    // EVT_FILE_BATCH/record_and_batch_event. The Linux producer already used
    // discriminant 42 (a prior collision with TaskRegistered's 26 forced the
    // remap - see that #define's own comment); missing from this enum until
    // now was a documentation gap only, not a wire mismatch.
    FileBatch = 42,
    // Antitheft-only (alert-visibility audit): protected_selfexec_forbidden()
    // - the shared fileless-code-execution defense `mmap_file`, `file_mprotect`
    // and `shm_shmat` all gate anonymous/tmpfs/SysV-shm executable mappings
    // behind for an already-protected process - denied real attempts with
    // zero telemetry at all before this, across all three call sites. See
    // `SelfExecDeniedDetails`.
    SelfExecDenied = 43,
    // same-user secret-broker socket connect
    // (ssh-agent/gpg-agent/1Password-agent/gnome-keyring-control) - AUDIT
    // ONLY, see `unix_stream_connect`'s doc comment in kinnector.bpf.c.
    SecretBrokerConnect = 44,
    // macOS: a fork(2)/vfork(2) the audit pipe or ESF reported, so a
    // process that forks without exec'ing (a shell's subshell) has a lifecycle. Linux's
    // forks come from the cloud collectors' own object and never use this.
    ProcessFork = 45,
    // macOS: a protected app's own files were changed. See AppModificationDetails.
    AppModification = 46,
    // Windows: a command line for a process this engine already emitted ProcessCreate
    // for, WITHOUT one - the MOF command-line source (src/windows/process_cmdline_source.h)
    // arrived after the manifest ProcessCreate had already gone out. There is no going back to
    // edit that event, so this carries the real creation time (not this event's own arrival time)
    // for the consumer to re-attach it to the right process instance. See
    // ProcessCommandLineDetails and src/windows/process_cmdline_correlator.h.
    ProcessCommandLine = 47
};

enum class TelemetrySource : uint8_t {
    ETW = 1,
    ESF = 2,
    OpenBSM = 3,
    eBPF = 4,
    fanotify = 5,
    BPF_LSM = 6,
    Log_FIM = 7,
    Clipboard = 8,
    CallStack = 9,
    // Windows app guard: a real write/new-file DirectoryWatcher confirmed for a
    // registered app-guard tree root, attributed (best-effort) to a recent FileCreate for the same
    // path. Carried as an ordinary EventType::FileWrite/FileWriteDetails - no new wire shape.
    DirWatch = 10,
    // Windows WS7 file guard: the oplock hold suspended this opener of a guarded file
    // before its first read. Carried as an ordinary EventType::FileCreate (Win32 path), stamped on
    // ETW's clock, so the agent judges and answers it even when the main session's own FileCreate
    // for that open is late or lost.
    FileGuard = 11,
    // Windows: a ProcessCreate/ProcessStop WMI reported and ETW did not
    // (src/windows/process_start_merge.h). Same wire shape; ETW's clock (100 ns since 1601);
    // no sequence numbers; the image path is a Win32 path, not an NT device path.
    Wmi = 12,
    // Windows: an ETW FileCreate of a file the WS7 oplock guard holds, which the
    // guard vouches read NO data - its RWH oplock was held from well before the open until after
    // it (FileGuard::VouchesNoDataOpen). Test-Path, Get-ChildItem, dir, stat: a listing or an
    // attribute query, not a read. Same wire shape as the ETW FileCreate it replaces. Only ever
    // a positive statement: an open the guard cannot vouch for keeps source ETW.
    GuardedNoData = 13
};

struct TelemetryHeader {
    uint64_t sequence_number;
    uint64_t timestamp_ns;
    uint32_t pid;
    EventType event_type;
    TelemetrySource source;
    // WS1: reuse-resistant identity of the
    // process this event is attributed to (`pid` above). On Windows this is the
    // Kernel-Process ProcessSequenceNumber resolved via ProcessRegistry; 0 means
    // "unavailable" (process pre-dated the engine, or an older OS build) - never
    // treat 0 as a real sequence value. Other platforms leave this 0 for now.
    //
    // ABI NOTE: appending this field shifts the offset of TelemetryEvent's
    // `details` union. Any consumer that decodes this struct off the wire (the
    // antitheft-agent named-pipe consumer) must be rebuilt against this header.
    uint64_t actor_sequence_number;
};

// Sub-details structures corresponding to ALERT-SCHEMA.md types
struct ProcessCreateDetails {
    uint32_t child_pid;
    uint32_t real_parent_pid;
    char child_image_path[512];
    char child_command_line[1024];
    // Reuse-resistant per-boot process identifiers (Windows Kernel-Process
    // ProcessSequenceNumber/ParentProcessSequenceNumber). 0 means "not
    // available on this OS build" (older Windows), not "sequence number 0" -
    // callers must not treat 0 as a valid sequence value for lineage keying.
    uint64_t child_sequence_number;
    uint64_t parent_sequence_number;
    // Container support (antitheft-side, telemetry-only): the executing
    // process's own mount/PID namespace identity at the moment of THIS exec,
    // read via the same get_current_mnt_ns_inum()/get_current_pid_ns_inum()
    // helpers is_container_restricted() already uses internally - purely
    // additive, no enforcement change. 0 means "not available" (Windows/
    // macOS leave this 0; Linux always populates it), same convention as the
    // sequence-number fields above. Lets a consumer compare a child's
    // namespace against its parent's without a racy /proc/<pid>/cgroup read -
    // a mismatch is a race-free, high-confidence "this process crossed a
    // namespace boundary at exec time" signal, complementary to
    // NamespaceChangeDetails below (which covers a LATER, in-place
    // setns/unshare, not a boundary already crossed by exec time).
    uint32_t mnt_ns_inum;
    uint32_t pid_ns_inum;
    // AppImage protection plan: the exec'ing task's real task->start_time
    // (Linux: kinnector.bpf.c's get_current_process_key(), read
    // synchronously at bprm_creds_for_exec/sys_enter_execve; 0 on
    // macOS where it isn't populated yet). Windows: the
    // process's exact creation time, FILETIME (Kernel-Process CreateTime, or
    // GetProcessTimes for a start WMI reported - the same value), 0 when not
    // known; never an event timestamp. Must match kinnector.bpf.c's
    // ProcessCreateDetails field-for-field.
    uint64_t child_start_time;
    // the kernel's verdict for THIS exec, read once it has
    // succeeded: the process's pkg_lifecycle_pids value (0 = in no install),
    // valid only with bit 0x01 (KINN_EXEC_VERDICT_PKG) in kernel_verdicts.
    // Other producers leave both 0 and consumers fall back to their lookup.
    uint8_t pkg_lifecycle;
    uint8_t kernel_verdicts;
};

struct ProcessStopDetails {
    int32_t exit_code;
    // Linux BPF's `_pad` (kinnector_types.h); 0.
    uint32_t _reserved;
    // Windows only: the stopped process's identity, ProcessSequenceNumber and exact
    // creation time (FILETIME), 0 when not known. A consumer applies the stop only to the process
    // with that identity, never to a newer one that took the pid. Not written on Linux or macOS.
    uint64_t sequence_number;
    uint64_t create_time;
};

// EventType::ProcessCommandLine (Windows only, reactive profile): a late command line for a
// process whose ProcessCreate already went out without one. `pid`/`create_time` identify the same
// process instance ProcessCreate carried (create_time is the manifest event's real CreateTime
// property, FILETIME, 100 ns since 1601 - the same basis as ProcessCreateDetails would have used
// had the command line been available at creation time), never pid alone (pids are reused).
//
// also sent when the kernel's record of the start (captured at creation) differs from the
// command line the start carried (read from the process's own memory, which it can rewrite: argument
// spoofing). `command_line` is then the kernel's and `changed` is 1. Not a finding by itself: Windows
// rewrites every console host's command line the same way (conhost.exe `0xffffffff -ForceV1` in the
// kernel's record, `0x4` in the process), and the agent logs it at debug only.
struct ProcessCommandLineDetails {
    uint32_t pid;
    uint64_t create_time;
    char command_line[1024];
    // The process's ProcessSequenceNumber, 0 when not known.
    uint64_t sequence_number;
    // Where `command_line` comes from: 1 the kernel's start record, 2 the process's own memory.
    uint8_t source;
    // 1: the process's own command line, as the start carried it, was not this one.
    uint8_t changed;
};

#define PROCESS_CMDLINE_SOURCE_KERNEL 1
#define PROCESS_CMDLINE_SOURCE_PROCESS 2

// EventType::ProcessFork (macOS). Start times are ns since the epoch (proc_bsdinfo's,
// or the audit record's own time when the process had already exited); 0 = unknown.
struct ProcessForkDetails {
    uint32_t child_pid;
    uint32_t parent_pid;
    uint64_t child_start_time;
    uint64_t parent_start_time;
};

// EventType::AppModification (macOS). `path` is what changed (for a rename, the side in the
// tree), `app_root` the protected app's tree (its `.app` folder, or its owner file). `op`:
// 1 write-open, 2 truncate, 3 rename, 4 delete, 5 exchangedata. `trust` bits: 0x1 the writer is
// validly signed by the app's team, 0x2 it runs from the app's own tree (an app with no team),
// 0x4 an Apple system service (IsExemptActor). `response`: 1 the writer was frozen (armed, and
// none of `trust`).
struct AppModificationDetails {
    char path[512];
    char app_root[512];
    uint8_t op;
    uint8_t trust;
    uint8_t response;
};

struct FileReadDetails {
    uint32_t bytes_requested;
    int32_t zone_id; // -1 if not set, or Windows ZoneId (3=internet, 4=untrusted)
    char file_path[512];
};

struct FileCreateDetails {
    int32_t zone_id;
    char file_path[512];
};

struct FileWriteDetails {
    uint32_t bytes_written;
    char file_path[512];
};

struct FileRenameDetails {
    char source_path[512];
    char destination_path[512];
};

struct FileDeleteDetails {
    char file_path[512];
};

// Antitheft resource-swap-defense follow-up: link(2)'s source (already
// existed) and destination (the new, necessarily-negative dentry link(2)
// creates) leaf names - same shape as FileRenameDetails, deliberately, since
// consumers treat this the same way (destination-basename lookup against a
// small set of tracked resource/owner paths).
struct FileLinkDetails {
    char source_path[512];
    char destination_path[512];
};

// Antitheft-only (deployment_mode == MODE_ANTITHEFT): emitted by the
// file_open LSM hook's storage-ownership branch (kinnector.bpf.c), carrying
// the exact resource identity the kernel already resolved via
// make_resource_id() at decision time. FileReadDetails' file_path is only
// the dentry's leaf name (d_name.name), not a full path - not enough to
// disambiguate e.g. "Login Data" across every browser profile on the box.
// resource_dev/resource_ino is antitheftd's own resolve_links() identity
// space, letting userspace reverse-map straight to which ProtectedResource
// (and, for browsers, which profile/extension) this was, with no path
// parsing of an ambiguous basename needed.
struct FileOpenDetails {
    uint64_t resource_dev;
    uint64_t resource_ino;
    uint8_t verdict; // 1 = allowed (recognized owner), 2 = denied
    char file_path[512]; // leaf name only, kept for human-readable logs
    // Appended (antitheft-cloud contract v12), mirrors
    // kinnector_types.h: a bit set of KINN_OPEN_* (0x01 read, 0x02 write,
    // 0x04 O_TRUNC, 0x80 known). 0 = unknown.
    uint8_t access_mode;
    // Appended (macOS port). What core already did about this
    // open before the agent saw it: 0 nothing, 1 the opener was SIGSTOP'ed
    // (macOS OpenBSM: the open had already succeeded, freezing is the closest
    // thing to a deny). Linux never sets it - its deny is verdict 2/3 itself.
    // With TelemetrySource::OpenBSM, verdict 2 means "not an owner", never
    // "denied". Union size unchanged (ProcessCreateDetails is the largest).
    uint8_t response;
    // Appended, mirrors kinnector_types.h. Persistence events only (verdict 5 denied,
    // 6 observed by a distro install's script, 8 written by anything else): the writer's
    // pkg_lifecycle_pids value at the moment of the write (0 = in no install) and the operation
    // (KINN_PERSIST_OP_* in kinnector_types.h: 1 create, 2 mkdir, 3 rename into, 4 rename away,
    // 5 link, 6 symlink, 7 unlink, 8 open for write). 0 elsewhere.
    uint8_t pkg_lifecycle;
    uint8_t persist_op;
    // Appended, mirrors kinnector_types.h. Every BPF FileOpen: the opener's parent (its
    // real_parent's tgid) and its own process start (the group leader's start_time, the value
    // ProcessCreateDetails::child_start_time carries). A forked child that writes before it execs
    // (a shell's `>>`) has had no ProcessCreate, so without these the agent could not say what it
    // was. 0 = not carried (the macOS and Windows producers zero their events).
    uint32_t parent_pid;
    uint64_t process_start_time;
};

// mirrors kinnector_types.h's SecretBrokerConnectDetails
// exactly. resource_dev/resource_ino identify WHICH registered secret-broker
// socket was connected to - same identity space as FileOpenDetails.
struct SecretBrokerConnectDetails {
    uint64_t resource_dev;
    uint64_t resource_ino;
    char socket_path[128]; // dentry leaf name of the socket file, for logs
};

struct NetworkConnectDetails {
    char destination_ip[46]; // support IPv6
    uint16_t destination_port;
    char protocol[8];        // TCP, UDP
};

struct NetworkAcceptDetails {
    char remote_ip[46];   // the connecting peer, support IPv6
    uint16_t remote_port;
    uint16_t local_port;  // the listening port the connection arrived on
};

struct ImageLoadDetails {
    uint8_t is_signed;
    char module_path[512];
    char signer_subject[256];
    // Antitheft-only (kernel-synchronous untrusted-.so deny):
    // 0 = allowed (the mapping already succeeded by the time this event was
    // emitted), 1 = denied (mmap_file refused it before it could ever map -
    // module_path still names what was attempted). Appended at the end so
    // existing byte offsets are unchanged, same discipline as
    // SignalDeliveryDetails/SelfExecDeniedDetails' own trailing verdict/via
    // bytes.
    uint8_t verdict;
};

struct RegistryWriteDetails {
    char key_path[512];
    char value_name[256];
    char value_data[512];
};

struct TaskRegisteredDetails {
    char task_name[512];
    char user_context[256];
};

// Cross-process memory operations (VirtualAlloc/VirtualProtect/
// WriteProcessMemory targeting a different process). Detection-only
// telemetry - records what happened, not an assessment of intent.
struct CrossProcessMemoryAccessDetails {
    uint32_t target_pid;
    uint64_t address;
    uint64_t size;
    char operation[32];  // "VirtualAlloc", "VirtualProtect", "WriteProcessMemory"
    char protection[64]; // page protection flags, when applicable
};

// Cross-process thread operations (SetThreadContext/QueueUserAPC/remote
// thread creation targeting a different process). Detection-only telemetry.
struct ThreadContextAccessDetails {
    uint32_t target_pid;
    uint32_t target_tid;
    uint64_t start_address; // function pointer target, 0 if not applicable
    char operation[32];     // "SetThreadContext", "QueueUserAPC", "RemoteThreadCreate"
};

// A thread's effective identity changing (impersonation applied/reverted).
// Records the calling thread and what its token looked like immediately
// before the change - pure data capture, no interpretation of whether the
// change is expected or not (that's a policy-layer decision).
struct ImpersonationChangeDetails {
    uint32_t calling_pid;
    uint32_t calling_tid;
    char direction[8];               // "UP", "DOWN", "REVERT"
    char previous_token_user[256];
    char previous_token_integrity[32];
    uint8_t previous_token_elevated;
};

// Microsoft-Windows-Crypto-DPAPI's DPAPIDefInformationEvent (Id=16385, Task=64
// ETW_TASK_DEF_INFORMATION, gated behind the Debug channel keyword
// 0x2000000000000000).
//
// EMPIRICALLY CONFIRMED LIMITATION: this event fires only for a process'
// FIRST DPAPI operation (Protect or Unprotect) in its lifetime, not per-call -
// a long-lived process making repeated CryptUnprotectData calls only produces
// ONE of these events total. Treat this as a "process used DPAPI at least
// once" signal, not a full per-operation audit trail.
//
// PID ATTRIBUTION - IMPORTANT DEVIATION FROM EVERY OTHER EVENT TYPE IN THIS
// FILE: DPAPI master-key operations are actually carried out by lsass.exe on
// the caller's behalf, so this event's raw ETW EventHeader.ProcessId is
// ALWAYS lsass.exe (confirmed empirically - QueryFullProcessImageNameW
// resolved it to C:\Windows\System32\lsass.exe, not the calling test
// process), never the real caller. Every other event type in telemetry.h
// sets TelemetryHeader.pid from EventHeader.ProcessId directly and that's
// correct there; for DpapiOperation specifically, etw_consumer.cpp
// deliberately overrides header.pid with this struct's own caller_pid
// (parsed from the CallerProcessID property) instead, since leaving it as
// lsass.exe's PID would make the field useless for 100% of these events.
struct DpapiOperationDetails {
    char operation_type[32];     // "SPCryptProtect" or "SPCryptUnprotect"
    // App-supplied, UNTRUSTED for attribution - a malicious/careless caller
    // controls this string directly (it's CryptProtectData's szDataDescr
    // argument), don't treat it as proof of which credential store was
    // touched. Real attribution needs to correlate the calling process
    // identity/master_key_guid against the config domain (§7)/owner-allowlist
    // model (§4), same as every other resource-ownership decision.
    char data_description[256];
    uint8_t master_key_guid[16]; // raw GUID bytes, not yet formatted
    uint32_t flags;
    uint32_t protection_flags;
    int32_t return_value;        // 0 == success
    uint32_t plaintext_data_size;
    // The real calling process' reuse-resistant composite identity - NEVER
    // key attribution on caller_pid alone, same PID-reuse discipline as
    // every lineage table elsewhere in this design (antitheft.md §3/§4,
    // core_windows_phase2_lineage). caller_pid duplicates header.pid (see
    // above) but is kept here too so the raw parsed value is always
    // available even if a future change stops overriding header.pid.
    uint32_t caller_pid;
    uint64_t caller_process_creation_time;
    // Windows' own separate composite process-identity value for this
    // event. Semantics not independently verified against
    // caller_process_creation_time above or against Kernel-Process's
    // ProcessSequenceNumber (core_windows_phase2_lineage) - treat as an
    // opaque correlation key scoped to this provider, not confirmed
    // equivalent to either.
    uint64_t caller_process_start_key;
};

struct ClipboardWriteDetails {
    uint32_t owner_pid;
    uint8_t owner_is_foreground;
    char previous_content[512];
    char new_content[512];
    char content_type[32]; // e.g. BTC_BECH32
    char attribution[16];   // ATTRIBUTED or NULL_OWNER
};

struct CallStackFrameDetails {
    uint32_t frame_index;
    uint64_t return_address;
    uint8_t is_file_backed;
    char module_path[512];
    char notes[128];
};

struct MemoryProtectDetails {
    uint32_t target_pid;
    uint64_t address;
    uint64_t length;
    char prot_flags[64];
    char old_prot_flags[64];
    // Runtime-revocation plan: the target's real kernel task->start_time,
    // NOT the same quantity as ProcessNode.start_time_ns on the Rust side
    // (that's a documented ProcessCreate-dispatch-time substitute). Needed
    // bit-for-bit to key revoked_pid_map's process_key correctly.
    uint64_t target_start_time;
};

// Runtime-revocation plan: this struct already existed as a kinnector.bpf.c-
// local mirror (used to fill EVT_MEMORY_MAP for anonymous PROT_EXEC mmap/
// mprotect) but was never added to this shared header, so no userspace
// consumer could ever decode it. Mirrored field-for-field from the BPF-side
// definition.
struct MemoryMapDetails {
    uint64_t addr;
    uint64_t length;
    uint32_t prot;          // PROT_READ | PROT_WRITE | PROT_EXEC
    uint32_t flags;         // MAP_ANONYMOUS | MAP_PRIVATE etc.
    int32_t  fd;            // -1 for anonymous
    uint64_t file_inode;    // inode of backing file (0 for anonymous regions)
    uint64_t target_start_time; // see MemoryProtectDetails' comment above
};

struct PtraceAttachDetails {
    uint32_t target_pid;
    char mode[32]; // e.g. PTRACE_ATTACH
    uint64_t target_start_time; // see MemoryProtectDetails' comment above
    // `verdict` (alert-visibility audit): 1 = observed (the
    // pre-existing unconditional emit - not a verdict, just "this ptrace
    // attempt happened"), 2 = denied (kernel already blocked it - the
    // antitheft protected-owner-family check in ptrace_access_check used to
    // return -EACCES before this event was ever emitted, so a real attacker
    // being blocked was invisible to userspace). See kinnector.bpf.c's
    // matching comment.
    uint8_t verdict;
};

struct SSHAuthDetails {
    char username[64];
    char source_ip[46];
    uint16_t port;
    char auth_method[32]; // publickey, password
    char status[16];      // SUCCESS, FAILURE
};

struct TerminalCommandDetails {
    char tty_device[32]; // e.g. /dev/pts/1
    char command[512];
};

// new - never existed in this header
// before. kinnector.bpf.c's local Dup2Details already declared old_fd_type
// (warden's Rust mirror has always expected it too); the kernel just never
// computed a real value for it until this plan's Phase 2 fix.
struct Dup2Details {
    uint32_t oldfd;
    uint32_t newfd;         // 0=stdin, 1=stdout, 2=stderr (reverse shell indicator)
    uint8_t old_fd_type;    // 0=unknown, 1=file, 2=socket, 3=pipe
    uint16_t old_fd_family; // for a socket: 1 AF_UNIX, 2 AF_INET, 10 AF_INET6; 0 unknown
};

// new - EVT_LISTEN's payload was always
// a meaningless zeroed reuse of ProcessCreateDetails before this.
struct ListenDetails {
    uint16_t port; // 0 if resolution failed (Unix socket, or a real failure)
};

// new event entirely, zero interaction
// with any existing struct. Presence-plus-short-value only, deliberately
// never a stronger claim than "this key was present with this value at exec
// time" - see kinnector.bpf.c's identical struct comment.
// ld_audit_present / interp_injection_mask: extends the original two-field struct in place,
// same bounded envp unroll tracepoint_sys_enter_execve already runs - no new
// hook, no new EventType. interp_injection_mask bits: 0=NODE_OPTIONS,
// 1=PYTHONPATH, 2=PYTHONSTARTUP, 3=PERL5LIB, 4=RUBYLIB, 5=CLASSPATH,
// 6=ELECTRON_RUN_AS_NODE (C1).
//
// Related, same plan (C3): in MODE_ANTITHEFT, ProcessCreateDetails::
// child_command_line from tracepoint_sys_enter_execve carries argv[0..7] as
// 8 fixed 128-byte NUL-terminated slots (first empty slot ends the list)
// instead of the filename. Field size and every other producer unchanged.
struct EnvironmentMarkersDetails {
    uint8_t ld_preload_present;
    uint8_t ld_library_path_present;
    uint8_t ld_audit_present;
    uint8_t interp_injection_mask;
    char ld_preload_value[128];
    // NODE_OPTIONS' value (truncated to
    // 128, empty when the variable is absent). Appended at the end so an
    // older consumer decoding the shorter layout still reads every field it
    // knows; the union stays sized by ProcessCreateDetails.
    char node_options_value[128];
};

// process_vm_readv/writev cross-
// process memory telemetry, reused for /proc/<pid>/mem access (direction
// extended to a 3rd/4th value rather than a parallel struct, since the
// underlying question - "did a process reach into another process's memory,
// and which direction" - is identical). Presence + direction + target only,
// deliberately not summing real byte counts from the iovec arrays.
struct CrossMemoryAccessDetails {
    uint32_t target_pid;
    uint8_t direction; // 0=process_vm_readv, 1=process_vm_writev,
                        // 2=/proc/<pid>/mem read, 3=/proc/<pid>/mem write
};

// capset's cap_effective delta -
// deliberately only cap_effective ("what can I do right now"), not
// permitted/inheritable/ambient/bset.
struct CapabilityChangeDetails {
    uint64_t old_effective;
    uint64_t new_effective;
};

// presence-only, task_prctl's
// PR_SET_KEEPCAPS (8) branch. arg2 is the enabled state (0 or 1).
struct PrctlKeepcapsDetails {
    uint8_t keepcaps_enabled;
};

// task_prctl's PR_SET_NAME (15)
// branch - a process rewriting its own kernel `comm` field (e.g. to
// "sshd"/"systemd"), directly poisoning any consumer that trusts `comm` for
// display/classification.
struct CommRenameDetails {
    char new_comm[16]; // TASK_COMM_LEN
};

// task_prctl's
// PR_SET_CHILD_SUBREAPER (36) branch - presence-only orphan-reparenting/
// persistence signal. Does NOT imply a ProcessTree lineage-integrity gap -
// lineage is built from sched_process_fork's real parent_pid at fork time,
// never from live /proc/<pid>/status PPid, so this is immune to subreaper
// reparenting by construction (see the plan doc's own "investigated and
// ruled out" note).
struct SubreaperSetDetails {
    uint8_t enabled;
};

// exec-time credential-delta -
// captures a setuid-bit/file-capability elevation that happens automatically
// during execve() with zero setuid()/capset() syscall from the process
// itself (the built-in capability LSM's cap_bprm_creds_for_exec runs before
// this file's bprm_creds_for_exec hook on this machine's real LSM stacking
// order - lockdown,capability,landlock,yama,apparmor,bpf,ima,evm - so
// bprm->cred already reflects the post-exec identity by the time this hook
// reads it). pre_exec_* is read from the calling task's cred (not yet
// replaced at this hook's execution point); post_exec_* is read from
// bprm->cred.
struct ExecCredentialDeltaDetails {
    uint32_t pre_exec_uid;
    uint32_t post_exec_euid;
    uint64_t pre_exec_cap_effective;
    uint64_t post_exec_cap_effective;
};

// setns/unshare/mount/chroot
// (existing hooks, telemetry-only addition - the is_container_restricted()
// enforcement they already carry is untouched) plus pivot_root and
// namespace-creating clone/clone3 (new hooks, zero enforcement). flags is
// setns's own `flags` field / unshare's `unshare_flags` / clone's
// `clone_flags` / clone3's clone_args->flags - 0 for mount/chroot/
// pivot_root, which have no equivalent single flags value.
struct NamespaceChangeDetails {
    uint8_t operation; // 0=setns, 1=unshare, 2=mount, 3=chroot,
                        // 4=pivot_root, 5=clone_ns
    uint64_t flags;
};

// Phase 1: task_fix_setuid's BPF producer writes these fields via raw
// details_buffer offsets (warden's/antitheft's Rust mirrors decode them the
// same way); this gives every other consumer a proper named accessor.
// Widened (impersonation plan Phase 1) from {old_uid, new_uid}
// alone - task_fix_setuid only ever compared cred->uid (the REAL uid), so a
// seteuid(0)-then-back pattern (the standard setuid-root-daemon/sudo
// temporary-elevation shape) changed only euid and never fired the hook at
// all. All four uid family members are now captured; the emit condition is
// "any of the four pairs differ", not just old_uid != new_uid.
struct PrivilegeChangeDetails {
    uint32_t old_uid, new_uid;
    uint32_t old_euid, new_euid;
    uint32_t old_suid, new_suid;
    uint32_t old_fsuid, new_fsuid;
};

// task_fix_setgid's gid-family
// mirror of PrivilegeChangeDetails above - same widened-four-pairs shape,
// separate event/struct since uid and gid are genuinely different privilege
// axes (a process can hold elevated group membership with zero uid change).
struct GroupChangeDetails {
    uint32_t old_gid, new_gid;
    uint32_t old_egid, new_egid;
    uint32_t old_sgid, new_sgid;
    uint32_t old_fsgid, new_fsgid;
};

// presence-only companion to
// GroupChangeDetails for a bare setgroups() call - task_fix_setgid may not
// independently observe supplementary-group-list changes (cred->group_info
// lives outside the uid/gid fields task_fix_setgid's own arguments expose),
// so this tracepoint fallback records "setgroups() was called with N
// entries" without attempting to read the actual gid array.
struct GroupSetDetails {
    int32_t gidsetsize;
};

// purely additive - shm_shmat's BPF
// producer already writes these two fields correctly via raw details_buffer
// offsets.
struct IPCAccessDetails {
    int32_t shmid;
    uint32_t creator_uid;
};

// purely additive - task_kill's BPF
// producer already writes these two fields correctly via raw details_buffer
// offsets.
//
// `verdict` (alert-visibility audit): task_kill's Warden-comm/
// admin-session branch actually blocks (`return -EPERM`) while its other two
// branches (antitheft protected-target report, SIGKILL/SIGSTOP-to-monitored
// observation) never do - all three used to emit this identical shape with
// no way to tell which happened, so a real blocked kill and a merely-
// observed one were indistinguishable to any consumer. 1 = delivered
// (observed, not blocked), 2 = denied (blocked). Appended at the end so
// existing byte offsets (target_pid @0, signal @4) are unchanged.
struct SignalDeliveryDetails {
    uint32_t target_pid;
    int32_t signal;
    uint8_t verdict;
};

// Antitheft-only (alert-visibility audit): protected_selfexec_forbidden()'s
// deny, reported by whichever of the three call sites actually hit it.
// `via` distinguishes them since the daemon can't otherwise tell a blocked
// SysV-shm exec from a blocked anonymous mmap/mprotect exec.
struct SelfExecDeniedDetails {
    uint8_t via; // 1 = mmap (anonymous), 2 = mmap (tmpfs-backed file), 3 = mprotect (anonymous), 4 = shmat (SHM_EXEC)
};

struct TelemetryEvent {
    TelemetryHeader header;
    union {
        ProcessCreateDetails process_create;
        ProcessStopDetails process_stop;
        FileReadDetails file_read;
        FileCreateDetails file_create;
        FileWriteDetails file_write;
        FileRenameDetails file_rename;
        FileDeleteDetails file_delete;
        FileOpenDetails file_open;
        NetworkConnectDetails network_connect;
        NetworkAcceptDetails network_accept;
        ImageLoadDetails image_load;
        RegistryWriteDetails registry_write;
        TaskRegisteredDetails task_registered;
        CrossProcessMemoryAccessDetails cross_process_memory_access;
        ThreadContextAccessDetails thread_context_access;
        ImpersonationChangeDetails impersonation_change;
        DpapiOperationDetails dpapi_operation;
        ClipboardWriteDetails clipboard_write;
        CallStackFrameDetails call_stack_frame;
        MemoryProtectDetails memory_protect;
        MemoryMapDetails memory_map;
        PtraceAttachDetails ptrace_attach;
        SSHAuthDetails ssh_auth;
        TerminalCommandDetails terminal_command;
        Dup2Details dup2;
        ListenDetails listen;
        EnvironmentMarkersDetails environment_markers;
        PrivilegeChangeDetails privilege_change;
        IPCAccessDetails ipc_access;
        SignalDeliveryDetails signal_delivery;
        GroupChangeDetails group_change;
        GroupSetDetails group_set;
        CrossMemoryAccessDetails cross_memory_access;
        CapabilityChangeDetails capability_change;
        PrctlKeepcapsDetails prctl_keepcaps;
        CommRenameDetails comm_rename;
        SubreaperSetDetails subreaper_set;
        ExecCredentialDeltaDetails exec_credential_delta;
        NamespaceChangeDetails namespace_change;
        ProcessForkDetails process_fork;
        AppModificationDetails app_modification;
        FileLinkDetails file_link;
        SelfExecDeniedDetails self_exec_denied;
        SecretBrokerConnectDetails secret_broker_connect;
        ProcessCommandLineDetails process_command_line;
    } details;
};

#pragma pack(pop)

// ABI lock. The Windows agent decodes TelemetryEvent straight off the named
// pipe (src/windows/api-specs.md); there is no version field, so the on-wire
// size must not drift silently. If either assert fires, the pipe ABI changed -
// rebuild the agent's mirror struct and bump both sides together.
static_assert(sizeof(TelemetryHeader) == 30, "TelemetryHeader ABI changed");
// 1590 -> 1598: ProcessCreateDetails grew by 8 bytes (mnt_ns_inum/
// pid_ns_inum, container support) - it remains the largest union member, so
// this is also TelemetryEvent's new total size. Rebuild every consumer's
// mirror struct together (antitheft-agent's telemetry.rs EXPECTED_EVENT_SIZE;
// warden's src/types.rs::TelemetryEventRaw reads a fixed, already-smaller
// details_buffer independent of this constant and is unaffected either way -
// see antitheft-agent's container-support notes for why).
// 1606 -> 1608: ProcessCreateDetails gained pkg_lifecycle and
// kernel_verdicts (the exec's install verdict, carried with its event).
static_assert(sizeof(TelemetryEvent) == 1608, "TelemetryEvent ABI changed");

#endif // KINNECTOR_TELEMETRY_H
