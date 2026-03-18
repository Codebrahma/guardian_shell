#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm,
        bpf_get_current_cgroup_id,
        bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    macros::{lsm, map, tracepoint},
    maps::{HashMap, LpmTrie, PerCpuArray, PerfEventArray},
    programs::{LsmContext, TracePointContext},
};
use aya_ebpf::maps::lpm_trie::Key;
use guardian_common::{ExecEvent, FileAccessEvent, NetworkEvent, MAX_FILENAME_LEN, EVENT_FLAG_TRUNCATED};

// =============================================================================
// Maps (Phase 8: capacity increased from 256 to 1024 for rule/config maps)
// =============================================================================

/// Process comm names to monitor (key: comm, value: 1).
#[map]
static WATCHED_COMMS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(1024, 0);

/// Process comm names in enforcement mode (key: comm, value: 1).
#[map]
static ENFORCE_COMMS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(1024, 0);

/// Watched cgroup IDs (key: cgroup_id, value: 1).
/// Phase 3: Primary identification method — unspoofable.
#[map]
static WATCHED_CGROUPS: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

/// Enforced cgroup IDs (key: cgroup_id, value: 1).
/// Phase 3: Enforcement for cgroup-based agents.
#[map]
static ENFORCE_CGROUPS: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

/// Default action per cgroup: key = cgroup_id, value: 0 = deny, 1 = allow.
#[map]
static CGROUP_DEFAULT_ACTION: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

/// Per-CPU scratch buffer for file access events.
#[map]
static EVENT_BUF: PerCpuArray<FileAccessEvent> = PerCpuArray::with_max_entries(1, 0);

/// Perf buffer for file access events to userspace.
#[map]
static EVENTS: PerfEventArray<FileAccessEvent> = PerfEventArray::new(0);

/// Per-CPU scratch buffer for exec events.
#[map]
static EXEC_BUF: PerCpuArray<ExecEvent> = PerCpuArray::with_max_entries(1, 0);

/// Perf buffer for exec events to userspace.
#[map]
static EXEC_EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

/// Pending deny decisions: key = pid_tgid, value = 1.
/// Set by the tracepoint, read by the LSM hook to block access.
#[map]
static PENDING_DENY: HashMap<u64, u8> = HashMap::with_max_entries(4096, 0);

/// Deny rules: LPM trie for prefix matching (/** patterns).
/// Key data is the path prefix (with trailing '/'), prefix_len in bits.
#[map]
static DENY_PREFIXES: LpmTrie<[u8; MAX_FILENAME_LEN], u8> =
    LpmTrie::with_max_entries(1024, 0);

/// Deny rules: HashMap for exact path matching.
#[map]
static DENY_EXACT: HashMap<[u8; MAX_FILENAME_LEN], u8> =
    HashMap::with_max_entries(1024, 0);

/// Allow rules: LPM trie for prefix matching (/** patterns).
#[map]
static ALLOW_PREFIXES: LpmTrie<[u8; MAX_FILENAME_LEN], u8> =
    LpmTrie::with_max_entries(1024, 0);

/// Allow rules: HashMap for exact path matching.
#[map]
static ALLOW_EXACT: HashMap<[u8; MAX_FILENAME_LEN], u8> =
    HashMap::with_max_entries(1024, 0);

/// Default action per comm: key = comm, value: 0 = deny, 1 = allow.
#[map]
static DEFAULT_ACTION: HashMap<[u8; 16], u8> = HashMap::with_max_entries(1024, 0);

/// Child PID tracking: key = child tgid, value = parent tgid.
#[map]
static CHILD_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(4096, 0);

/// Watched TGIDs: key = tgid, value = 1. Catches all threads of watched processes.
#[map]
static WATCHED_TGIDS: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

/// Enforce TGIDs: key = tgid, value = 1. Enforcement enabled for all threads of these processes.
#[map]
static ENFORCE_TGIDS: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

// =============================================================================
// Exec Enforcement Maps (Phase 7, capacity increased in Phase 8)
// =============================================================================

/// Exec deny rules: exact path matching.
#[map]
static EXEC_DENY_EXACT: HashMap<[u8; MAX_FILENAME_LEN], u8> =
    HashMap::with_max_entries(1024, 0);

/// Exec deny rules: LPM trie for prefix matching (/** patterns).
#[map]
static EXEC_DENY_PREFIXES: LpmTrie<[u8; MAX_FILENAME_LEN], u8> =
    LpmTrie::with_max_entries(1024, 0);

/// Exec allow rules: exact path matching.
#[map]
static EXEC_ALLOW_EXACT: HashMap<[u8; MAX_FILENAME_LEN], u8> =
    HashMap::with_max_entries(1024, 0);

/// Exec allow rules: LPM trie for prefix matching (/** patterns).
#[map]
static EXEC_ALLOW_PREFIXES: LpmTrie<[u8; MAX_FILENAME_LEN], u8> =
    LpmTrie::with_max_entries(1024, 0);

/// Default exec action per comm: key = comm, value: 0 = deny, 1 = allow.
#[map]
static EXEC_DEFAULT_ACTION: HashMap<[u8; 16], u8> = HashMap::with_max_entries(1024, 0);

/// Default exec action per cgroup: key = cgroup_id, value: 0 = deny, 1 = allow.
#[map]
static EXEC_CGROUP_DEFAULT_ACTION: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

/// Pending exec deny decisions: key = pid_tgid, value = 1.
/// Set by the execve tracepoint, consumed by the bprm_check_security LSM hook.
#[map]
static PENDING_EXEC_DENY: HashMap<u64, u8> = HashMap::with_max_entries(4096, 0);

// =============================================================================
// Network Monitoring + Enforcement Maps (Phase 7 monitoring, Phase 9 enforcement)
// =============================================================================

/// Per-CPU scratch buffer for network events.
#[map]
static NET_EVENT_BUF: PerCpuArray<NetworkEvent> = PerCpuArray::with_max_entries(1, 0);

/// Perf buffer for network events to userspace.
#[map]
static NET_EVENTS: PerfEventArray<NetworkEvent> = PerfEventArray::new(0);

/// Pending network deny decisions: key = pid_tgid, value = 1.
/// Set by sys_enter_connect tracepoint, consumed by LSM socket_connect.
#[map]
static PENDING_NET_DENY: HashMap<u64, u8> = HashMap::with_max_entries(4096, 0);

/// Network deny rules: denied destination ports. key = port (u16 as u32), value = 1.
#[map]
static NET_DENY_PORTS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

/// Network allow rules: allowed destination ports. key = port (u16 as u32), value = 1.
#[map]
static NET_ALLOW_PORTS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

/// Default network action per comm: key = comm, value: 0 = deny, 1 = allow.
#[map]
static NET_DEFAULT_ACTION: HashMap<[u8; 16], u8> = HashMap::with_max_entries(1024, 0);

/// Default network action per cgroup: key = cgroup_id, value: 0 = deny, 1 = allow.
#[map]
static NET_CGROUP_DEFAULT_ACTION: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

// =============================================================================
// Phase 8 Maps: Inode Protection (rename/unlink/hardlink enforcement)
// =============================================================================

/// Pending rename deny decisions: key = pid_tgid, value = 1.
/// Set by sys_enter_renameat2, consumed by LSM inode_rename.
#[map]
static PENDING_RENAME_DENY: HashMap<u64, u8> = HashMap::with_max_entries(4096, 0);

/// Pending unlink deny decisions: key = pid_tgid, value = 1.
/// Set by sys_enter_unlinkat, consumed by LSM inode_unlink.
#[map]
static PENDING_UNLINK_DENY: HashMap<u64, u8> = HashMap::with_max_entries(4096, 0);

/// Pending hardlink deny decisions: key = pid_tgid, value = 1.
/// Set by sys_enter_linkat, consumed by LSM inode_link.
#[map]
static PENDING_LINK_DENY: HashMap<u64, u8> = HashMap::with_max_entries(4096, 0);

// =============================================================================
// Phase 8 Maps: Dynamic Linker Detection
// =============================================================================

/// Known dynamic linker paths. When execve sees one, check argv[1] for the real binary.
#[map]
static DYNAMIC_LINKERS: HashMap<[u8; MAX_FILENAME_LEN], u8> =
    HashMap::with_max_entries(16, 0);

// =============================================================================
// Phase 8 Maps: Fail-Closed Mode
// =============================================================================

/// Cgroups configured for fail-closed behavior (deny on eBPF error).
/// key = cgroup_id, value = 1.
#[map]
static FAIL_CLOSED_CGROUPS: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

// =============================================================================
// Helpers
// =============================================================================

/// Check if the current process is watched, using 3-tier identification:
/// 1. Cgroup ID (Phase 3 — strongest, unspoofable)
/// 2. TGID / child PID tracking (Phase 2)
/// 3. Comm name (Phase 1 — fallback)
#[inline(always)]
fn is_process_watched(comm: &[u8; 16], tgid: u32, cgroup_id: u64) -> bool {
    // Priority 1: Cgroup-based identification (cannot be spoofed)
    if unsafe { WATCHED_CGROUPS.get(&cgroup_id) }.is_some() {
        return true;
    }
    // Priority 2: Comm-based and PID-based (Phase 1 & 2 fallback)
    unsafe { WATCHED_COMMS.get(comm) }.is_some()
        || unsafe { WATCHED_TGIDS.get(&tgid) }.is_some()
        || unsafe { CHILD_PIDS.get(&tgid) }.is_some()
}

/// Check if the current process is in enforcement mode.
#[inline(always)]
fn is_process_enforcing(comm: &[u8; 16], tgid: u32, cgroup_id: u64) -> bool {
    // Priority 1: Cgroup-based enforcement
    if unsafe { ENFORCE_CGROUPS.get(&cgroup_id) }.is_some() {
        return true;
    }
    // Priority 2: Comm/TGID-based enforcement
    unsafe { ENFORCE_COMMS.get(comm) }.is_some()
        || unsafe { ENFORCE_TGIDS.get(&tgid) }.is_some()
}

/// Evaluate exec deny/allow rules using map lookups (no loops).
/// Returns true if execution is allowed.
#[inline(always)]
fn evaluate_exec_policy(
    filename: &[u8; MAX_FILENAME_LEN],
    filename_len: usize,
    comm: &[u8; 16],
    cgroup_id: u64,
) -> bool {
    let prefix_bits = (filename_len as u32) * 8;
    let lpm_key = Key::new(prefix_bits, *filename);

    if unsafe { EXEC_DENY_EXACT.get(filename) }.is_some() {
        return false;
    }
    if EXEC_DENY_PREFIXES.get(&lpm_key).is_some() {
        return false;
    }
    if unsafe { EXEC_ALLOW_EXACT.get(filename) }.is_some() {
        return true;
    }
    if EXEC_ALLOW_PREFIXES.get(&lpm_key).is_some() {
        return true;
    }
    if let Some(&action) = unsafe { EXEC_CGROUP_DEFAULT_ACTION.get(&cgroup_id) } {
        return action == 1;
    }
    match unsafe { EXEC_DEFAULT_ACTION.get(comm) } {
        Some(&action) => action == 1,
        None => true, // fail-open if no exec default configured
    }
}

/// Evaluate deny/allow rules using map lookups (no loops).
/// Returns true if access is allowed.
#[inline(always)]
fn evaluate_policy(
    filename: &[u8; MAX_FILENAME_LEN],
    filename_len: usize,
    comm: &[u8; 16],
    cgroup_id: u64,
) -> bool {
    let prefix_bits = (filename_len as u32) * 8;
    let lpm_key = Key::new(prefix_bits, *filename);

    // Step 1: Check deny exact match
    if unsafe { DENY_EXACT.get(filename) }.is_some() {
        return false;
    }

    // Step 2: Check deny prefix match (/** patterns)
    if DENY_PREFIXES.get(&lpm_key).is_some() {
        return false;
    }

    // Step 3: Check allow exact match
    if unsafe { ALLOW_EXACT.get(filename) }.is_some() {
        return true;
    }

    // Step 4: Check allow prefix match (/** patterns)
    if ALLOW_PREFIXES.get(&lpm_key).is_some() {
        return true;
    }

    // Step 5: Default action — check by cgroup first, then by comm
    if let Some(&action) = unsafe { CGROUP_DEFAULT_ACTION.get(&cgroup_id) } {
        return action == 1;
    }
    match unsafe { DEFAULT_ACTION.get(comm) } {
        Some(&action) => action == 1,
        None => true, // fail-open if no default configured
    }
}

/// Evaluate network deny/allow rules using port-based map lookups.
/// Returns true if the connection is allowed.
#[inline(always)]
fn evaluate_net_policy(
    port: u16,
    comm: &[u8; 16],
    cgroup_id: u64,
) -> bool {
    let port_key = port as u32;

    // Step 1: Check deny port
    if unsafe { NET_DENY_PORTS.get(&port_key) }.is_some() {
        return false;
    }

    // Step 2: Check allow port
    if unsafe { NET_ALLOW_PORTS.get(&port_key) }.is_some() {
        return true;
    }

    // Step 3: Default action — check by cgroup first, then by comm
    if let Some(&action) = unsafe { NET_CGROUP_DEFAULT_ACTION.get(&cgroup_id) } {
        return action == 1;
    }
    match unsafe { NET_DEFAULT_ACTION.get(comm) } {
        Some(&action) => action == 1,
        None => true, // fail-open if no net default configured
    }
}

/// Phase 8: Check if cgroup is in fail-closed mode.
/// Returns -EACCES (-13) for fail-closed, 0 for fail-open.
#[inline(always)]
fn fail_mode_for_cgroup() -> i32 {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if unsafe { FAIL_CLOSED_CGROUPS.get(&cgroup_id) }.is_some() {
        -13 // -EACCES: fail-closed
    } else {
        0 // fail-open (default)
    }
}

// =============================================================================
// Tracepoint: sys_enter_openat (monitoring + enforcement decision)
// =============================================================================

#[tracepoint]
pub fn guardian_file_open(ctx: TracePointContext) -> u32 {
    match try_guardian_file_open(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_file_open(ctx: &TracePointContext) -> Result<u32, i64> {
    let comm = bpf_get_current_comm().map_err(|e| e)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if !is_process_watched(&comm, tgid, cgroup_id) {
        return Ok(0);
    }

    let event = unsafe {
        let ptr = EVENT_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    event.tgid = tgid;
    event.pid = pid_tgid as u32;
    event.uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    event.comm = comm;
    event.status_flags = 0;

    // Read tracepoint args (x86_64 offsets for sys_enter_openat)
    let filename_ptr: u64 = unsafe { ctx.read_at(24)? };
    let flags: u64 = unsafe { ctx.read_at(32)? };
    event.flags = flags as u32;

    match unsafe {
        bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.filename)
    } {
        Ok(name_bytes) => {
            event.filename_len = name_bytes.len() as u32;
            // Phase 8: Detect path truncation
            if name_bytes.len() >= MAX_FILENAME_LEN - 1 {
                event.status_flags |= EVENT_FLAG_TRUNCATED;
            }
        }
        Err(_) => {
            event.filename_len = 0;
        }
    }

    // Kernel-side policy evaluation for enforcement
    if is_process_enforcing(&comm, tgid, cgroup_id) && event.filename_len > 0 {
        if event.status_flags & EVENT_FLAG_TRUNCATED != 0 {
            // Phase 8: Truncated path — deny for safety (can't match policy correctly)
            let _ = PENDING_DENY.insert(&pid_tgid, &1u8, 0);
        } else {
            let allowed = evaluate_policy(&event.filename, event.filename_len as usize, &comm, cgroup_id);
            if !allowed {
                let _ = PENDING_DENY.insert(&pid_tgid, &1u8, 0);
            }
        }
    }

    // Always send event to userspace for logging
    EVENTS.output(ctx, event, 0);

    Ok(0)
}

// =============================================================================
// Tracepoint: sys_enter_openat2 (same as openat, covers newer syscall)
// =============================================================================

/// Handles openat2 syscall (Linux 5.6+). Reuses the same logic as openat.
/// openat2 tracepoint args (x86_64): dfd at 16, filename at 24, how at 32.
/// The 'how' arg is a struct open_how * (flags, mode, resolve fields).
#[tracepoint]
pub fn guardian_file_openat2(ctx: TracePointContext) -> u32 {
    match try_guardian_file_openat2(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_file_openat2(ctx: &TracePointContext) -> Result<u32, i64> {
    let comm = bpf_get_current_comm().map_err(|e| e)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if !is_process_watched(&comm, tgid, cgroup_id) {
        return Ok(0);
    }

    let event = unsafe {
        let ptr = EVENT_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    event.tgid = tgid;
    event.pid = pid_tgid as u32;
    event.uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    event.comm = comm;
    event.status_flags = 0;

    // Read tracepoint args (x86_64 offsets for sys_enter_openat2)
    // filename pointer at offset 24 (same position as openat)
    let filename_ptr: u64 = unsafe { ctx.read_at(24)? };

    // openat2's third arg is struct open_how * at offset 32.
    // Read flags from the struct (first u64 field of open_how).
    let how_ptr: u64 = unsafe { ctx.read_at(32)? };
    if how_ptr != 0 {
        // open_how.flags is the first field (u64)
        match unsafe {
            aya_ebpf::helpers::bpf_probe_read_user(how_ptr as *const u64)
        } {
            Ok(flags) => { event.flags = flags as u32; }
            Err(_) => { event.flags = 0; }
        }
    } else {
        event.flags = 0;
    }

    match unsafe {
        bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.filename)
    } {
        Ok(name_bytes) => {
            event.filename_len = name_bytes.len() as u32;
            if name_bytes.len() >= MAX_FILENAME_LEN - 1 {
                event.status_flags |= EVENT_FLAG_TRUNCATED;
            }
        }
        Err(_) => {
            event.filename_len = 0;
        }
    }

    // Kernel-side policy evaluation for enforcement
    if is_process_enforcing(&comm, tgid, cgroup_id) && event.filename_len > 0 {
        if event.status_flags & EVENT_FLAG_TRUNCATED != 0 {
            let _ = PENDING_DENY.insert(&pid_tgid, &1u8, 0);
        } else {
            let allowed = evaluate_policy(&event.filename, event.filename_len as usize, &comm, cgroup_id);
            if !allowed {
                let _ = PENDING_DENY.insert(&pid_tgid, &1u8, 0);
            }
        }
    }

    // Always send event to userspace for logging
    EVENTS.output(ctx, event, 0);

    Ok(0)
}

// =============================================================================
// LSM: file_open (enforcement - actually blocks access)
// =============================================================================

#[lsm(hook = "file_open")]
pub fn guardian_enforce_file_open(ctx: LsmContext) -> i32 {
    match try_enforce_file_open(&ctx) {
        Ok(ret) => ret,
        Err(_) => fail_mode_for_cgroup(), // Phase 8: fail-closed if configured
    }
}

fn try_enforce_file_open(_ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if unsafe { PENDING_DENY.get(&pid_tgid) }.is_some() {
        let _ = PENDING_DENY.remove(&pid_tgid);
        return Ok(-13); // -EACCES
    }

    Ok(0)
}

// =============================================================================
// Tracepoint: sys_enter_execve (command execution monitoring)
// =============================================================================

#[tracepoint]
pub fn guardian_exec_monitor(ctx: TracePointContext) -> u32 {
    match try_guardian_exec_monitor(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_exec_monitor(ctx: &TracePointContext) -> Result<u32, i64> {
    let comm = bpf_get_current_comm().map_err(|e| e)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if !is_process_watched(&comm, tgid, cgroup_id) {
        return Ok(0);
    }

    let event = unsafe {
        let ptr = EXEC_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    event.tgid = tgid;
    event.pid = pid_tgid as u32;
    event.uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    event.comm = comm;

    // sys_enter_execve: filename pointer at offset 16 (x86_64)
    let filename_ptr: u64 = unsafe { ctx.read_at(16)? };

    match unsafe {
        bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.filename)
    } {
        Ok(name_bytes) => {
            event.filename_len = name_bytes.len() as u32;
        }
        Err(_) => {
            event.filename_len = 0;
        }
    }

    // Phase 7+8: Kernel-side exec policy evaluation for enforcement
    if is_process_enforcing(&comm, tgid, cgroup_id) && event.filename_len > 0 {
        // Phase 8: Dynamic linker detection — if the binary is a known linker,
        // read argv[1] to find the real binary and evaluate policy on that.
        // We read argv[1] directly into event.filename to avoid a 256-byte
        // stack allocation that would exceed the BPF 512-byte stack limit.
        if unsafe { DYNAMIC_LINKERS.get(&event.filename) }.is_some() {
            // argv pointer is at offset 24 for sys_enter_execve (x86_64)
            let argv_ptr: u64 = unsafe { ctx.read_at(24)? };
            if argv_ptr != 0 {
                // argv[1] = *(argv_ptr + 8) — second element of the pointer array
                let argv1_ptr_result: Result<u64, i64> = unsafe {
                    aya_ebpf::helpers::bpf_probe_read_user((argv_ptr + 8) as *const u64)
                };
                if let Ok(argv1_ptr) = argv1_ptr_result {
                    if argv1_ptr != 0 {
                        // Read the real binary path directly into event.filename
                        // (overwriting the linker path — we already checked it)
                        if let Ok(name_bytes) = unsafe {
                            bpf_probe_read_user_str_bytes(argv1_ptr as *const u8, &mut event.filename)
                        } {
                            let real_len = name_bytes.len();
                            if real_len > 0 {
                                event.filename_len = real_len as u32;
                                let allowed = evaluate_exec_policy(&event.filename, real_len, &comm, cgroup_id);
                                if !allowed {
                                    let _ = PENDING_EXEC_DENY.insert(&pid_tgid, &1u8, 0);
                                }
                            }
                        }
                    }
                }
            }
        } else {
            let allowed = evaluate_exec_policy(&event.filename, event.filename_len as usize, &comm, cgroup_id);
            if !allowed {
                let _ = PENDING_EXEC_DENY.insert(&pid_tgid, &1u8, 0);
            }
        }
    }

    EXEC_EVENTS.output(ctx, event, 0);

    Ok(0)
}

// =============================================================================
// Phase 8: Tracepoint: sys_enter_execveat (covers memfd_create + AT_EMPTY_PATH)
// =============================================================================

/// Hooks the execveat syscall. Catches AT_EMPTY_PATH fd-based execution
/// (e.g., memfd_create + execveat) that bypasses the normal execve tracepoint.
#[tracepoint]
pub fn guardian_execveat_monitor(ctx: TracePointContext) -> u32 {
    match try_guardian_execveat_monitor(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_execveat_monitor(ctx: &TracePointContext) -> Result<u32, i64> {
    let comm = bpf_get_current_comm().map_err(|e| e)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if !is_process_watched(&comm, tgid, cgroup_id) {
        return Ok(0);
    }

    // sys_enter_execveat args (x86_64):
    // dfd at 16, filename at 24, argv at 32, envp at 40, flags at 48
    let flags: i32 = unsafe { ctx.read_at(48)? };

    let event = unsafe {
        let ptr = EXEC_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    event.tgid = tgid;
    event.pid = pid_tgid as u32;
    event.uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    event.comm = comm;

    // AT_EMPTY_PATH = 0x1000 — execution via fd (likely memfd)
    if flags & 0x1000 != 0 {
        // This is an AT_EMPTY_PATH execveat — likely memfd execution.
        // For enforced agents, deny unconditionally (no filesystem path to evaluate).
        if is_process_enforcing(&comm, tgid, cgroup_id) {
            let _ = PENDING_EXEC_DENY.insert(&pid_tgid, &1u8, 0);
        }
        // Set a placeholder filename for the event
        let memfd_path = b"/memfd:anonymous";
        let mut i = 0;
        while i < memfd_path.len() && i < MAX_FILENAME_LEN {
            event.filename[i] = memfd_path[i];
            i += 1;
        }
        while i < MAX_FILENAME_LEN {
            event.filename[i] = 0;
            i += 1;
        }
        event.filename_len = memfd_path.len() as u32;
    } else {
        // Normal execveat with a pathname — read and evaluate like execve
        let filename_ptr: u64 = unsafe { ctx.read_at(24)? };

        match unsafe {
            bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.filename)
        } {
            Ok(name_bytes) => {
                event.filename_len = name_bytes.len() as u32;
            }
            Err(_) => {
                event.filename_len = 0;
            }
        }

        if is_process_enforcing(&comm, tgid, cgroup_id) && event.filename_len > 0 {
            let allowed = evaluate_exec_policy(&event.filename, event.filename_len as usize, &comm, cgroup_id);
            if !allowed {
                let _ = PENDING_EXEC_DENY.insert(&pid_tgid, &1u8, 0);
            }
        }
    }

    EXEC_EVENTS.output(ctx, event, 0);

    Ok(0)
}

// =============================================================================
// Tracepoint: sched_process_fork (child process tracking)
// =============================================================================

#[tracepoint]
pub fn guardian_fork_track(ctx: TracePointContext) -> u32 {
    match try_guardian_fork_track(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_fork_track(ctx: &TracePointContext) -> Result<u32, i64> {
    let comm = bpf_get_current_comm().map_err(|e| e)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let parent_tgid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if !is_process_watched(&comm, parent_tgid, cgroup_id) {
        return Ok(0);
    }

    // sched_process_fork: child_pid at offset 44 (x86_64)
    let child_pid: u32 = unsafe { ctx.read_at(44)? };
    let _ = CHILD_PIDS.insert(&child_pid, &parent_tgid, 0);
    let _ = WATCHED_TGIDS.insert(&child_pid, &1u8, 0);

    Ok(0)
}

// =============================================================================
// Tracepoint: sched_process_exit (cleanup tracked processes)
// =============================================================================

#[tracepoint]
pub fn guardian_exit_track(ctx: TracePointContext) -> u32 {
    match try_guardian_exit_track(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_exit_track(_ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let _ = CHILD_PIDS.remove(&tgid);
    Ok(0)
}

// =============================================================================
// LSM: bprm_check_security (exec enforcement — blocks command execution)
// =============================================================================

#[lsm(hook = "bprm_check_security")]
pub fn guardian_enforce_exec(ctx: LsmContext) -> i32 {
    match try_enforce_exec(&ctx) {
        Ok(ret) => ret,
        Err(_) => fail_mode_for_cgroup(), // Phase 8: fail-closed if configured
    }
}

fn try_enforce_exec(_ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if unsafe { PENDING_EXEC_DENY.get(&pid_tgid) }.is_some() {
        let _ = PENDING_EXEC_DENY.remove(&pid_tgid);
        return Ok(-1); // -EPERM
    }

    Ok(0)
}

// =============================================================================
// Tracepoint: sys_enter_open (legacy open syscall — belt-and-suspenders)
// =============================================================================

#[tracepoint]
pub fn guardian_file_open_legacy(ctx: TracePointContext) -> u32 {
    match try_guardian_file_open_legacy(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_file_open_legacy(ctx: &TracePointContext) -> Result<u32, i64> {
    let comm = bpf_get_current_comm().map_err(|e| e)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if !is_process_watched(&comm, tgid, cgroup_id) {
        return Ok(0);
    }

    let event = unsafe {
        let ptr = EVENT_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    event.tgid = tgid;
    event.pid = pid_tgid as u32;
    event.uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    event.comm = comm;
    event.status_flags = 0;

    // sys_enter_open (x86_64): filename at offset 16, flags at offset 24
    let filename_ptr: u64 = unsafe { ctx.read_at(16)? };
    let flags: u64 = unsafe { ctx.read_at(24)? };
    event.flags = flags as u32;

    match unsafe {
        bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.filename)
    } {
        Ok(name_bytes) => {
            event.filename_len = name_bytes.len() as u32;
            if name_bytes.len() >= MAX_FILENAME_LEN - 1 {
                event.status_flags |= EVENT_FLAG_TRUNCATED;
            }
        }
        Err(_) => {
            event.filename_len = 0;
        }
    }

    if is_process_enforcing(&comm, tgid, cgroup_id) && event.filename_len > 0 {
        if event.status_flags & EVENT_FLAG_TRUNCATED != 0 {
            let _ = PENDING_DENY.insert(&pid_tgid, &1u8, 0);
        } else {
            let allowed = evaluate_policy(&event.filename, event.filename_len as usize, &comm, cgroup_id);
            if !allowed {
                let _ = PENDING_DENY.insert(&pid_tgid, &1u8, 0);
            }
        }
    }

    EVENTS.output(ctx, event, 0);

    Ok(0)
}

// =============================================================================
// Tracepoint: sys_enter_connect (network connection monitoring)
// =============================================================================

#[tracepoint]
pub fn guardian_net_connect(ctx: TracePointContext) -> u32 {
    match try_guardian_net_connect(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_net_connect(ctx: &TracePointContext) -> Result<u32, i64> {
    let comm = bpf_get_current_comm().map_err(|e| e)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if !is_process_watched(&comm, tgid, cgroup_id) {
        return Ok(0);
    }

    // sys_enter_connect (x86_64): fd at 16, sockaddr* at 24, addrlen at 32
    let addr_ptr: u64 = unsafe { ctx.read_at(24)? };
    if addr_ptr == 0 {
        return Ok(0);
    }

    // Read sa_family (first 2 bytes of sockaddr)
    let family: u16 = unsafe {
        aya_ebpf::helpers::bpf_probe_read_user(addr_ptr as *const u16)?
    };

    // Only monitor AF_INET (2) and AF_INET6 (10)
    if family != 2 && family != 10 {
        return Ok(0);
    }

    let event = unsafe {
        let ptr = NET_EVENT_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    event.tgid = tgid;
    event.pid = pid_tgid as u32;
    event.uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    event.comm = comm;
    event.family = family as u8;
    event._pad_proto = 0;
    event.dest_addr4 = 0;
    event.dest_addr6 = [0u8; 16];

    if family == 2 {
        // AF_INET: struct sockaddr_in { u16 family, u16 port, u32 addr, u8 zero[8] }
        let sockaddr: [u8; 8] = unsafe {
            aya_ebpf::helpers::bpf_probe_read_user(addr_ptr as *const [u8; 8])?
        };
        // port at offset 2 (network byte order)
        event.dest_port = u16::from_be_bytes([sockaddr[2], sockaddr[3]]);
        // addr at offset 4
        event.dest_addr4 = u32::from_ne_bytes([sockaddr[4], sockaddr[5], sockaddr[6], sockaddr[7]]);
    } else {
        // AF_INET6: struct sockaddr_in6 { u16 family, u16 port, u32 flowinfo, u8 addr[16], u32 scope }
        let sockaddr: [u8; 28] = unsafe {
            aya_ebpf::helpers::bpf_probe_read_user(addr_ptr as *const [u8; 28])?
        };
        event.dest_port = u16::from_be_bytes([sockaddr[2], sockaddr[3]]);
        let mut addr6 = [0u8; 16];
        let mut i = 0;
        while i < 16 {
            addr6[i] = sockaddr[8 + i];
            i += 1;
        }
        event.dest_addr6 = addr6;
    }

    // Phase 9: Kernel-side network policy evaluation for enforcement.
    // If the port is denied, set PENDING_NET_DENY so LSM socket_connect blocks it.
    if is_process_enforcing(&comm, tgid, cgroup_id) && event.dest_port > 0 {
        let allowed = evaluate_net_policy(event.dest_port, &comm, cgroup_id);
        if !allowed {
            let _ = PENDING_NET_DENY.insert(&pid_tgid, &1u8, 0);
        }
    }

    NET_EVENTS.output(ctx, event, 0);

    Ok(0)
}

// =============================================================================
// Phase 8: Tracepoint: sys_enter_renameat2 (rename monitoring + enforcement)
// =============================================================================

/// Monitors rename operations. Evaluates policy on both source and destination
/// paths. If either path is denied, blocks the rename via PENDING_RENAME_DENY.
#[tracepoint]
pub fn guardian_rename_monitor(ctx: TracePointContext) -> u32 {
    match try_guardian_rename_monitor(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_rename_monitor(ctx: &TracePointContext) -> Result<u32, i64> {
    let comm = bpf_get_current_comm().map_err(|e| e)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if !is_process_watched(&comm, tgid, cgroup_id) {
        return Ok(0);
    }

    if !is_process_enforcing(&comm, tgid, cgroup_id) {
        return Ok(0);
    }

    // sys_enter_renameat2 (x86_64): olddfd=16, oldname=24, newdfd=32, newname=40, flags=48
    let oldname_ptr: u64 = unsafe { ctx.read_at(24)? };
    let newname_ptr: u64 = unsafe { ctx.read_at(40)? };

    // Use EVENT_BUF as scratch space for path reading (only need the filename field)
    let scratch = unsafe {
        let ptr = EVENT_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    // Check source path — if it's denied, block rename of protected files
    if oldname_ptr != 0 {
        if let Ok(name_bytes) = unsafe {
            bpf_probe_read_user_str_bytes(oldname_ptr as *const u8, &mut scratch.filename)
        } {
            let len = name_bytes.len();
            if len > 0 {
                let allowed = evaluate_policy(&scratch.filename, len, &comm, cgroup_id);
                if !allowed {
                    let _ = PENDING_RENAME_DENY.insert(&pid_tgid, &1u8, 0);
                    return Ok(0);
                }
            }
        }
    }

    // Check destination path — block renaming INTO denied directories
    if newname_ptr != 0 {
        if let Ok(name_bytes) = unsafe {
            bpf_probe_read_user_str_bytes(newname_ptr as *const u8, &mut scratch.filename)
        } {
            let len = name_bytes.len();
            if len > 0 {
                let allowed = evaluate_policy(&scratch.filename, len, &comm, cgroup_id);
                if !allowed {
                    let _ = PENDING_RENAME_DENY.insert(&pid_tgid, &1u8, 0);
                }
            }
        }
    }

    Ok(0)
}

// =============================================================================
// Phase 8: LSM: inode_rename (blocks rename of protected files)
// =============================================================================

#[lsm(hook = "inode_rename")]
pub fn guardian_enforce_rename(ctx: LsmContext) -> i32 {
    match try_enforce_rename(&ctx) {
        Ok(ret) => ret,
        Err(_) => fail_mode_for_cgroup(),
    }
}

fn try_enforce_rename(_ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if unsafe { PENDING_RENAME_DENY.get(&pid_tgid) }.is_some() {
        let _ = PENDING_RENAME_DENY.remove(&pid_tgid);
        return Ok(-13); // -EACCES
    }

    Ok(0)
}

// =============================================================================
// Phase 8: Tracepoint: sys_enter_unlinkat (unlink/delete monitoring + enforcement)
// =============================================================================

/// Monitors file deletion. If the target path is denied, blocks the unlink.
#[tracepoint]
pub fn guardian_unlink_monitor(ctx: TracePointContext) -> u32 {
    match try_guardian_unlink_monitor(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_unlink_monitor(ctx: &TracePointContext) -> Result<u32, i64> {
    let comm = bpf_get_current_comm().map_err(|e| e)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if !is_process_watched(&comm, tgid, cgroup_id) {
        return Ok(0);
    }

    if !is_process_enforcing(&comm, tgid, cgroup_id) {
        return Ok(0);
    }

    // sys_enter_unlinkat (x86_64): dfd=16, pathname=24, flag=32
    let pathname_ptr: u64 = unsafe { ctx.read_at(24)? };

    if pathname_ptr == 0 {
        return Ok(0);
    }

    let scratch = unsafe {
        let ptr = EVENT_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    if let Ok(name_bytes) = unsafe {
        bpf_probe_read_user_str_bytes(pathname_ptr as *const u8, &mut scratch.filename)
    } {
        let len = name_bytes.len();
        if len > 0 {
            let allowed = evaluate_policy(&scratch.filename, len, &comm, cgroup_id);
            if !allowed {
                let _ = PENDING_UNLINK_DENY.insert(&pid_tgid, &1u8, 0);
            }
        }
    }

    Ok(0)
}

// =============================================================================
// Phase 8: LSM: inode_unlink (blocks deletion of protected files)
// =============================================================================

#[lsm(hook = "inode_unlink")]
pub fn guardian_enforce_unlink(ctx: LsmContext) -> i32 {
    match try_enforce_unlink(&ctx) {
        Ok(ret) => ret,
        Err(_) => fail_mode_for_cgroup(),
    }
}

fn try_enforce_unlink(_ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if unsafe { PENDING_UNLINK_DENY.get(&pid_tgid) }.is_some() {
        let _ = PENDING_UNLINK_DENY.remove(&pid_tgid);
        return Ok(-13); // -EACCES
    }

    Ok(0)
}

// =============================================================================
// Phase 8: Tracepoint: sys_enter_linkat (hardlink monitoring + enforcement)
// =============================================================================

/// Monitors hardlink creation. If the source file is denied, blocks the link.
#[tracepoint]
pub fn guardian_link_monitor(ctx: TracePointContext) -> u32 {
    match try_guardian_link_monitor(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_link_monitor(ctx: &TracePointContext) -> Result<u32, i64> {
    let comm = bpf_get_current_comm().map_err(|e| e)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if !is_process_watched(&comm, tgid, cgroup_id) {
        return Ok(0);
    }

    if !is_process_enforcing(&comm, tgid, cgroup_id) {
        return Ok(0);
    }

    // sys_enter_linkat (x86_64): olddfd=16, oldname=24, newdfd=32, newname=40, flags=48
    let oldname_ptr: u64 = unsafe { ctx.read_at(24)? };

    if oldname_ptr == 0 {
        return Ok(0);
    }

    let scratch = unsafe {
        let ptr = EVENT_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    // Check if the source file (being hardlinked) is in a deny list
    if let Ok(name_bytes) = unsafe {
        bpf_probe_read_user_str_bytes(oldname_ptr as *const u8, &mut scratch.filename)
    } {
        let len = name_bytes.len();
        if len > 0 {
            let allowed = evaluate_policy(&scratch.filename, len, &comm, cgroup_id);
            if !allowed {
                let _ = PENDING_LINK_DENY.insert(&pid_tgid, &1u8, 0);
            }
        }
    }

    Ok(0)
}

// =============================================================================
// Phase 8: LSM: inode_link (blocks hardlink creation for protected files)
// =============================================================================

#[lsm(hook = "inode_link")]
pub fn guardian_enforce_link(ctx: LsmContext) -> i32 {
    match try_enforce_link(&ctx) {
        Ok(ret) => ret,
        Err(_) => fail_mode_for_cgroup(),
    }
}

fn try_enforce_link(_ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if unsafe { PENDING_LINK_DENY.get(&pid_tgid) }.is_some() {
        let _ = PENDING_LINK_DENY.remove(&pid_tgid);
        return Ok(-13); // -EACCES
    }

    Ok(0)
}

// =============================================================================
// Phase 9: LSM: socket_connect (blocks denied outbound connections)
// =============================================================================

/// Enforces network connection policy. The sys_enter_connect tracepoint evaluates
/// port-based policy and sets PENDING_NET_DENY. This LSM hook consumes the entry
/// and returns -EACCES to block the connection.
#[lsm(hook = "socket_connect")]
pub fn guardian_enforce_net_connect(ctx: LsmContext) -> i32 {
    match try_enforce_net_connect(&ctx) {
        Ok(ret) => ret,
        Err(_) => fail_mode_for_cgroup(),
    }
}

fn try_enforce_net_connect(_ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if unsafe { PENDING_NET_DENY.get(&pid_tgid) }.is_some() {
        let _ = PENDING_NET_DENY.remove(&pid_tgid);
        return Ok(-111); // -ECONNREFUSED: more informative than -EACCES for network
    }

    Ok(0)
}

// =============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
