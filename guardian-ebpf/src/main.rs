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
use guardian_common::{ExecEvent, FileAccessEvent, MAX_FILENAME_LEN};

// =============================================================================
// Maps
// =============================================================================

/// Process comm names to monitor (key: comm, value: 1).
#[map]
static WATCHED_COMMS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(256, 0);

/// Process comm names in enforcement mode (key: comm, value: 1).
#[map]
static ENFORCE_COMMS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(256, 0);

/// Watched cgroup IDs (key: cgroup_id, value: 1).
/// Phase 3: Primary identification method — unspoofable.
#[map]
static WATCHED_CGROUPS: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);

/// Enforced cgroup IDs (key: cgroup_id, value: 1).
/// Phase 3: Enforcement for cgroup-based agents.
#[map]
static ENFORCE_CGROUPS: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);

/// Default action per cgroup: key = cgroup_id, value: 0 = deny, 1 = allow.
#[map]
static CGROUP_DEFAULT_ACTION: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);

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
    LpmTrie::with_max_entries(256, 0);

/// Deny rules: HashMap for exact path matching.
#[map]
static DENY_EXACT: HashMap<[u8; MAX_FILENAME_LEN], u8> =
    HashMap::with_max_entries(256, 0);

/// Allow rules: LPM trie for prefix matching (/** patterns).
#[map]
static ALLOW_PREFIXES: LpmTrie<[u8; MAX_FILENAME_LEN], u8> =
    LpmTrie::with_max_entries(256, 0);

/// Allow rules: HashMap for exact path matching.
#[map]
static ALLOW_EXACT: HashMap<[u8; MAX_FILENAME_LEN], u8> =
    HashMap::with_max_entries(256, 0);

/// Default action per comm: key = comm, value: 0 = deny, 1 = allow.
#[map]
static DEFAULT_ACTION: HashMap<[u8; 16], u8> = HashMap::with_max_entries(256, 0);

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

    // Read tracepoint args (x86_64 offsets for sys_enter_openat)
    let filename_ptr: u64 = unsafe { ctx.read_at(24)? };
    let flags: u64 = unsafe { ctx.read_at(32)? };
    event.flags = flags as u32;

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

    // Kernel-side policy evaluation for enforcement
    if is_process_enforcing(&comm, tgid, cgroup_id) && event.filename_len > 0 {
        let allowed = evaluate_policy(&event.filename, event.filename_len as usize, &comm, cgroup_id);
        if !allowed {
            let _ = PENDING_DENY.insert(&pid_tgid, &1u8, 0);
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
        }
        Err(_) => {
            event.filename_len = 0;
        }
    }

    // Kernel-side policy evaluation for enforcement
    if is_process_enforcing(&comm, tgid, cgroup_id) && event.filename_len > 0 {
        let allowed = evaluate_policy(&event.filename, event.filename_len as usize, &comm, cgroup_id);
        if !allowed {
            let _ = PENDING_DENY.insert(&pid_tgid, &1u8, 0);
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
        Err(_) => 0, // fail-open on error
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
