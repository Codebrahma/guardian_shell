#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm,
        bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    macros::{lsm, map, tracepoint},
    maps::{Array, HashMap, PerCpuArray, PerfEventArray},
    programs::{LsmContext, TracePointContext},
};
use guardian_common::{
    ExecEvent, FileAccessEvent, PolicyRule, MAX_FILENAME_LEN, MAX_POLICY_RULES,
};

// =============================================================================
// Maps
// =============================================================================

/// Process comm names to monitor (key: comm, value: 1 = watched).
#[map]
static WATCHED_COMMS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(256, 0);

/// Process comm names in enforcement mode (key: comm, value: 1 = enforce).
#[map]
static ENFORCE_COMMS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(256, 0);

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
/// Set by the tracepoint when policy says DENY, read by the LSM hook to block.
#[map]
static PENDING_DENY: HashMap<u64, u8> = HashMap::with_max_entries(4096, 0);

/// Deny rules for kernel-side policy evaluation.
#[map]
static DENY_RULES: Array<PolicyRule> = Array::with_max_entries(MAX_POLICY_RULES as u32, 0);

/// Number of active deny rules.
#[map]
static DENY_RULE_COUNT: Array<u32> = Array::with_max_entries(1, 0);

/// Allow rules for kernel-side policy evaluation.
#[map]
static ALLOW_RULES: Array<PolicyRule> = Array::with_max_entries(MAX_POLICY_RULES as u32, 0);

/// Number of active allow rules.
#[map]
static ALLOW_RULE_COUNT: Array<u32> = Array::with_max_entries(1, 0);

/// Default action per comm: key = comm, value: 0 = deny, 1 = allow.
#[map]
static DEFAULT_ACTION: HashMap<[u8; 16], u8> = HashMap::with_max_entries(256, 0);

/// Child PID tracking: key = child tgid, value = parent tgid.
#[map]
static CHILD_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(4096, 0);

// =============================================================================
// Helper: check if process is watched (by comm or child PID)
// =============================================================================

#[inline(always)]
fn is_process_watched(comm: &[u8; 16], tgid: u32) -> bool {
    unsafe { WATCHED_COMMS.get(comm) }.is_some()
        || unsafe { CHILD_PIDS.get(&tgid) }.is_some()
}

// =============================================================================
// Helper: kernel-side policy evaluation
// =============================================================================

/// Evaluate deny/allow rules against a filename. Returns true if access is allowed.
#[inline(always)]
fn evaluate_policy(filename: &[u8; MAX_FILENAME_LEN], filename_len: usize) -> bool {
    // Step 1: Check deny rules
    let deny_count = match DENY_RULE_COUNT.get(0) {
        Some(&count) => count as usize,
        None => 0,
    };

    let mut i = 0u32;
    while i < MAX_POLICY_RULES as u32 {
        if i as usize >= deny_count {
            break;
        }
        if let Some(rule) = DENY_RULES.get(i) {
            if rule_matches(filename, filename_len, rule) {
                return false; // Denied
            }
        }
        i += 1;
    }

    // Step 2: Check allow rules
    let allow_count = match ALLOW_RULE_COUNT.get(0) {
        Some(&count) => count as usize,
        None => 0,
    };

    i = 0;
    while i < MAX_POLICY_RULES as u32 {
        if i as usize >= allow_count {
            break;
        }
        if let Some(rule) = ALLOW_RULES.get(i) {
            if rule_matches(filename, filename_len, rule) {
                return true; // Allowed
            }
        }
        i += 1;
    }

    // Step 3: Default action (checked by caller via DEFAULT_ACTION map)
    // Return false here to indicate "no explicit match" - caller checks default
    false
}

/// Check if a filename matches a policy rule.
#[inline(always)]
fn rule_matches(
    filename: &[u8; MAX_FILENAME_LEN],
    filename_len: usize,
    rule: &PolicyRule,
) -> bool {
    let prefix_len = rule.prefix_len as usize;
    if prefix_len == 0 || filename_len == 0 {
        return false;
    }

    match rule.match_type {
        0 => {
            // Exact match
            if filename_len != prefix_len {
                return false;
            }
            bytes_equal(filename, &rule.path_prefix, prefix_len)
        }
        1 => {
            // Prefix match (/** pattern)
            // Path must start with prefix, and either:
            // - equal the prefix exactly (the directory itself)
            // - have a '/' immediately after the prefix
            if filename_len < prefix_len {
                return false;
            }
            if !bytes_equal(filename, &rule.path_prefix, prefix_len) {
                return false;
            }
            // Exact match with prefix, or next char is '/'
            filename_len == prefix_len
                || (prefix_len < MAX_FILENAME_LEN && filename[prefix_len] == b'/')
        }
        2 => {
            // Single-level wildcard (/* pattern)
            // Path must start with prefix + '/' and have no more '/' after
            if filename_len <= prefix_len {
                return false;
            }
            if !bytes_equal(filename, &rule.path_prefix, prefix_len) {
                return false;
            }
            if prefix_len >= MAX_FILENAME_LEN || filename[prefix_len] != b'/' {
                return false;
            }
            // Check no more '/' after prefix
            let mut j = prefix_len + 1;
            while j < filename_len && j < MAX_FILENAME_LEN {
                if filename[j] == b'/' {
                    return false;
                }
                j += 1;
            }
            true
        }
        _ => false,
    }
}

/// Compare first `len` bytes of two arrays.
#[inline(always)]
fn bytes_equal(a: &[u8; MAX_FILENAME_LEN], b: &[u8; MAX_FILENAME_LEN], len: usize) -> bool {
    let mut i = 0usize;
    while i < len && i < MAX_FILENAME_LEN {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
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

    if !is_process_watched(&comm, tgid) {
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
    let is_enforcing = unsafe { ENFORCE_COMMS.get(&comm) }.is_some();
    if is_enforcing && event.filename_len > 0 {
        let filename_len = event.filename_len as usize;
        let explicitly_allowed = evaluate_policy(&event.filename, filename_len);

        if !explicitly_allowed {
            // Check default action
            let default_allow = match unsafe { DEFAULT_ACTION.get(&comm) } {
                Some(&action) => action == 1,
                None => true, // fail-open if no default configured
            };

            if !default_allow {
                // Mark this syscall for denial by the LSM hook
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
        Err(_) => 0, // fail-open on error
    }
}

fn try_enforce_file_open(_ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    // Check if the tracepoint marked this syscall for denial
    if unsafe { PENDING_DENY.get(&pid_tgid) }.is_some() {
        // Clean up the pending entry
        let _ = PENDING_DENY.remove(&pid_tgid);
        // Block the file access: return -EACCES (13)
        return Ok(-13);
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

    if !is_process_watched(&comm, tgid) {
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

    if !is_process_watched(&comm, parent_tgid) {
        return Ok(0);
    }

    // sched_process_fork format (x86_64):
    //   parent_comm[16] at offset 8
    //   parent_pid at offset 24
    //   child_comm[16] at offset 28
    //   child_pid at offset 44
    let child_pid: u32 = unsafe { ctx.read_at(44)? };

    // Track the child process
    let _ = CHILD_PIDS.insert(&child_pid, &parent_tgid, 0);

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

    // Remove from child tracking if present
    let _ = CHILD_PIDS.remove(&tgid);

    Ok(0)
}

// =============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
