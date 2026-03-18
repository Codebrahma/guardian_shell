# Guardian Shell - Security Fixes & Implementation Guide

> **Version:** Phase 7 → Phase 8 Roadmap
> **Last Updated:** 2026-03-18
> **Companion document:** [security-limitations.md](security-limitations.md)
> **Purpose:** Concrete implementation plans to fix every known security limitation in Guardian Shell, ordered by priority.

---

## Table of Contents

1. [Fix Priority Overview](#1-fix-priority-overview)
2. [File Access Fixes](#2-file-access-fixes)
   - [2.1 Symlink Resolution via bpf_d_path()](#21-symlink-resolution-via-bpf_d_path)
   - [2.2 TOCTOU Mitigation via LSM-Only Enforcement](#22-toctou-mitigation-via-lsm-only-enforcement)
   - [2.3 Inode LSM Hooks for Rename/Unlink/Hardlink](#23-inode-lsm-hooks-for-renameunlinkhardlink)
   - [2.4 Block io_uring via Seccomp](#24-block-io_uring-via-seccomp)
   - [2.5 Handle Path Truncation Safely](#25-handle-path-truncation-safely)
   - [2.6 Increase BPF Map Capacity](#26-increase-bpf-map-capacity)
3. [Command Execution Fixes](#3-command-execution-fixes)
   - [3.1 Block memfd_create + execveat](#31-block-memfd_create--execveat)
   - [3.2 Dynamic Linker Detection](#32-dynamic-linker-detection)
   - [3.3 Enforce-or-Exit Mode](#33-enforce-or-exit-mode)
4. [Network Enforcement Fixes](#4-network-enforcement-fixes)
   - [4.1 Kernel-Level Connection Blocking via cgroup/connect](#41-kernel-level-connection-blocking-via-cgroupconnect)
   - [4.2 DNS Monitoring via Port 53 Inspection](#42-dns-monitoring-via-port-53-inspection)
5. [Approval Workflow Fixes](#5-approval-workflow-fixes)
   - [5.1 Risk-Based Configurable Timeouts](#51-risk-based-configurable-timeouts)
   - [5.2 CLI-Based Permission Approval](#52-cli-based-permission-approval)
   - [5.3 Approval Pattern Anomaly Detection](#53-approval-pattern-anomaly-detection)
   - [5.4 Grant Accumulation Limits](#54-grant-accumulation-limits)
   - [5.5 Improved Justification Analysis](#55-improved-justification-analysis)
6. [Platform & Deployment Fixes](#6-platform--deployment-fixes)
   - [6.1 Strict Enforcement Mode](#61-strict-enforcement-mode)
   - [6.2 Architecture-Portable Tracepoint Offsets via BTF](#62-architecture-portable-tracepoint-offsets-via-btf)
   - [6.3 openat2 Fallback via Seccomp](#63-openat2-fallback-via-seccomp)
7. [Design-Level Fixes](#7-design-level-fixes)
   - [7.1 Configurable Fail-Closed Mode](#71-configurable-fail-closed-mode)
   - [7.2 Dashboard Authentication](#72-dashboard-authentication)
   - [7.3 Live BPF Map Sync on Policy Edit](#73-live-bpf-map-sync-on-policy-edit)
   - [7.4 Full SIGHUP Reload Including Alerting](#74-full-sighup-reload-including-alerting)
8. [Implementation Phases](#8-implementation-phases)

---

## 1. Fix Priority Overview

| Priority | Fix | Severity Addressed | Effort | Kernel Requirement |
|----------|-----|-------------------|--------|-------------------|
| P0 | bpf_d_path() symlink resolution | CRITICAL | High | Linux 5.11+ |
| P0 | cgroup/connect network enforcement | CRITICAL | High | Linux 4.17+ |
| P1 | Inode LSM hooks (rename/unlink/link) | HIGH | Medium | CONFIG_BPF_LSM |
| P1 | Block io_uring via seccomp | HIGH | Low | Any |
| P1 | LSM-only enforcement (TOCTOU fix) | HIGH | High | Linux 5.11+ |
| P2 | Block memfd_create + execveat | MEDIUM-HIGH | Low | Any |
| P2 | Dynamic linker detection | MEDIUM | Medium | Any |
| P2 | Enforce-or-exit mode | MEDIUM | Low | Any |
| P2 | Dashboard authentication | MEDIUM | Medium | N/A |
| P2 | Live BPF map sync | MEDIUM | Medium | Any |
| P3 | Risk-based timeouts | MEDIUM | Low | N/A |
| P3 | CLI permission approval | MEDIUM | Medium | N/A |
| P3 | Anomaly detection | MEDIUM | High | N/A |
| P3 | Grant accumulation limits | MEDIUM | Low | N/A |
| P3 | Path truncation handling | MEDIUM | Low | Any |
| P3 | Increase BPF map capacity | MEDIUM | Low | Any |
| P4 | BTF-based portable offsets | MEDIUM | High | Linux 5.2+ BTF |
| P4 | Improved justification analysis | LOW | Medium | N/A |
| P4 | openat2 seccomp fallback | LOW | Low | Any |
| P4 | Full SIGHUP reload | LOW | Low | N/A |
| P4 | Configurable fail-closed mode | MEDIUM | Medium | Any |

---

## 2. File Access Fixes

### 2.1 Symlink Resolution via bpf_d_path()

**Fixes:** Symlink Attack Vulnerability (CRITICAL)
**Kernel requirement:** Linux 5.11+ (for `bpf_d_path()` helper)

#### Problem Recap

Guardian evaluates policy on raw userspace-provided paths. Symlinks are never resolved, so `ln -s /etc/shadow /tmp/x && cat /tmp/x` bypasses deny rules.

#### Solution: Dual-Layer Enforcement in LSM

Move policy evaluation from the tracepoint into the LSM `file_open` hook, where `bpf_d_path()` provides the kernel-resolved real path.

#### eBPF Changes (`guardian-ebpf/src/main.rs`)

Add a new map to pass resolved paths and a new LSM program:

```rust
// New map: stores resolved path for policy evaluation in LSM
#[map]
static RESOLVED_PATH_BUF: PerCpuArray<[u8; MAX_FILENAME_LEN]> =
    PerCpuArray::with_max_entries(1, 0);

// Enhanced LSM file_open hook
#[lsm(hook = "file_open")]
pub fn guardian_enforce_resolved(ctx: LsmContext) -> i32 {
    match try_guardian_enforce_resolved(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // fail-open on error
    }
}

fn try_guardian_enforce_resolved(ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    // 1. Check if this process is watched (cgroup > TGID > comm)
    if !is_watched_process() {
        return Ok(0); // not monitored, allow
    }

    // 2. Get the file struct pointer from LSM context
    //    arg0 of file_open is struct file *
    let file: *const c_void = unsafe { ctx.arg(0) };

    // 3. Use bpf_d_path() to get the REAL resolved path
    let buf = unsafe {
        let ptr = RESOLVED_PATH_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    // bpf_d_path resolves the full path including symlinks
    let path_len = unsafe {
        // file->f_path is at a known offset in struct file
        bpf_d_path(file as *mut _, buf.as_mut_ptr(), MAX_FILENAME_LEN as u32)
    };

    if path_len < 0 {
        return Ok(0); // can't resolve path, fail-open
    }

    // 4. Evaluate policy against the RESOLVED path
    let action = evaluate_policy(buf, path_len as usize);

    if action == ACTION_DENY {
        return Ok(-13); // -EACCES
    }

    Ok(0) // allow
}
```

#### Why This Works

- `bpf_d_path()` returns the path **after** the kernel has:
  - Followed all symlinks
  - Resolved all mount points
  - Canonicalized the path via the dentry cache
- The agent cannot influence this path — it comes from kernel VFS internals
- `ln -s /etc/shadow /tmp/x` → `bpf_d_path()` returns `/etc/shadow`, not `/tmp/x`

#### Migration Strategy

1. Keep existing tracepoint hooks for **monitoring** (they capture the raw path the agent requested — useful for audit)
2. Move **enforcement decisions** into the LSM hook using resolved paths
3. The tracepoint still populates `PENDING_DENY` as a fallback for kernels < 5.11 without `bpf_d_path()`
4. At startup, detect `bpf_d_path()` availability; if present, use resolved enforcement; if not, fall back to current tracepoint-based enforcement

#### Userspace Changes (`guardian/src/main.rs`)

```rust
// Detect bpf_d_path support at startup
let has_resolved_enforcement = match load_lsm_resolved(&mut bpf) {
    Ok(_) => {
        info!("LSM file_open with bpf_d_path() loaded — symlink-safe enforcement active");
        true
    }
    Err(e) => {
        warn!(
            "bpf_d_path() not available (kernel < 5.11?): {}. \
             Falling back to tracepoint-based enforcement (symlink bypass possible).",
            e
        );
        false
    }
};

// Log enforcement level clearly
if has_resolved_enforcement {
    info!("Enforcement level: FULL (symlink-safe)");
} else if has_lsm {
    info!("Enforcement level: BASIC (raw path, symlink bypass possible)");
} else {
    warn!("Enforcement level: MONITOR ONLY (no LSM support)");
}
```

---

### 2.2 TOCTOU Mitigation via LSM-Only Enforcement

**Fixes:** TOCTOU Race Condition (HIGH)
**Kernel requirement:** Linux 5.11+ (same as 2.1)

#### Problem Recap

The tracepoint reads a userspace path at time T1, but the LSM enforces at time T3. Between T1 and T3, the path could change.

#### Solution: Move Policy Evaluation Entirely Into LSM

This fix is a **direct consequence of implementing 2.1**. Once `bpf_d_path()` is used in the LSM hook:

- The LSM reads the path from **kernel memory** (dentry cache), not userspace
- The kernel has already committed to which file is being opened
- No TOCTOU window exists because the path is read at enforcement time

#### Transition Plan

| Phase | Tracepoint Role | LSM Role |
|-------|----------------|----------|
| Current (Phase 7) | Policy evaluation + `PENDING_DENY` | Read `PENDING_DENY`, enforce |
| After fix | Monitoring + event logging only | Full policy evaluation via `bpf_d_path()` + enforce |

The tracepoint remains useful for:
- Capturing the **requested** path (what the agent asked for — useful for detecting evasion attempts)
- Generating events for the dashboard and alert system
- Logging raw paths for forensic comparison against resolved paths

When the raw path differs from the resolved path, that's a **symlink/TOCTOU evasion attempt** — Guardian should flag this as a high-severity alert:

```rust
// In userspace event processing (main.rs)
// Compare raw path (from tracepoint event) against resolved path (from LSM)
if raw_path != resolved_path {
    alert!(
        "Path mismatch detected: agent '{}' requested '{}' but kernel resolved to '{}'. \
         Possible symlink/TOCTOU evasion attempt.",
        agent_name, raw_path, resolved_path
    );
}
```

---

### 2.3 Inode LSM Hooks for Rename/Unlink/Hardlink

**Fixes:** Rename/Unlink/Hardlink Bypass (HIGH)
**Kernel requirement:** CONFIG_BPF_LSM

#### Solution: Add Three New LSM Hooks

Add hooks for `security_inode_rename`, `security_inode_unlink`, and `security_inode_link` to prevent agents from manipulating files across policy boundaries.

#### eBPF Changes (`guardian-ebpf/src/main.rs`)

```rust
// ── New LSM hook: Block renaming of protected files ──
#[lsm(hook = "inode_rename")]
pub fn guardian_inode_rename(ctx: LsmContext) -> i32 {
    match try_guardian_inode_rename(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_inode_rename(ctx: &LsmContext) -> Result<i32, i64> {
    if !is_watched_process() {
        return Ok(0);
    }

    // LSM inode_rename args:
    // arg0: old_dir (struct inode *)
    // arg1: old_dentry (struct dentry *)
    // arg2: new_dir (struct inode *)
    // arg3: new_dentry (struct dentry *)

    // Use bpf_d_path on old_dentry to get source path
    let old_path = resolve_dentry_path(ctx, 1)?; // arg1 = old_dentry

    // Check if source is in deny list — block rename of protected files
    if is_denied_path(&old_path) {
        return Ok(-13); // -EACCES: cannot rename a denied file
    }

    // Also check if destination would move INTO a denied directory
    // (prevents planting files in protected directories)
    let new_path = resolve_dentry_path(ctx, 3)?; // arg3 = new_dentry
    if is_denied_path(&new_path) {
        return Ok(-13); // -EACCES: cannot rename into denied directory
    }

    Ok(0)
}

// ── New LSM hook: Block deletion of protected files ──
#[lsm(hook = "inode_unlink")]
pub fn guardian_inode_unlink(ctx: LsmContext) -> i32 {
    match try_guardian_inode_unlink(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_inode_unlink(ctx: &LsmContext) -> Result<i32, i64> {
    if !is_watched_process() {
        return Ok(0);
    }

    // arg1: dentry of the file being deleted
    let path = resolve_dentry_path(ctx, 1)?;

    if is_denied_path(&path) {
        return Ok(-13); // cannot delete protected files
    }

    Ok(0)
}

// ── New LSM hook: Block hardlink creation to protected files ──
#[lsm(hook = "inode_link")]
pub fn guardian_inode_link(ctx: LsmContext) -> i32 {
    match try_guardian_inode_link(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_inode_link(ctx: &LsmContext) -> Result<i32, i64> {
    if !is_watched_process() {
        return Ok(0);
    }

    // arg0: old_dentry (source file for hardlink)
    let source_path = resolve_dentry_path(ctx, 0)?;

    // Block hardlinking to any denied file
    if is_denied_path(&source_path) {
        return Ok(-13); // cannot create hardlink to denied file
    }

    Ok(0)
}
```

#### Policy Semantics

| Operation | What Guardian Checks | Decision |
|-----------|---------------------|----------|
| `rename(A, B)` | Is A denied? Is B denied? | Block if either is denied |
| `unlink(A)` | Is A denied? | Block deletion of denied files |
| `link(A, B)` | Is A (source) denied? | Block hardlinks to denied files |

#### Userspace Changes

Add LSM attachment for the three new hooks in `guardian/src/main.rs`:

```rust
// Load inode protection hooks (non-fatal if unavailable)
for (program, hook) in [
    ("guardian_inode_rename", "inode_rename"),
    ("guardian_inode_unlink", "inode_unlink"),
    ("guardian_inode_link", "inode_link"),
] {
    match load_lsm(&mut bpf, program, hook) {
        Ok(_) => info!("LSM {} loaded — {} protection active", hook, hook),
        Err(e) => warn!("LSM {} unavailable: {}. {} bypass possible.", hook, e, hook),
    }
}
```

---

### 2.4 Block io_uring via Seccomp

**Fixes:** io_uring File I/O Bypass (HIGH)
**Kernel requirement:** Any (seccomp is widely available)

#### Solution: Apply Seccomp Filter to Agent Cgroups

Block `io_uring_setup`, `io_uring_enter`, and `io_uring_register` syscalls for monitored agents. Apply the filter in `guardian-launch` before exec'ing the agent.

#### Changes to `guardian-launch/src/main.rs`

```rust
use seccompiler::{
    BpfProgram, SeccompAction, SeccompFilter, SeccompRule,
};

fn apply_iouring_seccomp_filter() -> anyhow::Result<()> {
    // Syscall numbers for io_uring (x86_64)
    const SYS_IO_URING_SETUP: i64 = 425;
    const SYS_IO_URING_ENTER: i64 = 426;
    const SYS_IO_URING_REGISTER: i64 = 427;

    let filter = SeccompFilter::new(
        vec![
            (SYS_IO_URING_SETUP, vec![SeccompRule::new(vec![])?]),
            (SYS_IO_URING_ENTER, vec![SeccompRule::new(vec![])?]),
            (SYS_IO_URING_REGISTER, vec![SeccompRule::new(vec![])?]),
        ]
        .into_iter()
        .collect(),
        // Default action: allow everything else
        SeccompAction::Allow,
        // Action for matched syscalls: return EPERM
        SeccompAction::Errno(libc::EPERM as u32),
        // Target arch
        seccompiler::TargetArch::x86_64,
    )?;

    let bpf_prog: BpfProgram = filter.try_into()?;
    seccompiler::apply_filter(&bpf_prog)?;

    info!("io_uring blocked via seccomp filter");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    // ... existing cgroup setup, IPC registration ...

    // Apply seccomp filter BEFORE exec'ing the agent
    apply_iouring_seccomp_filter()?;

    // Seccomp filters are inherited by child processes
    // so all agent children are also blocked from io_uring

    // exec the agent command
    let err = exec::execvp(&cmd, &args);
    // ...
}
```

#### Why Seccomp

- Seccomp filters are **inherited** by all child processes — the agent and all its children are covered
- Applied at the process level, independent of eBPF/LSM kernel config
- No kernel version requirement beyond basic seccomp support (Linux 3.17+)
- Minimal performance overhead (BPF filter runs before syscall entry)
- `io_uring` operations fail with `EPERM` — the agent gets a clear error, not silent behavior

#### Configuration

Make io_uring blocking configurable per-agent in `config.toml`:

```toml
[[agents]]
name = "untrusted-agent"
identity = "cgroup"
block_io_uring = true   # default: true for security

[agents.file_access]
default = "deny"
allow = ["/tmp/**"]
```

---

### 2.5 Handle Path Truncation Safely

**Fixes:** Path Truncation at 256 Bytes (MEDIUM)

#### Solution: Flag Truncated Paths and Deny by Default

When a path is truncated, the policy decision is unreliable. Add a truncation flag and let policy handle it.

#### eBPF Changes

Add a truncation flag to `FileAccessEvent`:

```rust
// In guardian-common/src/lib.rs
#[repr(C)]
pub struct FileAccessEvent {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub flags: i32,
    pub filename_len: u32,
    pub truncated: u32,   // NEW: 1 if path was truncated, 0 otherwise
    pub comm: [u8; MAX_COMM_LEN],
    pub filename: [u8; MAX_FILENAME_LEN],
}
```

In the tracepoint:

```rust
// In guardian-ebpf/src/main.rs, after bpf_probe_read_user_str_bytes
match unsafe {
    bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.filename)
} {
    Ok(name_bytes) => {
        event.filename_len = name_bytes.len() as u32;
        // Check if the buffer was fully consumed (likely truncated)
        if name_bytes.len() >= MAX_FILENAME_LEN - 1 {
            event.truncated = 1;
        }
    }
    Err(_) => {
        event.filename_len = 0;
        event.truncated = 1; // treat read errors as truncated
    }
}
```

#### Userspace Changes (`guardian/src/main.rs`)

```rust
// In the event processing loop
if event.truncated == 1 {
    warn!(
        "Path truncated at {} bytes for PID {}. Treating as DENY for safety.",
        MAX_FILENAME_LEN, event.pid
    );
    // In enforce mode, truncated paths are denied
    // The kernel-side evaluation already happened, but log the concern
}
```

#### Kernel-Side Policy Change

In the eBPF `evaluate_policy()` function, if the path consumed the full buffer, treat it as denied:

```rust
// If path was truncated, deny by default (we can't match policy correctly)
if filename_len >= MAX_FILENAME_LEN - 1 {
    return ACTION_DENY;
}
```

---

### 2.6 Increase BPF Map Capacity

**Fixes:** Max 256 Rules per BPF Map (MEDIUM)

#### Solution: Increase Default Limits and Make Configurable

```rust
// In guardian-ebpf/src/main.rs
// Increase from 256 to 1024 for rule maps
#[map]
static DENY_PREFIXES: LpmTrie<[u8; MAX_FILENAME_LEN], u8> =
    LpmTrie::with_max_entries(1024, 0);

#[map]
static ALLOW_PREFIXES: LpmTrie<[u8; MAX_FILENAME_LEN], u8> =
    LpmTrie::with_max_entries(1024, 0);

#[map]
static DENY_EXACT: HashMap<[u8; MAX_FILENAME_LEN], u8> =
    HashMap::with_max_entries(1024, 0);

#[map]
static ALLOW_EXACT: HashMap<[u8; MAX_FILENAME_LEN], u8> =
    HashMap::with_max_entries(1024, 0);

// Same for exec maps
#[map]
static EXEC_DENY_PREFIXES: LpmTrie<[u8; MAX_FILENAME_LEN], u8> =
    LpmTrie::with_max_entries(1024, 0);
// ... etc
```

Additionally, validate at config load time and warn if rules exceed capacity:

```rust
// In guardian/src/main.rs during map population
let total_deny = agent.file_access.deny.len();
let total_allow = agent.file_access.allow.len();

if total_deny > 1024 {
    error!(
        "Agent '{}' has {} deny rules but max is 1024. Rules beyond limit will be dropped!",
        agent.name, total_deny
    );
}
```

---

## 3. Command Execution Fixes

### 3.1 Block memfd_create + execveat

**Fixes:** memfd_create + execveat Bypass (MEDIUM-HIGH)

#### Solution A: Add Default Exec Deny for /memfd:*

The quickest fix — add `/memfd:*` to the default deny patterns:

```rust
// In guardian/src/config.rs, during config validation/defaults
const DEFAULT_EXEC_DENY: &[&str] = &[
    "/memfd:*",              // Block execution from anonymous memory files
    "/dev/fd/*",             // Block execution from file descriptors
    "/proc/self/fd/*",       // Block execution from /proc fd links
];
```

#### Solution B: Add execveat Tracepoint

Currently Guardian hooks `sys_enter_execve` but not `sys_enter_execveat`. Add coverage:

```rust
// In guardian-ebpf/src/main.rs

// New tracepoint for execveat (used with AT_EMPTY_PATH for memfd execution)
#[tracepoint]
pub fn guardian_execveat(ctx: TracePointContext) -> u32 {
    match try_guardian_execveat(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_execveat(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    if !is_watched(tgid) {
        return Ok(0);
    }

    // execveat args (x86_64): dirfd=16, pathname=24, flags=40
    let dirfd: i32 = unsafe { ctx.read_at(16)? };
    let flags: i32 = unsafe { ctx.read_at(40)? };

    // AT_EMPTY_PATH (0x1000) with a dirfd = memfd/fd execution
    if flags & 0x1000 != 0 {
        // This is an AT_EMPTY_PATH execveat — likely memfd execution
        // Set PENDING_EXEC_DENY unconditionally (deny by default)
        PENDING_EXEC_DENY.insert(&pid_tgid, &1, 0)?;

        // Log the event
        let buf = unsafe {
            let ptr = EXEC_BUF.get_ptr_mut(0).ok_or(1i64)?;
            &mut *ptr
        };
        let event = unsafe { &mut *(buf as *mut _ as *mut ExecEvent) };
        event.pid = pid_tgid as u32;
        event.tgid = tgid;
        // filename = "/memfd:<anonymous>" placeholder
        let memfd_path = b"/memfd:anonymous\0";
        event.filename[..memfd_path.len()].copy_from_slice(memfd_path);
        event.filename_len = memfd_path.len() as u32;

        EXEC_EVENTS.output(ctx, buf, 0);
    }

    Ok(0)
}
```

#### Solution C: Block memfd_create via Seccomp (Strongest)

Add `memfd_create` to the seccomp filter in `guardian-launch`:

```rust
// Add to the seccomp filter in guardian-launch/src/main.rs
const SYS_MEMFD_CREATE: i64 = 319;  // x86_64

// Add to the filter rules alongside io_uring:
(SYS_MEMFD_CREATE, vec![SeccompRule::new(vec![])?]),
```

This is the strongest approach — the agent cannot create memfd at all. Make it configurable:

```toml
[[agents]]
name = "untrusted-agent"
block_memfd = true    # default: true
block_io_uring = true # default: true
```

---

### 3.2 Dynamic Linker Detection

**Fixes:** Dynamic Linker Bypass (MEDIUM)

#### Solution: Linker Path Map + Argument Inspection

When `bprm_check_security` sees a known dynamic linker path, inspect the first argument to find the real binary being loaded.

#### New BPF Map

```rust
// In guardian-ebpf/src/main.rs
// Map of known dynamic linker paths
#[map]
static DYNAMIC_LINKERS: HashMap<[u8; MAX_FILENAME_LEN], u8> =
    HashMap::with_max_entries(16, 0);
```

#### Userspace Population (`guardian/src/main.rs`)

```rust
// Populate known linker paths at startup
const KNOWN_LINKERS: &[&str] = &[
    "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    "/lib64/ld-linux-x86-64.so.2",
    "/lib/ld-linux.so.2",
    "/lib/ld-linux-aarch64.so.1",
    "/usr/lib/ld-linux-x86-64.so.2",
    "/lib/ld-musl-x86_64.so.1",
];

for linker_path in KNOWN_LINKERS {
    let mut key = [0u8; MAX_FILENAME_LEN];
    let bytes = linker_path.as_bytes();
    key[..bytes.len()].copy_from_slice(bytes);
    dynamic_linkers_map.insert(&key, &1u8, 0)?;
}
```

#### Enhanced Exec Tracepoint

```rust
// In sys_enter_execve handler
fn try_guardian_exec(ctx: &TracePointContext) -> Result<u32, i64> {
    // ... existing code to read filename ...

    // Check if this is a known dynamic linker
    if DYNAMIC_LINKERS.get(&event.filename).is_some() {
        // This is a linker invocation — the REAL binary is argv[1]
        // Read argv pointer (sys_enter_execve: argv at offset 24 on x86_64)
        let argv_ptr: u64 = unsafe { ctx.read_at(24)? };

        // argv[1] is the actual binary the linker will load
        let argv1_ptr: u64 = unsafe {
            bpf_probe_read_user(&(argv_ptr as *const u64).add(1))?
        };

        if argv1_ptr != 0 {
            // Read the real binary path from argv[1]
            let mut real_binary = [0u8; MAX_FILENAME_LEN];
            unsafe {
                bpf_probe_read_user_str_bytes(
                    argv1_ptr as *const u8,
                    &mut real_binary,
                )?;
            }

            // Evaluate exec policy against the REAL binary, not the linker
            let action = evaluate_exec_policy(&real_binary, real_binary.len());
            if action == ACTION_DENY {
                PENDING_EXEC_DENY.insert(&pid_tgid, &1, 0)?;
            }

            // Update event to show the real binary path
            event.filename = real_binary;
        }

        return Ok(0);
    }

    // ... existing policy evaluation for non-linker executions ...
}
```

#### How This Stops the Attack

```
Before fix:
  /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /usr/bin/curl evil.com
  → bprm sees: ld-linux → not in deny list → ALLOWED

After fix:
  /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /usr/bin/curl evil.com
  → bprm sees: ld-linux → known linker! → read argv[1] → /usr/bin/curl
  → evaluate policy against /usr/bin/curl → DENIED
```

---

### 3.3 Enforce-or-Exit Mode

**Fixes:** Silent LSM Enforcement Fallback (MEDIUM)

#### Solution: Add `strict` Enforcement Mode

Add a new mode that refuses to start if LSM is unavailable:

```rust
// In guardian/src/config.rs
#[derive(Debug, Clone, Deserialize)]
pub enum Mode {
    #[serde(rename = "monitor")]
    Monitor,
    #[serde(rename = "enforce")]
    Enforce,       // Current behavior: fallback to monitor if LSM unavailable
    #[serde(rename = "strict")]
    Strict,        // NEW: exit with error if LSM unavailable
}
```

```rust
// In guardian/src/main.rs during LSM loading
let file_lsm_ok = load_lsm(&mut bpf, "guardian_enforce", "file_open").is_ok();
let exec_lsm_ok = load_lsm(&mut bpf, "guardian_enforce_exec", "bprm_check_security").is_ok();

match config.global.mode {
    Mode::Strict => {
        if !file_lsm_ok {
            error!("STRICT mode: LSM file_open failed to load. Cannot guarantee enforcement.");
            error!("Ensure CONFIG_BPF_LSM=y and 'bpf' is in the LSM list.");
            error!("Use mode = \"enforce\" for best-effort enforcement, or \"monitor\" for logging only.");
            std::process::exit(1);
        }
        if !exec_lsm_ok {
            error!("STRICT mode: LSM bprm_check_security failed to load. Cannot guarantee exec enforcement.");
            std::process::exit(1);
        }
        info!("STRICT mode: All LSM hooks loaded successfully. Full enforcement active.");
    }
    Mode::Enforce => {
        // Current behavior: warn and continue
        if !file_lsm_ok {
            warn!("ENFORCE mode: File enforcement unavailable. Running in monitor-only for file access.");
        }
        if !exec_lsm_ok {
            warn!("ENFORCE mode: Exec enforcement unavailable. Running in monitor-only for exec.");
        }
    }
    Mode::Monitor => {
        info!("MONITOR mode: Logging only, no enforcement.");
    }
}
```

#### Dashboard Health Indicator

Expose enforcement status via the dashboard and API:

```rust
// In GET /api/health (new endpoint)
#[derive(Serialize)]
struct HealthStatus {
    mode: String,
    file_enforcement: bool,
    exec_enforcement: bool,
    network_enforcement: bool,
    symlink_safe: bool,         // true if bpf_d_path() is active
    inode_protection: bool,     // true if rename/unlink/link hooks loaded
    io_uring_blocked: bool,     // true if seccomp filter applied
}
```

---

## 4. Network Enforcement Fixes

### 4.1 Kernel-Level Connection Blocking via cgroup/connect

**Fixes:** Network Enforcement is Log-Only (CRITICAL)
**Kernel requirement:** Linux 4.17+ (cgroup BPF)

#### Solution: cgroup/connect4 and cgroup/connect6 BPF Programs

These BPF program types attach to a cgroup and intercept `connect()` calls **before** they reach the network stack. They can modify or reject connection attempts.

#### New BPF Maps

```rust
// In guardian-ebpf/src/main.rs

// Denied destination ports (e.g., block all outbound SSH)
#[map]
static NET_DENY_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

// Allowed destination ports (e.g., only allow 80, 443)
#[map]
static NET_ALLOW_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

// Default network action: 0 = deny, 1 = allow
#[map]
static NET_DEFAULT_ACTION: Array<u8> = Array::with_max_entries(1, 0);

// Denied destination IPs (IPv4, stored as u32)
#[map]
static NET_DENY_IPV4: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

// Allowed destination IPs (IPv4)
#[map]
static NET_ALLOW_IPV4: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

// Denied CIDR ranges (using LPM trie)
#[map]
static NET_DENY_CIDR: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(256, 0);
```

#### cgroup BPF Program

```rust
// New file or section in guardian-ebpf/src/main.rs

#[cgroup_sock_addr(connect4)]
pub fn guardian_connect4(ctx: SockAddrContext) -> i32 {
    match try_guardian_connect4(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1, // fail-open on error (1 = allow for cgroup programs)
    }
}

fn try_guardian_connect4(ctx: &SockAddrContext) -> Result<i32, i64> {
    // Get destination IP and port from the socket address
    let dest_ip: u32 = unsafe { (*ctx.sock_addr).user_ip4 };
    let dest_port: u16 = unsafe { ((*ctx.sock_addr).user_port as u16).to_be() };

    // Skip localhost connections (127.0.0.0/8)
    if (dest_ip & 0xFF) == 127 {
        return Ok(1); // allow localhost
    }

    // Check deny-first policy
    // 1. Check denied ports
    if NET_DENY_PORTS.get(&dest_port).is_some() {
        return Ok(0); // block
    }

    // 2. Check denied IPs
    if NET_DENY_IPV4.get(&dest_ip).is_some() {
        return Ok(0); // block
    }

    // 3. Check denied CIDR ranges
    let cidr_key = Key::new(32, dest_ip.to_be_bytes());
    if NET_DENY_CIDR.get(&cidr_key).is_some() {
        return Ok(0); // block
    }

    // 4. Check default action
    let default = unsafe { NET_DEFAULT_ACTION.get(0).copied().unwrap_or(1) };
    if default == 0 {
        // Default deny — check allow lists
        if NET_ALLOW_PORTS.get(&dest_port).is_some() {
            return Ok(1); // explicitly allowed port
        }
        if NET_ALLOW_IPV4.get(&dest_ip).is_some() {
            return Ok(1); // explicitly allowed IP
        }
        return Ok(0); // default deny, not in allow list → block
    }

    Ok(1) // default allow
}
```

#### Attaching to Agent Cgroups

The cgroup BPF programs are attached **per-cgroup**, not globally. This ensures only monitored agents are affected:

```rust
// In guardian/src/main.rs, when an agent registers via IPC

fn attach_network_enforcement(
    bpf: &mut Bpf,
    cgroup_path: &str,
    agent_config: &AgentConfig,
) -> anyhow::Result<()> {
    let cgroup_fd = std::fs::File::open(cgroup_path)?;

    // Load and attach connect4 program to agent's cgroup
    let prog: &mut CgroupSockAddr = bpf.program_mut("guardian_connect4")
        .unwrap()
        .try_into()?;
    prog.load()?;
    prog.attach(cgroup_fd)?;

    // Populate network policy maps from agent config
    if let Some(net_policy) = &agent_config.network {
        for port in &net_policy.deny_ports {
            net_deny_ports.insert(port, &1u8, 0)?;
        }
        for port in &net_policy.allow_ports {
            net_allow_ports.insert(port, &1u8, 0)?;
        }
    }

    info!("Network enforcement attached to cgroup {}", cgroup_path);
    Ok(())
}
```

#### Config Example

```toml
[[agents]]
name = "restricted-agent"
identity = "cgroup"

[agents.network]
default = "deny"
allow_ports = [80, 443]           # Only HTTP/HTTPS
deny_ports = [22, 25, 3306]       # Block SSH, SMTP, MySQL
allow_ips = ["10.0.0.0/8"]        # Allow internal network
deny_ips = ["0.0.0.0/0"]          # Deny everything else
```

---

### 4.2 DNS Monitoring via Port 53 Inspection

**Fixes:** DNS is Completely Unmonitored (MEDIUM)

#### Solution: Intercept DNS Queries on Port 53

Monitor all UDP traffic to port 53 (DNS) and extract queried domain names for logging and policy enforcement.

#### Approach: Tracepoint on `sys_enter_sendto` for UDP port 53

```rust
// In guardian-ebpf/src/main.rs

#[tracepoint]
pub fn guardian_dns_monitor(ctx: TracePointContext) -> u32 {
    match try_guardian_dns_monitor(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_dns_monitor(ctx: &TracePointContext) -> Result<u32, i64> {
    // sys_enter_sendto: fd=16, buf=24, len=32, flags=40, addr=48
    let addr_ptr: u64 = unsafe { ctx.read_at(48)? };
    if addr_ptr == 0 {
        return Ok(0);
    }

    // Read sockaddr to check if destination is port 53
    let family: u16 = unsafe { bpf_probe_read_user(&(addr_ptr as *const u16))? };
    if family != 2 { // AF_INET
        return Ok(0);
    }

    let port: u16 = unsafe {
        bpf_probe_read_user(&((addr_ptr + 2) as *const u16))?
    };
    let port = u16::from_be(port);

    if port != 53 {
        return Ok(0); // not a DNS query
    }

    // Read the query payload to extract domain name
    let buf_ptr: u64 = unsafe { ctx.read_at(24)? };
    let buf_len: u32 = unsafe { ctx.read_at(32)? };

    // DNS query starts at byte 12 (after header)
    // Domain is encoded as length-prefixed labels
    // e.g., 3www6google3com0 = www.google.com
    // Read up to 128 bytes of the query for domain extraction
    let mut dns_buf = [0u8; 128];
    let read_len = core::cmp::min(buf_len as usize, 128);
    unsafe {
        bpf_probe_read_user_buf(buf_ptr as *const u8, &mut dns_buf[..read_len])?;
    }

    // Send DNS event to userspace for domain name parsing
    // (Full DNS parsing is too complex for eBPF — do it in userspace)
    // ... emit event via DNS_EVENTS perf array ...

    Ok(0)
}
```

#### Userspace Domain Resolution (`guardian/src/main.rs`)

For domain-based blocking in the `cgroup/connect` programs, resolve configured domains at startup:

```rust
use tokio::net::lookup_host;

async fn resolve_denied_domains(
    config: &NetworkPolicy,
    deny_ipv4_map: &mut HashMap<u32, u8>,
) -> anyhow::Result<()> {
    if let Some(deny_domains) = &config.deny_domains {
        for domain in deny_domains {
            match lookup_host(format!("{}:0", domain)).await {
                Ok(addrs) => {
                    for addr in addrs {
                        if let std::net::SocketAddr::V4(v4) = addr {
                            let ip_bytes = v4.ip().octets();
                            let ip_u32 = u32::from_be_bytes(ip_bytes);
                            deny_ipv4_map.insert(&ip_u32, &1u8, 0)?;
                            info!("Resolved {} -> {} (denied)", domain, v4.ip());
                        }
                    }
                }
                Err(e) => warn!("Failed to resolve {}: {}", domain, e),
            }
        }
    }
    Ok(())
}

// Periodic refresh task (DNS TTLs expire)
async fn dns_refresh_task(config: NetworkPolicy, map: SharedMap) {
    let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 min
    loop {
        interval.tick().await;
        if let Err(e) = resolve_denied_domains(&config, &mut map.lock().await).await {
            warn!("DNS refresh failed: {}", e);
        }
    }
}
```

#### Config Example

```toml
[agents.network]
default = "deny"
allow_ports = [80, 443]
deny_domains = ["evil.com", "*.malware.io", "c2-server.net"]
allow_domains = ["api.github.com", "registry.npmjs.org"]
```

---

## 5. Approval Workflow Fixes

### 5.1 Risk-Based Configurable Timeouts

**Fixes:** Fixed 120-Second Timeout (MEDIUM)

#### Solution: Per-Risk-Level Timeout Configuration

```rust
// In guardian-common/src/lib.rs — replace the single constant
// Remove: pub const PERMISSION_TIMEOUT_SECS: u64 = 120;

// In guardian/src/config.rs — add to PermissionsConfig
#[derive(Debug, Clone, Deserialize)]
pub struct PermissionsConfig {
    // ... existing fields ...

    /// Timeout in seconds per risk level [low, medium, high, critical]
    #[serde(default = "default_timeouts")]
    pub timeout_secs: RiskTimeouts,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RiskTimeouts {
    pub low: u64,       // default: 180 (3 min)
    pub medium: u64,    // default: 120 (2 min)
    pub high: u64,      // default: 60  (1 min)
    pub critical: u64,  // default: 30  (30 sec — force quick decision)
}

fn default_timeouts() -> RiskTimeouts {
    RiskTimeouts {
        low: 180,
        medium: 120,
        high: 60,
        critical: 30,
    }
}
```

```toml
# In config.toml
[permissions]
[permissions.timeouts]
low = 180
medium = 120
high = 60
critical = 30   # Critical requests auto-deny quickly
```

#### Apply in IPC handler (`guardian/src/ipc.rs`)

```rust
// When creating the permission request
let timeout = match risk_level {
    RiskLevel::Low => config.permissions.timeout_secs.low,
    RiskLevel::Medium => config.permissions.timeout_secs.medium,
    RiskLevel::High => config.permissions.timeout_secs.high,
    RiskLevel::Critical => config.permissions.timeout_secs.critical,
};

let pending = PendingPermission {
    timeout_secs: timeout,
    // ... rest of fields ...
};
```

---

### 5.2 CLI-Based Permission Approval

**Fixes:** Permissions Require Dashboard Enabled (MEDIUM)

#### Solution: Add `guardian-ctl approve/deny` Commands

Extend `guardian-ctl` to list and resolve pending permissions via IPC:

```rust
// In guardian-ctl/src/main.rs — add new subcommands

#[derive(Subcommand)]
enum Commands {
    // ... existing: List, Stop, Grant, RequestPermission ...

    /// List pending permission requests
    Pending,

    /// Approve a pending permission request
    Approve {
        /// Request ID
        #[arg(short, long)]
        id: u64,

        /// Grant duration in seconds
        #[arg(short, long, default_value = "300")]
        duration: u64,
    },

    /// Deny a pending permission request
    Deny {
        /// Request ID
        #[arg(short, long)]
        id: u64,

        /// Reason for denial
        #[arg(short, long, default_value = "Denied via CLI")]
        reason: String,
    },
}
```

#### New IPC Messages (`guardian-common/src/lib.rs`)

```rust
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    // ... existing variants ...
    ListPendingPermissions,
    ResolvePermission {
        id: u64,
        approved: bool,
        duration_secs: Option<u64>,
        reason: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    // ... existing variants ...
    PendingPermissions(Vec<PendingPermissionInfo>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PendingPermissionInfo {
    pub id: u64,
    pub agent_name: String,
    pub resource_type: String,
    pub resource_path: String,
    pub justification: Option<String>,
    pub risk_level: String,
    pub risk_flags: Vec<String>,
    pub requested_at: String,
    pub timeout_secs: u64,
    pub seconds_remaining: u64,
}
```

#### IPC Handler (`guardian/src/ipc.rs`)

```rust
IpcRequest::ListPendingPermissions => {
    let state = ipc_state.lock().await;
    let pending: Vec<PendingPermissionInfo> = state
        .pending_permissions
        .iter()
        .map(|p| PendingPermissionInfo {
            id: p.id,
            agent_name: p.agent_name.clone(),
            resource_type: p.resource_type.clone(),
            resource_path: p.resource_path.clone(),
            justification: p.justification.clone(),
            risk_level: format!("{:?}", p.risk_level),
            risk_flags: p.risk_flags.clone(),
            requested_at: p.requested_at_utc.to_rfc3339(),
            timeout_secs: p.timeout_secs,
            seconds_remaining: p.timeout_secs
                .saturating_sub(p.requested_at.elapsed().as_secs()),
        })
        .collect();
    IpcResponse::PendingPermissions(pending)
}

IpcRequest::ResolvePermission { id, approved, duration_secs, reason } => {
    resolve_permission(&ipc_state, id, approved, duration_secs, reason).await
}
```

#### CLI Usage

```bash
# List pending requests
sudo guardian-ctl pending

# Output:
# ID  Agent          Resource                Risk     Time Left
# 1   test-agent     /etc/passwd (file)      HIGH     45s
# 2   test-agent     /usr/bin/curl (exec)    MEDIUM   98s

# Approve with 5-minute grant
sudo guardian-ctl approve --id 1 --duration 300

# Deny with reason
sudo guardian-ctl deny --id 2 --reason "curl not authorized for this agent"
```

This allows permission management **without** the dashboard, making Guardian usable in headless/server environments.

---

### 5.3 Approval Pattern Anomaly Detection

**Fixes:** No Anomaly Detection on Approval Patterns (MEDIUM)

#### Solution: Background Analysis Task on SQLite Audit Trail

Add a periodic task that queries the audit database and generates alerts for suspicious patterns.

```rust
// In guardian/src/permissions.rs — new module

pub struct AnomalyDetector {
    db: Arc<EventDb>,
    alert_sender: AlertSender,
    config: AnomalyConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AnomalyConfig {
    /// Trigger if approval rate exceeds this threshold in 24h
    pub rubber_stamp_threshold: f64,   // default: 0.90 (90%)

    /// Trigger if an agent has more than N requests in 24h
    pub flood_threshold: u32,          // default: 20

    /// Trigger if same resource denied N+ times then approved
    pub persistence_threshold: u32,    // default: 3

    /// Trigger if approvals happen outside these hours (24h format)
    pub active_hours: Option<(u8, u8)>, // e.g., (8, 18) for 8AM-6PM

    /// Check interval in seconds
    pub check_interval_secs: u64,      // default: 300 (5 min)
}

impl AnomalyDetector {
    pub async fn run(&self) {
        let mut interval = tokio::time::interval(
            Duration::from_secs(self.config.check_interval_secs)
        );

        loop {
            interval.tick().await;
            self.check_rubber_stamping().await;
            self.check_flood_attacks().await;
            self.check_persistence_attacks().await;
            self.check_off_hours_approvals().await;
        }
    }

    async fn check_rubber_stamping(&self) {
        // Query: approval rate in last 24 hours
        let stats = self.db.query_approval_stats_24h().await;

        if stats.total > 10 && stats.approval_rate > self.config.rubber_stamp_threshold {
            self.alert_sender.send(AlertEvent {
                severity: Severity::Warning,
                event_type: "anomaly_rubber_stamp".into(),
                message: format!(
                    "High approval rate detected: {:.0}% ({}/{} requests approved in 24h). \
                     Possible approval fatigue.",
                    stats.approval_rate * 100.0,
                    stats.approved,
                    stats.total,
                ),
                // ...
            }).await;
        }
    }

    async fn check_persistence_attacks(&self) {
        // Query: resources denied N+ times then approved for same agent
        let suspicious = self.db.query_deny_then_approve_patterns(
            self.config.persistence_threshold
        ).await;

        for pattern in suspicious {
            self.alert_sender.send(AlertEvent {
                severity: Severity::Critical,
                event_type: "anomaly_persistence".into(),
                message: format!(
                    "Persistence attack pattern: agent '{}' was denied access to '{}' \
                     {} times, then approved. Possible social engineering.",
                    pattern.agent_name,
                    pattern.resource_path,
                    pattern.denial_count,
                ),
                // ...
            }).await;
        }
    }

    async fn check_flood_attacks(&self) {
        // Query: agents with > N requests in 24h
        let flooded = self.db.query_high_request_agents(
            self.config.flood_threshold
        ).await;

        for agent in flooded {
            self.alert_sender.send(AlertEvent {
                severity: Severity::Warning,
                event_type: "anomaly_flood".into(),
                message: format!(
                    "Request flood: agent '{}' made {} permission requests in 24h \
                     (threshold: {}). Possible approval fatigue attack.",
                    agent.name,
                    agent.request_count,
                    self.config.flood_threshold,
                ),
                // ...
            }).await;
        }
    }

    async fn check_off_hours_approvals(&self) {
        if let Some((start, end)) = self.config.active_hours {
            let off_hours = self.db.query_off_hours_approvals(start, end).await;

            if !off_hours.is_empty() {
                self.alert_sender.send(AlertEvent {
                    severity: Severity::Warning,
                    event_type: "anomaly_off_hours".into(),
                    message: format!(
                        "{} permissions approved outside active hours ({:02}:00-{:02}:00). \
                         Verify these were intentional.",
                        off_hours.len(), start, end,
                    ),
                    // ...
                }).await;
            }
        }
    }
}
```

#### Config

```toml
[permissions.anomaly_detection]
rubber_stamp_threshold = 0.90
flood_threshold = 20
persistence_threshold = 3
active_hours = [8, 18]
check_interval_secs = 300
```

---

### 5.4 Grant Accumulation Limits

**Fixes:** Grant Duration Accumulation (MEDIUM)

#### Solution: Per-Resource Maximum Total Grant Duration

Track total granted time per resource per agent and enforce a ceiling.

```rust
// In guardian/src/permissions.rs — add to AgentRateLimit

pub struct AgentRateLimit {
    // ... existing fields ...

    /// Total grant seconds accumulated per resource in the last 24h
    pub grant_accumulation: HashMap<String, GrantAccumulation>,
}

pub struct GrantAccumulation {
    pub total_seconds: u64,
    pub grants: Vec<Instant>,  // timestamps of grants for sliding window
}

impl AgentRateLimit {
    pub fn check_grant_limit(
        &mut self,
        resource: &str,
        requested_duration: u64,
        max_daily_grant_secs: u64,  // default: 3600 (1 hour total per day)
    ) -> Result<(), String> {
        let accum = self.grant_accumulation
            .entry(resource.to_string())
            .or_insert(GrantAccumulation {
                total_seconds: 0,
                grants: Vec::new(),
            });

        // Remove grants older than 24h from the sliding window
        let cutoff = Instant::now() - Duration::from_secs(86400);
        accum.grants.retain(|t| *t > cutoff);

        if accum.total_seconds + requested_duration > max_daily_grant_secs {
            return Err(format!(
                "Grant limit exceeded: {}s already granted for '{}' in 24h (max: {}s). \
                 Request for additional {}s denied.",
                accum.total_seconds, resource, max_daily_grant_secs, requested_duration,
            ));
        }

        Ok(())
    }

    pub fn record_grant(&mut self, resource: &str, duration_secs: u64) {
        let accum = self.grant_accumulation
            .entry(resource.to_string())
            .or_insert(GrantAccumulation {
                total_seconds: 0,
                grants: Vec::new(),
            });
        accum.total_seconds += duration_secs;
        accum.grants.push(Instant::now());
    }
}
```

#### Config

```toml
[permissions]
max_daily_grant_secs = 3600   # Max 1 hour total grant time per resource per agent per day
```

---

### 5.5 Improved Justification Analysis

**Fixes:** Justification Analysis is Easily Bypassed (LOW)

#### Solution: Multi-Signal Scoring with Severity Scaling

Replace the binary "any match = risk bump" with a weighted scoring system:

```rust
// In guardian/src/permissions.rs

#[derive(Debug, Clone)]
pub struct JustificationAnalysis {
    pub total_score: f32,
    pub findings: Vec<JustificationFinding>,
}

#[derive(Debug, Clone)]
pub struct JustificationFinding {
    pub category: String,
    pub matched_text: String,
    pub weight: f32,
}

pub fn analyze_justification_v2(text: &str) -> JustificationAnalysis {
    let lower = text.to_lowercase();
    let mut findings = Vec::new();

    // Category weights — multiple findings from different categories
    // stack to produce higher scores
    let categories: Vec<(&str, f32, Vec<&str>)> = vec![
        ("urgency", 1.0, vec![
            "urgent", "immediately", "asap", "right now", "emergency",
            "critical", "time-sensitive", "pressing", "hurry", "rush",
        ]),
        ("security_bypass", 2.0, vec![
            "trust me", "don't worry", "it's safe", "override", "bypass",
            "disable", "skip", "ignore", "workaround", "just this once",
        ]),
        ("authority_claim", 1.5, vec![
            "admin told", "manager said", "authorized by", "supervisor",
            "leadership", "approved by", "ops team", "per direction",
        ]),
        ("reassurance", 1.0, vec![
            "nothing bad", "harmless", "no risk", "perfectly safe",
            "won't hurt", "totally fine", "no problem", "relax",
        ]),
        ("sensitive_mention", 0.5, vec![
            "ssh", "password", "credential", "token", "api key",
            "secret", "private key", "certificate",
        ]),
    ];

    for (category, weight, patterns) in &categories {
        for pattern in patterns {
            if lower.contains(pattern) {
                findings.push(JustificationFinding {
                    category: category.to_string(),
                    matched_text: pattern.to_string(),
                    weight: *weight,
                });
            }
        }
    }

    // Fuzzy matching: flag short justifications (low effort = suspicious)
    if text.len() < 10 && !text.is_empty() {
        findings.push(JustificationFinding {
            category: "low_effort".into(),
            matched_text: "justification too short".into(),
            weight: 0.5,
        });
    }

    // Score = sum of unique category weights (same category doesn't stack)
    let mut seen_categories = std::collections::HashSet::new();
    let total_score: f32 = findings.iter()
        .filter(|f| seen_categories.insert(f.category.clone()))
        .map(|f| f.weight)
        .sum();

    JustificationAnalysis { total_score, findings }
}

/// Risk bump now scales with score
pub fn justification_risk_bump_v2(analysis: &JustificationAnalysis) -> u32 {
    // 0-1.0: no bump
    // 1.0-2.0: +1 risk tier
    // 2.0-3.0: +2 risk tiers
    // 3.0+: jump straight to CRITICAL
    if analysis.total_score >= 3.0 {
        3  // jump to CRITICAL
    } else if analysis.total_score >= 2.0 {
        2
    } else if analysis.total_score >= 1.0 {
        1
    } else {
        0
    }
}
```

This is still pattern-matching (not NLP), but it's significantly harder to game because:
- Multiple categories stack (urgency + authority + bypass = score 4.5 → CRITICAL)
- More patterns per category reduce typo bypasses
- Low-effort justifications are flagged
- Category weights reflect actual risk (bypass language weighted 2x vs urgency)

---

## 6. Platform & Deployment Fixes

### 6.1 Strict Enforcement Mode

(See [3.3 Enforce-or-Exit Mode](#33-enforce-or-exit-mode) — same fix)

---

### 6.2 Architecture-Portable Tracepoint Offsets via BTF

**Fixes:** x86_64 Tracepoint Offsets Hardcoded (MEDIUM)
**Kernel requirement:** Linux 5.2+ with BTF enabled

#### Solution: Use BTF-Derived Offsets

BTF (BPF Type Format) provides type information that lets eBPF programs access struct fields by name instead of hardcoded offsets. The Aya framework supports this via `aya-bpf`'s BTF integration.

#### Changes to `guardian-ebpf/src/main.rs`

Replace hardcoded offsets with BTF-aware access:

```rust
// BEFORE (hardcoded x86_64 offsets):
let filename_ptr: u64 = unsafe { ctx.read_at(24)? };  // offset 24 = x86_64 only
let flags: i32 = unsafe { ctx.read_at(32)? };

// AFTER (BTF-portable via vmlinux.h bindings):
// Use aya-bpf's tracepoint context with typed args

// Generate vmlinux bindings at build time:
// In xtask/src/main.rs:
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > guardian-ebpf/src/vmlinux.h

// Then use typed access:
#[repr(C)]
struct SysEnterOpenatArgs {
    _common: [u8; 8],   // common tracepoint fields
    __syscall_nr: i32,
    dfd: i64,
    filename: u64,       // pointer
    flags: i64,
    mode: i64,
}

fn try_guardian_file_open(ctx: &TracePointContext) -> Result<u32, i64> {
    // Safe typed access — no hardcoded offsets
    let args: &SysEnterOpenatArgs = unsafe { ctx.read_at(0)? };
    let filename_ptr = args.filename;
    let flags = args.flags as i32;
    // ...
}
```

#### Build-Time Offset Detection

For kernels without BTF, fall back to runtime detection:

```rust
// In guardian/src/main.rs at startup
fn detect_tracepoint_offsets() -> anyhow::Result<TracepointOffsets> {
    // Read the tracepoint format file to determine field offsets
    let format = std::fs::read_to_string(
        "/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format"
    )?;

    // Parse field offsets from format file
    // Example line: "field:const char * filename;  offset:24;  size:8;  signed:0;"
    let filename_offset = parse_field_offset(&format, "filename")?;
    let flags_offset = parse_field_offset(&format, "flags")?;

    Ok(TracepointOffsets {
        openat_filename: filename_offset,
        openat_flags: flags_offset,
        // ... other fields ...
    })
}
```

---

### 6.3 openat2 Fallback via Seccomp

**Fixes:** openat2 Requires Kernel 5.6+ (LOW)

#### Solution: Block openat2 Syscall When Tracepoint Unavailable

If the `sys_enter_openat2` tracepoint can't be loaded (kernel < 5.6), block the syscall entirely via seccomp in `guardian-launch`:

```rust
// In guardian-launch/src/main.rs
// If daemon reports openat2 monitoring is unavailable, block it

fn apply_openat2_seccomp_if_needed(daemon_caps: &DaemonCapabilities) -> anyhow::Result<()> {
    if !daemon_caps.has_openat2_monitoring {
        const SYS_OPENAT2: i64 = 437;  // x86_64
        // Add to seccomp filter: block openat2 → agent falls back to openat
        // (openat IS monitored, so no bypass)
        info!("openat2 monitoring unavailable — blocking syscall via seccomp");
        add_seccomp_deny(SYS_OPENAT2)?;
    }
    Ok(())
}
```

This ensures agents cannot use `openat2` to bypass monitoring on older kernels.

---

## 7. Design-Level Fixes

### 7.1 Configurable Fail-Closed Mode

**Fixes:** Fail-Open on All eBPF Errors (MEDIUM)

#### Solution: Optional Fail-Closed for High-Security Deployments

Add a per-agent option to fail closed (deny on error) instead of fail open:

```rust
// In guardian-ebpf/src/main.rs

// New map: per-cgroup fail-closed flag
#[map]
static FAIL_CLOSED_CGROUPS: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);

#[lsm(hook = "file_open")]
pub fn guardian_enforce(ctx: LsmContext) -> i32 {
    match try_guardian_enforce(&ctx) {
        Ok(ret) => ret,
        Err(_) => {
            // Check if this cgroup is in fail-closed mode
            let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
            if FAIL_CLOSED_CGROUPS.get(&cgroup_id).is_some() {
                -13 // EACCES — deny on error (fail-closed)
            } else {
                0   // allow on error (fail-open, default)
            }
        }
    }
}
```

#### Config

```toml
[[agents]]
name = "high-security-agent"
identity = "cgroup"
fail_closed = true   # deny on eBPF error (default: false)
```

**Warning:** Fail-closed mode can break the agent if eBPF encounters transient errors (e.g., memory pressure). Only recommended for high-security deployments where denial is preferable to potential bypass.

---

### 7.2 Dashboard Authentication

**Fixes:** Dashboard Has No Authentication (MEDIUM)

#### Solution: Token-Based Authentication with axum Middleware

Add a simple bearer token authentication layer:

```rust
// In guardian/src/dashboard/mod.rs

use axum::{
    middleware::{self, Next},
    http::{Request, StatusCode, header},
    response::Response,
};

async fn auth_middleware<B>(
    State(state): State<DashboardState>,
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    // Skip auth for static assets
    if request.uri().path().starts_with("/static/") {
        return Ok(next.run(request).await);
    }

    let token = state.config.dashboard_token.as_ref();

    // If no token configured, allow all (backward compatible)
    let Some(expected_token) = token else {
        return Ok(next.run(request).await);
    };

    // Check Authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    // Check query param (for SSE connections from browser)
    let query_token = request
        .uri()
        .query()
        .and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == "token")
                .map(|(_, v)| v.to_string())
        });

    // Check cookie (for browser sessions)
    let cookie_token = request
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';')
                .find_map(|c| {
                    let c = c.trim();
                    c.strip_prefix("guardian_token=")
                })
        })
        .map(String::from);

    let provided_token = auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(String::from)
        .or(query_token)
        .or(cookie_token);

    match provided_token {
        Some(t) if t == *expected_token => Ok(next.run(request).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

// Apply middleware to router
let app = Router::new()
    .merge(page_routes())
    .merge(api_routes())
    .merge(sse_routes())
    .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
    .with_state(state);
```

#### Config

```toml
[dashboard]
enabled = true
listen_address = "127.0.0.1:8080"
token = "your-secret-token-here"  # Optional: if set, all requests must authenticate
```

#### Auto-Generated Token

If no token is configured but the dashboard binds to a non-localhost address, generate one automatically:

```rust
// In guardian/src/main.rs during dashboard setup
if dashboard_config.listen_address != "127.0.0.1" && dashboard_config.token.is_none() {
    let generated = generate_random_token();
    warn!(
        "Dashboard bound to non-localhost ({}) without authentication token. \
         Auto-generated token: {}",
        dashboard_config.listen_address, generated
    );
    dashboard_config.token = Some(generated);
}
```

---

### 7.3 Live BPF Map Sync on Policy Edit

**Fixes:** BPF Maps Not Updated on Dashboard Policy Edit (MEDIUM)

#### Solution: Reuse SIGHUP Map Reload Logic on Policy Save

When the dashboard saves a policy change, trigger the same BPF map update that SIGHUP performs:

```rust
// In guardian/src/dashboard/routes/api.rs

async fn update_policy(
    State(state): State<DashboardState>,
    Path(agent_name): Path<String>,
    Json(new_policy): Json<PolicyUpdate>,
) -> impl IntoResponse {
    // 1. Update config in memory (existing code)
    // 2. Save to disk (existing code)

    // 3. NEW: Sync BPF maps with updated policy
    if let Err(e) = sync_bpf_maps(&state, &agent_name, &new_policy).await {
        warn!("Failed to sync BPF maps after policy update: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Policy saved but BPF maps not updated. Send SIGHUP to reload.");
    }

    info!("Policy updated and BPF maps synced for agent '{}'", agent_name);
    (StatusCode::OK, "Policy updated and enforcement active")
}
```

```rust
// In guardian/src/main.rs — extract map update logic into reusable function

pub async fn sync_bpf_maps(
    bpf: &mut Bpf,
    agent: &AgentConfig,
) -> anyhow::Result<()> {
    // Clear existing entries for this agent
    clear_agent_maps(bpf, agent)?;

    // Re-populate from new config
    populate_deny_maps(bpf, &agent.file_access)?;
    populate_allow_maps(bpf, &agent.file_access)?;
    populate_exec_deny_maps(bpf, &agent.exec)?;
    populate_exec_allow_maps(bpf, &agent.exec)?;

    info!("BPF maps synced for agent '{}'", agent.name);
    Ok(())
}
```

---

### 7.4 Full SIGHUP Reload Including Alerting

**Fixes:** SIGHUP Reload Skips Alerting Outputs (LOW)

#### Solution: Reconstruct AlertManager on Reload

```rust
// In the SIGHUP handler (guardian/src/main.rs)

async fn handle_sighup(
    config_path: &str,
    state: &mut AppState,
) -> anyhow::Result<()> {
    let new_config = Config::from_file(config_path)?;

    // Existing: reload agent policies + BPF maps
    reload_agent_policies(&new_config, &mut state.bpf).await?;

    // NEW: reload alerting configuration
    if new_config.alerting != state.config.alerting {
        info!("Alerting configuration changed — rebuilding alert outputs");

        // Create new alert senders from updated config
        let new_alert_manager = AlertManager::new(&new_config.alerting).await?;

        // Replace the old alert manager
        // The old one's tasks will be dropped (cancelled)
        state.alert_manager = new_alert_manager;

        info!("Alert outputs reloaded successfully");
    }

    // NEW: reload permissions config
    if new_config.permissions != state.config.permissions {
        info!("Permissions configuration changed — updating hardening rules");
        state.permissions_config = new_config.permissions.clone();
    }

    state.config = new_config;
    Ok(())
}
```

---

## 8. Implementation Phases

### Phase 8a: Critical Security (P0 + P1)

**Goal:** Close the two CRITICAL and three HIGH severity gaps.

| Fix | Files Changed | Estimated Complexity |
|-----|---------------|---------------------|
| 2.1 bpf_d_path() LSM enforcement | guardian-ebpf/src/main.rs, guardian/src/main.rs | High |
| 2.2 TOCTOU elimination (consequence of 2.1) | Same as 2.1 | Included |
| 2.3 Inode LSM hooks | guardian-ebpf/src/main.rs, guardian/src/main.rs | Medium |
| 2.4 io_uring seccomp blocking | guardian-launch/src/main.rs, Cargo.toml | Low |
| 4.1 cgroup/connect network enforcement | guardian-ebpf/src/main.rs, guardian/src/main.rs, config.rs | High |

**Kernel requirements:** Linux 5.11+ with CONFIG_BPF_LSM for full coverage.

### Phase 8b: Exec Hardening + Dashboard Security (P2)

| Fix | Files Changed | Estimated Complexity |
|-----|---------------|---------------------|
| 3.1 memfd_create blocking | guardian-launch/src/main.rs, config.rs | Low |
| 3.2 Dynamic linker detection | guardian-ebpf/src/main.rs, guardian/src/main.rs | Medium |
| 3.3 Strict enforcement mode | guardian/src/main.rs, config.rs | Low |
| 7.2 Dashboard authentication | guardian/src/dashboard/mod.rs, config.rs | Medium |
| 7.3 Live BPF map sync | guardian/src/dashboard/routes/api.rs, main.rs | Medium |

### Phase 8c: Approval Hardening + Monitoring (P3)

| Fix | Files Changed | Estimated Complexity |
|-----|---------------|---------------------|
| 5.1 Risk-based timeouts | guardian-common/src/lib.rs, config.rs, ipc.rs | Low |
| 5.2 CLI permission approval | guardian-ctl/src/main.rs, guardian-common, ipc.rs | Medium |
| 5.3 Anomaly detection | guardian/src/permissions.rs, main.rs | High |
| 5.4 Grant accumulation limits | guardian/src/permissions.rs, ipc.rs | Low |
| 2.5 Path truncation handling | guardian-ebpf/src/main.rs, guardian-common | Low |
| 2.6 BPF map capacity increase | guardian-ebpf/src/main.rs, main.rs | Low |

### Phase 8d: Polish + Portability (P4)

| Fix | Files Changed | Estimated Complexity |
|-----|---------------|---------------------|
| 6.2 BTF portable offsets | guardian-ebpf/src/main.rs, xtask | High |
| 5.5 Improved justification analysis | guardian/src/permissions.rs | Medium |
| 6.3 openat2 seccomp fallback | guardian-launch/src/main.rs | Low |
| 7.4 Full SIGHUP reload | guardian/src/main.rs | Low |
| 7.1 Configurable fail-closed | guardian-ebpf/src/main.rs, config.rs | Medium |
| 4.2 DNS monitoring | guardian-ebpf/src/main.rs, main.rs | Medium |

---

## Appendix: New Dependencies Required

| Crate | Version | Purpose | Phase |
|-------|---------|---------|-------|
| seccompiler | 0.4+ | Seccomp BPF filter generation | 8a |
| url | 2 | Query parameter parsing (dashboard auth) | 8b |
| rand | 0.8 | Auto-generated auth tokens | 8b |

## Appendix: Kernel Feature Matrix

| Feature | Minimum Kernel | Config Flag | Used By |
|---------|---------------|-------------|---------|
| Basic eBPF | 4.15 | CONFIG_BPF=y | All monitoring |
| PerfEventArray | 5.2 | CONFIG_BPF=y | Event streaming |
| BPF LSM | 5.7 | CONFIG_BPF_LSM=y | File/exec enforcement |
| bpf_d_path() | 5.11 | CONFIG_BPF_LSM=y | Symlink-safe enforcement |
| cgroup/connect | 4.17 | CONFIG_CGROUP_BPF=y | Network enforcement |
| openat2 tracepoint | 5.6 | — | openat2 monitoring |
| Seccomp | 3.17 | CONFIG_SECCOMP=y | io_uring/memfd blocking |
| BTF | 5.2 | CONFIG_DEBUG_INFO_BTF=y | Portable offsets |
