# Code Quality & Best Practices Improvements

## Overview

A comprehensive code quality audit identified issues across the Guardian Shell codebase in seven categories: panic-inducing unwraps, missing input validation, magic numbers, silent error swallowing, dead code, missing security logging, and unsafe string operations. This document describes each fix, its rationale, and the files changed.

All changes compile with zero errors and zero warnings. All 25 existing tests pass.

---

## 1. Named Constants for Magic Numbers

**Problem:** The IPC message size limit (`1024 * 1024`) was hardcoded in two locations (`guardian-common/src/lib.rs:329` and `guardian/src/ipc.rs:210`). Field length limits for agent names, resource paths, and justification text were not defined anywhere.

**Fix:** Added named constants to `guardian-common/src/lib.rs`:

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_IPC_MESSAGE_LEN` | 1 MiB | Maximum IPC message size (sender + receiver) |
| `MAX_AGENT_NAME_LEN` | 128 | Maximum agent name length |
| `MAX_RESOURCE_PATH_LEN` | 4096 | Maximum resource path length |
| `MAX_JUSTIFICATION_LEN` | 2048 | Maximum justification text length |

All constants are `#[cfg(feature = "user")]` to avoid pulling them into the eBPF no_std target.

**Files changed:**
- `guardian-common/src/lib.rs` — New constants + `recv_message()` uses `MAX_IPC_MESSAGE_LEN`
- `guardian/src/ipc.rs` — `handle_connection()` uses `MAX_IPC_MESSAGE_LEN`

---

## 2. Panic Prevention (unwrap/expect Removal)

**Problem:** Seven locations used `.unwrap()` or `.expect()` on fallible operations in production code paths. Any failure would crash the daemon, potentially leaving agents unmonitored.

### 2a. Agent config lookup (`ipc.rs`)

**Before:**
```rust
let agent_config = agent_config.unwrap().clone();
```

**After:**
```rust
let agent_config = match state.config.agents.iter().find(|a| a.name == agent_name) {
    Some(cfg) => cfg.clone(),
    None => { return IpcResponse::Error { ... }; }
};
```

### 2b. Prometheus metric registration (`alerting/metrics.rs`)

**Before:**
```rust
registry.register(Box::new(file_events.clone())).unwrap();
// ... 4 more unwraps
```

**After:** Loop with named metrics and `warn!` on failure:
```rust
for (name, collector) in [("file_events", Box::new(file_events.clone()) as Box<dyn Collector>), ...] {
    if let Err(e) = registry.register(collector) {
        log::warn!("Failed to register Prometheus metric '{}': {}", name, e);
    }
}
```

### 2c. Prometheus encoding (`dashboard/routes/api.rs` and `alerting/metrics.rs`)

**Before:** `encoder.encode(&metric_families, &mut body).unwrap()` — panics on encoding error, crashing the daemon from an HTTP request.

**After:** Returns HTTP 500 on failure. The dashboard endpoint now returns `Response` instead of `impl IntoResponse` to support early error returns.

### 2d. Event database open (`main.rs`)

**Before:** `EventDb::open(&db_path).expect("Failed to open event database")` — daemon crashes if SQLite file can't be created (e.g., permissions, disk full).

**After:** Falls back to in-memory SQLite with a logged error:
```rust
let db = match dashboard::db::EventDb::open(&db_path) {
    Ok(db) => Arc::new(db),
    Err(e) => {
        error!("Failed to open event database at '{}': {} — events will not be persisted", ...);
        Arc::new(dashboard::db::EventDb::open(":memory:")
            .expect("in-memory SQLite should always succeed"))
    }
};
```

### 2e. Seccomp rule creation (`guardian-launch/src/main.rs`)

**Before:** `SeccompRule::new(vec![always_match.clone()]).unwrap()` inside a loop.

**After:** Proper error propagation with `?`:
```rust
let rule = SeccompRule::new(vec![always_match.clone()])
    .map_err(|e| anyhow::anyhow!("Failed to create seccomp rule for syscall {}: {:?}", syscall_nr, e))?;
```

**Files changed:**
- `guardian/src/ipc.rs` — Agent config match
- `guardian/src/alerting/metrics.rs` — Registry registration + encoding
- `guardian/src/dashboard/routes/api.rs` — Metrics endpoint encoding + return type
- `guardian/src/main.rs` — Database open fallback
- `guardian-launch/src/main.rs` — Seccomp rule creation

---

## 3. IPC Input Validation

**Problem:** IPC requests were deserialized and processed without validating field contents. A malicious or buggy client could send:
- Empty agent names (causing confusing errors downstream)
- Agent names with `/` (path traversal in cgroup creation)
- Agent names with null bytes (C string truncation attacks)
- Multi-megabyte resource paths or justification strings
- Zero or unreasonably large duration values

**Fix:** New `validate_request()` function in `ipc.rs`, called after deserialization and before `process_request()`. Returns an `IpcResponse::Error` immediately on invalid input.

| Request Type | Validations |
|-------------|-------------|
| `Register` | agent_name: 1-128 chars, no `/` or `\0`; cgroup_path: no `\0` |
| `StopAgent` | agent_name: non-empty |
| `GrantAccess` | agent_name: non-empty; path: 1-4096 chars; duration: 1-86400s |
| `RequestPermission` | agent_name: non-empty; resource_path: 1-4096; justification: max 2048 |
| `ApprovePermission` | duration: 1-86400s |
| `ListAgents`, `ListPending`, `DenyPermission` | No validation needed |

**Files changed:**
- `guardian/src/ipc.rs` — New `validate_request()` function + call site in `handle_connection()`

---

## 4. Unsafe Path Slicing Fix

**Problem:** Three locations used `&path[..path.len() - 3]` to strip the `/**` glob suffix. If a path was shorter than 3 bytes (e.g., `""`, `"/"`), this would panic with an underflow/out-of-bounds error.

**Locations:**
1. `handle_grant_access()` — file grant BPF map insertion
2. `resolve_permission()` — permission approval BPF map insertion
3. Grant expiry cleanup — BPF map removal

**Fix:** New `strip_glob_to_prefix()` helper:
```rust
fn strip_glob_to_prefix(path: &str) -> String {
    path.strip_suffix("/**")
        .unwrap_or(path)
        .to_string()
        + "/"
}
```

Uses `strip_suffix()` which safely returns `None` if the suffix isn't present, eliminating the bounds check entirely.

**Files changed:**
- `guardian/src/ipc.rs` — New helper + 3 call sites replaced

---

## 5. Silent Error Handling Fixes

**Problem:** Multiple operations silently discarded errors with `let _ = ...`, making failures invisible in logs.

### 5a. Broadcast channel sends

Three `let _ = bus.send(PermissionEvent { ... })` calls silently dropped permission events when no SSE subscribers were connected.

**After:** `if let Err(e) = bus.send(...) { debug!("No SSE subscribers: {}", e); }`

This uses `debug!` rather than `warn!` because having no subscribers is expected when no dashboard tab is open.

### 5b. Permission audit persistence

Four `let _ = db.insert_permission_audit(...)` calls silently lost audit records on database errors.

**After:** `if let Err(e) = db.insert_permission_audit(...) { warn!("Failed to persist permission audit: {}", e); }`

### 5c. BPF map operations in grants

Grant creation logged failures at `warn!` but grant expiry used `let _ = policy_maps.allow_prefixes.remove(...)` silently.

**After:** Expiry removals now log at `debug!` level. Grant creation log messages now include the path for easier debugging.

### 5d. Inconsistent log macro usage

One location used `log::warn!(...)` instead of the imported `warn!` macro. Fixed for consistency.

**Files changed:**
- `guardian/src/ipc.rs` — 3 broadcast sends, 4 audit inserts, 3 BPF map operations, 1 log macro

---

## 6. Dead Code Removal

**Problem:** Three items were marked `#[allow(dead_code)]` and genuinely unused.

| Item | Location | Reason for Removal |
|------|----------|-------------------|
| `PERMISSION_TIMEOUT_SECS` | `ipc.rs:117` | Superseded by `RiskLevel::timeout_secs()` in Phase 8 |
| `GrantAccumulator::total_secs()` | `permissions.rs:218` | Never called; `record_and_check()` serves same purpose |
| `get_cgroup_id()` | `ipc.rs:1195` | Duplicate of function in `guardian-launch/src/main.rs` |

**Not removed** (legitimately needed):
- `pattern_to_policy_rule()` in `config.rs` — used by tests
- `EventType` variants in `alerting/mod.rs` — constructed conditionally
- `event_bus()` in `alerting/mod.rs` — used by dashboard state setup
- All `#[allow(dead_code)]` on Askama template fields in `pages.rs` — required by template rendering

**Files changed:**
- `guardian/src/ipc.rs` — Removed constant and function
- `guardian/src/permissions.rs` — Removed method

---

## 7. Authentication Failure Logging

**Problem:** The dashboard auth middleware returned HTTP 401 on failed authentication attempts but did not log them. An attacker brute-forcing tokens would generate no log evidence.

**Fix:** Added `log::warn!` before the 401 response:
```rust
log::warn!(
    "Unauthorized dashboard access attempt: {} {} (no valid token)",
    req.method(), path
);
```

**Files changed:**
- `guardian/src/dashboard/mod.rs` — Auth middleware

---

## Summary of Changes

| File | Changes |
|------|---------|
| `guardian-common/src/lib.rs` | +4 constants, 1 magic number replaced |
| `guardian/src/ipc.rs` | +52 line validation function, 3 path slicing fixes, 10 error handling fixes, 3 dead code removals |
| `guardian/src/main.rs` | 1 expect → graceful fallback |
| `guardian/src/permissions.rs` | 1 dead method removed |
| `guardian/src/alerting/metrics.rs` | 2 unwrap removals (registration + encoding) |
| `guardian/src/dashboard/routes/api.rs` | 1 unwrap → HTTP 500, return type fix |
| `guardian/src/dashboard/mod.rs` | 1 auth failure log added |
| `guardian-launch/src/main.rs` | 1 unwrap → error propagation |

**Total: 8 files changed, ~90 lines added, ~40 lines removed.**

---

## Verification

```
$ cargo check
    Finished `dev` profile [optimized + debuginfo] target(s) in 3.32s
    # 0 errors, 0 warnings

$ cargo test
    running 25 tests
    test result: ok. 25 passed; 0 failed; 0 ignored
```

---

## Remaining Items (Not Addressed)

These were identified during the audit but intentionally deferred as they require larger architectural changes or are low-priority:

| Item | Reason Deferred |
|------|----------------|
| Breaking up `main()` (662 lines) and `start_ipc_server()` (1066 lines) | Invasive refactor, no functional impact |
| CSRF protection on dashboard API endpoints | Dashboard is localhost-bound; use reverse proxy for remote access |
| Connection pool for SQLite | `Mutex<Connection>` is adequate for single-daemon workload |
| Webhook/email retry logic | Would add significant complexity; operators monitor `alerts_sent{status="error"}` |
| `remove_dir` → retry loop for cgroup cleanup | Race window is small; processes usually exit within seconds of SIGTERM |
| Query parameter token removal from auth | Documented trade-off for dashboard embedding ease |
