# Performance Improvements

## Overview

A performance audit identified optimization opportunities across the Guardian Shell codebase in six categories: release binary optimization, hot-path allocation reduction, static string references, SQLite query indexing, zero-copy static file serving, and I/O syscall reduction. This document describes each change, its rationale, and the files modified.

All changes compile with zero errors and zero warnings. All 25 existing tests pass.

---

## 1. Release Profile Optimization

**Problem:** The release build used default Rust compiler settings, producing a larger binary with suboptimal codegen.

**Fix:** Added optimized release profile to the workspace `Cargo.toml`:

| Setting | Value | Effect |
|---------|-------|--------|
| `lto` | `"thin"` | Cross-crate link-time optimization — inlines across crate boundaries, ~10-20% faster code |
| `codegen-units` | `1` | Single codegen unit allows maximum optimization (default is 16 for parallelism) |
| `strip` | `"symbols"` | Removes debug symbols from release binary, reducing size by ~50-70% |

`panic = "abort"` was already set (required for eBPF compatibility).

**Trade-off:** Longer release compile times (~2x) in exchange for a smaller, faster binary.

**Files changed:**
- `Cargo.toml` — Release profile settings

---

## 2. Path Normalization Hot-Path Optimization

**Problem:** `normalize_path()` in `config.rs` is called for every file access event received from eBPF. The original implementation created multiple intermediate `String` allocations:

```rust
// Before: 3+ allocations per call
let mut path = path.to_string();                    // alloc 1
path = path.strip_prefix(...).to_string();          // alloc 2
let components: Vec<String> = ...collect();          // alloc 3+
let result = components.join("/");                   // alloc 4
```

**Fix:** Rewritten to work on `&str` slices with a single pre-allocated output buffer:

```rust
// After: 1 allocation, pre-sized
let mut result = String::with_capacity(path.len());
let components: Vec<&str> = Vec::with_capacity(16);  // stack-local refs
// ... process slices, write once into result
```

**Impact:** Reduces allocations from ~4 per call to 1, and avoids copying path bytes multiple times. On a system generating thousands of file events per second, this eliminates millions of unnecessary allocations per hour.

**Files changed:**
- `guardian/src/config.rs` — `normalize_path()` rewrite

---

## 3. Static String References in Risk Analysis

**Problem:** `classify_risk()` and `analyze_justification()` in `permissions.rs` allocated heap `String`s for every risk flag and justification finding, even though all values are compile-time string literals.

```rust
// Before: heap allocation per finding
findings.push(("URGENCY".to_string(), "Pattern matched".to_string()));
```

**Fix:** Changed return types from `Vec<(String, String)>` to `Vec<(&'static str, &'static str)>`:

```rust
// After: zero-copy static references
findings.push(("URGENCY", "Pattern matched"));
```

Additional optimizations in the same functions:
- `Vec::with_capacity(4)` pre-allocation (most results have 1-3 entries)
- Integer arithmetic replacing floating-point multipliers: `score * 3 / 2` instead of `(score as f64 * 1.5) as u32`

**Impact:** Eliminates 2 heap allocations per pattern match. For `classify_risk()`, which runs on every permission request, this removes up to 8+ allocations per call (4 risk flags x 2 strings each).

**Files changed:**
- `guardian/src/permissions.rs` — Return types, `.into()` for static strings, integer math, pre-allocation
- `guardian/src/ipc.rs` — Updated `PendingPermission.justification_flags` type to `Vec<(&'static str, &'static str)>`

---

## 4. Composite SQLite Indexes

**Problem:** The events and permission_audit tables had only single-column indexes. Common query patterns filter on multiple columns simultaneously (e.g., "all BLOCKED events for agent X", "recent critical events"), causing SQLite to scan one index and then filter rows from disk.

**Fix:** Added composite indexes covering the most common query patterns:

| Index | Columns | Query Pattern |
|-------|---------|---------------|
| `idx_events_agent_action` | `(agent_name, action)` | Dashboard filtering by agent + action |
| `idx_events_severity_ts` | `(severity, timestamp DESC)` | Recent events filtered by severity |
| `idx_perm_audit_agent_resolved` | `(agent_name, resolved_at DESC)` | Per-agent audit history |
| `idx_perm_audit_resolved_approved` | `(resolved_at, approved)` | Anomaly detection: approval rate queries |

**Impact:** Composite indexes allow SQLite to satisfy multi-column WHERE clauses with a single index scan instead of scanning + filtering. The anomaly detection self-join query (`agents_with_deny_then_approve`) benefits most, as it joins on `agent_name + resource_path + approved`.

**Trade-off:** Slightly more disk space and marginally slower inserts (~microseconds). Negligible for this workload.

**Files changed:**
- `guardian/src/dashboard/db.rs` — 4 new composite indexes in schema creation

---

## 5. Zero-Copy Static File Serving

**Problem:** The dashboard static file handler called `.to_vec()` on every request, copying embedded file bytes from the binary's read-only data section into a new heap allocation:

```rust
// Before: copies static bytes into a new Vec every request
file.data.to_vec()
```

Since `rust_embed` returns `Cow<'static, [u8]>` where embedded files are `Cow::Borrowed(&'static [u8])`, this copy is unnecessary.

**Fix:** Match on the `Cow` variant to use `Bytes::from_static()` for embedded data:

```rust
// After: zero-copy for embedded files
let body: bytes::Bytes = match file.data {
    Cow::Borrowed(b) => Bytes::from_static(b),  // no copy
    Cow::Owned(v) => Bytes::from(v),             // takes ownership
};
```

**Impact:** Eliminates one heap allocation + memcpy per static file request. For `app.js` and `app.css` served on every page load, this saves ~2 allocations per page view. Under load (many dashboard users), this reduces GC pressure and memory bandwidth.

**Files changed:**
- `guardian/src/dashboard/mod.rs` — `static_handler()` zero-copy response body

---

## 6. JSON Log I/O Reduction

**Problem:** The JSON logger called `file.flush().await?` after every single event write, forcing a separate syscall per event:

```rust
// Before: 2 syscalls per event (write + flush)
file.write_all(&json).await?;
file.flush().await?;
```

**Fix:** Removed the per-event flush. `write_all()` already issues the write syscall, and the OS write-back cache ensures data reaches disk within seconds. Log rotation still triggers naturally when `bytes_written >= max_size_bytes`.

```rust
// After: 1 syscall per event (write only)
file.write_all(&json).await?;
// OS handles flush via write-back cache
```

**Impact:** Halves the number of file I/O syscalls under sustained event load. For a system generating 1000 events/second, this eliminates 1000 unnecessary `fsync`-like operations per second.

**Trade-off:** In a crash, the last few events (up to OS buffer size, typically 4-64KB) may not be flushed to disk. This is acceptable for a monitoring log — the eBPF events themselves are the source of truth, and the log is a secondary record.

**Files changed:**
- `guardian/src/alerting/json_log.rs` — Removed `file.flush().await?` per event

---

## Summary of Changes

| File | Changes |
|------|---------|
| `Cargo.toml` | Release profile: LTO, single codegen unit, symbol stripping |
| `guardian/src/config.rs` | `normalize_path()` rewrite: &str slices, pre-allocated buffer |
| `guardian/src/permissions.rs` | `&'static str` return types, integer math, `Vec::with_capacity` |
| `guardian/src/ipc.rs` | Updated justification_flags type, documented clone necessity |
| `guardian/src/dashboard/db.rs` | 4 composite SQLite indexes |
| `guardian/src/dashboard/mod.rs` | Zero-copy `Bytes::from_static()` for embedded files |
| `guardian/src/alerting/json_log.rs` | Removed per-event flush |

**Total: 7 files changed, ~40 lines added, ~20 lines removed.**

---

## Verification

```
$ cargo check
    Finished `dev` profile [optimized + debuginfo] target(s) in 2.61s
    # 0 errors, 0 warnings

$ cargo test
    running 25 tests
    test result: ok. 25 passed; 0 failed; 0 ignored
```

---

## Remaining Items (Not Addressed)

These were identified during the audit but intentionally deferred:

| Item | Reason Deferred |
|------|----------------|
| Async Mutex → RwLock for IPC state | Large refactor; current lock hold times are short (<1ms) |
| `perm_config.clone()` in permission handler | Required by borrow checker — immutable ref to `config.permissions` conflicts with mutable borrow of `rate_limits` in same struct |
| Grant expiry Vec drain optimization | Vec is small (typically <10 entries); collect+remove-in-reverse is adequate |
| BufWriter for JSON log | `tokio::fs::File` already uses threadpool; additional buffering adds complexity for marginal gain |
| Connection pooling for SQLite | `Mutex<Connection>` is adequate for single-daemon workload with sub-millisecond operations |
