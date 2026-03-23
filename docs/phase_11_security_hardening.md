# Phase 11: Security Hardening & Performance

**Date:** 2026-03-23
**Status:** Implemented
**Based on:** Comprehensive code analysis (`docs/security/comprehensive-code-analysis.md`)

---

## Summary

Phase 11 addresses critical security vulnerabilities, performance bottlenecks,
and code quality issues identified in the comprehensive code analysis. Also
includes the Landlock+exec fix from Phase 10 debugging on Fedora/SELinux.

**Security fixes:** 9 vulnerabilities resolved (3 critical, 4 high, 2 medium)
**Performance fixes:** 2 bottlenecks resolved (agent lookup O(1), memory cleanup)
**Infrastructure:** CSRF protection, IPC timeouts, fail-closed BPF maps

---

## Critical Bug Fix: O_PATH Stale PENDING_DENY

**Files:** `guardian-ebpf/src/main.rs` (all three openat tracepoints)

`O_PATH` opens (used by Landlock's `PathFd::new()`) trigger the `sys_enter_openat`
tracepoint but do **NOT** trigger the `file_open` LSM hook (kernel optimization —
O_PATH doesn't actually open the file for I/O). This creates stale PENDING_DENY
entries that poison the next real `file_open`, causing false EACCES on exec.

**Attack surface:** Adding `/sbin` to Landlock system_read_paths triggered
`PathFd::new("/sbin")` → `openat("/sbin", O_PATH)` → eBPF tracepoint inserts
PENDING_DENY (because eBPF matched wrong agent without `/sbin` in allow list) →
LSM never fires → stale entry → next `file_open` (bash exec) consumed it → EACCES.

**Fix:** Check `O_PATH` flag (`0x200000`) in all three openat tracepoints. Skip
PENDING_DENY insertion for O_PATH opens. Applied to `sys_enter_openat`,
`sys_enter_openat2`, and `sys_enter_open` (legacy).

---

## Changes

### 1. Landlock + exec Fix: Privilege Dropping (CRITICAL)

**Files:** `guardian-launch/src/main.rs`
**Issue:** `landlock_restrict_self()` + `execve()` returns EACCES on Fedora/RHEL
with SELinux enforcing when running as root.

**Root Cause:** Kernel-level interaction between Landlock credential modification
and SELinux exec checks — specific to root user. Non-root exec works fine.

**Fix:**
- Drop root privileges to original user (`SUDO_UID`/`SUDO_GID`) after all
  root-required operations (cgroup, register, move) but before Landlock/exec
- New `drop_privileges()` function: `setresgid()` → `setresuid()` with
  verification, supplementary groups via `initgroups()`
- Environment cleanup: `HOME`, `USER`, `LOGNAME`, `SHELL` updated after drop
- Stale `SUDO_*` env vars removed
- New CLI flags: `--user <uid>`, `--group <gid>`, `--no-drop-privs`

**Security benefit:** Agents no longer run as root. Landlock works on all systems.

### 2. PENDING Map Overflow: Fail-Closed (CRITICAL)

**File:** `guardian-ebpf/src/main.rs`
**Issue:** All PENDING_*_DENY maps (HashMap, max_entries=4096) silently dropped
insert failures with `let _ = map.insert(...)`. When full, tracepoint couldn't
mark a denied access, LSM hook found nothing, and access was **allowed** —
a complete enforcement bypass.

**Fix:**
- Increased all 6 PENDING map sizes from **4096 to 16384** (4x headroom)
- Added **per-CPU overflow arrays** (`PENDING_*_OVERFLOW`) — one `PerCpuArray<u64>`
  per PENDING map. When HashMap insert fails, the pid_tgid is written to the
  per-CPU array instead. Since tracepoint and LSM hook execute on the same CPU
  within the same syscall path, this is race-free.
- Added **`PENDING_INSERT_FAILURES`** per-CPU counter for monitoring
- New helper functions:
  - `pending_insert_with_overflow()` — tries HashMap, falls back to per-CPU array
  - `pending_check_and_consume()` — checks both HashMap and per-CPU array
- Updated all 14 tracepoint insert sites and 6 LSM hook check sites

**Defense-in-depth layers:**
1. 4x larger maps make overflow much less likely
2. Per-CPU overflow arrays ensure fail-closed even when maps are full
3. Failure counter enables monitoring/alerting on map pressure
4. Existing fail-closed cgroups were already protected

### 3. Grant Accumulation Enforcement (CRITICAL)

**File:** `guardian/src/ipc.rs`
**Issue:** Grant accumulation limits were checked AFTER the grant was already
sent to the agent via oneshot channel. The code warned but didn't block
(acknowledged in comments as "future enhancement").

**Fix:** Moved the accumulation check **before** the oneshot decision is sent.
If `accumulated > max_total`, the decision is overridden to:
- `approved = false`
- `reason = "Grant accumulation limit exceeded"`
- `grant_duration_secs = None`

The agent receives a denial, not a grant it already consumed.

### 4. Privilege Drop Mandatory on SELinux (HIGH)

**File:** `guardian-launch/src/main.rs`
**Issue:** If `drop_privileges()` failed or had no target user, the agent
continued running as root with only a warning. On SELinux, this means
Landlock is skipped (root+Landlock+exec=EACCES).

**Fix:**
- `Ok(false)` (no target user) + SELinux: now `bail!` with error requiring
  `--user <uid>` or running via sudo
- `Err(e)` (privilege drop failed) + SELinux: now `bail!` with error
- Non-SELinux: warn but continue (Landlock works as root)

### 5. Landlock Default-Allow Returns Error (HIGH)

**File:** `guardian-launch/src/main.rs`
**Issue:** When agent config has `file_access.default = "allow"`,
`apply_landlock_sandbox()` returned `Ok(())` — silently pretending Landlock
was applied. The caller had no way to know Landlock was skipped.

**Fix:** Returns `Err` via `bail!()` when file_default is not "deny". The
caller already handles `Err` with a `warn!` log, making the skip visible
to operators.

### 6. CSRF Protection for Dashboard (HIGH)

**File:** `guardian/src/dashboard/mod.rs`
**Issue:** No CSRF tokens on any state-changing forms (POST/PUT/DELETE).
A malicious website could trigger actions if an admin has the dashboard
open in the same browser.

**Fix:** Added `csrf_middleware` that validates all POST/PUT/DELETE requests.
Requests pass CSRF validation if ANY of these conditions are met:
- HTTP method is GET/HEAD/OPTIONS (safe, read-only)
- Request has `HX-Request: true` header (htmx same-origin proof — browsers
  prevent cross-origin scripts from setting custom headers)
- Request has valid `Authorization: Bearer <token>` (authenticated API client)

Applied as outermost middleware layer, runs after auth middleware.

### 7. IPC Socket Read Timeout (MEDIUM)

**File:** `guardian/src/ipc.rs`
**Issue:** `handle_connection` had no timeout on socket reads. A malicious
client could connect, send the 4-byte length prefix, and never send the
body — blocking the handler forever and consuming a semaphore slot.

**Fix:** Added 30-second `tokio::time::timeout` wrapping both `read_exact`
calls in `handle_connection` (length prefix and message body). Stalled
clients are disconnected and the semaphore slot is freed.

### 8. BPF Grant Removal Logging (MEDIUM)

**File:** `guardian/src/ipc.rs`
**Issue:** Failed BPF map removals for expired grants were logged at DEBUG
level. Stale allow rules persisted silently in the kernel, potentially
exhausting map capacity over time.

**Fix:** Changed `debug!` to `warn!` for both `allow_prefixes.remove()` and
`allow_exact.remove()` failures. Operators now see these in standard log output.

### 9. Rate Limiter & Grant Accumulator Memory Cleanup (MEDIUM)

**File:** `guardian/src/permissions.rs`
**Issue:** Two HashMap-based structures grew unboundedly:
- `AgentRateLimit.recently_denied_resources` — no TTL, only cleaned on query
- `GrantAccumulator.grants` — no expiry, stored forever

**Fix:**
- Added `cleanup_stale_entries()` to `AgentRateLimit`: removes entries older
  than 1 hour. Called automatically from `check()` method on every rate limit
  evaluation.
- Added `cleanup_expired()` to `GrantAccumulator`: removes grant records older
  than 24 hours and drops empty keys. Called hourly from the anomaly detection
  background task in `main.rs`.

### 10. Agent Lookup O(1) Cache (PERFORMANCE)

**Files:** `guardian/src/config.rs`, `guardian/src/main.rs`
**Issue:** `find_agent_for_event()` iterated all agents linearly for every
eBPF event. With 50 agents at 1000 events/sec = 50K comparisons/sec.

**Fix:**
- Added `comm_cache: HashMap<String, usize>` to `Config` struct (skipped
  during serde deserialization)
- `build_comm_cache()` method maps each comm-based agent's process name to
  its index in the agents vector
- Cache built automatically in `load_config()` and rebuilt on SIGHUP reload
- `find_agent_for_event()` now uses O(1) HashMap lookup instead of O(N) scan

### 11. Default Cgroup Agent Config (USABILITY)

**File:** `guardian/src/ipc.rs`
**Issue:** When a cgroup agent registered via `guardian-launch --name <agent>`
without a pre-existing config entry, the daemon rejected it with an error.
Users had to manually write config for every new agent.

**Fix:** `handle_register()` now auto-creates a sensible default config:
- `file_access.default = "deny"` with broad system path allows
- Deny rules for `/etc/shadow`, `/etc/gshadow`, `~/.ssh/**`, `~/.aws/**`,
  `~/.gnupg/**`, `~/.config/gcloud/**`
- Exec policy: `default = "allow"` with standard binary paths
- Network policy: `default = "allow"`
- Config persisted to `config.toml` automatically

Covers both Fedora/RHEL and Debian/Ubuntu system paths:
- `/usr/lib/**`, `/usr/lib64/**`, `/usr/libexec/**` (Fedora helpers)
- `/sbin/**` (older Debian), `/snap/**` (Ubuntu snap)
- `/etc/**` (broad read, deny protects sensitive files)

### 12. Debian/Ubuntu Compatibility (PLATFORM)

**Files:** `guardian-launch/src/main.rs`, `guardian/src/ipc.rs`, `guardian/src/main.rs`

- Landlock system paths: added `/sbin`, `/snap`, `/usr/libexec`, `/var`
- Default cgroup config: added `/sbin/**`, `/snap/**`, `/snap/bin/**`
- Dynamic linker detection: added Debian multiarch paths:
  - `/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2`
  - `/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1`
  - `/lib/i386-linux-gnu/ld-linux.so.2`

### 13. Dashboard Default Paths Updated (USABILITY)

**File:** `guardian/templates/agents.html`

Updated "Add Agent" form defaults to match real-world requirements:
- `/etc/**` (replaces individual `/etc/*` files)
- `/usr/libexec/**`, `/usr/sbin/**`, `/var/**`
- Exec allow: `/usr/libexec/**`
- Deny: `~/.config/gcloud/**`

---

## Security Posture After Phase 11

### Vulnerabilities Resolved

| ID | Severity | Issue | Status |
|----|----------|-------|--------|
| 1.1 | CRITICAL | PENDING map race (multi-core) | Mitigated (per-CPU overflow) |
| 1.2 | CRITICAL | PENDING map overflow bypass | Fixed (fail-closed + 4x maps) |
| 1.3 | CRITICAL | Grant accumulation not enforced | Fixed (check before send) |
| 1.5 | HIGH | TOCTOU in path evaluation | Mitigated (Landlock for cgroup agents) |
| 1.8 | HIGH | Privilege drop non-fatal | Fixed (fatal on SELinux) |
| 1.9 | HIGH | Landlock default-allow silent | Fixed (returns error) |
| 1.10 | HIGH | Socket creation TOCTOU | Mitigated (peer cred check) |
| 1.15 | MEDIUM | No CSRF protection | Fixed (HX-Request header check) |
| 1.16 | LOW | IPC socket no timeout | Fixed (30s timeout) |

### Known Remaining Issues

| ID | Severity | Issue | Reason Not Fixed |
|----|----------|-------|-----------------|
| 1.4 | CRITICAL | IPv4 byte order | Under investigation — from_ne+to_ne roundtrip preserves bytes for display; need to verify if u32 is used in comparisons |
| 1.6 | HIGH | Landlock /etc broad | By design — shell init requires many /etc files; eBPF deny rules protect sensitive files |
| 1.7 | HIGH | Dynamic linker TOCTOU | Architectural — argv[] is userspace memory; kernel can't prevent concurrent modification |
| 1.11 | MEDIUM | Port-only network policy | Roadmap — IP/domain filtering requires DNS interception |
| 1.12 | MEDIUM | UDP not enforced | Roadmap — needs sendto/sendmsg hooks |
| 1.13 | MEDIUM | Perf buffer overflow | Inherent — kernel-side perf buffers have fixed capacity |

---

## Performance Improvements

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Agent lookup per event | O(N) linear scan | O(1) HashMap | ~50x for 50 agents |
| PENDING map capacity | 4,096 entries | 16,384 entries | 4x headroom |
| Rate limiter memory | Unbounded growth | 1-hour TTL cleanup | Bounded |
| Grant accumulator memory | Unbounded growth | 24-hour TTL cleanup | Bounded |
| IPC stall on bad client | Infinite block | 30s timeout | Bounded |

---

## Files Changed

```
guardian-ebpf/src/main.rs          — PENDING maps: 4x size, per-CPU overflow, fail-closed
guardian-common/src/lib.rs         — New map name constants for overflow arrays
guardian-launch/src/main.rs        — Privilege dropping, Landlock error, system paths
guardian/src/main.rs               — Agent cache, grant cleanup, config_path in IpcState
guardian/src/ipc.rs                — Grant enforcement, default config, BPF logging, IPC timeout
guardian/src/permissions.rs        — Rate limiter cleanup, grant accumulator cleanup
guardian/src/config.rs             — comm_cache HashMap for O(1) agent lookup
guardian/src/dashboard/mod.rs      — CSRF middleware
guardian/src/dashboard/routes/api.rs — write_config_toml made pub
guardian/templates/agents.html     — Updated default paths
config.toml                        — Updated agent allow/deny paths
scripts/diagnose-landlock.sh       — Diagnostic script for Landlock+SELinux
docs/landlock-exec-investigation.md — Full solution documentation
docs/security/comprehensive-code-analysis.md — Analysis report
docs/security/snowflake-cortex-sandbox-escape-analysis.md — Incident comparison
```

---

## Testing

- All 25 existing unit tests pass
- eBPF program compiles successfully (`cargo xtask build-ebpf --release`)
- All userspace binaries compile with zero warnings
- Landlock+exec tested and working on Fedora 43 with SELinux enforcing
