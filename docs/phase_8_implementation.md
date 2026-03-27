# Phase 8 Implementation: Security Hardening

## What Phase 8 Solves

Phase 7 gave us path normalization, openat2 coverage, risk-based approval workflows, and an SQLite audit trail. But a security audit (`docs/security/security-limitations.md`) identified **2 CRITICAL, 3 HIGH, and 14 MEDIUM** vulnerabilities remaining across six categories. Phase 8 implements 16 concrete fixes from `docs/security/security-fixes.md`, organized into four sub-phases by priority.

**Problem 1: File manipulation bypasses.** Guardian monitors `open`/`openat`/`openat2` but not `rename`, `unlink`, or `link`. An agent can move a denied file to an allowed directory (`os.rename("/etc/shadow", "/tmp/shadow")`), read it there, and move it back. Hardlinks create same-inode copies in allowed paths. Unlink attacks can delete Guardian's own config or audit database.

**Problem 2: io_uring and memfd_create bypasses.** `io_uring` performs file I/O via ring buffers in shared memory, bypassing all syscall tracepoints entirely — Guardian sees nothing. `memfd_create` + `execveat(AT_EMPTY_PATH)` creates and executes in-memory binaries with no filesystem path for exec policy to match. Both are known blind spots in syscall-based security tools.

**Problem 3: BPF map capacity and path truncation.** With only 256 entries per map, complex policies silently drop rules. Paths longer than 256 bytes are silently truncated — policy evaluates against an incomplete path. An agent can craft paths designed to appear benign when truncated.

**Problem 4: Exec evasion via dynamic linkers.** An agent can invoke the dynamic linker directly (`/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /usr/bin/curl`) — Guardian's `bprm_check_security` sees only the linker path (allowed), not the real binary (`curl`, which should be denied).

**Problem 5: No fail-closed mode, no dashboard auth, no strict mode.** Every eBPF error silently allows access (fail-open). The dashboard has zero authentication — anyone reaching the port can approve permissions, stop agents, or weaken policy. If LSM hooks fail to load in enforce mode, Guardian silently degrades to monitor-only with a log warning.

**Problem 6: Approval workflow gaps.** Fixed 120-second timeout for all risk levels. No CLI-based approval (dashboard required). No anomaly detection on approval patterns. No limit on accumulated grant duration — a patient agent can maintain permanent access through repeated renewals.

---

## What Was Built

### Phase 8a: Critical Security (P0+P1)

| File | Lines Changed | What |
|------|---------------|------|
| `guardian-ebpf/src/main.rs` | +180 | 6 new BPF maps, 3 tracepoints (rename/unlink/link), 3 LSM hooks (inode_rename/unlink/link), execveat tracepoint, dynamic linker detection, fail-closed map, path truncation flags |
| `guardian-common/src/lib.rs` | +25 | `MAX_POLICY_RULES` 64→1024, `EVENT_FLAG_TRUNCATED` constant, `status_flags` field on `FileAccessEvent`, 5 new map name constants |
| `guardian-launch/src/main.rs` | +55 | `apply_seccomp_filter()` blocking io_uring (syscalls 425-427) + memfd_create (319) with EPERM |
| `guardian-launch/Cargo.toml` | +1 | `seccompiler = "0.4"` dependency |
| `guardian/src/main.rs` | +90 | Load/attach new tracepoints and LSM hooks, `populate_dynamic_linkers()`, default `/memfd:` exec deny, truncation warning logging, strict mode bail |

### Phase 8b: Exec Hardening + Dashboard Security (P2)

| File | Lines Changed | What |
|------|---------------|------|
| `guardian-ebpf/src/main.rs` | (included above) | `DYNAMIC_LINKERS` map, argv[1] inspection in exec monitor, `execveat` tracepoint with `AT_EMPTY_PATH` detection |
| `guardian/src/config.rs` | +30 | `auth_token` in `DashboardConfig`, `"strict"` mode validation, `fail_closed` in `AgentConfig` |
| `guardian/src/dashboard/mod.rs` | +45 | `auth_middleware()` — Bearer token + `?token=` query param, skips `/metrics` and `/static/` |
| `guardian/src/dashboard/state.rs` | +1 | `auth_token: Option<String>` field |

### Phase 8c: Approval Hardening (P3)

| File | Lines Changed | What |
|------|---------------|------|
| `guardian/src/config.rs` | +40 | `RiskTimeoutConfig` struct (low/medium/high/critical), `max_grant_total_secs` field, `timeouts` on `PermissionsConfig` |
| `guardian/src/permissions.rs` | +120 | `timeout_secs()` on `RiskLevel`, `GrantAccumulator` struct, weighted `SUSPICIOUS_PATTERNS`, graduated `justification_risk_bump()`, `AnomalyDetector` struct |
| `guardian/src/ipc.rs` | +100 | Risk-based timeouts, grant accumulation check, `handle_list_pending()`, `handle_approve_permission()`, `handle_deny_permission()` |
| `guardian-common/src/lib.rs` | +30 | `ListPending`, `ApprovePermission`, `DenyPermission` IPC variants, `PendingPermissions` response, `PendingPermissionInfo` struct |
| `guardian-ctl/src/main.rs` | +45 | `pending`, `approve`, `deny` subcommands with formatted table output |

### Phase 8d: Polish (P4)

| File | Lines Changed | What |
|------|---------------|------|
| `guardian/src/dashboard/db.rs` | +70 | `approval_rate_24h()`, `high_volume_agents_24h()`, `agents_with_deny_then_approve()` SQL queries |
| `guardian/src/main.rs` | +20 | Hourly anomaly detection background task, SIGHUP reload comment |

---

## Architecture

### Phase 8a: Inode Protection (Rename/Unlink/Hardlink)

Guardian already used the tracepoint-PENDING-LSM pattern for file open and exec. Phase 8 extends this to three additional inode operations:

```
Tracepoint                     BPF Map                    LSM Hook
─────────────────             ────────────────            ─────────────────
sys_enter_renameat2  ──SET──> PENDING_RENAME_DENY ──CHK──> inode_rename
sys_enter_unlinkat   ──SET──> PENDING_UNLINK_DENY ──CHK──> inode_unlink
sys_enter_linkat     ──SET──> PENDING_LINK_DENY   ──CHK──> inode_link
```

Each tracepoint reads the path from syscall arguments, evaluates it against the deny/allow policy maps, and sets the corresponding PENDING map entry if denied. The LSM hook fires later in the same syscall, checks the PENDING map, and returns `-EACCES` to block the operation.

**New BPF maps (3):**

| Map | Type | Max Entries | Purpose |
|-----|------|-------------|---------|
| `PENDING_RENAME_DENY` | `HashMap<u64, u8>` | 4096 | pid_tgid → deny flag for rename |
| `PENDING_UNLINK_DENY` | `HashMap<u64, u8>` | 4096 | pid_tgid → deny flag for unlink |
| `PENDING_LINK_DENY` | `HashMap<u64, u8>` | 4096 | pid_tgid → deny flag for hardlink |

**New eBPF programs (6):**

| Program | Hook Point | Function |
|---------|-----------|----------|
| `guardian_rename_monitor` | `sys_enter_renameat2` | Read source/dest paths, evaluate policy, set PENDING_RENAME_DENY |
| `guardian_unlink_monitor` | `sys_enter_unlinkat` | Read path, evaluate deny policy, set PENDING_UNLINK_DENY |
| `guardian_link_monitor` | `sys_enter_linkat` | Read source/dest paths, evaluate policy, set PENDING_LINK_DENY |
| `guardian_enforce_rename` | LSM `inode_rename` | Check + consume PENDING_RENAME_DENY, return -EACCES if set |
| `guardian_enforce_unlink` | LSM `inode_unlink` | Check + consume PENDING_UNLINK_DENY, return -EACCES if set |
| `guardian_enforce_link` | LSM `inode_link` | Check + consume PENDING_LINK_DENY, return -EACCES if set |

All six programs use graceful fallback — if LSM attachment fails, a warning is logged and the daemon continues. In `strict` mode, failure to attach any LSM hook causes the daemon to exit.

### Phase 8a: io_uring + memfd_create Seccomp Blocking

Since `io_uring` operations bypass all syscall tracepoints and `memfd_create` enables fileless exec, Phase 8 blocks these at the seccomp level in `guardian-launch`:

```
guardian-launch startup flow:
┌──────────────────┐
│ 1. Parse CLI args│
│ 2. Create cgroup │
│ 3. Set resources │
│ 4. Register IPC  │
│ 5. Move to cgroup│
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────┐
│ 6. apply_seccomp_filter()            │
│    Block with EPERM:                 │
│    - io_uring_setup     (syscall 425)│
│    - io_uring_enter     (syscall 426)│
│    - io_uring_register  (syscall 427)│
│    - memfd_create       (syscall 319)│
│    Default: Allow everything else    │
└────────┬─────────────────────────────┘
         │
         ▼
┌──────────────────┐
│ 7. exec(agent)   │
│    Agent inherits │
│    seccomp filter │
└──────────────────┘
```

The filter is applied **after** cgroup setup but **before** `exec()`, so the agent process and all its children inherit the restriction. The seccomp filter is compiled via `seccompiler` crate using `BpfProgram` with `SeccompAction::Errno(EPERM)` for matched syscalls and `SeccompAction::Allow` as the default.

**Architecture portability:** The filter uses `std::env::consts::ARCH.try_into()` for the target architecture instead of hardcoding x86_64. The seccomp application is best-effort — if it fails (e.g., seccomp not available), a warning is logged and the agent launches without the filter.

### Phase 8a: BPF Map Capacity and Path Truncation

**Map capacity increase (256 → 1024):**

All rule and config maps were increased from 256 to 1024 entries:

```rust
// Before (Phase 7):
static DENY_PREFIXES: LpmTrie<...> = LpmTrie::with_max_entries(256, 0);

// After (Phase 8):
static DENY_PREFIXES: LpmTrie<...> = LpmTrie::with_max_entries(1024, 0);
```

Affected maps: `WATCHED_COMMS`, `ENFORCE_COMMS`, `WATCHED_CGROUPS`, `ENFORCE_CGROUPS`, `CGROUP_DEFAULT_ACTION`, `DEFAULT_ACTION`, `DENY_PREFIXES`, `DENY_EXACT`, `ALLOW_PREFIXES`, `ALLOW_EXACT`, `EXEC_DENY_EXACT`, `EXEC_DENY_PREFIXES`, `EXEC_ALLOW_EXACT`, `EXEC_ALLOW_PREFIXES`, `EXEC_DEFAULT_ACTION`, `EXEC_CGROUP_DEFAULT_ACTION`.

The `MAX_POLICY_RULES` constant in `guardian-common` was updated from 64 to 1024 to match.

**Path truncation detection:**

A `status_flags` field was added to `FileAccessEvent`:

```rust
// guardian-common/src/lib.rs
pub const EVENT_FLAG_TRUNCATED: u32 = 1;

#[repr(C)]
pub struct FileAccessEvent {
    // ... existing fields ...
    pub filename_len: u32,
    pub status_flags: u32,   // NEW: bit 0 = path was truncated
    pub filename: [u8; MAX_FILENAME_LEN],
}
```

In eBPF tracepoints, if the path length equals or exceeds `MAX_FILENAME_LEN - 1`, the truncation flag is set. In enforcement mode, truncated paths are denied by default (inserted into PENDING_DENY). Userspace logs a warning:

```
[WARN] Truncated path detected (256 bytes): /very/long/path/... — denying by default
```

### Phase 8b: Dynamic Linker Detection

When `bprm_check_security` sees a known dynamic linker, Guardian inspects `argv[1]` to find the real binary being loaded:

```
Normal exec:  execve("/usr/bin/curl", ...)
              → bprm_check_security sees "/usr/bin/curl" → DENY

Linker bypass: execve("/lib/.../ld-linux-x86-64.so.2", ["/usr/bin/curl", ...])
              → bprm_check_security sees "/lib/.../ld-linux-x86-64.so.2"

Phase 8 fix:  → DYNAMIC_LINKERS map lookup → HIT
              → Read argv[1] → "/usr/bin/curl"
              → Evaluate exec policy against "/usr/bin/curl" → DENY
```

**New BPF map:**

| Map | Type | Max Entries | Purpose |
|-----|------|-------------|---------|
| `DYNAMIC_LINKERS` | `HashMap<[u8; 256], u8>` | 16 | Known linker paths → 1 |

**Populated by `populate_dynamic_linkers()` in main.rs:**

```rust
fn populate_dynamic_linkers(map: &mut HashMap<MapData, [u8; MAX_FILENAME_LEN], u8>) {
    let linkers = [
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "/lib64/ld-linux-x86-64.so.2",
        "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "/lib/ld-linux-x86-64.so.2",
        "/lib/ld-linux-aarch64.so.1",
        "/lib/ld-linux.so.2",
    ];
    // Insert each into the BPF map
}
```

### Phase 8b: execveat Tracepoint

A new `sys_enter_execveat` tracepoint catches the `execveat()` syscall, which `execve()` does not cover:

```
  if flags & AT_EMPTY_PATH (0x1000) != 0:
      → This is fd-based exec (memfd attack vector)
      → DENY unconditionally for enforced agents
  else:
      → Read filename, evaluate exec policy normally
```

This closes the `memfd_create` + `execveat(fd, "", ..., AT_EMPTY_PATH)` attack vector at the kernel level, complementing the seccomp-level blocking in `guardian-launch`.

### Phase 8b: Dashboard Authentication

Phase 8 adds optional Bearer token authentication to the dashboard:

```toml
[dashboard]
enabled = true
listen = "127.0.0.1:8080"
auth_token = "your-secret-token-here"  # NEW: optional
```

**Middleware behavior:**

```
Request arrives
    │
    ├── Path is /metrics or /static/* → SKIP AUTH (Prometheus scrapers need direct access)
    │
    ├── auth_token is None → SKIP AUTH (backward compatible)
    │
    ├── Authorization: Bearer <token> header matches → ALLOW
    │
    ├── ?token=<token> query parameter matches → ALLOW
    │
    └── Otherwise → 401 Unauthorized
```

When no `auth_token` is configured, the dashboard behaves exactly as before (no auth). This preserves backward compatibility for existing deployments.

### Phase 8b: Strict Enforcement Mode

Phase 8 adds `"strict"` as a valid global mode alongside `"monitor"` and `"enforce"`:

```toml
[global]
mode = "strict"  # NEW: exit on LSM failure
```

| Mode | LSM Hook Fails | Behavior |
|------|----------------|----------|
| `monitor` | — | No LSM hooks loaded, monitoring only |
| `enforce` | `warn!()` | Log warning, continue in monitor-only mode |
| `strict` | `bail!()` | **Exit immediately** — refuse to run without enforcement |

In strict mode, if any LSM hook (`file_open`, `bprm_check_security`, `inode_rename`, `inode_unlink`, `inode_link`) fails to attach, the daemon exits with a clear error message. This prevents silent degradation to monitor-only mode.

### Phase 8b: Default /memfd: Exec Deny

Phase 8 unconditionally adds `/memfd:` as a prefix deny rule in the exec policy maps at startup:

```rust
// In main.rs, after loading exec maps:
let memfd_prefix = b"/memfd:";
let key = path_to_lpm_key(memfd_prefix);
exec_deny_prefixes.insert(&key, 1, 0)?;
```

This blocks execution of any binary whose path starts with `/memfd:` — the pseudo-path that `memfd_create()` binaries have. Combined with the seccomp filter and execveat tracepoint, this provides three-layer defense against fileless execution.

### Phase 8c: Risk-Based Configurable Timeouts

Permission request timeouts are now configurable per risk level:

```toml
[permissions.timeouts]
low = 60        # 1 minute for low-risk requests
medium = 120    # 2 minutes for medium-risk
high = 180      # 3 minutes for high-risk
critical = 300  # 5 minutes for critical resources
```

**Implementation:**

```rust
// guardian/src/config.rs
pub struct RiskTimeoutConfig {
    pub low: u64,      // default: 60
    pub medium: u64,   // default: 120
    pub high: u64,     // default: 180
    pub critical: u64, // default: 300
}

// guardian/src/permissions.rs
impl RiskLevel {
    pub fn timeout_secs(&self, config: Option<&RiskTimeoutConfig>) -> u64 {
        match config {
            Some(c) => match self {
                RiskLevel::Low => c.low,
                RiskLevel::Medium => c.medium,
                RiskLevel::High => c.high,
                RiskLevel::Critical => c.critical,
            },
            None => match self {
                RiskLevel::Low => 60,
                RiskLevel::Medium => 120,
                RiskLevel::High => 180,
                RiskLevel::Critical => 300,
            },
        }
    }
}
```

When no `[permissions.timeouts]` section is configured, the defaults above are used. This replaces the fixed `PERMISSION_TIMEOUT_SECS = 120` constant.

### Phase 8c: CLI Permission Approval

Permission requests can now be managed from the command line without requiring the dashboard:

```bash
# List all pending permission requests
sudo guardian-ctl pending

# Output:
# ID     AGENT              TYPE     RESOURCE                                 RISK       AGE
# ------------------------------------------------------------------------------------------
# 42     my-agent           exec     /usr/bin/curl                            medium     15s
#        Justification: Need to fetch config from internal API

# Approve a request (grant for 5 minutes)
sudo guardian-ctl approve --id 42 --duration 300

# Deny a request with reason
sudo guardian-ctl deny --id 42 --reason "curl access not authorized for this agent"
```

**New IPC messages:**

| Message | Direction | Purpose |
|---------|-----------|---------|
| `ListPending` | Request | List all pending permission requests |
| `PendingPermissions { requests }` | Response | Vector of `PendingPermissionInfo` structs |
| `ApprovePermission { request_id, duration_secs }` | Request | Approve by ID with grant duration |
| `DenyPermission { request_id, reason }` | Request | Deny by ID with optional reason |

The `approve` and `deny` commands reuse the existing `resolve_permission()` function, which handles grant creation, rate limiter updates, audit trail persistence, and SSE broadcast — identical behavior to dashboard approval.

### Phase 8c: Grant Accumulation Limits

A new `GrantAccumulator` tracks cumulative grant durations per agent per resource within a 24-hour sliding window:

```
T=0:00  Agent requests /etc/shadow → Approved for 3600s
T=0:30  Accumulator: agent=my-agent, resource=/etc/shadow, total=3600s
T=1:00  Agent requests /etc/shadow again → Approved for 3600s
T=1:00  Accumulator: total=7200s > limit=3600s → WARNING logged

Config:
[permissions]
max_grant_total_secs = 3600  # 1 hour max accumulated grant per resource per 24h
```

**Implementation:**

```rust
pub struct GrantAccumulator {
    grants: HashMap<(String, String), Vec<(Instant, u64)>>,
}

impl GrantAccumulator {
    pub fn record_and_check(&mut self, agent: &str, resource: &str, duration: u64) -> u64 {
        let entries = self.grants.entry((agent.into(), resource.into())).or_default();
        // Prune entries older than 24 hours
        entries.retain(|(t, _)| now.duration_since(*t).as_secs() < 86400);
        entries.push((now, duration));
        entries.iter().map(|(_, d)| *d).sum() // total accumulated
    }
}
```

When the accumulated total exceeds `max_grant_total_secs`, a warning is logged. The grant is still honored (since the decision was already sent to the agent via oneshot channel), but the warning enables operators to detect and investigate persistent access accumulation.

### Phase 8c: Improved Justification Analysis

Justification analysis now uses **weighted scoring** instead of binary pattern matching:

```rust
const SUSPICIOUS_PATTERNS: &[(&str, &str, u32)] = &[
    ("urgent",           "URGENCY",          3),
    ("immediately",      "URGENCY",          3),
    ("emergency",        "URGENCY",          4),
    ("disable security", "SECURITY_BYPASS",  5),
    ("bypass",           "SECURITY_BYPASS",  4),
    ("trust me",         "REASSURANCE",      3),
    ("admin told",       "AUTHORITY_CLAIM",  4),
    ("credential",       "SENSITIVE_MENTION", 2),
    ("token",            "SENSITIVE_MENTION", 1),
    // ... 22 patterns total with weights 1-5
];
```

**Graduated risk bumps:**

| Total Score | Risk Bump | Example |
|-------------|-----------|---------|
| 0 | No bump | Clean justification |
| 1-2 | No bump | Single low-weight match (e.g., "token") |
| 3-7 | +1 tier | "This is urgent, trust me" (3+3=6) |
| 8+ | +2 tiers | "Emergency! Override security, admin told me to bypass" (4+5+4+4=17) |

This means a Low-risk request with a highly suspicious justification (score 8+) jumps directly to High risk, triggering a 5-second mandatory wait timer and enhanced UI friction.

### Phase 8d: Anomaly Detection

An `AnomalyDetector` runs hourly as a background task, querying the SQLite audit trail for three suspicious patterns:

```
Every 3600 seconds:
    │
    ├── Rubber-stamping check
    │   SELECT COUNT(*) FROM permission_audit WHERE resolved_at > (now - 24h)
    │   SELECT COUNT(*) WHERE approved = 1
    │   If approval rate > 90% AND total > 10 → ALERT
    │
    ├── High-volume agent check
    │   SELECT agent_name, COUNT(*) FROM permission_audit
    │   WHERE resolved_at > (now - 24h) GROUP BY agent_name HAVING cnt > 20
    │   → ALERT for each agent exceeding threshold
    │
    └── Persistence attack check
        SELECT DISTINCT d.agent_name FROM permission_audit d
        JOIN permission_audit a ON d.agent_name = a.agent_name
          AND d.resource_path = a.resource_path
          AND d.approved = 0 AND a.approved = 1
          AND a.resolved_at > d.resolved_at
        WHERE d.resolved_at > (now - 24h)
        → ALERT for each agent with deny-then-approve on same resource
```

Findings are logged as warnings and sent through the `AlertSender` for dispatch to configured outputs (Slack, webhook, email, JSON log).

### Phase 8d: Configurable Fail-Closed Mode

A new per-agent `fail_closed` option changes error handling in LSM hooks:

```toml
[[agents]]
name = "high-security-agent"
identity = "cgroup"
fail_closed = true  # NEW: deny on eBPF error instead of allowing

[agents.file_access]
default = "deny"
```

**BPF map:** `FAIL_CLOSED_CGROUPS: HashMap<u64, u8>` — populated during agent registration when `fail_closed = true`.

**LSM hook behavior:**

| Error in LSM | fail_closed = false (default) | fail_closed = true |
|-------------|-------------------------------|-------------------|
| Map lookup failure | return 0 (allow) | return -EACCES (deny) |
| Per-CPU array allocation failure | return 0 (allow) | return -EACCES (deny) |
| Any other eBPF error | return 0 (allow) | return -EACCES (deny) |

This is a per-cgroup setting, so agents with different security requirements can coexist on the same system.

---

## Configuration Reference

### New Configuration Fields

```toml
[global]
mode = "strict"  # NEW: "monitor", "enforce", or "strict"

[dashboard]
enabled = true
listen = "127.0.0.1:8080"
auth_token = "your-secret-token"  # NEW: optional Bearer token

[permissions]
auto_deny = ["/etc/shadow", "/root/.ssh/**"]
auto_approve = [{ pattern = "/tmp/**", max_duration_secs = 300 }]
rate_limit_per_minute = 3
rate_limit_per_hour = 15
deny_cooldown_secs = 30
max_pending_per_agent = 2
max_grant_total_secs = 3600  # NEW: max accumulated grant duration per resource (24h window)

[permissions.timeouts]  # NEW: risk-based timeout configuration
low = 60
medium = 120
high = 180
critical = 300

[[agents]]
name = "secure-agent"
identity = "cgroup"
fail_closed = true  # NEW: deny on eBPF error

[agents.file_access]
default = "deny"
allow = ["/tmp/**"]
deny = ["/etc/shadow"]
```

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Seccomp for io_uring/memfd blocking | eBPF tracepoints can't intercept io_uring ring buffer operations. Seccomp operates at the syscall boundary before io_uring setup, blocking it completely. Applied in guardian-launch so agent inherits the filter. |
| Three-layer memfd defense | Seccomp blocks `memfd_create`, execveat tracepoint catches `AT_EMPTY_PATH`, and default `/memfd:` deny catches LSM-level exec. Any one layer is sufficient, but defense-in-depth is essential for security-critical code paths. |
| Separate PENDING maps per inode op | Reusing PENDING_DENY would cause races: if a rename triggers both file_open and inode_rename LSM hooks, the first to consume the pending entry would leave the second unprotected. |
| Warn-only for grant accumulation | The decision is already sent to the agent via oneshot channel before we can check accumulation. Moving the check before the oneshot send would require restructuring the entire approval flow. Warning + logging is sufficient for Phase 8. |
| auth_token in config (not generated) | Auto-generating tokens adds startup complexity and makes config non-reproducible. Operators can use any secret management tool to populate the token field. |
| Strict mode exits on LSM failure | Operator explicitly opted into "no monitoring without enforcement." A warning log is easily missed; an exit with a clear error message forces resolution before the system is considered operational. |
| Hourly anomaly detection interval | Frequent enough to catch patterns within a shift, infrequent enough to avoid query overhead. SQLite queries are indexed and sub-millisecond. |
| Weighted justification scoring | Binary detection (any match → bump) was too aggressive for benign mentions like "token" or "credential." Weights allow fine-grained tuning: "token" (weight 1) alone doesn't trigger a bump, but "emergency override bypass" (weight 4+4+3=11) jumps +2 tiers. |
| Per-cgroup fail-closed | System-wide fail-closed would break non-critical agents on transient eBPF errors. Per-cgroup allows security-critical agents to have strict error handling while development agents remain fail-open. |

---

## Files Changed: Detailed Summary

### `guardian-ebpf/src/main.rs`

| Section | Change |
|---------|--------|
| Maps (lines 19-188) | All rule maps: 256→1024 entries. 3 new PENDING maps for rename/unlink/link. DYNAMIC_LINKERS map (16 entries). FAIL_CLOSED_CGROUPS map (1024 entries). |
| `try_guardian_file_open()` | Set `event.status_flags |= EVENT_FLAG_TRUNCATED` when path fills entire buffer. Deny truncated paths in enforce mode. |
| `try_guardian_exec_monitor()` | Check DYNAMIC_LINKERS map — if hit, read argv[1] pointer and evaluate exec policy against the real binary. |
| NEW: `guardian_execveat_monitor()` | Tracepoint on `sys_enter_execveat`. Detects `AT_EMPTY_PATH` flag for memfd-based exec. Denies unconditionally for enforced agents. |
| NEW: `guardian_rename_monitor()` | Tracepoint on `sys_enter_renameat2`. Reads source path, evaluates policy, sets PENDING_RENAME_DENY. |
| NEW: `guardian_unlink_monitor()` | Tracepoint on `sys_enter_unlinkat`. Reads path, evaluates deny policy, sets PENDING_UNLINK_DENY. |
| NEW: `guardian_link_monitor()` | Tracepoint on `sys_enter_linkat`. Reads source/dest paths, evaluates policy, sets PENDING_LINK_DENY. |
| NEW: `guardian_enforce_rename()` | LSM `inode_rename`. Checks PENDING_RENAME_DENY, returns -EACCES if set. Falls back based on FAIL_CLOSED_CGROUPS. |
| NEW: `guardian_enforce_unlink()` | LSM `inode_unlink`. Same pattern as rename. |
| NEW: `guardian_enforce_link()` | LSM `inode_link`. Same pattern as rename. |

### `guardian-common/src/lib.rs`

| Change | Detail |
|--------|--------|
| `MAX_POLICY_RULES` | 64 → 1024 |
| `FileAccessEvent` | Added `status_flags: u32` field after `filename_len` |
| `EVENT_FLAG_TRUNCATED` | New constant: `pub const EVENT_FLAG_TRUNCATED: u32 = 1;` |
| Map name constants | Added `MAP_PENDING_RENAME_DENY`, `MAP_PENDING_UNLINK_DENY`, `MAP_PENDING_LINK_DENY`, `MAP_DYNAMIC_LINKERS`, `MAP_FAIL_CLOSED_CGROUPS` |
| IPC protocol | Added `ListPending`, `ApprovePermission { request_id, duration_secs }`, `DenyPermission { request_id, reason }` request variants |
| IPC responses | Added `PendingPermissions { requests: Vec<PendingPermissionInfo> }` response variant |
| `PendingPermissionInfo` | New struct: `request_id`, `agent_name`, `resource_type`, `resource_path`, `justification`, `risk_level`, `elapsed_secs` |

### `guardian/src/config.rs`

| Change | Detail |
|--------|--------|
| `DashboardConfig` | Added `auth_token: Option<String>` |
| `PermissionsConfig` | Added `timeouts: Option<RiskTimeoutConfig>`, `max_grant_total_secs: u64` (default 3600) |
| `RiskTimeoutConfig` | New struct with `low/medium/high/critical` u64 fields, serde defaults 60/120/180/300 |
| `AgentConfig` | Added `fail_closed: Option<bool>` |
| `validate_config()` | `"strict"` added as valid mode |

### `guardian/src/permissions.rs`

| Change | Detail |
|--------|--------|
| `RiskLevel::timeout_secs()` | New method taking `Option<&RiskTimeoutConfig>`, returns per-risk-level timeout |
| `GrantAccumulator` | New struct tracking cumulative grants per (agent, resource) in 24h sliding window |
| `SUSPICIOUS_PATTERNS` | Changed from `(&str, &str)` to `(&str, &str, u32)` — added per-pattern weights |
| `analyze_justification()` | Returns `(Vec<(String, String)>, u32)` — findings + total score |
| `justification_risk_bump()` | Takes score parameter, returns 0/1/2 bumps instead of bool |
| `AnomalyDetector` | New struct with `detect_anomalies()` querying SQLite for rubber-stamping, persistence, floods |

### `guardian/src/ipc.rs`

| Change | Detail |
|--------|--------|
| `IpcState` | Added `fail_closed_map`, `grant_accumulator` fields |
| `process_request()` | Handle `ListPending`, `ApprovePermission`, `DenyPermission` |
| `handle_register()` | Populate FAIL_CLOSED_CGROUPS map for `fail_closed` agents |
| `handle_request_permission()` | Use `risk_level.timeout_secs(timeout_config)` instead of fixed 120s. Updated justification analysis to use weighted scoring and graduated bumps. |
| `resolve_permission()` | Added grant accumulation check — `grant_accumulator.record_and_check()` with warning log |
| NEW: `handle_list_pending()` | Returns Vec<PendingPermissionInfo> |
| NEW: `handle_approve_permission()` | Calls `resolve_permission()` with "Approved via CLI" reason |
| NEW: `handle_deny_permission()` | Calls `resolve_permission()` with custom or default reason |

### `guardian/src/dashboard/mod.rs`

| Change | Detail |
|--------|--------|
| `router()` | Conditionally applies auth middleware when `auth_token` is Some |
| NEW: `auth_middleware()` | Checks Bearer token header, `?token=` query param. Skips `/metrics` and `/static/`. Returns 401 if not authenticated. |

### `guardian-launch/src/main.rs`

| Change | Detail |
|--------|--------|
| NEW: `apply_seccomp_filter()` | Blocks io_uring (425-427) + memfd_create (319) via seccompiler. Uses `MaskedEq(0)` always-true condition. Applied after cgroup setup, before exec. Best-effort with warning on failure. |

### `guardian-ctl/src/main.rs`

| Change | Detail |
|--------|--------|
| `Commands` enum | Added `Pending`, `Approve { id, duration }`, `Deny { id, reason }` variants |
| `process_request()` | Maps new commands to `ListPending`, `ApprovePermission`, `DenyPermission` IPC messages |
| Response handling | Added `PendingPermissions` formatter with table output showing ID, agent, type, resource, risk level, age |

---

## What's Not Fixed (Deferred)

| Issue | Severity | Why Deferred |
|-------|----------|-------------|
| Symlink resolution via `bpf_d_path()` | CRITICAL | Requires Linux 5.11+ and complex raw eBPF helper calls not yet supported by aya |
| TOCTOU race condition | HIGH | Architectural limitation of tracepoint+LSM pattern; requires LSM-only enforcement (depends on bpf_d_path) |
| `cgroup/connect4/6` network enforcement | CRITICAL | Requires per-cgroup BPF attachment which aya doesn't natively support well |
| DNS monitoring | MEDIUM | Requires port 53 packet inspection and periodic DNS resolution |
| BTF-portable tracepoint offsets | MEDIUM | Requires build-time vmlinux.h generation and BTF field access |
| Live BPF map sync on dashboard policy edit | MEDIUM | Requires refactoring map population into a reusable `sync_bpf_maps()` function |
| Full SIGHUP reload including alerting | LOW | Requires wrapping `AlertSender` in `Arc<RwLock>` for concurrent access |

---

## What's Next

- **Phase 9 (planned):** Symlink resolution via `bpf_d_path()` (requires Linux 5.11+ kernel and aya raw helper support), network enforcement via `cgroup/connect4/6`, DNS monitoring, live BPF map sync on dashboard policy edit
- **Stretch goals:** Content hashing via IMA (Integrity Measurement Architecture), BTF-portable tracepoint offsets, `mmap_file` LSM hook for memory-mapped file access control
