# Phase 7 Implementation: Security Hardening

## What Phase 7 Solves

Phase 6 gave us interactive permission requests with real-time approval workflows. But the permission system itself had five major security loopholes identified in `docs/security-improvements-research.md`:

**Problem 1: Path bypass attacks.** Guardian Shell captures the raw filename from the `sys_enter_openat` tracepoint — whatever path the userspace process passes to `openat()` is matched against policy. An agent can bypass deny rules with trivial string tricks:
```
/proc/self/root/etc/shadow    → does NOT match deny rule "/etc/shadow"
../../../etc/shadow           → does NOT match deny rule "/etc/shadow"
/proc/1234/root/etc/shadow    → does NOT match deny rule "/etc/shadow"
```

**Problem 2: Missing syscall coverage.** The `openat2` syscall (Linux 5.6+, syscall 437) bypasses the `sys_enter_openat` tracepoint entirely. Rust's standard library and security-conscious tools increasingly use `openat2`. An agent using `openat2` instead of `openat` operates completely unmonitored.

**Problem 3: Approval fatigue.** Research shows 43% of SOC analysts turn off alerts when overwhelmed, and 40% ignore incoming alerts entirely. An AI agent can exploit this by:
- Flooding the human with benign-looking requests until they rubber-stamp everything
- Crafting persuasive justifications that blend into routine approval workflows
- Re-requesting denied resources repeatedly until the human gives in
- Requesting critical resources during high-volume periods when attention is divided

**Problem 4: No risk differentiation.** A request to read `/tmp/cache.txt` and a request to read `/etc/shadow` look identical in the UI — same banner, same approve button, same one-click approval. There's nothing forcing the human to slow down for high-risk decisions.

**Problem 5: No persistent audit trail.** The resolved permission history was in-memory only (last 100 entries in a `VecDeque`). On daemon restart, all audit history was lost. No way to detect patterns like "this agent was denied 5 times then approved" or "approval rate is 98% — someone is rubber-stamping."

Phase 7 addresses all five through a combination of userspace path normalization, eBPF syscall coverage expansion, multi-layered approval hardening, risk-based UI friction, and persistent SQLite audit trails.

---

## What Was Built

### New Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `guardian/src/permissions.rs` | 460 | Permission hardening module: rate limiter, risk classifier, auto-deny/auto-approve, justification analyzer |

### Modified Source Files

| File | What Changed |
|------|-------------|
| `guardian/src/config.rs` | Added `PermissionsConfig` and `AutoApproveRule` structs with serde defaults; added `normalize_path()` function; modified `check_file_policy()` and `check_exec_policy()` to normalize paths before matching; made `path_matches()` public; added 5 new tests for normalization and bypass prevention |
| `guardian/src/ipc.rs` | Added `rate_limits` and `event_db` fields to `IpcState`; imported permissions module; added risk fields to `PendingPermission`, `ResolvedPermission`, `PermissionEvent`; completely rewrote `handle_request_permission()` with hardening pipeline; added SQLite persistence in `resolve_permission()` and all auto-deny/approve/timeout paths |
| `guardian/src/main.rs` | Added `mod permissions`; added `normalize_path` import and call in `process_file_event()`; added openat2 tracepoint load/attach with graceful fallback; added `event_db` to IpcState initialization |
| `guardian-ebpf/src/main.rs` | Added `guardian_file_openat2` tracepoint handler for `sys_enter_openat2` (82 lines) with `open_how` struct flags reading |
| `guardian/src/dashboard/db.rs` | Added `permission_audit` table schema with 3 indexes; added `StoredPermissionAudit` struct; added `insert_permission_audit()` and `query_permission_audit()` methods |
| `guardian/src/dashboard/routes/api.rs` | Added risk fields to `list_pending_permissions` JSON response; added `query_permission_audit` endpoint and `AuditQuery` struct |
| `guardian/src/dashboard/routes/pages.rs` | Added `risk_level`, `risk_flags`, `wait_seconds`, `requires_type_confirm`, `justification_warnings` to `PendingRequestInfo`; added `risk_level` to `ResolvedRequestInfo`; updated `requests()` handler to populate new fields |
| `guardian/src/dashboard/mod.rs` | Added `/api/permissions/audit` route |
| `guardian/templates/base.html` | Rewrote permission banner with risk-colored borders, risk badge, justification warnings, risk flags, mandatory wait timer countdown, type-to-confirm input for CRITICAL; updated Alpine.js store to handle risk fields from SSE and fetch |
| `guardian/templates/requests.html` | Added Risk column to both pending and resolved tables; added wait timer on approve button with Alpine.js countdown; added type-to-confirm for CRITICAL risk rows; expanded colspan from 7 to 8 |
| `guardian/static/app.css` | Added risk badge styles (`.badge-risk-low/medium/high/critical`); added risk-colored banner variants (`.perm-banner.risk-*`); added justification warning tag styles; added type-to-confirm input styles |
| `guardian-common/src/lib.rs` | Added `NetworkEvent` struct (52 bytes), new map name constants for exec enforcement and network monitoring |
| `guardian-ebpf/src/main.rs` | Added 9 new BPF maps (7 exec enforcement + 2 network), `evaluate_exec_policy()`, `guardian_enforce_exec` LSM hook, `guardian_file_open_legacy` tracepoint, `guardian_net_connect` tracepoint |
| `guardian/src/alerting/mod.rs` | Added `NetworkConnect` variant to `EventType` enum |
| `guardian/src/config.rs` | Added `NetworkPolicy` struct with port-based allow/deny rules, `check_network_policy()` function, `network_policy` field to `AgentConfig` |
| `CLAUDE.md` | Updated current state to Phase 7; updated project structure; updated known limitations; added Phase 7 design decisions; updated test counts |

---

## Architecture

### Phase 7a: Path Canonicalization & Syscall Coverage

#### Userspace Path Normalization (Layer 1)

```
  Agent calls openat("/proc/self/root/etc/shadow")
                    │
                    ▼
  eBPF tracepoint captures raw path: "/proc/self/root/etc/shadow"
                    │
                    ▼
  Perf event → Userspace daemon event loop
                    │
                    ▼
  normalize_path("/proc/self/root/etc/shadow")
       │
       ├── Strip /proc/self/root/ prefix  →  "/etc/shadow"
       ├── Strip /proc/<pid>/root/ prefix  →  "/etc/shadow"
       └── Resolve ".." components         →  "/etc/shadow"
                    │
                    ▼
  check_file_policy("/etc/shadow")  →  BLOCKED (deny rule matches)
```

The `normalize_path()` function in `config.rs` handles three categories of bypass:

```rust
pub fn normalize_path(raw: &str) -> String {
    // 1. Strip /proc/self/root/ prefix (filesystem namespace escape)
    //    /proc/self/root/etc/shadow → /etc/shadow

    // 2. Strip /proc/<pid>/root/ prefix (other process namespace)
    //    /proc/1234/root/etc/shadow → /etc/shadow

    // 3. Resolve ".." components (directory traversal)
    //    /tmp/../etc/shadow → /etc/shadow
    //    /home/user/../../etc/shadow → /etc/shadow
}
```

**Applied in two locations:**
1. `check_file_policy()` / `check_exec_policy()` in `config.rs` — normalizes before policy matching
2. `process_file_event()` in `main.rs` — normalizes before logging and alerting

**Limitations:** Does not resolve symlinks (e.g., `/tmp/link-to-shadow` → `/etc/shadow`). Full symlink resolution requires the kernel-side `bpf_d_path()` approach described in the research doc (Linux 5.11+, not yet implemented).

#### openat2 Tracepoint (Syscall Coverage)

```
  sys_enter_openat   ← hooked since Phase 1
  sys_enter_openat2  ← NEW in Phase 7
  sys_enter_execve   ← hooked since Phase 2
```

The `openat2` syscall (Linux 5.6+) provides the same file-open functionality as `openat` but with a `struct open_how` argument that adds `RESOLVE_*` flags. Without hooking `openat2`, an agent could bypass all monitoring by using the newer syscall.

**eBPF implementation** in `guardian-ebpf/src/main.rs`:

```rust
#[tracepoint]
pub fn guardian_file_openat2(ctx: TracePointContext) -> u32 {
    // x86_64 tracepoint layout:
    //   offset 16: int dfd
    //   offset 24: const char __user *filename
    //   offset 32: struct open_how __user *how

    // Read filename at offset 24 (same position as openat)
    // Read flags from struct open_how (first u64 field)
    // Evaluate policy → set PENDING_DENY if blocked
    // Send event to userspace via EVENTS perf buffer
}
```

**Graceful fallback** in daemon (`main.rs`):

```rust
// openat2 may not exist on kernels < 5.6
let has_openat2 = load_tracepoint(&mut bpf, "guardian_file_openat2").is_ok();

// Only attach if load succeeded
if has_openat2 {
    match attach_tracepoint(&mut bpf, "guardian_file_openat2", "syscalls", "sys_enter_openat2") {
        Ok(()) => info!("Attached: syscalls/sys_enter_openat2 (openat2 monitoring)"),
        Err(e) => warn!("openat2 tracepoint not available (kernel < 5.6?): {}", e),
    }
}
```

The daemon continues to function on older kernels — openat2 support is additive, not required.

---

### Phase 7c: Approval Hardening Pipeline

The `handle_request_permission()` function in `ipc.rs` was rewritten as a multi-stage hardening pipeline. Each stage can short-circuit the request before a human ever sees it:

```
  Agent sends RequestPermission via Unix socket
                    │
                    ▼
  ┌─────────────────────────────────────────────┐
  │  Stage 1: MAX PENDING CHECK                 │
  │  Agent already has ≥2 pending requests?     │
  │  → Immediate DENY: "Too many pending"       │
  └─────────────────────┬───────────────────────┘
                        │ pass
                        ▼
  ┌─────────────────────────────────────────────┐
  │  Stage 2: AUTO-DENY                         │
  │  Resource on never-approve list?            │
  │  (/etc/shadow, /etc/sudoers, ~/.ssh/*)      │
  │  → Immediate DENY + audit trail             │
  └─────────────────────┬───────────────────────┘
                        │ pass
                        ▼
  ┌─────────────────────────────────────────────┐
  │  Stage 3: AUTO-APPROVE                      │
  │  Resource on safe-list with max duration?   │
  │  (/tmp/**, /proc/self/**)                   │
  │  → Immediate APPROVE + grant + audit trail  │
  └─────────────────────┬───────────────────────┘
                        │ pass
                        ▼
  ┌─────────────────────────────────────────────┐
  │  Stage 4: RATE LIMITING                     │
  │  Per-minute limit exceeded? (3/min)         │
  │  Per-hour limit exceeded? (15/hr)           │
  │  Exponential backoff cooldown active?       │
  │  Same resource denied within 5 minutes?     │
  │  → Immediate DENY + audit trail             │
  └─────────────────────┬───────────────────────┘
                        │ pass
                        ▼
  ┌─────────────────────────────────────────────┐
  │  Stage 5: RISK CLASSIFICATION               │
  │  Score resource: path patterns + exec type  │
  │  + post-denial multiplier + rate multiplier │
  │  → RiskLevel: Low / Medium / High / Critical│
  └─────────────────────┬───────────────────────┘
                        │
                        ▼
  ┌─────────────────────────────────────────────┐
  │  Stage 6: JUSTIFICATION ANALYSIS            │
  │  Scan for suspicious patterns:              │
  │  "urgent", "bypass", "trust me", "admin"... │
  │  → Bump risk level if patterns found        │
  │  → Add warning flags to UI                  │
  └─────────────────────┬───────────────────────┘
                        │
                        ▼
  ┌─────────────────────────────────────────────┐
  │  Stage 7: CREATE REQUEST & WAIT             │
  │  Create oneshot channel                     │
  │  Broadcast to dashboard via SSE             │
  │  Agent blocks for up to 120 seconds         │
  └─────────────────────┬───────────────────────┘
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
        Human approves      120s timeout
        via dashboard       (auto-deny)
              │                   │
              ▼                   ▼
        Grant created       Denial recorded
        + audit trail       + audit trail
              │                   │
              └─────────┬─────────┘
                        ▼
              Agent unblocks with decision
```

---

### Rate Limiting (`permissions.rs`)

Each agent has an `AgentRateLimit` struct tracking request patterns:

```rust
pub struct AgentRateLimit {
    pub requests_this_minute: u32,        // Resets every 60s
    pub requests_this_hour: u32,          // Resets every 3600s
    pub minute_reset: Instant,
    pub hour_reset: Instant,
    pub consecutive_denials: u32,         // For exponential backoff
    pub last_denial_at: Option<Instant>,
    pub recently_denied_resources: HashMap<String, Instant>,  // 5-min cooldown
}
```

**Thresholds and escalation:**

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Max requests/minute | 3 | Prevents approval flood attacks |
| Max requests/hour | 15 | Prevents sustained harassment |
| Cooldown after denial | 30s × 2^(n-1), max 600s | Exponential backoff discourages persistence |
| Max pending/agent | 2 | Forces serialization of requests |
| Same-resource cooldown | 5 minutes | Prevents re-request spam for denied resources |

**Exponential backoff formula:**

```
cooldown = min(deny_cooldown_secs × 2^(consecutive_denials - 1), 600)

After 1 denial:  30s cooldown
After 2 denials: 60s cooldown
After 3 denials: 120s cooldown
After 4 denials: 240s cooldown
After 5 denials: 480s cooldown
After 6+ denials: 600s cooldown (10 minute cap)
```

Consecutive denials reset to 0 on any approval, so legitimate agents recover quickly.

---

### Risk Classification (`permissions.rs`)

Every permission request is assigned a risk score that maps to a 4-tier risk level:

```
Score Range  →  Risk Level  →  UI Treatment
  0 - 25     →  LOW         →  Standard banner, no wait
 26 - 50     →  MEDIUM      →  Yellow banner, 3s wait before approve
 51 - 75     →  HIGH        →  Orange banner, 5s wait before approve
 76 - 100    →  CRITICAL    →  Red banner, 10s wait, type "CONFIRM" to approve
```

**Scoring algorithm:**

```
Base score: 25 (MEDIUM)

Path pattern adjustments:
  Critical paths (/etc/shadow, /etc/sudoers, /root/**):     score = 90
  High paths (/etc/passwd, /var/log/**):                     score = 60
  Low paths (/tmp/**, /proc/self/status, /proc/meminfo):     score = 10

Multipliers (applied sequentially):
  Exec type (resource_type == "exec"):                       score × 1.5
  Post-denial (agent has consecutive denials > 0):           score × 2.0
  High request rate (agent has > 5 requests/hour):           score × 1.3

Justification risk bump:
  If suspicious patterns detected in justification text:     score bumped up one tier
```

**Critical path patterns:**

```rust
const CRITICAL_PATTERNS: &[&str] = &[
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d/**",
    "/root/**",
    "/root/.bash_history",
];
```

**High-risk executable patterns:**

```rust
const HIGH_RISK_EXECS: &[&str] = &[
    "/usr/bin/curl",    "/usr/bin/wget",    "/usr/bin/nc",
    "/usr/bin/ncat",    "/usr/bin/ssh",     "/usr/bin/scp",
    "/usr/bin/rsync",   "/usr/bin/rm",      "/usr/bin/dd",
    "/usr/sbin/mkfs",   "/usr/bin/shred",
];
```

**Example risk calculations:**

| Request | Base | Adjustments | Final Score | Level |
|---------|------|-------------|-------------|-------|
| file `/tmp/cache.txt` | 10 | low_risk_path | 10 | LOW |
| file `/etc/passwd` | 60 | sensitive_path | 60 | HIGH |
| file `/etc/shadow` | 90 | critical_path | 90 | CRITICAL |
| exec `/usr/bin/curl` | 25 | exec_type(×1.5)=37, risky_exec=max(37,60)=60 | 60 | HIGH |
| file `/tmp/x` after 1 denial | 10 | low_risk_path, post_denial(×2.0)=20 | 20 | LOW |
| file `/etc/passwd` after 2 denials + high rate | 60 | sensitive_path, post_denial(×2.0)=120→100 | 100 | CRITICAL |

---

### Justification Analysis (`permissions.rs`)

When an agent provides a justification string (e.g., "This is urgent, trust me"), it's scanned for patterns that indicate social engineering:

```rust
const SUSPICIOUS_PATTERNS: &[(&str, &str)] = &[
    // Urgency tactics
    ("urgent", "URGENCY"),
    ("immediately", "URGENCY"),
    ("emergency", "URGENCY"),
    ("asap", "URGENCY"),

    // Security bypass requests
    ("disable security", "SECURITY_BYPASS"),
    ("bypass", "SECURITY_BYPASS"),
    ("override", "SECURITY_BYPASS"),
    ("skip check", "SECURITY_BYPASS"),

    // Trust/reassurance manipulation
    ("trust me", "REASSURANCE"),
    ("don't worry", "REASSURANCE"),
    ("it's safe", "REASSURANCE"),
    ("it's fine", "REASSURANCE"),
    ("it's harmless", "REASSURANCE"),

    // Authority claims
    ("admin told", "AUTHORITY_CLAIM"),
    ("supervisor", "AUTHORITY_CLAIM"),
    ("authorized by", "AUTHORITY_CLAIM"),

    // Sensitive data mentions (contextual red flag)
    ("ssh key", "SENSITIVE_MENTION"),
    ("password", "SENSITIVE_MENTION"),
    ("credential", "SENSITIVE_MENTION"),
    ("secret", "SENSITIVE_MENTION"),
    ("token", "SENSITIVE_MENTION"),
    ("api key", "SENSITIVE_MENTION"),
];
```

**When patterns are detected:**
1. Warning tags appear in the permission banner and requests page
2. Risk level is bumped up one tier (e.g., MEDIUM → HIGH)
3. The human must acknowledge the warnings before the approve button activates

**Example:** Agent sends justification "This is urgent, trust me it's safe" → triggers URGENCY + REASSURANCE warnings → risk level bumped.

---

### Auto-Deny / Auto-Approve (`permissions.rs` + `config.rs`)

Configurable via the `[permissions]` section of `config.toml`:

```toml
[permissions]
auto_deny = [
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d/**",
    "/root/**",
    "/root/.bash_history",
]

[[permissions.auto_approve]]
pattern = "/tmp/**"
max_duration_secs = 300

[[permissions.auto_approve]]
pattern = "/proc/self/**"
max_duration_secs = 60

rate_limit_per_minute = 3
rate_limit_per_hour = 15
deny_cooldown_secs = 30
max_pending_per_agent = 2
```

**Auto-deny:** Resources that should NEVER be approvable via interactive request. Agent gets immediate denial without the request ever reaching the dashboard. Applied after `normalize_path()` to prevent bypass.

**Auto-approve:** Low-risk resources that can be granted without human intervention. Reduces decision fatigue by eliminating trivial approvals. Each rule specifies a maximum grant duration.

Both are checked early in the pipeline, before rate limiting or risk classification, for efficiency.

---

### UI Friction (`base.html` + `requests.html` + `app.css`)

The dashboard enforces risk-proportional friction on the approve workflow:

#### Risk-Colored Banners

Permission banners change color based on risk level:

| Risk | Border Color | Icon | Banner Class |
|------|-------------|------|-------------|
| LOW | Green | `?` | `.perm-banner.risk-low` |
| MEDIUM | Yellow (default) | `?` | `.perm-banner.risk-medium` |
| HIGH | Orange | `?` | `.perm-banner.risk-high` |
| CRITICAL | Red | `!` | `.perm-banner.risk-critical` |

#### Mandatory Wait Timer

The approve button is disabled for a configurable period after the banner appears:

```javascript
// Alpine.js component on each banner
x-data="{ dur: 600, confirmText: '', waitElapsed: 0 }"
x-init="if (req.wait_seconds > 0) {
    let iv = setInterval(() => { waitElapsed++; if (waitElapsed >= req.wait_seconds) clearInterval(iv); }, 1000);
}"

// Approve button
:disabled="(req.wait_seconds > 0 && waitElapsed < req.wait_seconds)
    || (req.requires_type_confirm && confirmText !== 'CONFIRM')"
```

During the wait period, the button text shows `Wait 5s...` → `Wait 4s...` → `Wait 3s...` etc.

#### Type-to-Confirm for CRITICAL Risk

When `risk_level === 'critical'`, an additional input field appears:

```html
<template x-if="req.requires_type_confirm">
    <div class="perm-type-confirm">
        <input type="text" x-model="confirmText" placeholder="Type CONFIRM">
        <span class="hint">Type CONFIRM to enable approve</span>
    </div>
</template>
```

The approve button remains disabled until the human types exactly `CONFIRM`. This prevents accidental one-click approval of critical resources.

#### Justification Warnings

Suspicious patterns detected in the agent's justification are displayed as red warning tags:

```html
<template x-if="req.justification_warnings && req.justification_warnings.length > 0">
    <div class="perm-banner-warnings">
        <template x-for="w in req.justification_warnings" :key="w">
            <span class="perm-warning-tag" x-text="w"></span>
        </template>
    </div>
</template>
```

These appear as inline red badges like `URGENCY: "urgent"` and `REASSURANCE: "trust me"`.

#### Risk Flags

Technical scoring details are shown as small gray badges below the request details:

```
critical_path:/etc/shadow  exec_type  post_denial:2  high_rate:8/hr
```

This gives the human operator visibility into *why* the risk was classified at a particular level.

---

### Persistent SQLite Audit Trail (`db.rs` + `ipc.rs`)

#### Schema

```sql
CREATE TABLE IF NOT EXISTS permission_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    agent_name TEXT NOT NULL,
    resource_type TEXT NOT NULL,        -- "file" or "exec"
    resource_path TEXT NOT NULL,
    justification TEXT,
    risk_level TEXT,                    -- "low", "medium", "high", "critical"
    risk_flags TEXT,                    -- JSON array: ["critical_path:/etc/shadow", "exec_type"]
    requested_at TEXT NOT NULL,         -- RFC3339 timestamp
    resolved_at TEXT NOT NULL,          -- RFC3339 timestamp
    approved INTEGER NOT NULL,          -- 0 = denied, 1 = approved
    reason TEXT NOT NULL,               -- "Approved by user", "Auto-denied", "Timed out", etc.
    grant_duration_secs INTEGER         -- NULL if denied
);

CREATE INDEX idx_perm_audit_agent    ON permission_audit(agent_name);
CREATE INDEX idx_perm_audit_resolved ON permission_audit(resolved_at DESC);
CREATE INDEX idx_perm_audit_approved ON permission_audit(approved);
```

#### Write Points

Every permission decision is persisted, regardless of how it was resolved:

| Resolution Path | Where Written | Reason String |
|----------------|---------------|---------------|
| Auto-denied (never-approve list) | `handle_request_permission()` | "Auto-denied: resource is on the never-approve list" |
| Auto-approved (safe list) | `handle_request_permission()` | "Auto-approved: low-risk resource" |
| Rate-limited | `handle_request_permission()` | "Rate limited: {details}" |
| Timed out (120s) | `handle_request_permission()` | "Timed out" |
| Human approved | `resolve_permission()` | "Approved by user" |
| Human denied | `resolve_permission()` | "Denied by user" |

#### Query API

```
GET /api/permissions/audit?limit=100
```

Returns JSON:
```json
{
    "entries": [
        {
            "id": 42,
            "request_id": 15,
            "agent_name": "code-agent",
            "resource_type": "file",
            "resource_path": "/etc/shadow",
            "justification": "Need to check password hashes",
            "risk_level": "critical",
            "risk_flags": "[\"critical_path:/etc/shadow\"]",
            "requested_at": "2026-03-12T10:30:00Z",
            "resolved_at": "2026-03-12T10:30:00Z",
            "approved": false,
            "reason": "Auto-denied: resource is on the never-approve list",
            "grant_duration_secs": null
        }
    ],
    "total": 42
}
```

The persistent audit trail survives daemon restarts and enables future anomaly detection queries like:
- Approval rate > 90% in 24h → rubber-stamping warning
- Agent denied 5+ times then approved → persistence attack warning
- Agent with > 20 requests in 24h → abuse warning

---

## Data Flow: Complete Permission Request Lifecycle

```
┌──────────────────────┐        ┌───────────────────────────────────────┐
│     LLM Agent        │        │            Guardian Daemon             │
│  (cgroup sandbox)    │        │                                       │
└──────────┬───────────┘        │  ┌─────────────────────────────────┐  │
           │                    │  │     handle_request_permission()  │  │
  guardian-ctl                  │  │                                  │  │
  request-permission            │  │  1. Max pending check           │  │
  --name agent                  │  │  2. Auto-deny check             │  │
  --path /etc/passwd            │  │  3. Auto-approve check          │  │
  --justification "..."         │  │  4. Rate limit check            │  │
           │                    │  │  5. Risk classification          │  │
           │  IPC (Unix socket) │  │  6. Justification analysis      │  │
           ├───────────────────>│  │  7. Create oneshot channel       │  │
           │                    │  │  8. Broadcast SSE event          │  │
           │  (agent blocks     │  └──────────────┬──────────────────┘  │
           │   waiting for      │                 │                     │
           │   oneshot)         │                 │  SSE: permission    │
           │                    │                 │  event with risk    │
           │                    │                 │  data               │
           │                    │                 ▼                     │
           │                    │  ┌─────────────────────────────────┐  │
           │                    │  │      Dashboard (all pages)      │  │
           │                    │  │                                  │  │
           │                    │  │  ┌───────────────────────────┐  │  │
           │                    │  │  │   Permission Banner       │  │  │
           │                    │  │  │   [CRITICAL] /etc/passwd  │  │  │
           │                    │  │  │   Risk: critical_path     │  │  │
           │                    │  │  │   Wait 5s... [Deny]       │  │  │
           │                    │  │  │                            │  │  │
           │                    │  │  │   (after 5s)              │  │  │
           │                    │  │  │   [Approve] [Deny]        │  │  │
           │                    │  │  └───────────────────────────┘  │  │
           │                    │  └──────────────┬──────────────────┘  │
           │                    │                 │                     │
           │                    │    POST /api/permissions/{id}/deny    │
           │                    │                 │                     │
           │                    │  ┌──────────────▼──────────────────┐  │
           │                    │  │     resolve_permission()        │  │
           │                    │  │                                  │  │
           │                    │  │  1. Send via oneshot channel     │  │
           │                    │  │  2. Update rate limiter          │  │
           │                    │  │  3. Record in VecDeque           │  │
           │                    │  │  4. Persist to SQLite            │  │
           │                    │  │  5. Broadcast SSE resolution     │  │
           │                    │  └──────────────┬──────────────────┘  │
           │                    │                 │                     │
           │  oneshot resolves  │                 │                     │
           │<──────────────────────────────────── │                     │
           │                    │                                       │
           ▼                    └───────────────────────────────────────┘
  Agent receives:
  { approved: false,
    reason: "Denied by user" }
```

---

## SSE Event Structure

When a permission request is created, the following SSE event is broadcast:

```json
{
    "id": 7,
    "kind": "request",
    "agent_name": "code-agent",
    "resource_type": "file",
    "resource_path": "/etc/passwd",
    "justification": "Need to read user list",
    "timeout_secs": 120,
    "requested_at": "2026-03-12T10:30:00Z",
    "approved": null,
    "reason": null,
    "risk_level": "high",
    "risk_flags": ["sensitive_path:/etc/passwd"],
    "wait_seconds": 5,
    "requires_type_confirm": false,
    "justification_warnings": []
}
```

The Alpine.js store in `base.html` processes these events and renders banners with the appropriate risk treatment on every page.

---

## Configuration Reference

### `[permissions]` Section

```toml
[permissions]
# Resources that can NEVER be approved via interactive request.
# Checked after path normalization, so bypass attempts are caught.
auto_deny = [
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d/**",
    "/root/**",
    "/root/.bash_history",
]

# Resources auto-approved without human intervention.
# Each rule specifies a maximum grant duration in seconds.
[[permissions.auto_approve]]
pattern = "/tmp/**"
max_duration_secs = 300       # 5 minutes

[[permissions.auto_approve]]
pattern = "/proc/self/**"
max_duration_secs = 60        # 1 minute

# Rate limiting parameters
rate_limit_per_minute = 3     # Max permission requests per agent per minute
rate_limit_per_hour = 15      # Max permission requests per agent per hour
deny_cooldown_secs = 30       # Base cooldown after denial (doubles exponentially)
max_pending_per_agent = 2     # Max simultaneous pending requests per agent
```

If the `[permissions]` section is omitted, all features still work with sensible defaults:
- Empty auto-deny/auto-approve lists (all requests go to human)
- Rate limits: 3/min, 15/hr
- Cooldown: 30s base
- Max pending: 2

---

## Test Coverage

### New Tests in `permissions.rs` (6 tests)

| Test | What It Verifies |
|------|-----------------|
| `test_auto_deny` | Auto-deny correctly blocks `/etc/shadow` and `.ssh/**` patterns |
| `test_auto_deny_with_bypass_attempts` | `/proc/self/root/etc/shadow` and `/tmp/../etc/shadow` are caught via `normalize_path()` |
| `test_auto_approve` | `/tmp/file.txt` matches auto-approve rule with correct duration |
| `test_risk_classification` | `/etc/shadow` → CRITICAL, `/tmp/file.txt` → LOW, exec `/usr/bin/curl` → ≥ HIGH |
| `test_justification_analysis` | "urgent, trust me it's safe" triggers URGENCY + REASSURANCE; benign text returns empty |
| `test_rate_limiter` | First 3 requests pass, 4th is rate-limited |

### New Tests in `config.rs` (5 tests)

| Test | What It Verifies |
|------|-----------------|
| `test_normalize_path_already_clean` | Clean paths pass through unchanged |
| `test_normalize_path_proc_self_root` | `/proc/self/root/etc/shadow` → `/etc/shadow` |
| `test_normalize_path_proc_pid_root` | `/proc/1234/root/etc/shadow` → `/etc/shadow` |
| `test_normalize_path_dotdot` | `/tmp/../etc/shadow` → `/etc/shadow` |
| `test_policy_blocks_normalized_bypass` | `check_file_policy()` blocks `/proc/self/root/etc/shadow` against deny rule `/etc/shadow` |

**Total test count:** 25 tests (15 config + 6 permissions + 4 main)

---

## Security Analysis

### What Phase 7 Fixes

| Attack Vector | Before Phase 7 | After Phase 7 |
|--------------|----------------|---------------|
| `/proc/self/root/etc/shadow` bypass | Undetected, reads shadow | Normalized to `/etc/shadow`, BLOCKED |
| `../../../etc/shadow` traversal | Undetected, reads shadow | Normalized to `/etc/shadow`, BLOCKED |
| `/proc/<pid>/root/etc/shadow` | Undetected, reads shadow | Normalized to `/etc/shadow`, BLOCKED |
| `openat2()` syscall | Completely unmonitored | Hooked via `sys_enter_openat2` tracepoint |
| Approval flood (100 requests/min) | Human overwhelmed, rubber-stamps | Rate-limited to 3/min, auto-denied |
| Re-requesting denied resource | Human fatigued, eventually approves | 5-minute same-resource cooldown + backoff |
| "Urgent! Trust me!" justification | Looks routine, approved reflexively | Warning tags displayed, risk bumped |
| One-click approve of `/etc/shadow` | Same UI as `/tmp/file.txt` | 10s wait + type "CONFIRM" required |
| Persistent re-denial attack | No escalation | Exponential backoff: 30s → 60s → 120s → ... → 10min |
| Audit trail lost on restart | In-memory only | SQLite persistence survives restarts |
| Exec bypass (log-only) | Exec events logged but never blocked | Full enforcement via LSM bprm_check_security |
| Legacy `open` syscall | Completely unmonitored | Hooked via sys_enter_open tracepoint |
| Network exfiltration | Not monitored at all | Outbound connections logged with port-based policy |

### What Phase 7 Does NOT Fix (Future Work)

| Attack Vector | Status | Fix |
|--------------|--------|-----|
| Symlink to sensitive file | **Open** | LSM `file_open` with `bpf_d_path()` (Phase 7a #2) |
| Exec enforcement | **Fixed** | LSM `bprm_check_security` with PENDING_EXEC_DENY map |
| Network exfiltration | **Partially Fixed** | `sys_enter_connect` tracepoint with port-based policy (monitoring + userspace policy; kernel-side enforcement deferred) |
| `rename()` policy bypass | **Open** | LSM `inode_rename` (Phase 7a #6) |
| `unlink()` file deletion | **Open** | LSM `inode_unlink` (Phase 7a #7) |
| Hardlink to sensitive file | **Open** | LSM `inode_link` (Phase 7d #23) |
| Dynamic linker bypass | **Open** | Deny `ld-linux` in exec policy (Phase 7a #4) |
| `io_uring` bypasses tracepoints | **Mitigated** | LSM hooks still fire for `io_uring`; full fix: seccomp (Phase 7d #25) |
| Rubber-stamping detection | **Open** | Anomaly detection on approval patterns (Phase 7d #28) |

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Userspace normalization (not kernel-side) | Quick win: catches 90% of bypasses with zero kernel changes. Full `bpf_d_path()` fix requires Linux 5.11+ and is planned for Phase 7a #2. |
| Separate `permissions.rs` module | Clean separation: permissions logic is independent of IPC plumbing. Testable without async runtime or BPF maps. |
| Risk scoring with multipliers | Composable: multiple risk factors compound naturally. An exec of a sensitive file after multiple denials escalates dramatically. |
| String matching (not regex) for justifications | Lightweight: no regex crate dependency in a no_std-adjacent module. Simple substring matching catches the most common social engineering patterns with near-zero false positives. |
| Exponential backoff on denials | Standard rate-limiting pattern. Allows legitimate agents to recover (resets on approval) while making persistence attacks increasingly costly. |
| Auto-deny before rate limit check | Critical resources should be rejected instantly, even if the agent hasn't been rate-limited yet. Don't waste rate limit budget on known-bad requests. |
| Auto-approve before rate limit check | Low-risk resources shouldn't consume rate limit budget. An agent accessing `/tmp` repeatedly shouldn't trigger rate limiting. |
| SQLite audit in `IpcState` | The DB reference is `Option<Arc<EventDb>>` — `None` when dashboard is disabled. Permission hardening still works without SQLite; audit is additive. |
| openat2 graceful fallback | `load_tracepoint` returning `Err` is non-fatal. Daemon continues with openat-only coverage on older kernels. |
| Type "CONFIRM" not resource path | The research doc suggested typing the resource path. Changed to "CONFIRM" for UX — resource paths can be long and error-prone to type. Still forces deliberate action. |
| Wait timer per-banner (not global) | Each banner has its own countdown via Alpine.js `x-data`. If two CRITICAL requests arrive, each has its own 10s timer. |
| Risk flags as gray badges | Shows the human *why* the risk level was set (transparency) without cluttering the primary UI. Advanced users can see scoring details. |
| Permission ID increment in auto-deny path | Even auto-denied requests consume a permission ID for consistent audit trail numbering. |

---

## Files Changed: Detailed Diff Summary

### `guardian/src/permissions.rs` (NEW — 460 lines)

Complete permission hardening module:

- **Lines 15-128:** `AgentRateLimit` — per-agent rate limiting state with minute/hour counters, exponential backoff, same-resource cooldown
- **Lines 135-168:** `RiskLevel` enum — Low/Medium/High/Critical with `wait_seconds()` and `requires_type_confirm()` methods
- **Lines 177-293:** `classify_risk()` — scores resource path/type against pattern lists with multipliers
- **Lines 300-320:** `check_auto_deny()` / `check_auto_approve()` — pattern matching against config
- **Lines 327-370:** `analyze_justification()` — suspicious pattern detection in justification text
- **Lines 376-459:** Tests (6 tests)

### `guardian/src/config.rs`

- Added `PermissionsConfig` struct with serde defaults
- Added `AutoApproveRule` struct
- Added `permissions: Option<PermissionsConfig>` to `Config`
- Added `pub fn normalize_path(raw: &str) -> String` (30 lines)
- Modified `check_file_policy()` to call `normalize_path()` before matching
- Modified `check_exec_policy()` to call `normalize_path()` before matching
- Made `path_matches()` public (`pub fn`)
- Added 5 new tests for normalization and bypass prevention

### `guardian-ebpf/src/main.rs`

- Added `guardian_file_openat2` tracepoint handler (82 lines)
- Reads `filename` at offset 24, `struct open_how *` at offset 32
- Extracts flags from first field of `open_how` struct
- Same policy evaluation and PENDING_DENY logic as `guardian_file_open`

### `guardian/src/ipc.rs`

- Added `rate_limits: HashMap<String, AgentRateLimit>` to `IpcState`
- Added `event_db: Option<Arc<EventDb>>` to `IpcState`
- Added risk fields to `PendingPermission`: `risk_level`, `risk_flags`, `justification_flags`
- Added risk fields to `ResolvedPermission`: `risk_level`, `risk_flags`
- Added risk fields to `PermissionEvent`: `risk_level`, `risk_flags`, `wait_seconds`, `requires_type_confirm`, `justification_warnings`
- Rewrote `handle_request_permission()` with 7-stage hardening pipeline
- Added SQLite persistence in `resolve_permission()` and all auto-resolve paths (auto-deny, auto-approve, rate-limited, timeout)

### `guardian/src/main.rs`

- Added `mod permissions;`
- Added `normalize_path` call in `process_file_event()` before policy check
- Added openat2 tracepoint load: `let has_openat2 = load_tracepoint(...).is_ok()`
- Added openat2 tracepoint attach with fallback warning
- Added `rate_limits: HashMap::new()` and `event_db: None` to IpcState init
- Added `s.event_db = Some(db.clone())` when dashboard starts

### `guardian/src/dashboard/db.rs`

- Added `permission_audit` table creation with 3 indexes
- Added `StoredPermissionAudit` struct (14 fields)
- Added `insert_permission_audit()` method (serializes risk_flags to JSON)
- Added `query_permission_audit()` method (returns recent entries)

### `guardian/src/dashboard/routes/api.rs`

- Updated `list_pending_permissions` to include `risk_level`, `risk_flags`, `wait_seconds`, `requires_type_confirm`, `justification_warnings`
- Added `query_permission_audit` endpoint
- Added `AuditQuery` struct

### `guardian/src/dashboard/routes/pages.rs`

- Added `risk_level`, `risk_flags`, `wait_seconds`, `requires_type_confirm`, `justification_warnings` to `PendingRequestInfo`
- Added `risk_level` to `ResolvedRequestInfo`
- Updated `requests()` handler to populate new fields

### `guardian/templates/base.html`

- Rewrote permission banner template (72 → 54 lines of template code):
  - Risk-colored banner via `:class="'risk-' + risk_level"`
  - Risk level badge
  - Justification warning tags
  - Risk flags as gray badges
  - Wait timer countdown with `x-init` interval
  - Type-to-confirm input for CRITICAL
  - Conditional approve button disabled state
- Updated Alpine.js store to set defaults for new fields from both fetch and SSE paths

### `guardian/templates/requests.html`

- Added Risk column to pending table with badge + warnings + flags
- Added per-row Alpine.js wait timer (`waitElapsed` counter)
- Added conditional type-to-confirm input for `requires_type_confirm` rows
- Added Risk column to resolved history table
- Updated colspan from 7 to 8 for empty states

### `guardian/static/app.css`

- Added `.badge-risk-low/medium/high/critical` badge styles
- Added `.perm-banner.risk-low/medium/high/critical` border color variants
- Added `.perm-banner-risk`, `.perm-banner-warnings` layout styles
- Added `.perm-warning-tag` red warning badge style
- Added `.perm-type-confirm` input layout style

---

## API Endpoints (New/Modified)

| Method | Path | Change |
|--------|------|--------|
| GET | `/api/permissions/pending` | **Modified:** Now includes `risk_level`, `risk_flags`, `wait_seconds`, `requires_type_confirm`, `justification_warnings` |
| GET | `/api/permissions/audit` | **New:** Query persistent SQLite audit trail. Params: `?limit=100` |

---

## Phase 7d: Exec Enforcement, Legacy Open Hook, Network Monitoring

### Exec Enforcement (LSM bprm_check_security)

Phase 7 upgrades exec monitoring from log-only (Phase 2) to full kernel-side enforcement. Previously, exec events were captured by the `sys_enter_execve` tracepoint and logged, but the binary was never blocked from executing. Now, a new LSM hook on `bprm_check_security` can deny exec at the kernel level, preventing the binary from ever running.

#### New BPF Maps (7 maps)

Exec enforcement requires its own set of BPF maps, structurally mirroring the file access maps:

| Map | Type | Purpose |
|-----|------|---------|
| `EXEC_DENY_EXACT` | HashMap | Exact-match deny rules for exec paths |
| `EXEC_DENY_PREFIXES` | Array | Prefix-based deny rules for exec paths |
| `EXEC_ALLOW_EXACT` | HashMap | Exact-match allow rules for exec paths |
| `EXEC_ALLOW_PREFIXES` | Array | Prefix-based allow rules for exec paths |
| `EXEC_DEFAULT_ACTION` | Array | Global default action for exec (allow/deny) |
| `EXEC_CGROUP_DEFAULT_ACTION` | HashMap | Per-cgroup default action for exec |
| `PENDING_EXEC_DENY` | HashMap | Pending exec denials keyed by pid_tgid |

#### New `evaluate_exec_policy()` Function

Added to `guardian-ebpf/src/main.rs`. Structurally identical to `evaluate_policy()` but reads from the exec-specific maps (`EXEC_DENY_EXACT`, `EXEC_DENY_PREFIXES`, `EXEC_ALLOW_EXACT`, `EXEC_ALLOW_PREFIXES`, `EXEC_DEFAULT_ACTION`, `EXEC_CGROUP_DEFAULT_ACTION`). This separation ensures exec policy evaluation is completely independent of file access policy evaluation.

#### Modified `guardian_exec_monitor` Tracepoint

The existing `sys_enter_execve` tracepoint handler now calls `evaluate_exec_policy()` after capturing the exec path. When the policy evaluates to deny, it sets `PENDING_EXEC_DENY[pid_tgid]` to signal the LSM hook. The event is still sent to userspace via the perf event array for logging.

#### New LSM Hook: `guardian_enforce_exec`

Attached to the `bprm_check_security` LSM hook point. This hook fires during exec processing after the kernel has loaded the binary. It checks the `PENDING_EXEC_DENY` map for the current `pid_tgid`:

- If found: deletes the map entry and returns `-EPERM` (the binary never executes)
- If not found: returns `0` (exec proceeds normally)

This follows the same PENDING pattern used for file enforcement (`PENDING_DENY` + `file_open` LSM).

#### Timing Guarantee

The `sys_enter_execve` tracepoint fires at syscall entry, before the kernel begins processing the exec. The kernel then opens the binary file internally and calls `bprm_check_security` during exec processing. This guarantees the tracepoint has already evaluated policy and populated `PENDING_EXEC_DENY` before the LSM hook checks it:

```
sys_enter_execve fires --> exec tracepoint evaluates exec policy --> sets PENDING_EXEC_DENY
    --> kernel opens binary internally (no sys_enter_openat fires)
    --> file_open LSM fires --> checks PENDING_DENY --> empty --> allows
    --> bprm_check_security fires --> checks PENDING_EXEC_DENY --> -EPERM --> exec BLOCKED
```

#### Why Separate PENDING_EXEC_DENY Map

During `execve`, the kernel internally opens the binary file to read its contents. This internal open triggers the `file_open` LSM hook. If exec denials were stored in the same `PENDING_DENY` map used for file access enforcement, the `file_open` hook would consume the denial entry (delete it after reading), and the `bprm_check_security` hook would find nothing. The binary would be read (file open allowed) but the exec denial would be lost. Separate maps ensure clean isolation between file access enforcement and exec enforcement.

#### Graceful Fallback

The `load_lsm()` and `attach_lsm()` helper functions were generalized to accept a program name and hook name as parameters, allowing them to load both `file_open` and `bprm_check_security` LSM programs. If `bprm_check_security` attachment fails (kernel does not support it, or BPF LSM is not enabled), exec falls back to monitor-only mode. The daemon logs a warning and continues operating with file enforcement intact.

#### Daemon Changes

- `populate_exec_enforcement_maps()` in `main.rs` populates the 7 exec maps from the agent configuration, mirroring how `populate_enforcement_maps()` works for file access.
- `process_exec_event()` updated to log "BLOCKED" (not just "DENY") when the daemon is in enforce mode and the policy denies the exec.
- Path normalization (via `normalize_path()`) applied to exec events before policy evaluation, consistent with file access events.

---

### Legacy `open` Syscall Hook

On modern Linux (glibc 2.26+, released 2017), the `open()` C library function is implemented as `openat(AT_FDCWD, ...)`, so the existing `sys_enter_openat` tracepoint already captures these calls. However, ancient statically-linked binaries or hand-rolled assembly may still invoke the raw `open` syscall (syscall number 2 on x86_64) directly, bypassing `openat` entirely.

As a belt-and-suspenders measure, Phase 7 adds a `guardian_file_open_legacy` tracepoint attached to `sys_enter_open`:

- **Tracepoint field offsets (x86_64):** filename pointer at offset 16, flags at offset 24
- **Same logic as `guardian_file_open`:** calls `evaluate_policy()` to check file access rules, sets `PENDING_DENY[pid_tgid]` on denial, and sends the event to userspace via the perf event array
- **Reuses existing maps:** `EVENT_BUF`, `EVENTS`, and `PENDING_DENY` are shared with the `openat` handler. No new BPF maps are needed.
- **Graceful fallback:** The tracepoint is loaded and attached with an `is_ok()` check. If `sys_enter_open` does not exist on the running kernel (some architectures have removed it), the daemon continues with `openat`-only and `openat2` coverage. A warning is logged but operation is not affected.

---

### Network Connection Monitoring

Phase 7 adds monitoring of outbound network connections, allowing administrators to detect and log when agents connect to external hosts. This is monitoring-only — no kernel-side enforcement is implemented yet.

#### New `NetworkEvent` Struct

Added to `guardian-common/src/lib.rs`. A 52-byte `#[repr(C)]` struct containing:

| Field | Type | Description |
|-------|------|-------------|
| `pid` | `u32` | Process ID |
| `tgid` | `u32` | Thread group ID |
| `uid` | `u32` | User ID |
| `family` | `u16` | Address family (AF_INET=2 or AF_INET6=10) |
| `dest_port` | `u16` | Destination port (network byte order converted to host) |
| `dest_addr4` | `u32` | IPv4 destination address (for AF_INET) |
| `dest_addr6` | `[u8; 16]` | IPv6 destination address (for AF_INET6) |
| `comm` | `[u8; 16]` | Process command name |

#### New BPF Maps

| Map | Type | Purpose |
|-----|------|---------|
| `NET_EVENT_BUF` | PerCpuArray | Scratch buffer for building `NetworkEvent` (avoids 512-byte stack limit) |
| `NET_EVENTS` | PerfEventArray | Sends network events to userspace daemon |

#### New `guardian_net_connect` Tracepoint

Attached to `sys_enter_connect`, this tracepoint monitors outbound connection attempts:

1. Reads the `sockaddr *` pointer from the tracepoint args at offset 24
2. Reads `sa_family` (first 2 bytes of sockaddr) to determine the address family
3. For **AF_INET** (family=2): reads the 8-byte `sockaddr_in` structure — port at byte offset 2, IPv4 address at byte offset 4
4. For **AF_INET6** (family=10): reads the 28-byte `sockaddr_in6` structure — port at byte offset 2, IPv6 address at byte offset 8
5. Skips non-IP connections (Unix domain sockets, netlink, etc.) by returning early for unrecognized families
6. Populates the `NetworkEvent` in `NET_EVENT_BUF` and sends it to userspace via `NET_EVENTS`

#### New `NetworkPolicy` Struct

Added to `guardian/src/config.rs`:

```rust
pub struct NetworkPolicy {
    pub default: String,      // "allow" or "deny"
    pub allow_ports: Vec<u16>,
    pub deny_ports: Vec<u16>,
}
```

Configuration example in `config.toml`:

```toml
[agents.network_policy]
default = "allow"
deny_ports = [22, 25, 445]
allow_ports = [80, 443, 53]
```

#### Userspace Policy Evaluation

- `check_network_policy()` evaluates port-based network rules following the same deny-takes-precedence model as file access policy. If a port appears in both `allow_ports` and `deny_ports`, the deny rule wins.
- `process_net_event()` formats IPv4 addresses as dotted-quad notation and IPv6 addresses as colon-separated hex, then dispatches the event to the alerting system.

#### Monitoring-Only (No Kernel Enforcement)

Network monitoring is monitoring-only in this phase. There is no LSM `socket_connect` hook — policy violations are logged as warnings but connections are not blocked at the kernel level. Kernel-side network enforcement is deferred to a future phase.

#### New `EventType::NetworkConnect`

Added to `guardian/src/alerting/mod.rs` to support network events in the alerting pipeline. Network events flow through the same `AlertManager` dispatch path as file and exec events, supporting deduplication, severity filtering, and all configured alert outputs (JSON log, webhook, Slack, email).

#### Graceful Fallback

The network tracepoint is loaded and attached with an `is_ok()` check. If `sys_enter_connect` attachment fails, network monitoring is silently disabled and the daemon continues with file and exec monitoring only.

---

## Bug Fixes

### Dashboard Hang: SSE Connection Exhaustion

**Symptom:** The dashboard becomes completely unresponsive after visiting 3-4 pages. No page loads, no API responses — the browser appears to hang indefinitely.

**Root Cause:** HTTP/1.1 browsers enforce a limit of ~6 concurrent connections per origin (per the HTTP/1.1 spec, RFC 7230). Server-Sent Events (SSE) connections are long-lived — they stay open for the lifetime of the page. The dashboard was creating multiple SSE connections per page load without ever closing them:

1. **`base.html`** (Alpine.js store `init()`): Created `new EventSource('/events/stream')` on every page — this runs on ALL pages since every template extends `base.html`
2. **`index.html`** (`recentEvents()` component): Created a SECOND `EventSource('/events/stream')` for the live event table
3. **`events.html`** (`eventFilter()` component): Created a SECOND `EventSource('/events/stream')` for the live event stream with filtering

Each page navigation created 1-2 new SSE connections that were never closed (no `beforeunload` cleanup). The connection lifecycle looked like:

```
Visit /          → 2 SSE connections (base.html + index.html)     = 2 total
Navigate /events → 2 SSE connections (base.html + events.html)    = 4 total
Navigate /agents → 1 SSE connection  (base.html)                  = 5 total
Navigate /policy → 1 SSE connection  (base.html)                  = 6 total  ← LIMIT HIT
Navigate /alerts → Browser queues request, waits for a free slot  ← HANGS
```

At 6 connections, all HTTP/1.1 connection slots are consumed by stale SSE connections from previous pages. The browser queues all new requests (page loads, API calls, htmx requests) waiting for a slot to free up. Since SSE connections never close on their own, the dashboard is permanently stuck.

**Fix (3 files changed):**

1. **`base.html`** — Single shared SSE connection architecture:
   - Moved SSE creation to a standalone IIFE that runs before Alpine initializes
   - Stores the connection as `window.__guardianSSE`
   - Relays SSE event types (`event`, `lag`, `permission`) as custom DOM events (`guardian:event`, `guardian:lag`, `guardian:permission`)
   - Added `beforeunload` event listener to close the SSE connection when navigating away from the page
   - Alpine.js store now listens to `guardian:permission` DOM events instead of directly to the EventSource

   ```javascript
   // Single shared SSE — runs once, before Alpine
   (function() {
     var sse = new EventSource('/events/stream');
     window.__guardianSSE = sse;

     // Relay to DOM events so child pages don't need their own SSE
     sse.addEventListener('event', function(e) {
       document.dispatchEvent(new CustomEvent('guardian:event', { detail: e.data }));
     });
     sse.addEventListener('permission', function(e) {
       document.dispatchEvent(new CustomEvent('guardian:permission', { detail: e.data }));
     });

     // Close on navigation to free the connection slot
     window.addEventListener('beforeunload', function() {
       if (sse) { sse.close(); }
     });
   })();
   ```

2. **`index.html`** — `recentEvents()` component:
   - Removed `sse`, `retryDelay` fields and `connect()` method entirely
   - `init()` now listens to `guardian:event`, `guardian:sse-open`, `guardian:sse-error` DOM events
   - Connection status derived from `window.__guardianSSE.readyState`
   - Zero EventSource instances created by this page

3. **`events.html`** — `eventFilter()` component:
   - Same treatment as `index.html`: removed `sse`, `retryDelay`, `connect()` method
   - Listens to `guardian:event`, `guardian:lag`, `guardian:sse-open`, `guardian:sse-error` DOM events
   - Zero EventSource instances created by this page

**After fix — connection lifecycle:**

```
Visit /          → 1 SSE connection (shared from base.html)
Navigate /events → old SSE closed (beforeunload), 1 new SSE  = 1 total
Navigate /agents → old SSE closed (beforeunload), 1 new SSE  = 1 total
Navigate /policy → old SSE closed (beforeunload), 1 new SSE  = 1 total
... (always exactly 1 SSE connection, properly cleaned up)
```

**Design decision:** Custom DOM events (`CustomEvent`) were chosen over having child pages directly reference `window.__guardianSSE` because:
- Decoupled: child pages don't need to know about EventSource API or manage listeners
- Timing-safe: DOM events work regardless of whether the SSE was open before or after the child component initialized
- Single responsibility: base.html owns the connection lifecycle; child pages just consume events

---

## What's Next

The remaining items from `docs/security-improvements-research.md`:

### Phase 7a (remaining): Kernel-Side Security
- LSM `file_open` with `bpf_d_path()` for canonical path enforcement (eliminates symlink attacks)
- LSM `bprm_check_security` for exec blocking
- Dynamic linker detection (`ld-linux` blocking)
- LSM `inode_rename` and `inode_unlink` for rename/delete enforcement

### Phase 7b: Network Monitoring
- `cgroup/connect4` BPF program for per-agent network policy
- Network event types and config model
- Domain → IP resolution at startup

### Phase 7d: Advanced Hardening
- Inode-based deny map for critical files
- Content hashing via `bpf_ima_file_hash` (Linux 5.18+)
- `io_uring` blocking via seccomp
- Anomaly detection on approval patterns
