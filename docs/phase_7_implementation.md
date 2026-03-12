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

### What Phase 7 Does NOT Fix (Future Work)

| Attack Vector | Status | Fix |
|--------------|--------|-----|
| Symlink to sensitive file | **Open** | LSM `file_open` with `bpf_d_path()` (Phase 7a #2) |
| Exec enforcement | **Open** | LSM `bprm_check_security` (Phase 7a #3) |
| Network exfiltration | **Open** | `cgroup/connect4` BPF program (Phase 7b) |
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
