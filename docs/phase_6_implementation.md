# Phase 6 Implementation: Interactive Permission Requests

## What Phase 6 Solves

Phase 5 gave us a web dashboard with real-time event streaming, visual policy editing, agent management, and alert configuration. But permission management was still static — you either pre-configured allow/deny rules, or used `guardian-ctl grant` manually from the CLI:

**Problem 1: No interactive permission negotiation.** An LLM agent that needs to access a sensitive file or run a restricted command has no way to *ask* for permission. It either gets blocked (and fails) or the human operator must anticipate every need in advance and pre-configure allow rules. There's no middle ground.

**Problem 2: No real-time approval workflow.** When an agent needs temporary access to `/etc/shadow` or wants to run `curl`, the human must SSH into the server, run `guardian-ctl grant`, and hope the timing is right. There's no in-browser notification, no countdown, no one-click approve/deny.

**Problem 3: No audit trail for ad-hoc permissions.** Even with `guardian-ctl grant`, there's no record of *why* access was granted, *who* approved it, or *what the agent's justification was*. Temporary grants are fire-and-forget with no accountability.

**Problem 4: No agent-initiated communication.** The IPC protocol was one-directional for control commands. Agents could be registered and managed, but they couldn't initiate a request that requires a human response. There was no long-poll mechanism for blocking until a decision arrives.

Phase 6 solves all four by adding interactive permission requests: an agent (via `guardian-ctl request-permission`) asks the daemon for access, the request appears as a real-time notification banner on every dashboard page, the human approves or denies with a click, and the agent receives the decision instantly. All requests are tracked in an audit trail visible on a dedicated `/requests` page.

---

## What Was Built

### New Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `guardian/templates/requests.html` | 115 | Dedicated permission requests page with pending table and resolved history |

### Modified Source Files

| File | What Changed |
|------|-------------|
| `guardian-common/src/lib.rs` | Added `RequestPermission` variant to `IpcRequest` and `PermissionDecision` variant to `IpcResponse` |
| `guardian/src/ipc.rs` | Added permission request infrastructure: `PermissionDecision`, `PendingPermission`, `ResolvedPermission`, `PermissionEvent` types; `handle_request_permission()` with oneshot long-poll; `resolve_permission()` public API; exec grant support in cleanup task |
| `guardian/src/dashboard/state.rs` | Added `permission_bus: broadcast::Sender<PermissionEvent>` to `DashboardState` |
| `guardian/src/dashboard/mod.rs` | Added 5 new routes: `/requests` page, permission pending/resolved JSON endpoints, approve/deny API endpoints |
| `guardian/src/dashboard/routes/pages.rs` | Added `RequestsTemplate`, `PendingRequestInfo`, `ResolvedRequestInfo` structs and `requests()` page handler |
| `guardian/src/dashboard/routes/api.rs` | Added `approve_permission()`, `deny_permission()`, `list_pending_permissions()`, `list_resolved_permissions()` handlers; added `ApproveForm` struct; added exec grant type support to `grant_access()` |
| `guardian/src/dashboard/routes/sse.rs` | Complete rewrite: merged two broadcast streams (alert events + permission events) via `tokio_stream::StreamExt::merge` into single SSE endpoint |
| `guardian/src/main.rs` | Created `permission_bus` broadcast channel (capacity 256), extended `IpcState` initialization with permission fields, connected permission bus to dashboard state |
| `guardian/templates/base.html` | Added "Requests" nav link with Alpine.js pending count badge; added permission request banner template (shows on all pages); added `Alpine.store('perms', {...})` with SSE listener, countdown timer, approve/deny handlers |
| `guardian/templates/agents.html` | Added exec grant type selector to grant form (File Access / Exec Command) with dynamic labels |
| `guardian/static/app.css` | Added `.perm-banner` styles (slide-in animation, header/body/actions layout), `.perm-banner-icon`, `.perm-banner-timer`, `.nav-badge` |
| `guardian-ctl/src/main.rs` | Added `RequestPermission` CLI subcommand with `--name`, `--resource-type`, `--path`, `--justification` flags; updated `send_request()` for long-poll timeout (180s); added `PermissionDecision` response handling |

---

## Architecture

### Permission Request Flow

```
                           ┌─────────────────────────────┐
                           │     LLM Agent Process       │
                           │  (inside cgroup sandbox)    │
                           └─────────────┬───────────────┘
                                         │
                             guardian-ctl request-permission
                             --name agent --path /usr/bin/curl
                                         │
                                         ▼
                           ┌─────────────────────────────┐
                           │   Guardian Daemon (IPC)      │
                           │                              │
                           │  1. Create oneshot channel    │
                           │  2. Store PendingPermission   │
                           │  3. Broadcast via perm_bus    │
                           │  4. Release lock              │
                           │  5. await rx (up to 120s)     │
                           └──────────┬──────────┬────────┘
                                      │          │
                         broadcast    │          │  oneshot
                                      ▼          │
                           ┌──────────────────┐  │
                           │  SSE Endpoint     │  │
                           │  /events/stream   │  │
                           └────────┬─────────┘  │
                                    │             │
                    event: permission│             │
                    data: {kind:     │             │
                     "request",...}  │             │
                                    ▼             │
                           ┌──────────────────┐  │
                           │  Browser          │  │
                           │                   │  │
                           │  Alpine.js store  │  │
                           │  → Banner popup   │  │
                           │  → Countdown      │  │
                           │                   │  │
                           │  [Approve] [Deny] │  │
                           └────────┬─────────┘  │
                                    │             │
                        POST /api/  │             │
                        permissions/│             │
                        {id}/approve│             │
                                    ▼             │
                           ┌──────────────────┐  │
                           │  Dashboard API    │  │
                           │                   │  │
                           │  resolve_permis-  │  │
                           │  sion() →         │──┘
                           │  oneshot::send()  │
                           │                   │
                           │  + Create temp    │
                           │    grant if       │
                           │    approved       │
                           └──────────────────┘
                                    │
                                    ▼
                           ┌──────────────────┐
                           │  Agent unblocks   │
                           │                   │
                           │  IpcResponse::    │
                           │  PermissionDecis- │
                           │  ion { approved:  │
                           │  true, ... }      │
                           └──────────────────┘
```

### SSE Stream Merging

```
  broadcast::Sender<AlertEvent>         broadcast::Sender<PermissionEvent>
          │                                        │
          ▼                                        ▼
  BroadcastStream::new(event_rx)        BroadcastStream::new(perm_rx)
          │                                        │
          ▼                                        ▼
  .map(|e| Event("event", json))        .map(|e| Event("permission", json))
          │                                        │
          └───────────────┬────────────────────────┘
                          │
                    .merge()
                          │
                          ▼
                   Single SSE stream
                   /events/stream
                          │
                          ▼
                   Browser EventSource
                   ├── "event"      → Live events table
                   ├── "permission" → Alpine.store('perms')
                   └── "lag"        → Missed events counter
```

### Key Design: Oneshot Channel Long-Poll

The core mechanism that enables agents to block while waiting for human approval is `tokio::sync::oneshot`:

```rust
// In handle_request_permission():
let (tx, rx) = oneshot::channel::<PermissionDecision>();

{
    let mut s = state.lock().await;
    // Store tx in PendingPermission, broadcast to dashboard
    s.pending_permissions.push(PendingPermission {
        responder: Some(tx),
        // ...
    });
} // Lock released — IPC connection stays open

// Agent blocks here for up to 120 seconds
match tokio::time::timeout(Duration::from_secs(120), rx).await {
    Ok(Ok(decision)) => { /* return decision to agent */ }
    _ => { /* auto-deny on timeout */ }
}
```

```rust
// In resolve_permission() (called by dashboard API):
if let Some(responder) = pending.responder.take() {
    let _ = responder.send(PermissionDecision {
        approved: true,
        reason: "Approved by user".to_string(),
        grant_duration_secs: Some(600),
    });
}
```

The oneshot sender is stored inside `PendingPermission`. When the dashboard API calls `resolve_permission()`, it takes the sender and sends the decision. The `handle_request_permission()` function, which has been awaiting the receiver, unblocks immediately and returns the response to the agent.

---

## Permission Request Lifecycle

### 1. Agent Sends Request

The agent (or a wrapper script) runs:

```bash
guardian-ctl request-permission \
  --name my-agent \
  --resource-type exec \
  --path /usr/bin/curl \
  --justification "Need to fetch API data from internal service"
```

This connects to the daemon's Unix socket and sends:

```json
{
  "request_permission": {
    "agent_name": "my-agent",
    "resource_type": "exec",
    "resource_path": "/usr/bin/curl",
    "justification": "Need to fetch API data from internal service"
  }
}
```

The CLI then blocks, waiting for the daemon's response (up to 180 seconds client-side read timeout).

### 2. Daemon Creates Pending Request

The daemon's IPC handler:
1. Validates the agent exists (in config or registered)
2. Checks the dashboard/permission bus is enabled (auto-denies if not)
3. Assigns an incrementing ID
4. Creates a `PendingPermission` with a `oneshot::Sender` inside
5. Broadcasts a `PermissionEvent { kind: "request", ... }` to the permission bus
6. Releases the state lock
7. Awaits the `oneshot::Receiver` with a 120-second timeout

### 3. Dashboard Receives Notification

The SSE endpoint merges the permission broadcast stream with the alert event stream. When a permission request event arrives, it's sent as:

```
event: permission
data: {"id":1,"kind":"request","agent_name":"my-agent","resource_type":"exec","resource_path":"/usr/bin/curl","justification":"Need to fetch API data","timeout_secs":120,"requested_at":"2026-03-10T14:30:00+00:00"}
```

The Alpine.js `perms` store (loaded on every page via `base.html`) receives this event and pushes it to the `pending` array. This triggers:
- A notification banner at the top of the current page (any page)
- A badge counter on the "Requests" nav item in the sidebar

### 4. Human Approves or Denies

The banner shows:
- Agent name and resource details
- The justification text
- A countdown timer (120 seconds)
- A duration selector (1 min / 5 min / 10 min / 30 min / 1 hour)
- Approve and Deny buttons

When the user clicks **Approve**:
1. Alpine.js sends `POST /api/permissions/{id}/approve` with `duration=600`
2. The API handler calls `ipc::resolve_permission()` with `approved=true`
3. `resolve_permission()` takes the `oneshot::Sender` from the pending request and sends the decision
4. If approved, a `TemporaryGrant` is created (file access → BPF map entry; exec → config allow list entry)
5. The pending request is moved to the resolved history
6. A `PermissionEvent { kind: "resolved", approved: true }` is broadcast
7. All dashboard clients dismiss the banner

### 5. Agent Receives Decision

The `handle_request_permission()` function, which was awaiting the oneshot receiver, unblocks:
- Returns `IpcResponse::PermissionDecision { approved: true, reason: "Approved by user", grant_duration_secs: Some(600) }`
- The IPC response is sent back to `guardian-ctl` over the Unix socket
- `guardian-ctl` prints `APPROVED: Approved by user (granted for 600s)` and exits with code 0

### 6. Timeout (No Response)

If no human responds within 120 seconds:
- The `tokio::time::timeout` fires
- The request is auto-denied with reason "Timed out"
- The pending request is moved to resolved history
- A resolution event is broadcast to dashboard clients
- The agent receives `IpcResponse::PermissionDecision { approved: false, reason: "Request timed out (no response within 120 seconds)" }`
- `guardian-ctl` prints `DENIED: Request timed out...` and exits with code 1

---

## IPC Protocol Extensions

### New IPC Request Variant

```rust
#[serde(rename = "request_permission")]
RequestPermission {
    agent_name: String,
    resource_type: String,       // "file" or "exec"
    resource_path: String,       // e.g., "/usr/bin/curl" or "/etc/shadow"
    justification: Option<String>,
}
```

### New IPC Response Variant

```rust
#[serde(rename = "permission_decision")]
PermissionDecision {
    approved: bool,
    reason: String,
    grant_duration_secs: Option<u64>,
}
```

### Long-Poll Behavior

Unlike other IPC requests (list, stop, grant) which return immediately, `RequestPermission` is a **long-poll** request. The daemon holds the connection open for up to 120 seconds while waiting for human input.

`guardian-ctl` handles this by:
- Setting a 180-second read timeout (vs 10 seconds for normal requests)
- Printing `"Waiting for human approval via dashboard (up to 120s)..."` to stderr
- Exiting with code 1 if denied (code 0 if approved)

---

## SSE Protocol Changes

Phase 5's SSE endpoint sent a single event type (`event`). Phase 6 adds a second event type (`permission`) by merging two broadcast streams:

```
event: event
data: {"timestamp":"2026-03-10T14:30:00Z","severity":"critical",...}

event: permission
data: {"id":1,"kind":"request","agent_name":"my-agent","resource_type":"exec","resource_path":"/usr/bin/curl","justification":"...","timeout_secs":120,"requested_at":"2026-03-10T14:30:00+00:00"}

event: permission
data: {"id":1,"kind":"resolved","agent_name":"my-agent","approved":true,"reason":"Approved by user"}

event: lag
data: {"missed": 5}

:heartbeat
```

- **`event`**: Normal alert event (file access, exec attempt)
- **`permission`**: Permission request or resolution — `kind` is either `"request"` or `"resolved"`
- **`lag`**: Broadcast channel overflow
- **`:heartbeat`**: Keep-alive comment every 5 seconds

### Stream Merging Implementation

```rust
// Two independent broadcast receivers
let event_rx = state.event_bus.subscribe();
let perm_rx = state.permission_bus.subscribe();

// Map each to SSE events with different event names
let event_stream = BroadcastStream::new(event_rx)
    .map(|r| Ok(Event::default().event("event").data(json)));
let perm_stream = BroadcastStream::new(perm_rx)
    .map(|r| Ok(Event::default().event("permission").data(json)));

// Merge into a single stream
let merged = event_stream.merge(perm_stream);
Sse::new(merged).keep_alive(...)
```

`tokio_stream::StreamExt::merge` alternates between the two source streams, delivering events from whichever stream has data available. This means a single `EventSource` connection receives both alert events and permission events.

---

## Dashboard UI Components

### Permission Banner (All Pages)

The permission banner is rendered in `base.html`, making it visible on every page. It uses Alpine.js's `x-for` directive to render one banner per pending request:

```html
<template x-for="req in $store.perms.pending" :key="req.id">
  <div class="perm-banner">
    <div class="perm-banner-header">
      <span class="perm-banner-icon">?</span>
      Permission Request from <strong x-text="req.agent_name"></strong>
      <span class="perm-banner-timer" x-text="$store.perms.remaining(req)"></span>s left
    </div>
    <div class="perm-banner-body">
      Wants to <span class="badge" x-text="req.resource_type.toUpperCase()"></span>
      <code x-text="req.resource_path"></code>
      <div x-show="req.justification" x-text="req.justification"></div>
    </div>
    <div class="perm-banner-actions">
      <select x-model="dur"> <!-- 1m / 5m / 10m / 30m / 1h --> </select>
      <button @click="$store.perms.approve(req.id, dur)">Approve</button>
      <button @click="$store.perms.deny(req.id)">Deny</button>
    </div>
  </div>
</template>
```

**Countdown timer reactivity:** Alpine.js doesn't detect `setInterval` mutations on object properties. The solution is a `_tick` counter that increments every second. The `remaining()` method reads `_tick` to create a reactive dependency:

```javascript
Alpine.store('perms', {
  _tick: 0,
  init() {
    setInterval(() => { this._tick++; }, 1000);
  },
  remaining(req) {
    void this._tick; // Access to create Alpine dependency
    return Math.max(0, Math.ceil((req.deadline - Date.now()) / 1000));
  }
});
```

### Sidebar Badge

The "Requests" nav item shows a yellow pill badge when there are pending requests:

```html
<template x-if="$store.perms.pending.length > 0">
  <span class="nav-badge" x-text="$store.perms.pending.length"></span>
</template>
```

### Requests Page (`/requests`)

A dedicated page with two tables:

**Pending Requests Table:**
- ID, Agent, Type (badge), Resource, Justification, Waiting time (elapsed/timeout), Actions (duration select + approve/deny)

**Resolved History Table:**
- ID, Agent, Type, Resource, Decision (approved/denied badge), Reason, Duration
- Last 100 resolved requests, newest first
- Scrollable with max-height

### Agent Grant Type Selector (Dashboard Agents Page)

The Agents page grant form now supports **exec command grants** in addition to file access grants. This was the user's original request — allowing a command like `grep` for 10 minutes directly from the dashboard.

```html
<select name="grant_type" x-model="grantType">
  <option value="file">File Access</option>
  <option value="exec">Exec Command</option>
</select>
```

When "Exec Command" is selected:
- The label changes from "File Path" to "Command Path"
- The placeholder changes from `/path/to/file` to `/usr/bin/grep`
- The submit button changes from "Grant File Access" to "Grant Exec Access"
- Default duration is 600 seconds (10 minutes)

**How exec grants work:**
1. The dashboard sends `POST /api/agents/{name}/grant` with `grant_type=exec&path=/usr/bin/grep&duration=600`
2. The API handler adds `/usr/bin/grep` to the agent's `exec_policy.allow` list in the config
3. A `TemporaryGrant { grant_type: GrantType::Exec }` is stored with an expiry timestamp
4. For the next 10 minutes, exec events for `/usr/bin/grep` will be logged as "allowed"
5. After expiry, the background cleanup task removes the command from the exec allow list
6. The agent's exec policy returns to its original state automatically

---

## API Endpoints (Phase 6 Additions)

### Page Routes

| Method | Path | Description | Response |
|--------|------|-------------|----------|
| GET | `/requests` | Permission requests page | Full HTML page |

### JSON API Routes

| Method | Path | Parameters | Description | Response |
|--------|------|-----------|-------------|----------|
| GET | `/api/permissions/pending` | — | List pending permission requests | JSON array |
| GET | `/api/permissions/resolved` | — | List resolved permission history | JSON array |

### Action API Routes

| Method | Path | Parameters | Description | Response |
|--------|------|-----------|-------------|----------|
| POST | `/api/permissions/{id}/approve` | `duration` (form, optional, default 600) | Approve a pending request | HTML toast |
| POST | `/api/permissions/{id}/deny` | — | Deny a pending request | HTML toast |

### JSON Payloads

**GET /api/permissions/pending:**

```json
[
  {
    "id": 1,
    "agent_name": "my-agent",
    "resource_type": "exec",
    "resource_path": "/usr/bin/curl",
    "justification": "Need to fetch API data",
    "timeout_secs": 120,
    "requested_at": "2026-03-10T14:30:00+00:00",
    "elapsed_secs": 45
  }
]
```

**GET /api/permissions/resolved:**

```json
[
  {
    "id": 1,
    "agent_name": "my-agent",
    "resource_type": "exec",
    "resource_path": "/usr/bin/curl",
    "justification": "Need to fetch API data",
    "requested_at": "2026-03-10T14:30:00+00:00",
    "resolved_at": "2026-03-10T14:30:45+00:00",
    "approved": true,
    "reason": "Approved by user",
    "grant_duration_secs": 600
  }
]
```

---

## Alpine.js Permission Store

The permission store is defined in `base.html` and available globally on every page:

```javascript
Alpine.store('perms', {
  pending: [],
  _tick: 0,

  init() {
    const self = this;

    // Tick every second for countdown reactivity
    setInterval(() => { self._tick++; }, 1000);

    // Fetch existing pending requests on page load
    fetch('/api/permissions/pending')
      .then(r => r.json())
      .then(data => {
        data.forEach(req => {
          req.deadline = new Date(req.requested_at).getTime()
                       + req.timeout_secs * 1000;
          if (!self.pending.find(p => p.id === req.id)) {
            self.pending.push(req);
          }
        });
      });

    // Listen for real-time permission events via SSE
    const sse = new EventSource('/events/stream');
    sse.addEventListener('permission', function(e) {
      const data = JSON.parse(e.data);
      if (data.kind === 'request') {
        data.deadline = new Date(data.requested_at).getTime()
                      + data.timeout_secs * 1000;
        if (!self.pending.find(p => p.id === data.id)) {
          self.pending.push(data);
        }
      } else if (data.kind === 'resolved') {
        self.dismiss(data.id);
      }
    });
  },

  remaining(req) {
    void this._tick;
    return Math.max(0, Math.ceil((req.deadline - Date.now()) / 1000));
  },

  approve(id, duration) {
    fetch('/api/permissions/' + id + '/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'duration=' + duration
    }).then(() => this.dismiss(id));
  },

  deny(id) {
    fetch('/api/permissions/' + id + '/deny', { method: 'POST' })
      .then(() => this.dismiss(id));
  },

  dismiss(id) {
    this.pending = this.pending.filter(p => p.id !== id);
  }
});
```

### Why Two Data Sources

The store fetches pending requests via `GET /api/permissions/pending` on page load AND listens to SSE for new requests. This handles two scenarios:

1. **SSE**: Delivers requests that arrive while the page is open (real-time)
2. **HTTP fetch**: Catches requests that arrived before the page was opened (e.g., user navigates to dashboard after agent already sent a request)

Both sources use deduplication (`find(p => p.id === req.id)`) to prevent duplicate banners.

---

## Temporary Grant Creation on Approval

When a permission request is approved, `resolve_permission()` creates a `TemporaryGrant` with automatic expiry:

### File Access Grants
- Path is added to the BPF allow maps (`allow_exact` or `allow_prefixes`)
- A `TemporaryGrant { grant_type: GrantType::FileAccess }` is stored
- The background cleanup task removes it from BPF maps when it expires

### Exec Grants
- Command is added to the agent's exec policy allow list in the config
- A `TemporaryGrant { grant_type: GrantType::Exec }` is stored
- The background cleanup task removes it from the config allow list when it expires

The cleanup task runs every 5 seconds, checking `grant.expires_at` against `Instant::now()`.

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Oneshot channel for long-poll** | `tokio::sync::oneshot` is designed for single-use send/receive. The sender is stored in the pending request; the receiver blocks the IPC handler. When the dashboard sends a decision, the handler unblocks immediately. No polling, no sleep loops. |
| **120-second timeout** | Long enough for a human to notice and act. Short enough to not hold IPC connections indefinitely. Auto-deny on timeout is fail-secure. |
| **Broadcast channel for permission events** | Separate from the alert event bus (which carries `AlertEvent`). Permission events have different structure (`PermissionEvent`) and different semantics. The SSE endpoint merges both streams. |
| **Stream merging via `StreamExt::merge`** | Avoids requiring two separate SSE connections or a shared enum wrapper. The browser's `EventSource` can listen for different event names on the same connection. |
| **Alpine.js global store** | `Alpine.store('perms')` is accessible from any page because it's defined in `base.html`. The banner template is also in `base.html`. This means permission notifications appear on *every* page — overview, events, agents, policy, alerts — without duplicating code. |
| **`_tick` counter for countdown** | Alpine.js reactive system detects property reads. By reading `_tick` inside `remaining()`, the computed value re-evaluates every second when `_tick` changes. This drives the countdown without complex timer management. |
| **Dual data sources (fetch + SSE)** | SSE delivers real-time events but only after connection. HTTP fetch on `init()` catches pending requests from before the page loaded. Both are needed for a seamless experience. |
| **Banner + dedicated page** | Banner provides urgency (visible everywhere, impossible to miss). The `/requests` page provides history and audit trail. Both serve different needs. |
| **Exit code 1 on denial** | `guardian-ctl request-permission` exits with code 1 when denied. This allows shell scripts and agent wrappers to check `$?` and handle denials programmatically. |
| **Exec grant as config change** | Unlike file grants (BPF map entries), exec grants modify the in-memory agent config. This is because exec monitoring is log-only (not enforced in BPF). The config allow list is what determines the log message severity. |
| **Dashboard required for requests** | If the dashboard is disabled, permission requests are auto-denied with "Dashboard not enabled — no one to approve requests". This prevents agents from hanging indefinitely when no human interface exists. |
| **100-entry resolved history** | A bounded `VecDeque` prevents unbounded memory growth. Oldest entries are dropped first. For longer-term auditing, use the SQLite event store or external SIEM. |

---

## Comparison: Phase 5 → 6

| Feature | Phase 5 | Phase 6 |
|---------|---------|---------|
| **Permission model** | Static: pre-configured rules | Static **+ interactive: agents can ask** |
| **Agent communication** | One-way: daemon controls agent | **Two-way: agent can request, daemon responds** |
| **Approval workflow** | CLI: `guardian-ctl grant` | CLI **+ browser: real-time banner + one-click** |
| **Audit trail** | None for ad-hoc grants | **Full: who requested, why, decision, duration** |
| **Dashboard notifications** | None | **Real-time banners on all pages** |
| **SSE event types** | `event`, `lag` | `event`, `lag`, **`permission`** |
| **IPC protocol** | 4 request types | **6 request types** (+RequestPermission) |
| **IPC response types** | 3 response types | **4 response types** (+PermissionDecision) |
| **Dashboard pages** | 5 pages (overview, events, agents, policy, alerts) | **7 pages** (+requests, metrics) |
| **Grant types** | File access only | **File access + exec commands** |
| **Nav badge** | None | **Pending request count badge** |

---

## Testing

### Unit Tests

All 14 existing unit tests pass without modification:

```
running 14 tests
test config::tests::test_effective_identity_comm ... ok
test config::tests::test_effective_identity_cgroup ... ok
test config::tests::test_exact_match ... ok
test config::tests::test_exec_policy ... ok
test config::tests::test_pattern_to_policy_rule ... ok
test config::tests::test_policy_default_allow ... ok
test config::tests::test_policy_default_deny ... ok
test config::tests::test_policy_deny_takes_precedence ... ok
test config::tests::test_recursive_wildcard ... ok
test config::tests::test_single_level_wildcard ... ok
test tests::test_comm_to_key ... ok
test tests::test_decode_open_flags_rdwr_trunc ... ok
test tests::test_decode_open_flags_read_only ... ok
test tests::test_decode_open_flags_write_create ... ok

test result: ok. 14 passed; 0 failed; 0 ignored
```

### Build Verification

All three binaries compile cleanly:

```bash
cargo build --release -p guardian -p guardian-ctl -p guardian-launch
# Zero errors, zero warnings
```

### Manual Testing: Full Permission Request Flow

```bash
# Terminal 1: Start daemon with dashboard enabled
sudo RUST_LOG=info target/release/guardian --config config.toml

# Terminal 2: Open dashboard
xdg-open http://127.0.0.1:8080

# Terminal 3: Send a permission request
sudo target/release/guardian-ctl request-permission \
  --name test-agent \
  --resource-type exec \
  --path /usr/bin/curl \
  --justification "Need to download a file"
# Output: "Waiting for human approval via dashboard (up to 120s)..."
```

In the browser:
1. A yellow banner slides in at the top of the current page
2. Shows: "Permission Request from **test-agent** — Wants to EXEC `/usr/bin/curl`"
3. Justification text displayed below
4. Countdown timer ticking down from 120s
5. Duration selector (default 10 min) and Approve/Deny buttons
6. Click **Approve** — banner dismisses, toast shows "Permission #1 approved (600s grant)"

Back in Terminal 3:
```
APPROVED: Approved by user (granted for 600s)
```

### Testing Timeout

```bash
# Send request and don't approve
sudo target/release/guardian-ctl request-permission \
  --name test-agent --path /tmp/test -t file
# Wait 120 seconds...
# Output: "DENIED: Request timed out (no response within 120 seconds)"
# Exit code: 1
```

### Testing Dashboard-Disabled Scenario

```bash
# With [dashboard] enabled = false in config
sudo target/release/guardian-ctl request-permission \
  --name test-agent --path /usr/bin/curl
# Output: "Error: DENIED: Dashboard not enabled — no one to approve requests"
```

### Testing Requests Page

Navigate to `http://127.0.0.1:8080/requests`:
- Pending requests table shows active requests with live "Waiting" column
- Resolved history table shows approved/denied/timed-out requests with timestamps
- Actions column has approve/deny buttons that work independently of the banner

---

## Security Considerations

### Permission Request Attack Surface

1. **Any process with socket access can request permissions.** The `guardian-ctl request-permission` command connects to the daemon's Unix socket. Any process that can reach `/run/guardian.sock` can send permission requests. Mitigate by restricting socket permissions (`chmod 660`, owner root:guardian-group).

2. **Social engineering via justification text.** A malicious agent could craft convincing justification text to trick humans into approving dangerous access. The dashboard shows the exact resource path — operators should verify the path, not just the justification.

3. **Timing attacks.** An agent could send many requests in rapid succession, hoping the human approves without careful review. The 120-second timeout and per-request approval buttons mitigate this, but operators should review each request individually.

4. **Auto-deny is fail-secure.** If no human responds within 120 seconds, the request is automatically denied. This prevents agents from gaining access by waiting indefinitely.

5. **Dashboard required.** Permission requests are auto-denied when the dashboard is disabled. An agent cannot circumvent this by requesting permissions when no human interface exists.

### Audit Trail

All permission requests are recorded in the resolved history:
- Who requested (agent name)
- What was requested (resource type + path)
- Why (justification text)
- Decision (approved/denied/timed out)
- Duration (if approved)
- Timestamps (requested at, resolved at)

The history is kept in memory (last 100 entries). For persistent auditing, forward events to an external SIEM via the webhook or JSON log alerting outputs.

---

## Known Limitations

| Limitation | Impact | Workaround |
|-----------|--------|------------|
| **120s fixed timeout** | Cannot configure per-request or per-agent timeouts | Sufficient for interactive approval; change `PERMISSION_TIMEOUT_SECS` constant and rebuild |
| **In-memory audit trail only** | Resolved history lost on daemon restart (max 100 entries) | Use webhook/JSON log for persistent audit trail |
| **No request deduplication** | Agent can send the same request multiple times | Each gets a unique ID; human can deny duplicates |
| **No auto-approve rules** | Cannot pre-approve certain request patterns automatically | Use static policy rules for known-safe patterns |
| **Banner requires open browser** | If no dashboard tab is open, the request times out | Keep a dashboard tab open; consider browser notifications in a future phase |
| **Single approver** | No multi-party approval or quorum requirements | Suitable for single-operator setups; enterprise features in a future phase |
| **No request cancellation** | Agent cannot cancel a pending request | Request times out after 120s; denied requests have no negative side effects |
| **Exec grants are config-level** | Exec grant modifies config allow list, not BPF maps | Exec monitoring is log-only; config-level grant changes log severity |
