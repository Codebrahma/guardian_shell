# Phase 5 Implementation: Dashboard & UI

## What Phase 5 Solves

Phase 4 gave us structured logging, webhooks, Slack, email, and Prometheus metrics. But managing Guardian Shell still required SSH access, editing TOML files, and reading raw logs:

**Problem 1: No visual overview.** There's no at-a-glance view of system status — how many agents are active, how many events have fired, what's been blocked. You had to run `guardian-ctl list` and query Prometheus manually.

**Problem 2: No real-time event visibility.** Watching events required tailing log files or stderr. There was no way to filter events by severity, agent, or action without `grep`. Incident response meant scrolling through walls of text.

**Problem 3: Policy editing is error-prone.** Editing TOML files by hand is tedious and error-prone. One misplaced quote breaks the config. There's no immediate feedback on what rules are active for each agent.

**Problem 4: Agent management requires CLI.** Stopping an agent or granting temporary access required `guardian-ctl` over SSH. There was no web-based management interface for teams.

**Problem 5: Alert configuration is static.** Changing webhook URLs, enabling Slack, or adjusting severity thresholds required editing the config file and restarting the daemon.

Phase 5 solves all five by embedding a web dashboard directly into the guardian binary: real-time SSE event streaming, visual policy editing, agent management, alert configuration — all from a browser.

---

## What Was Built

### New Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `guardian/src/dashboard/mod.rs` | 84 | Axum router, static file handler via rust-embed, server startup |
| `guardian/src/dashboard/state.rs` | 16 | `DashboardState` struct: shared refs to IPC state, alert sender, event bus, SQLite DB |
| `guardian/src/dashboard/db.rs` | 200 | SQLite event store: schema, insert, query with filters, pagination, pruning |
| `guardian/src/dashboard/routes/mod.rs` | 3 | Route sub-module declarations |
| `guardian/src/dashboard/routes/pages.rs` | 188 | Full page handlers with askama template rendering for all 5 pages |
| `guardian/src/dashboard/routes/api.rs` | 420 | API handlers: stop/grant agents, policy CRUD, alert config, config reload, Prometheus, event query |
| `guardian/src/dashboard/routes/sse.rs` | 35 | Resilient SSE endpoint with lag event forwarding via tokio broadcast channel |
| `guardian/askama.toml` | 2 | Askama template directory configuration |
| `guardian/templates/base.html` | 62 | Base layout: sidebar navigation, TailwindCSS/htmx/Alpine.js CDN links, toast area |
| `guardian/templates/index.html` | 105 | Overview page: auto-refreshing status cards + SSE recent events with reconnection |
| `guardian/templates/events.html` | 200 | Events page: Live + History tabs, SSE with reconnection, SQLite-backed history with pagination |
| `guardian/templates/agents.html` | 95 | Agent management: configured agents table + active cgroup agents with stop/grant |
| `guardian/templates/policy.html` | 82 | Policy editor: accordion per agent, editable allow/deny/exec rules |
| `guardian/templates/alerts.html` | 100 | Alert config: global settings + per-output toggle and field editing |
| `guardian/static/app.js` | 45 | Custom JavaScript for SSE event rendering (index page) |
| `guardian/static/app.css` | 2 | Custom CSS placeholder (TailwindCSS handles most styling) |

### Modified Source Files

| File | What Changed |
|------|-------------|
| `guardian/Cargo.toml` | Added `axum` 0.8, `askama` 0.12, `askama_axum` 0.4, `rust-embed` 8, `tower` 0.5, `tower-http` 0.6, `tokio-stream` 0.1, `rusqlite` 0.31 (bundled) |
| `guardian/src/main.rs` | Added `mod dashboard`, created `broadcast::channel` for SSE, spawned dashboard tokio task, spawned DB writer task and daily pruning task, added dashboard handle to shutdown cleanup |
| `guardian/src/config.rs` | Added `DashboardConfig` struct with `enabled`, `listen_address`, and `db_path` fields. Added `dashboard` field to `Config`. |
| `guardian/src/alerting/mod.rs` | Extended `AlertSender` with `event_bus: Option<broadcast::Sender<AlertEvent>>`, added `with_event_bus()` builder method. `send()` now broadcasts to SSE clients before queuing to AlertManager. |
| `guardian/src/ipc.rs` | Added public wrapper functions (`cleanup_agent_pub`, `path_to_lpm_key_pub`, `path_to_map_key_pub`) for dashboard API access |
| `config.toml` | Added `[dashboard]` section with `enabled = true` and `listen_address` |
| `configs/development.toml` | Added `[dashboard]` section |
| `CLAUDE.md` | Updated to Phase 5 with new file structure, design decisions, dependencies, limitations |

---

## Architecture

### System Overview

```
                         USER SPACE
 ┌──────────────────────────────────────────────────────────────────┐
 │                                                                  │
 │   guardian-launch                    Guardian Daemon              │
 │   ┌────────────────┐     IPC        ┌──────────────────────┐    │
 │   │ Create cgroup   ├──────────────>│ Unix socket listener │    │
 │   │ Set limits      │  register     │ /run/guardian.sock    │    │
 │   │ Register        │<─────────────┤                      │    │
 │   │ exec(agent)     │   ACK        │ Populates BPF maps   │    │
 │   └────────────────┘              │ Background tasks     │    │
 │                                    └──────────┬───────────┘    │
 │                                                │                │
 │   Alerting Subsystem (Phase 4):                │                │
 │   ┌──────────────────────────────────────┐     │                │
 │   │ Event Processors  ──► AlertSender    │     │                │
 │   │   ├► Prometheus counters (sync)      │     │                │
 │   │   ├► broadcast::channel ──► SSE ─────┼─────┼─► Browser      │
 │   │   └► mpsc channel ──► AlertManager   │     │                │
 │   │        ├► JSON Log  ├► Webhook       │     │                │
 │   │        ├► Slack     └► Email         │     │                │
 │   └──────────────────────────────────────┘     │                │
 │                                                │                │
 │   Dashboard (Phase 5):                         │                │
 │   ┌──────────────────────────────────────┐     │                │
 │   │ axum HTTP server (:8080)             │     │                │
 │   │   ├► GET /           Overview page   │     │                │
 │   │   ├► GET /events     Live SSE feed   │     │                │
 │   │   ├► GET /agents     Agent mgmt      │     │                │
 │   │   ├► GET /policy     Policy editor   │     │                │
 │   │   ├► GET /alerts     Alert config    │     │                │
 │   │   ├► GET /metrics    Prometheus      │     │                │
 │   │   ├► GET /events/stream  SSE endpoint│     │                │
 │   │   ├► POST /api/agents/*/stop         │     │                │
 │   │   ├► POST /api/agents/*/grant        │     │                │
 │   │   ├► PUT  /api/policy/*              │     │                │
 │   │   ├► PUT  /api/alerts                │     │                │
 │   │   ├► POST /api/config/reload         │     │                │
 │   │   └► GET  /api/status    (htmx poll) │     │                │
 │   │                                      │     │                │
 │   │ State: Arc<DashboardState>           │     │                │
 │   │   ├► ipc_state (SharedIpcState)      │     │                │
 │   │   ├► alert_sender (AlertSender)      │     │                │
 │   │   ├► event_bus (broadcast::Sender)   │     │                │
 │   │   ├► config_path (PathBuf)           │     │                │
 │   │   └► db (Arc<EventDb>)              │     │                │
 │   └──────────────────────────────────────┘     │                │
 │                                                │                │
 │   SQLite Event Store:                          │                │
 │   ┌──────────────────────────────────────┐     │                │
 │   │ /var/lib/guardian/events.db          │     │                │
 │   │   ├► events table (all fields)      │     │                │
 │   │   ├► Indexes: timestamp, severity,  │     │                │
 │   │   │  agent_name, action             │     │                │
 │   │   ├► WAL mode (concurrent R/W)      │     │                │
 │   │   └► Auto-prune after 30 days       │     │                │
 │   └──────────────────────────────────────┘     │                │
 │                                                │                │
 ├════════════════════════════════════════════════╪════════════════┤
 │                        KERNEL SPACE            │                │
 │   eBPF Programs (unchanged from Phase 4)       │                │
 └──────────────────────────────────────────────────────────────────┘
```

### Event Flow for SSE

```
eBPF event  →  per-CPU perf reader  →  process_file_event()
                                           │
                                           ├─► AlertSender.send()
                                           │     │
                                           │     ├─► Prometheus counter (atomic)
                                           │     ├─► broadcast::channel
                                           │     │         │
                                           │     │         ├─► SSE subscribers (/events/stream)
                                           │     │         │     │
                                           │     │         │     └─► EventSource (browser)
                                           │     │         │           ├─► Overview recent events
                                           │     │         │           └─► Live events tab
                                           │     │         │
                                           │     │         ├─► DB writer task ──► SQLite
                                           │     │         │     └─► events table (persistent)
                                           │     │         │           └─► /api/events (history queries)
                                           │     │         │                 └─► History tab (browser)
                                           │     │         │
                                           │     │         └─► (lagged clients receive "lag" SSE event)
                                           │     │
                                           │     └─► mpsc channel  ──► AlertManager
                                           │           └─► JSON/webhook/Slack/email
                                           │
                                           └─► env_logger (stderr, unchanged)
```

### Why This Architecture

**Embedded server, not standalone.** The dashboard runs inside the guardian daemon as a tokio task — no separate process, no separate binary, no IPC overhead. It shares the same `SharedIpcState` that the IPC server uses, and the same `AlertSender` metrics that event processors use.

**Broadcast channel for fan-out.** `tokio::sync::broadcast` is designed for multi-consumer scenarios. Each SSE client subscribes and gets its own receiver. A dedicated DB writer task also subscribes, persisting every event to SQLite. If a client falls behind, the `BroadcastStream` adapter handles the `Lagged` error by sending a `"lag"` SSE event to the client — no backpressure, no blocking of event producers, and the client knows events were missed.

**SQLite for event persistence.** All events are stored in a local SQLite database (WAL mode for concurrent reads/writes). This enables historical queries via the `/api/events` endpoint and the History tab. A background pruning task removes events older than 30 days to prevent unbounded growth. The `rusqlite` crate with the `bundled` feature compiles SQLite from source — no system library dependency.

**Server-rendered HTML with htmx.** Full pages are rendered server-side by askama templates. Interactive updates (status cards, agent stop, policy save) use htmx for partial page swaps. This avoids a separate JavaScript build process, npm, webpack, or any Node.js tooling. The entire frontend is `<30KB` of CDN-loaded libraries.

**Alpine.js for client-side filtering.** The live events page uses Alpine.js `x-data` components for local filtering by severity and action. Events arrive via `EventSource` (native browser SSE) and are prepended to the table. No events are re-fetched from the server — filtering is purely client-side on the buffered event list.

**rust-embed for single binary.** Static files (`app.js`, `app.css`) are embedded into the binary at compile time. The binary is completely self-contained — no external file dependencies, no `static/` directory to deploy alongside.

---

## Dashboard Pages: Detail

### 1. Overview (`/`)

The landing page provides a quick system health snapshot.

**Status Cards** (auto-refresh every 5 seconds via `hx-get="/api/status" hx-trigger="every 5s"`):
- **Mode**: `enforce` (red badge) or `monitor` (blue badge)
- **Configured Agents**: Total count with active cgroup sub-count
- **File Events**: Total file access events from Prometheus counter
- **Blocked**: Total blocked events (enforce mode) in red

**Recent Events** (SSE via Alpine.js `EventSource` with auto-reconnection):
- Last 50 events, most recent first
- Color-coded severity and action columns
- Auto-updates as events arrive — no polling, no page refresh
- Green/red "Live" / "Reconnecting..." connection status indicator
- Automatic reconnection with exponential backoff on disconnect

### 2. Events (`/events`)

Dual-mode event viewer with **Live** and **History** tabs.

#### Live Tab
Real-time event feed via SSE with resilient reconnection.

**Features:**
- SSE connection to `/events/stream` with automatic reconnection (exponential backoff, 1s → 30s max)
- Green/red connection status indicator ("Connected" / "Reconnecting...")
- Missed-events counter (shown when broadcast channel lag occurs)
- Alpine.js-driven severity filter dropdown (All / Info / Warning / Critical)
- Action filter dropdown (All / Allow / Deny / Blocked)
- Clear button to reset the event list
- Event counter showing total buffered events
- Scrollable table with 500-event client-side buffer
- Full event details: timestamp (ms precision), severity, agent, type, action, PID, comm, path, access mode

**Client-side filtering:** Events are stored in an Alpine.js reactive array. Filters use computed properties — filtering is instant with no server round-trip.

**Reconnection logic:** The `EventSource` has `onopen`, `onerror`, and `lag` event handlers. On disconnect, the connection is closed and a reconnect is scheduled with exponential backoff (capped at 30s). On successful reconnect, the backoff resets to 1s.

#### History Tab
SQLite-backed event history with server-side filtering and pagination.

**Features:**
- Search form: agent name, path contains, event type dropdown
- Server-side filtering via `GET /api/events` query parameters
- Pagination with Previous/Next buttons, showing "X-Y of Z"
- Same table layout as Live tab for visual consistency
- Severity and action filters shared with Live tab (applied both client-side and server-side)

### 3. Agents (`/agents`)

Two-section agent management interface.

**Configured Agents** (read-only table):
- Name, identity type (comm/cgroup badge), default action, allow/deny rule counts, exec policy status
- Shows all agents from `config.toml`, not just active ones

**Active Cgroup Agents** (interactive):
- Name, cgroup path, cgroup ID, process count, uptime
- **Stop** button: `hx-post` with confirmation dialog, sends SIGTERM to all cgroup processes
- **Grant** button: Alpine.js popover form with path input and duration selector, `hx-post` to `/api/agents/{name}/grant`

### 4. Policy Editor (`/policy`)

Accordion-based per-agent policy editor.

**Per agent section:**
- Collapsible panel (first agent open by default)
- Agent name with identity badge and current default action
- Two-column layout: File Access Policy (left) and Exec Policy (right)
- **File Access**: default action dropdown, allow rules textarea (one per line), deny rules textarea
- **Exec Policy**: default action dropdown, allow/deny rules textareas (if configured)
- **Save** button per agent: `hx-put="/api/policy/{name}"` — updates in-memory config, writes TOML to disk

**Config write-back:** The API handler modifies the `Config` in `IpcState`, then serializes the entire config to TOML using a manual serializer (not `serde_toml`) to maintain readable formatting. The file is written to the original config path.

### 5. Alert Configuration (`/alerts`)

Form-based alerting output editor.

**Global Settings:**
- Min severity dropdown (info / warning / critical)
- Dedup window seconds (numeric input)
- Rate limit per minute (numeric input)

**Output Channels** (grid of cards, each with enable toggle):
- **JSON Log**: path input
- **Webhook**: URL input
- **Slack**: webhook URL input
- **Email**: SMTP host input
- **Prometheus**: listen address input

**Save** button: `hx-put="/api/alerts"` — updates alerting config in memory and writes to disk. Note: alerting output changes require daemon restart to take effect (the `AlertManager` is initialized once at startup).

---

## SSE Implementation Detail

### Server Side (`dashboard/routes/sse.rs`)

The SSE stream uses `map` (not `filter_map`) so that broadcast lag errors become real SSE events instead of being silently dropped. This prevents the stream from appearing frozen when the client falls behind.

```rust
pub async fn event_stream(
    State(state): State<Arc<DashboardState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.event_bus.subscribe();
    let stream = BroadcastStream::new(rx).map(|result| match result {
        Ok(event) => {
            let json = serde_json::to_string(&event).unwrap_or_default();
            Ok(Event::default().event("event").data(json))
        }
        Err(BroadcastStreamRecvError::Lagged(n)) => {
            // BroadcastStream internally resubscribes after lag.
            // Send a "lag" event so the client knows events were missed.
            let msg = format!("{{\"missed\": {}}}", n);
            Ok(Event::default().event("lag").data(msg))
        }
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(5))
            .text("heartbeat"),
    )
}
```

**Key fix:** The previous implementation used `filter_map` which mapped lag errors to `None` (silently skipping them). While `BroadcastStream` internally resubscribes after a `Lagged` error, if many lags happened in succession the client would see no data, appearing frozen. By using `map` and converting lags to actual `"lag"` SSE events, the stream stays active and the client is informed.

### Client Side (Alpine.js `EventSource` with Reconnection)

```javascript
connect() {
    if (this.sse) { this.sse.close(); this.sse = null; }
    this.sse = new EventSource('/events/stream');

    this.sse.onopen = () => {
        this.connected = true;
        this.retryDelay = 1000;  // Reset backoff on success
    };

    this.sse.addEventListener('event', (e) => {
        const data = JSON.parse(e.data);
        data.id = this.nextId++;
        this.events.unshift(data);
        if (this.events.length > 500) this.events.pop();
    });

    this.sse.addEventListener('lag', (e) => {
        const data = JSON.parse(e.data);
        this.missedEvents += data.missed;
    });

    this.sse.onerror = () => {
        this.connected = false;
        this.sse.close(); this.sse = null;
        // Exponential backoff: 1s → 2s → 4s → ... → 30s max
        const delay = Math.min(this.retryDelay, 30000);
        this.retryDelay = Math.min(this.retryDelay * 2, 30000);
        setTimeout(() => this.connect(), delay);
    };
}
```

**Reconnection strategy:** The native `EventSource` has built-in reconnection, but it is unreliable across browsers and doesn't support backoff. Our implementation closes the connection on error and manually reconnects with exponential backoff (1s doubling up to 30s max). The UI shows a red "Reconnecting..." indicator during disconnection.

### SSE Protocol

The SSE stream sends two event types:

```
event: event
data: {"timestamp":"2026-03-10T14:30:00Z","severity":"critical",...}

event: lag
data: {"missed": 42}

:heartbeat

event: event
data: {"timestamp":"2026-03-10T14:30:01Z","severity":"info",...}
```

- **`event`**: Normal alert event, full `AlertEvent` as JSON
- **`lag`**: Broadcast channel overflow notification, tells client how many events were missed
- **`:heartbeat`**: SSE comment sent every 5 seconds to keep the connection alive through proxies

---

## API Endpoints

### Page Routes

| Method | Path | Description | Response |
|--------|------|-------------|----------|
| GET | `/` | Dashboard overview | Full HTML page |
| GET | `/events` | Live event feed | Full HTML page |
| GET | `/agents` | Agent management | Full HTML page |
| GET | `/policy` | Policy editor | Full HTML page |
| GET | `/alerts` | Alert configuration | Full HTML page |

### API Routes (htmx targets)

| Method | Path | Parameters | Description | Response |
|--------|------|-----------|-------------|----------|
| GET | `/api/status` | — | Status summary cards | HTML partial (4 cards) |
| POST | `/api/agents/{name}/stop` | — | Stop cgroup agent | HTML partial (stopped row) |
| POST | `/api/agents/{name}/grant` | `path`, `duration` (form) | Grant temp access | HTML partial (toast) |
| PUT | `/api/policy/{agent_name}` | `default_action`, `allow_rules`, `deny_rules`, `exec_*` (form) | Update agent policy | HTML partial (toast) |
| PUT | `/api/alerts` | `min_severity`, `dedup_*`, `rate_*`, output fields (form) | Update alerting config | HTML partial (toast) |
| POST | `/api/config/reload` | — | Reload config from disk | HTML partial (toast) |
| GET | `/metrics` | — | Prometheus metrics | `text/plain` (Prometheus format) |

### JSON API Routes

| Method | Path | Parameters | Description | Response |
|--------|------|-----------|-------------|----------|
| GET | `/api/events` | `severity`, `action`, `agent_name`, `event_type`, `path_contains`, `limit`, `offset` (query) | Query historical events from SQLite | JSON: `{ events: [...], total, limit, offset }` |

### SSE Route

| Method | Path | Description | Protocol |
|--------|------|-------------|----------|
| GET | `/events/stream` | Live event stream | SSE (`text/event-stream`) |

### Static Files

| Method | Path | Description |
|--------|------|-------------|
| GET | `/static/{*path}` | Embedded static files (app.js, app.css) |

---

## Config Write-Back

When the dashboard saves policy or alert changes, it writes the full config back to disk as valid TOML. The serialization is done manually (not via `serde::Serialize`) to produce readable, well-formatted output.

### Write-Back Process

1. **User saves** policy or alerts via dashboard form
2. **API handler** modifies `IpcState.config` in memory (under Mutex lock)
3. **Serializer** converts the full `Config` struct to TOML string with proper formatting:
   - `[global]` section with all fields
   - `[dashboard]` section if present
   - `[alerting]` section with sub-tables
   - `[[agents]]` array entries with `[agents.file_access]`, `[agents.exec_policy]`, `[agents.resources]`
4. **Write** to the original config file path stored in `DashboardState.config_path`
5. **Response** includes toast notification with success/failure message

### Limitations of Write-Back

- **Comments are lost.** The original TOML comments are not preserved. The output is clean, machine-generated TOML.
- **Policy changes don't update BPF maps.** File access rules that are enforced in-kernel via BPF maps are populated at daemon startup. Dashboard edits update the userspace config (affecting monitor-mode decisions) and disk. To apply changes to kernel enforcement, use "Reload Config" or restart the daemon.
- **Alerting output changes require restart.** The `AlertManager` and its output connections (webhook client, SMTP transport) are initialized once at startup. Changing URLs or credentials via the dashboard saves to disk but requires a daemon restart to take effect.

---

## SQLite Event Store

### Overview

All alert events are persisted to a local SQLite database, enabling historical queries, audit trails, and the History tab on the events page. The database is created automatically on first startup.

### Schema

```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,         -- ISO 8601 (RFC 3339)
    severity TEXT NOT NULL,          -- "info", "warning", "critical"
    event_type TEXT NOT NULL,        -- "file_access", "exec_attempt"
    action TEXT NOT NULL,            -- "allow", "deny", "blocked"
    agent_name TEXT NOT NULL,
    pid INTEGER NOT NULL,
    comm TEXT NOT NULL,
    path TEXT NOT NULL,
    access_mode TEXT NOT NULL DEFAULT '',
    identity_method TEXT NOT NULL DEFAULT '',
    policy_mode TEXT NOT NULL DEFAULT ''
);

-- Indexes for common query patterns
CREATE INDEX idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX idx_events_severity ON events(severity);
CREATE INDEX idx_events_agent ON events(agent_name);
CREATE INDEX idx_events_action ON events(action);
```

### Configuration

```toml
[dashboard]
enabled = true
listen_address = "127.0.0.1:8080"
db_path = "/var/lib/guardian/events.db"    # Optional, this is the default
```

### Data Flow

1. **eBPF event** arrives via perf buffer → `process_file_event()` → `AlertSender.send()`
2. **Broadcast channel** fans out to all subscribers (SSE clients + DB writer)
3. **DB writer task** (dedicated tokio task) receives events and calls `EventDb::insert_event()`
4. **SQLite** stores the event with WAL mode (concurrent reads during writes)
5. **History queries** via `GET /api/events` call `EventDb::query_events()` with filters
6. **Daily pruning** task calls `EventDb::prune_old_events(30)` to remove events older than 30 days

### Query API

`GET /api/events` accepts these query parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `severity` | string | Filter by severity: `info`, `warning`, `critical` |
| `action` | string | Filter by action: `allow`, `deny`, `blocked` |
| `agent_name` | string | Filter by exact agent name |
| `event_type` | string | Filter by type: `file_access`, `exec_attempt` |
| `path_contains` | string | Substring match on path (SQL `LIKE %...%`) |
| `limit` | u32 | Max results (default: 100, max: 1000) |
| `offset` | u32 | Skip N results for pagination |

**Response:**

```json
{
  "events": [
    {
      "id": 42,
      "timestamp": "2026-03-10T14:30:00+00:00",
      "severity": "critical",
      "event_type": "file_access",
      "action": "blocked",
      "agent_name": "claude-code",
      "pid": 12345,
      "comm": "cat",
      "path": "/etc/shadow",
      "access_mode": "READ",
      "identity_method": "cgroup",
      "policy_mode": "enforce"
    }
  ],
  "total": 1847,
  "limit": 100,
  "offset": 0
}
```

### Performance Considerations

- **WAL mode** enables concurrent readers during writes — the DB writer never blocks API queries
- **`std::sync::Mutex`** (not `tokio::Mutex`) wraps the connection because all operations are sub-millisecond
- **Indexed columns** (timestamp, severity, agent, action) ensure fast filtered queries
- **Single-row inserts** are adequate for typical event rates (hundreds/sec). For higher throughput, batch inserts could be added
- **30-day retention** with automatic pruning prevents unbounded disk growth

---

## Frontend Technology Stack

### Libraries (CDN-loaded)

| Library | Version | Size | Purpose |
|---------|---------|------|---------|
| TailwindCSS | 2.2.19 | 16KB (gzip) | Utility-first CSS framework |
| htmx | 2.0.4 | 14KB (gzip) | HTML-over-the-wire for partial page updates |
| htmx SSE extension | 2.2.2 | 2KB | SSE integration for htmx (available for future use) |
| Alpine.js | 3.14.8 | 8KB (gzip) | Lightweight reactive JavaScript |

**Total frontend size: ~40KB** (gzipped, CDN-cached after first load)

### Why These Libraries

| Decision | Rationale |
|----------|-----------|
| **TailwindCSS via CDN** | No build step. Utility classes work directly in templates. CDN is cached globally. |
| **htmx** | Server-rendered HTML fragments with AJAX-like behavior. No client-side routing, no virtual DOM, no state management complexity. |
| **Alpine.js** | "jQuery for the modern web." Reactive `x-data` components inline in HTML. Perfect for client-side filtering and toggle state. |
| **No React/Vue/Svelte** | A full SPA framework would require Node.js, webpack/vite, npm, and a build pipeline. This is a security tool — build simplicity matters. |
| **No bundling** | CDN is faster than embedding minified JS (cache shared across sites). For air-gapped deployments, replace CDN URLs with local copies via rust-embed. |

### Template Engine: askama

Askama is a compile-time template engine for Rust, inspired by Jinja2.

**Key features used:**
- Template inheritance (`{% extends "base.html" %}`)
- Named blocks (`{% block content %}`)
- Variable interpolation (`{{ agent.name }}`)
- Loops (`{% for agent in agents %}`)
- Conditionals (`{% if agent.has_exec_policy %}`)
- Method calls in templates (`{% if agent.exec_default.is_some() %}`)

**Compile-time safety:** Template variables are checked against Rust struct fields at compile time. If a template references `{{ foo.bar }}` and the struct doesn't have a `bar` field, the build fails. This eliminates an entire class of runtime template errors.

---

## Dependencies Added

| Crate | Version | Features | Purpose |
|-------|---------|----------|---------|
| `axum` | 0.8 | `macros` | HTTP framework with native tokio integration |
| `askama` | 0.12 | — | Compile-time Jinja2-like template engine |
| `askama_axum` | 0.4 | — | `IntoResponse` impl for askama templates |
| `rust-embed` | 8 | — | Embed static files into the binary at compile time |
| `tower` | 0.5 | — | Service trait (required by axum) |
| `tower-http` | 0.6 | `cors` | CORS middleware for dashboard |
| `tokio-stream` | 0.1 | `sync` | `BroadcastStream` adapter for SSE |
| `rusqlite` | 0.31 | `bundled` | Embedded SQLite database for event persistence |

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Embedded dashboard** | Single binary deployment. No separate process, no reverse proxy required. The daemon itself serves the dashboard. |
| **axum over warp/actix** | Axum is built on top of tokio (already a dependency). It has first-class SSE support via `axum::response::Sse`. The `0.8` version has a clean extractor-based API. |
| **askama over tera/handlebars** | Compile-time checking catches template errors at build time. Zero-allocation rendering. Jinja2-like syntax is familiar to most developers. |
| **CDN for frontend libraries** | Avoids 200MB+ of node_modules. No npm, no webpack, no build pipeline for JavaScript. Guardian Shell is a security tool — keeping the build simple reduces supply chain risk. |
| **rust-embed for static files** | Embeds files at compile time. The binary is fully self-contained — `scp` it to any machine and it works. No `static/` directory to manage. |
| **broadcast channel for SSE** | `tokio::sync::broadcast` is designed for multi-consumer fan-out. The `BroadcastStream` adapter handles lagged clients by sending `"lag"` SSE events (not silently dropping). |
| **SQLite for event persistence** | Embedded database with zero external dependencies (`bundled` feature). WAL mode enables concurrent reads during writes. `std::sync::Mutex` wrapping is safe because all DB operations are sub-millisecond. |
| **Dedicated DB writer task** | A separate tokio task subscribes to the broadcast channel and writes events to SQLite. This decouples persistence from the event hot path — DB latency never affects SSE or alerting. |
| **Exponential backoff reconnection** | Client-side `EventSource` reconnection uses 1s → 2s → 4s → ... → 30s backoff. Prevents thundering herd on server restart. Resets on successful connect. |
| **`map` over `filter_map` for SSE lag** | Using `map` converts lag errors into real `"lag"` SSE events. The previous `filter_map` approach silently dropped them as `None`, making the stream appear frozen under load. |
| **30-day event retention** | Background pruning task runs daily, deleting events older than 30 days. Prevents unbounded disk growth while keeping useful audit history. |
| **No authentication** | The dashboard listens on localhost by default. For remote access, use a reverse proxy (nginx, caddy) with authentication. Adding auth to the daemon itself would add complexity without solving the common case. |
| **Manual TOML serializer** | `toml::to_string` (via serde) produces valid but ugly TOML — arrays on single lines, no comments, inconsistent formatting. The manual serializer produces human-readable output with proper indentation and array formatting. |
| **htmx for partial updates** | Status cards auto-refresh via `hx-trigger="every 5s"`. Agent stop/grant actions swap single table rows. No full page reloads except navigation. |
| **Alpine.js for event filtering** | Client-side filtering is instant — no server round-trip. The event buffer (500 items) is filtered via Alpine.js computed properties. Perfect for the "show only critical" use case. |
| **Dashboard behind `enabled` flag** | Zero overhead when disabled. No axum server spawned. No broadcast channel fan-out. The `event_bus` field on `AlertSender` is `Option<broadcast::Sender>`. |
| **Prometheus on dashboard port** | When the dashboard is enabled, `/metrics` is served on the same port (8080). This eliminates the need for a separate Prometheus TCP server on port 9090. Both can coexist — the dashboard serves `/metrics` in addition to the existing standalone server. |

---

## Research Findings Applied

This implementation was informed by analysis of several open-source security and observability dashboards:

| Pattern | Source Project | How We Applied It |
|---------|---------------|-------------------|
| Server-rendered HTML + htmx | FleetDM (osquery management) | Full pages rendered by askama, partial updates via htmx |
| SSE for real-time events | Hubble UI (Cilium), Grafana Live | `EventSource` + Alpine.js for event streaming, no WebSocket complexity |
| Sidebar navigation | Wazuh Dashboard, Grafana | Fixed sidebar with section links, active state highlighting |
| Accordion policy editor | FleetDM query editor | Collapsible per-agent sections with save-per-section |
| Status cards with auto-refresh | Grafana stat panels | htmx polling every 5s for mode/agent/event/blocked counts |
| Single binary deployment | Tetragon, Vector | rust-embed + askama compiled-in templates, zero external dependencies |
| CDN for frontend frameworks | Many admin dashboards | TailwindCSS + htmx + Alpine.js loaded from CDN, ~40KB total |
| Toast notifications for actions | Modern SPA patterns | htmx `hx-target="#toast"` for action feedback |

---

## Comparison: Phase 1 → 5

| Feature | Phase 1 | Phase 2 | Phase 3 | Phase 4 | Phase 5 |
|---------|---------|---------|---------|---------|---------|
| **Output** | stderr | stderr | stderr | JSON + webhook + Slack + email | **+ Web dashboard** |
| **Metrics** | None | None | None | Prometheus | Prometheus **+ dashboard cards** |
| **Event persistence** | None | None | None | JSON log file | **SQLite database** |
| **Real-time view** | `tail -f` stderr | `tail -f` stderr | `tail -f` stderr | `jq` on JSON log | **SSE event stream + History tab** |
| **Agent management** | Edit config | Edit config | `guardian-ctl` CLI | `guardian-ctl` CLI | **+ Web UI stop/grant** |
| **Policy editing** | Edit TOML | Edit TOML | Edit TOML | Edit TOML + `--validate-config` | **+ Visual editor** |
| **Alert config** | N/A | N/A | N/A | Edit TOML | **+ Web form** |
| **Config reload** | Restart daemon | Restart daemon | Restart daemon | SIGHUP | SIGHUP **+ dashboard button** |
| **Enforcement** | Monitor only | Kernel blocks | Kernel blocks | Kernel blocks | Kernel blocks |
| **Identity** | Comm name | Comm + TGID | Cgroup (unspoofable) | Cgroup | Cgroup |
| **Resource limits** | None | None | Memory/CPU/PIDs | Memory/CPU/PIDs | Memory/CPU/PIDs |

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

### Config Validation

All 5 config files pass `--validate-config`:

```bash
$ for f in config.toml configs/*.toml; do
    echo "=== $f ==="
    target/release/guardian --config "$f" --validate-config 2>&1 | grep -E "valid|enabled"
  done

=== config.toml ===
Configuration is valid.
  JSON log: enabled
  Prometheus: enabled

=== configs/development.toml ===
Configuration is valid.
  JSON log: enabled
  Prometheus: enabled

=== configs/minimal.toml ===
Configuration is valid.
Alerting: not configured

=== configs/recommended.toml ===
Configuration is valid.
  JSON log: enabled
  Prometheus: enabled

=== configs/strict.toml ===
Configuration is valid.
  JSON log: enabled
  Prometheus: enabled
```

### Build Verification

Both debug and release builds compile cleanly:

```bash
cargo build --package guardian            # debug: OK
cargo build --package guardian --release  # release: OK
```

Zero warnings.

### Manual Dashboard Testing

To test the dashboard manually:

```bash
# Terminal 1: Start the daemon (requires root for eBPF)
sudo RUST_LOG=info target/release/guardian --config config.toml

# Terminal 2: Open the dashboard
xdg-open http://127.0.0.1:8080

# Terminal 3: Generate events (trigger file access)
cat /tmp/test.txt          # Should show as ALLOW
cat /etc/shadow            # Should show as DENY/BLOCKED
```

The dashboard should show:
- Status cards with mode, agent count, event counts
- Recent events appearing in real-time via SSE with green "Live" indicator
- Navigation to all pages
- Functional policy editor and alert configuration forms

**Testing SSE resilience:**
1. Open the Events page → Live tab should show green "Connected"
2. Restart the daemon → UI should show red "Reconnecting..." then auto-reconnect
3. Generate many events rapidly → any lag shows "(N missed)" counter
4. Switch to History tab → events from SQLite should appear with pagination

**Testing History queries:**
```bash
# Query all events (JSON API)
curl http://127.0.0.1:8080/api/events

# Filter by severity
curl "http://127.0.0.1:8080/api/events?severity=critical&limit=10"

# Search by path
curl "http://127.0.0.1:8080/api/events?path_contains=/etc&action=blocked"
```

---

## Security Considerations

### Dashboard Access

The dashboard listens on `127.0.0.1:8080` by default — **localhost only**. This is intentional:

1. **No authentication.** The dashboard provides full control over agent policies and can stop agents. It should not be exposed to untrusted networks without authentication.
2. **Config file writes.** The dashboard can write to the config file. An attacker with dashboard access could weaken security policies.
3. **Agent management.** The stop/grant actions directly affect running agents.

**For remote access**, use a reverse proxy with authentication:

```nginx
# nginx reverse proxy with basic auth
server {
    listen 443 ssl;
    server_name guardian.internal;

    auth_basic "Guardian Shell";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;

        # SSE requires these headers
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        chunked_transfer_encoding off;
        proxy_buffering off;
        proxy_cache off;
    }
}
```

### Config Write-Back Safety

- The dashboard only writes to the original config file path (specified via `--config`)
- Writes use `std::fs::write` which is atomic on most filesystems
- The API validates policy rules before saving (empty/invalid rules are filtered)
- The "Reload Config" button re-validates the config from disk before applying

### SQLite Database Security

- The DB file (`/var/lib/guardian/events.db`) is created by the daemon running as root
- It contains a full audit trail of all file access events (paths, PIDs, agent names)
- The `/api/events` endpoint exposes this data without authentication — bind to localhost
- WAL mode creates additional `-wal` and `-shm` files alongside the main DB
- For sensitive environments, ensure the DB directory has restrictive permissions (`chmod 700`)

### CDN Dependencies

The dashboard loads TailwindCSS, htmx, and Alpine.js from CDN. For air-gapped or high-security environments:

1. Download the CDN files
2. Place them in `guardian/static/`
3. Update the `<script>` and `<link>` tags in `templates/base.html` to use `/static/` paths
4. Rebuild — rust-embed will embed them in the binary

---

## Known Limitations

| Limitation | Impact | Workaround |
|-----------|--------|------------|
| **No authentication** | Anyone with network access to the port can control the daemon | Bind to localhost; use reverse proxy with auth |
| **CDN dependency** | First dashboard load requires internet | Bundle libraries locally via rust-embed |
| **Policy edits don't update BPF maps** | Kernel enforcement rules unchanged until restart | Use "Reload Config" button or send SIGHUP |
| **Config comments lost on save** | Original TOML comments removed by write-back | Maintain comments in a separate file or use version control |
| **Alerting changes need restart** | Output connections (SMTP, webhook) initialized once | Restart daemon after changing alert output config |
| **500-event live buffer** | Only last 500 events visible in Live tab | Switch to History tab for full SQLite-backed event archive |
| **DB path needs writable directory** | SQLite DB at `/var/lib/guardian/events.db` requires the directory to exist and be writable | Configure `db_path` in `[dashboard]` config, or ensure `/var/lib/guardian/` exists |
| **No mobile responsive design** | Dashboard designed for desktop browsers | Use on desktop or laptop screens |
| **SQLite single-process only** | Only one guardian daemon can write to a given DB file at a time | Use separate `db_path` per daemon instance |
