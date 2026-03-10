# Phase 4 Implementation: Alerting & Integration

## What Phase 4 Solves

Phase 3 gave us unspoofable cgroup-based agent identity, resource limits, and time-based access grants. But all output went to stderr via `env_logger` — fine for a terminal, useless for production:

**Problem 1: No structured logs.** The `[ALLOW]` / `[DENY]` log lines are human-readable but machine-unfriendly. SIEMs, log aggregators, and dashboards can't parse them without custom regex. A single missed regex change breaks the pipeline.

**Problem 2: No real-time notifications.** If an agent is blocked from reading `/etc/shadow` at 3 AM, nobody knows until someone reads the logs the next day. There's no way to send an alert to Slack, email, or a webhook when a policy violation occurs.

**Problem 3: No observability metrics.** Questions like "how many file access events per minute?", "how many policy violations today?", or "is the daemon even running?" require manually parsing logs. There's no Prometheus endpoint for dashboards or alerting rules.

**Problem 4: No alert hygiene.** A single misconfigured agent can generate thousands of identical DENY events per minute (e.g., a polling loop hitting a denied path). Without deduplication or rate limiting, any notification system would be overwhelmed.

Phase 4 solves all four by adding a complete alerting and observability layer: structured JSON logging, webhook/Slack/email notifications, Prometheus metrics, and built-in dedup/throttling — all configured via the same TOML config file.

---

## What Was Built

### New Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `guardian/src/alerting/mod.rs` | 427 | AlertManager, AlertSender, AlertEvent types, dedup/throttle, dispatch |
| `guardian/src/alerting/json_log.rs` | 195 | SIEM-compatible JSONL file logger with size-based rotation |
| `guardian/src/alerting/webhook.rs` | 86 | Generic HTTP POST to any endpoint with auth headers |
| `guardian/src/alerting/slack.rs` | 111 | Slack Block Kit formatted messages with severity colors |
| `guardian/src/alerting/email.rs` | 109 | Async SMTP email via lettre with STARTTLS |
| `guardian/src/alerting/metrics.rs` | 164 | Prometheus counters + lightweight TCP HTTP server |
| `configs/minimal.toml` | — | Preset: bare minimum, monitor-only |
| `configs/recommended.toml` | — | Preset: production defaults with JSON + Prometheus |
| `configs/strict.toml` | — | Preset: maximum security, all outputs |
| `configs/development.toml` | — | Preset: verbose, permissive, stdout JSON |

### Modified Source Files

| File | What Changed |
|------|-------------|
| `guardian/Cargo.toml` | Added `reqwest` (HTTP), `lettre` (SMTP), `chrono` (timestamps), `prometheus` (metrics) |
| `guardian/src/config.rs` | Added `AlertingConfig`, `JsonLogConfig`, `WebhookConfig`, `SlackConfig`, `EmailConfig`, `PrometheusConfig` structs. Added `validate_alerting_config()` with URL/severity/required-field checks. Made `alerting` an optional field in `Config`. |
| `guardian/src/main.rs` | Added `mod alerting`. Integrated `AlertSender` into event processing pipeline. Added `--validate-config` CLI flag. Added SIGHUP handler for config hot-reload. Updated step numbering (6→13 steps). |
| `config.toml` | Added complete `[alerting]` section with all output examples (JSON log + Prometheus enabled, webhook/Slack/email commented). |

---

## Architecture

### Event Flow

```
                         eBPF (KERNEL)
┌─────────────────────────────────────────────────────────────────────┐
│ sys_enter_openat  ──► capture event ──► perf buffer (per-CPU)       │
│ sys_enter_execve  ──► capture event ──► perf buffer (per-CPU)       │
└────────────────────────────────────────┬────────────────────────────┘
                                         │
                                         │ async read
                                         ▼
                        USERSPACE (per-CPU tokio tasks)
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  process_file_event() / process_exec_event()                        │
│    │                                                                │
│    ├──► env_logger (existing stderr output, unchanged)              │
│    │     [ALLOW] / [DENY|MONITOR] / [BLOCKED|ENFORCE]               │
│    │                                                                │
│    ├──► AlertSender.send()                                          │
│    │     │                                                          │
│    │     ├──► Prometheus counters (synchronous, atomic)             │
│    │     │     guardian_file_events_total{agent, action}             │
│    │     │     guardian_exec_events_total{agent, action}             │
│    │     │                                                          │
│    │     └──► mpsc::channel (4096 buffer, non-blocking)             │
│    │           │                                                    │
│    │           ▼                                                    │
│    │     AlertManager (tokio task)                                   │
│    │       │                                                        │
│    │       ├──► Severity filter (global min_severity)               │
│    │       ├──► Dedup filter (hash-based, configurable window)      │
│    │       ├──► Rate limiter (per-minute cap)                       │
│    │       │                                                        │
│    │       ├──► JSON Log   (JSONL file, size-based rotation)        │
│    │       ├──► Webhook    (HTTP POST, JSON payload)                │
│    │       ├──► Slack      (Block Kit, colored sidebar)             │
│    │       └──► Email      (SMTP/STARTTLS, plain text)              │
│    │                                                                │
│    └──► events_lost counter (on perf buffer overflow)               │
│                                                                     │
│  Prometheus HTTP Server (separate tokio task)                       │
│    GET /metrics  ──►  prometheus::TextEncoder ──► HTTP 200          │
│                                                                     │
│  SIGHUP Handler (separate tokio task)                               │
│    SIGHUP  ──►  reload config.toml  ──►  update IpcState.config     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Why This Architecture

**Synchronous metrics, async alerts.** Prometheus counters are updated directly in the event processors using atomic operations — no channel involved. This means metrics are always accurate, even if the alert channel is full or the AlertManager is busy sending a slow webhook. Alert delivery (JSON log, webhook, Slack, email) happens asynchronously in a separate task so it never blocks event processing.

**Non-blocking channel with backpressure.** The `mpsc::channel(4096)` buffer absorbs bursts. `try_send()` drops the event (and increments `alerts_dropped`) rather than blocking. This is the correct trade-off: a slow webhook endpoint should never slow down eBPF event processing.

**Single AlertManager task.** All dedup/throttle state lives in one task. No locking needed. The channel serializes events naturally. Cleanup runs on a 60-second interval via `tokio::select!`.

---

## Alert Processing Pipeline: Step-by-Step

When a file access event occurs, here is the complete flow:

### Step 1: Event Processor Creates AlertEvent

In `process_file_event()` (`guardian/src/main.rs`), after evaluating the policy:

```rust
let (severity, action) = if allowed {
    (Severity::Info, Action::Allow)
} else if enforce_mode {
    (Severity::Critical, Action::Blocked)
} else {
    (Severity::Warning, Action::Deny)
};

alert_tx.send(AlertEvent {
    timestamp: chrono::Utc::now(),
    severity,
    event_type: EventType::FileAccess,
    action,
    agent_name: agent.name.clone(),
    pid: event.tgid,
    comm: comm.to_string(),
    path: filename.to_string(),
    access_mode: access_mode.clone(),
    identity_method: agent.effective_identity().to_string(),
    policy_mode: mode_tag.to_lowercase(),
});
```

The severity mapping is:

| Condition | Severity | Action |
|-----------|----------|--------|
| File access allowed | `Info` | `Allow` |
| File access denied, monitor mode | `Warning` | `Deny` |
| File access blocked, enforce mode | `Critical` | `Blocked` |
| Exec allowed | `Info` | `Allow` |
| Exec denied | `Warning` | `Deny` |

### Step 2: AlertSender Updates Metrics and Queues

```rust
impl AlertSender {
    pub fn send(&self, event: AlertEvent) {
        // Synchronous: always runs, even if channel is full
        self.metrics.record_event(&event);

        // Async: drops event if channel buffer (4096) is full
        if self.tx.try_send(event).is_err() {
            self.metrics.alerts_dropped.inc();
        }
    }
}
```

### Step 3: AlertManager Receives and Filters

The AlertManager task runs a `tokio::select!` loop:

```rust
async fn run(&mut self, mut rx: mpsc::Receiver<AlertEvent>) {
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                self.process_event(event).await;
            }
            _ = cleanup_interval.tick() => {
                self.cleanup_dedup_cache();
            }
        }
    }
}
```

For each event, three filters are applied in order:

**Filter 1: Global severity threshold.** If the event's severity is below `min_severity` (default: `"warning"`), it's dropped. This means `Info` events (allowed accesses) are not alerted by default — they're only in Prometheus counters.

**Filter 2: Deduplication.** A hash is computed from `(agent_name, event_type, path, action)`. If the same hash was seen within `dedup_window_seconds` (default: 300), the event is suppressed. This prevents alert storms when an agent polls a denied path in a loop.

```rust
fn dedup_key(&self) -> u64 {
    let mut hasher = DefaultHasher::new();
    self.agent_name.hash(&mut hasher);
    self.event_type.hash(&mut hasher);
    self.path.hash(&mut hasher);
    self.action.hash(&mut hasher);
    hasher.finish()
}
```

**Filter 3: Rate limiting.** A sliding 1-minute window caps total alerts to `rate_limit_per_minute` (default: 100). If the cap is hit, remaining events in that minute are dropped. The window resets every 60 seconds.

### Step 4: Dispatch to Outputs

Each output has its own severity filter (independent of the global filter). The dispatch order is:

1. **JSON Log** — writes to file (or stdout), always processes all events that pass the global filter
2. **Webhook** — HTTP POST if `event.severity >= webhook.min_severity`
3. **Slack** — Slack webhook if `event.severity >= slack.min_severity`
4. **Email** — SMTP send if `event.severity >= email.min_severity`

Each output's success/failure is tracked in the `guardian_alerts_sent_total{output, status}` Prometheus counter.

---

## Output Formats

### JSON Log (JSONL)

Each line is a self-contained JSON object. This format is called JSONL (JSON Lines) and is the standard for SIEM ingestion (Elasticsearch, Splunk, Loki, etc.).

```json
{"timestamp":"2026-03-10T14:30:00.123456Z","severity":"critical","event_type":"file_access","action":"blocked","agent":{"name":"claude-code","identity":"cgroup","pid":12345,"comm":"cat"},"file":{"path":"/etc/shadow","flags":"READ"},"policy":{"mode":"enforce"},"host":{"hostname":"myhost"}}
```

Pretty-printed for readability:

```json
{
  "timestamp": "2026-03-10T14:30:00.123456Z",
  "severity": "critical",
  "event_type": "file_access",
  "action": "blocked",
  "agent": {
    "name": "claude-code",
    "identity": "cgroup",
    "pid": 12345,
    "comm": "cat"
  },
  "file": {
    "path": "/etc/shadow",
    "flags": "READ"
  },
  "policy": {
    "mode": "enforce"
  },
  "host": {
    "hostname": "myhost"
  }
}
```

**Field reference:**

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | ISO 8601 | UTC timestamp with microsecond precision |
| `severity` | string | `"info"`, `"warning"`, or `"critical"` |
| `event_type` | string | `"file_access"` or `"exec_attempt"` |
| `action` | string | `"allow"`, `"deny"`, or `"blocked"` |
| `agent.name` | string | Agent name from config |
| `agent.identity` | string | `"comm"` or `"cgroup"` |
| `agent.pid` | integer | Process TGID |
| `agent.comm` | string | Process comm name (from `/proc/PID/comm`) |
| `file.path` | string | File path from the `openat()` syscall |
| `file.flags` | string | Open flags: `"READ"`, `"WRITE|CREATE"`, etc. |
| `policy.mode` | string | `"enforce"` or `"monitor"` |
| `host.hostname` | string | Machine hostname from `/etc/hostname` |

**Log rotation:** When the file exceeds `max_size_mb` (default: 100 MB), the logger rotates:
- `events.json` → `events.json.1`
- `events.json.1` → `events.json.2`
- ... up to `max_files` (default: 5)
- New `events.json` is created empty

### Webhook Payload

HTTP POST with `Content-Type: application/json`:

```json
{
  "version": "1.0",
  "source": "guardian-shell",
  "timestamp": "2026-03-10T14:30:00.123456Z",
  "hostname": "myhost",
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
```

Optional headers:
- `Authorization` header via `auth_header` config field
- Custom headers via `headers` map (e.g., `X-Source = "guardian-shell"`)

### Slack Message

Uses Slack's [Block Kit](https://api.slack.com/block-kit) for rich formatting with a color-coded sidebar:

- **Red** (`#dc3545`) for `critical` severity
- **Yellow** (`#ffc107`) for `warning` severity
- **Blue** (`#17a2b8`) for `info` severity

The message includes a header with severity emoji, a section with agent/event/path/PID fields, and a context bar with hostname, mode, identity method, and timestamp.

### Email

Plain-text email with structured fields:

```
Subject: [Guardian Shell] CRITICAL — BLOCKED on /etc/shadow (agent: claude-code)

Guardian Shell Security Alert
================================

Severity:  critical
Event:     file_access
Action:    blocked
Timestamp: 2026-03-10T14:30:00Z

Agent:     claude-code
PID:       12345 (cat)
Identity:  cgroup
Path:      /etc/shadow
Flags:     READ
Mode:      enforce
Host:      myhost

---
This alert was generated by Guardian Shell.
```

Uses SMTP with STARTTLS on the configured port (default: 587). Supports username/password authentication.

---

## Prometheus Metrics

### Exposed Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `guardian_guardian_file_events_total` | Counter | `agent`, `action` | Total file access events observed |
| `guardian_guardian_exec_events_total` | Counter | `agent`, `action` | Total exec attempt events observed |
| `guardian_guardian_ebpf_events_lost_total` | Counter | — | Total eBPF events lost due to full perf buffer |
| `guardian_guardian_alerts_sent_total` | Counter | `output`, `status` | Total alerts sent to each output destination |
| `guardian_guardian_alerts_dropped_total` | Counter | — | Total alerts dropped due to full channel |

### How Metrics Are Updated

Metrics are updated at two levels:

1. **Event processors** (synchronous, per-CPU tasks): `file_events_total` and `exec_events_total` are incremented via `AlertSender.send()` before the event enters the channel. This means counters are accurate even if the AlertManager drops events.

2. **AlertManager** (async, single task): `alerts_sent_total` is incremented after each output dispatch attempt, with `status="success"` or `status="error"`.

3. **Perf buffer readers**: `events_lost` is incremented when the kernel reports dropped events from the perf ring buffer.

### Prometheus HTTP Server

A lightweight TCP server (no framework dependency) listens on the configured address (default: `127.0.0.1:9090`). It handles GET requests to the configured endpoint (default: `/metrics`) and responds with Prometheus text exposition format.

```
$ curl http://127.0.0.1:9090/metrics
# HELP guardian_guardian_file_events_total Total file access events observed
# TYPE guardian_guardian_file_events_total counter
guardian_guardian_file_events_total{agent="claude-code",action="allow"} 14523
guardian_guardian_file_events_total{agent="claude-code",action="blocked"} 7
# HELP guardian_guardian_exec_events_total Total exec attempt events observed
# TYPE guardian_guardian_exec_events_total counter
guardian_guardian_exec_events_total{agent="claude-code",action="allow"} 892
# HELP guardian_guardian_ebpf_events_lost_total Total eBPF events lost due to full perf buffer
# TYPE guardian_guardian_ebpf_events_lost_total counter
guardian_guardian_ebpf_events_lost_total 0
# HELP guardian_guardian_alerts_sent_total Total alerts sent to output destinations
# TYPE guardian_guardian_alerts_sent_total counter
guardian_guardian_alerts_sent_total{output="json_log",status="success"} 7
guardian_guardian_alerts_sent_total{output="webhook",status="success"} 5
guardian_guardian_alerts_sent_total{output="webhook",status="error"} 2
# HELP guardian_guardian_alerts_dropped_total Total alerts dropped due to full channel
# TYPE guardian_guardian_alerts_dropped_total counter
guardian_guardian_alerts_dropped_total 0
```

### Grafana Integration

Add the Prometheus endpoint as a data source in Grafana, then create dashboards:

**Useful queries:**
```promql
# Policy violations per minute
rate(guardian_guardian_file_events_total{action="blocked"}[5m]) * 60

# Alert delivery success rate
sum(rate(guardian_guardian_alerts_sent_total{status="success"}[5m]))
/
sum(rate(guardian_guardian_alerts_sent_total[5m]))

# Events lost ratio
rate(guardian_guardian_ebpf_events_lost_total[5m])
/
(rate(guardian_guardian_file_events_total[5m]) + rate(guardian_guardian_ebpf_events_lost_total[5m]))
```

---

## CLI Enhancements

### --validate-config

Validates the configuration file and exits without starting the daemon:

```bash
$ sudo target/release/guardian --config config.toml --validate-config
[INFO  guardian] Configuration is valid.
[INFO  guardian] Alerting: configured
[INFO  guardian]   JSON log: enabled
[INFO  guardian]   Prometheus: enabled
```

Validation checks include:
- TOML syntax and field types
- Mode must be `"monitor"` or `"enforce"`
- Agent identity must be `"comm"` or `"cgroup"`
- Severity values must be `"info"`, `"warning"`, or `"critical"`
- Webhook URL must start with `http://` or `https://` (warning)
- Slack webhook URL must look like a Slack URL (warning)
- Enabled outputs must have required fields (URL, SMTP host, from/to addresses)
- Overly permissive allow patterns are flagged

This is useful for CI/CD pipelines, pre-deployment checks, and config file editing.

### SIGHUP Config Reload

Reload agent policies without restarting the daemon:

```bash
$ sudo kill -HUP $(pidof guardian)
```

On SIGHUP, the daemon:
1. Reads and validates the config file
2. Updates the `IpcState.config` (shared with IPC handlers)
3. Logs the reload result

```
[INFO  guardian] SIGHUP received — reloading configuration...
[INFO  guardian] Configuration reloaded: 2 agent(s), mode=enforce
```

If the new config is invalid, the previous config is kept:

```
[ERROR guardian] Config reload failed (keeping previous config): Agent 'test': invalid default action 'invalid'. Must be 'allow' or 'deny'
```

**What reloads:** Agent file access policies, exec policies, agent list.

**What does NOT reload:** Alerting outputs (webhook URLs, Slack tokens, etc.), BPF maps for existing agents, enforcement mode. These require a full daemon restart because they involve persistent connections and kernel state.

---

## Configuration Reference

### Full Alerting Config

```toml
[alerting]
# Global minimum severity: events below this are not alerted.
# "info" = all events, "warning" = denials only, "critical" = enforced blocks only
min_severity = "warning"

# Suppress duplicate alerts (same agent + event type + path + action)
# within this time window. Set to 0 to disable dedup.
dedup_window_seconds = 300

# Maximum alerts dispatched per minute across all outputs.
# Prevents alert storms from overwhelming downstream systems.
rate_limit_per_minute = 100

# --- Structured JSON Logging ---
[alerting.json_log]
enabled = true
path = "/var/log/guardian/events.json"  # Omit for stdout
max_size_mb = 100                       # Rotate when file exceeds this
max_files = 5                           # Keep N rotated files

# --- Webhook (generic HTTP POST) ---
[alerting.webhook]
enabled = true
url = "https://siem.example.com/api/v1/events"
auth_header = "Bearer your-api-token"
min_severity = "warning"

# Optional custom headers
[alerting.webhook.headers]
X-Source = "guardian-shell"
X-Environment = "production"

# --- Slack ---
[alerting.slack]
enabled = true
webhook_url = "https://hooks.slack.com/services/T.../B.../xxx"
channel = "#security-alerts"            # Optional channel override
min_severity = "critical"

# --- Email (SMTP) ---
[alerting.email]
enabled = true
smtp_host = "smtp.gmail.com"
smtp_port = 587                         # STARTTLS
username = "alerts@example.com"
password = "app-password-here"
from = "Guardian Shell <guardian@example.com>"
to = ["security-team@example.com", "oncall@example.com"]
min_severity = "critical"

# --- Prometheus Metrics ---
[alerting.prometheus]
enabled = true
listen_address = "127.0.0.1:9090"
endpoint = "/metrics"
```

### Severity Levels

| Level | Meaning | Typical Output |
|-------|---------|---------------|
| `info` | Allowed access events | JSON log only (high volume) |
| `warning` | Denied access in monitor mode | JSON log, webhook |
| `critical` | Blocked access in enforce mode | All outputs |

Each output can set its own `min_severity` independently. The global `min_severity` acts as a pre-filter before any per-output filter.

### Preset Configurations

Four ready-to-use configs are in `configs/`:

| Preset | `mode` | Alerting | Best For |
|--------|--------|----------|----------|
| `minimal.toml` | monitor | None | Quick testing, learning the tool |
| `recommended.toml` | enforce | JSON log + Prometheus | Production deployments |
| `strict.toml` | enforce | All outputs (commented) | Maximum security |
| `development.toml` | monitor | JSON to stdout + Prometheus | Debugging, development |

---

## Dependencies Added

| Crate | Version | Features | Purpose |
|-------|---------|----------|---------|
| `reqwest` | 0.12 | `rustls-tls`, `json` | HTTP client for webhooks and Slack (uses rustls, no openssl) |
| `lettre` | 0.11 | `tokio1-rustls-tls`, `smtp-transport`, `builder` | Async SMTP email transport |
| `chrono` | 0.4 | `serde` | ISO 8601 timestamps with microsecond precision |
| `prometheus` | 0.13 | — | Counter/gauge metrics with text encoding |

All TLS uses `rustls` — no OpenSSL system dependency required.

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Async mpsc channel** | Event processors never block on I/O. The 4096-element buffer absorbs bursts. `try_send()` drops rather than blocks — eBPF event processing is higher priority than alert delivery. |
| **Synchronous Prometheus counters** | Metrics must be accurate regardless of channel state. Atomic counter increments have negligible overhead. This is how Tetragon handles it too. |
| **Per-output severity filters** | Webhook might want all warnings, but Slack/email should only fire for critical events. One global filter + per-output overrides provides flexible noise control. |
| **Hash-based dedup** | Computing `hash(agent, event_type, path, action)` is O(1) and the HashMap lookup is O(1). No sorting, no windowing, no external state. Dedup cache is cleaned every 60 seconds. |
| **JSONL format** | One JSON object per line. No parser state between lines. Works with `grep`, `jq`, `tail -f`, Elasticsearch bulk API, Loki, Splunk HEC. Industry standard for structured logs. |
| **Slack Block Kit** | Slack's recommended formatting API. Color-coded sidebar makes severity instantly visible. Structured fields (agent, path, PID) are scannable without reading prose. |
| **Size-based log rotation** | Simple, no external dependency (`logrotate` not required). The daemon handles its own rotation. Configurable max size and max files. |
| **Simple TCP metrics server** | A full HTTP framework (axum) is unnecessary for serving `/metrics`. The lightweight TCP handler is ~40 lines. Axum will be added in Phase 5 for the dashboard. |
| **SIGHUP config reload** | Standard Unix daemon pattern. Used by nginx, haproxy, falco, and most production daemons. Reloads policy without disrupting active monitoring. |
| **Optional alerting section** | Existing Phase 3 configs work unchanged. The `[alerting]` table is `Option<AlertingConfig>` — when absent, a no-op `AlertSender` is used that only tracks internal metrics. |
| **Preset config templates** | Falco ships commented default configs. Having four presets (minimal → strict) reduces onboarding friction and shows best practices. |
| **`--validate-config` flag** | Catches config errors before deployment. Essential for CI/CD. Returns exit code 0 on success, non-zero on failure. |
| **reqwest with rustls** | Avoids the `openssl-dev` system dependency that breaks builds on minimal containers. Rustls is pure-Rust and statically linked. |

---

## Research Findings Applied

This implementation was informed by analysis of five major open-source security monitoring tools:

| Pattern | Source Project | How We Applied It |
|---------|---------------|-------------------|
| Per-output enable + severity filter | Falco (`falco.yaml` output channels) | Each output in `[alerting.*]` has `enabled` and `min_severity` |
| Sidecar separation for complex routing | Falcosidekick (60+ output plugins) | Core daemon handles 5 outputs directly; complex routing deferred to Phase 5 |
| JSONL event export format | Tetragon (`export-file` config) | One JSON per line with nested `agent`, `file`, `policy`, `host` objects |
| Drop-in config snippets | Tetragon (`/etc/tetragon/tetragon.conf.d/`) | Preset configs in `configs/` directory |
| Prometheus metrics with namespace prefix | Tetragon (port 2112, `--metrics-label-filter`) | `guardian_` prefix, label-based cardinality control |
| Commented default config file | Falco (ships a 200+ line `falco.yaml` with every option) | `config.toml` has all outputs as commented examples |
| SIGHUP config reload | Falco, nginx, HAProxy | `tokio::signal::unix::SignalKind::hangup()` handler |
| Alert throttling/dedup | Prometheus Alertmanager (`group_wait`, `repeat_interval`) | Hash-based dedup window + per-minute rate limit |
| Config validation subcommand | Tetragon (`--generate-docs`), nginx (`-t` flag) | `--validate-config` flag |
| Block Kit formatted Slack messages | Falcosidekick Slack output | Color-coded sidebar, structured fields, context bar |

---

## Comparison: Phase 1 → 2 → 3 → 4

| Feature | Phase 1 | Phase 2 | Phase 3 | Phase 4 |
|---------|---------|---------|---------|---------|
| **Output** | stderr only | stderr only | stderr only | **JSON + webhook + Slack + email** |
| **Metrics** | None | None | None | **Prometheus endpoint** |
| **Notifications** | None | None | None | **Real-time (webhook, Slack, email)** |
| **Alert hygiene** | None | None | None | **Dedup + rate limiting** |
| **Config validation** | Basic | Basic | Basic | **`--validate-config` + URL checks** |
| **Hot reload** | None | None | None | **SIGHUP** |
| **Preset configs** | None | None | None | **4 templates** |
| **Enforcement** | Monitor only | Kernel blocks | Kernel blocks | Kernel blocks |
| **Identity** | Comm name | Comm + TGID | Cgroup (unspoofable) | Cgroup (unspoofable) |
| **Resource limits** | None | None | Memory/CPU/PIDs | Memory/CPU/PIDs |

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
cargo build --package guardian         # debug: OK
cargo build --package guardian --release  # release: OK (1m 01s)
```

Only pre-existing warnings from Phase 3 code (unused `log_level` field, unused `get_cgroup_id` function).
