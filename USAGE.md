# Guardian Shell - Usage Guide

Guardian Shell is a Linux security tool that monitors and enforces file access policies for LLM agents (Claude Code, OpenAI Codex, Aider, OpenClaw, Cursor, etc.) using eBPF. It hooks into the kernel's file-open syscall, evaluates every file access against your policy rules in real time, and can block unauthorized access at the kernel level.

**Current mode: Phase 5 — Dashboard, UI & Full Application Control**

Guardian Shell now provides five layers of protection:
- **Phase 1**: Monitor-only file access logging via eBPF tracepoints
- **Phase 2**: Kernel-level enforcement via LSM BPF hooks (blocks denied access)
- **Phase 3**: Unspoofable cgroup-based agent identity, resource limits, launcher wrapper, and time-based access grants
- **Phase 4**: Structured JSON logging, webhook/Slack/email alerts, Prometheus metrics, and config validation
- **Phase 5**: Web dashboard with real-time event streaming, policy editor, agent management, and full application control

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Building from Source](#building-from-source)
4. [Configuration](#configuration)
   - [Global Settings](#global-settings)
   - [Agent Definitions](#agent-definitions)
   - [Cgroup-Based Agents (Phase 3)](#cgroup-based-agents-phase-3)
   - [File Access Policies](#file-access-policies)
   - [Pattern Matching](#pattern-matching)
   - [Policy Evaluation Order](#policy-evaluation-order)
5. [Running Guardian Shell](#running-guardian-shell)
   - [CLI Options](#cli-options)
   - [Log Levels](#log-levels)
6. [guardian-launch: Launching Agents with Cgroup Isolation](#guardian-launch-launching-agents-with-cgroup-isolation)
   - [What guardian-launch Does](#what-guardian-launch-does)
   - [Why You Need It](#why-you-need-it)
   - [Usage](#guardian-launch-usage)
   - [Resource Limits](#resource-limits)
7. [guardian-ctl: Managing Running Agents](#guardian-ctl-managing-running-agents)
   - [Listing Agents](#listing-agents)
   - [Stopping Agents](#stopping-agents)
   - [Temporary Access Grants](#temporary-access-grants)
8. [Alerting & Integration (Phase 4)](#alerting--integration-phase-4)
   - [Alerting Configuration](#alerting-configuration)
   - [JSON Logging for SIEM](#json-logging-for-siem)
   - [Webhook Alerts](#webhook-alerts)
   - [Slack Notifications](#slack-notifications)
   - [Email Notifications](#email-notifications)
   - [Prometheus Metrics](#prometheus-metrics)
   - [Alert Deduplication & Rate Limiting](#alert-deduplication--rate-limiting)
   - [Config Validation](#config-validation)
   - [Config Hot-Reload (SIGHUP)](#config-hot-reload-sighup)
   - [Preset Configurations](#preset-configurations)
9. [Web Dashboard (Phase 5)](#web-dashboard-phase-5)
   - [Enabling the Dashboard](#enabling-the-dashboard)
   - [Dashboard Pages](#dashboard-pages)
   - [Live Event Stream (SSE)](#live-event-stream-sse)
   - [Managing Agents from Dashboard](#managing-agents-from-dashboard)
   - [Editing Policies from Dashboard](#editing-policies-from-dashboard)
   - [Configuring Alerts from Dashboard](#configuring-alerts-from-dashboard)
   - [Dashboard Security](#dashboard-security)
10. [Understanding the Output](#understanding-the-output)
   - [Startup Messages](#startup-messages)
   - [ALLOW Events](#allow-events)
   - [DENY Events](#deny-events)
   - [Event Fields](#event-fields)
11. [Writing Effective Policies](#writing-effective-policies)
    - [Principle of Least Privilege](#principle-of-least-privilege)
    - [Common Allow Patterns](#common-allow-patterns)
    - [Recommended Deny Patterns](#recommended-deny-patterns)
    - [Per-Agent Policies](#per-agent-policies)
    - [Tuning Your Policy](#tuning-your-policy)
12. [Real-World Examples](#real-world-examples)
    - [Monitoring Claude Code (comm-based)](#monitoring-claude-code-comm-based)
    - [Isolating Aider with Cgroups](#isolating-aider-with-cgroups)
    - [Running OpenClaw in a Sandbox](#running-openclaw-in-a-sandbox)
    - [Securing OpenAI Codex CLI Agent](#securing-openai-codex-cli-agent)
    - [Multiple LLM Agents Side by Side](#multiple-llm-agents-side-by-side)
    - [Strict Lockdown Policy](#strict-lockdown-policy)
    - [Permissive Audit Policy](#permissive-audit-policy)
13. [How It Works](#how-it-works)
    - [Architecture Overview](#architecture-overview)
    - [eBPF and Tracepoints](#ebpf-and-tracepoints)
    - [3-Tier Agent Identification](#3-tier-agent-identification)
    - [Event Pipeline](#event-pipeline)
13. [LLM Agent Security: Why This Matters](#llm-agent-security-why-this-matters)
14. [Troubleshooting](#troubleshooting)
15. [Security Considerations](#security-considerations)
16. [Known Limitations](#known-limitations)
17. [Roadmap](#roadmap)

---

## Quick Start

### Option A: Comm-based monitoring (Phase 1/2 — simple, works with any process)

```bash
# 1. Build (one-time)
cargo xtask build-ebpf --release
cargo build --release

# 2. Create a policy file
cat > my-policy.toml << 'EOF'
[global]
log_level = "info"
mode = "enforce"
socket_path = "/run/guardian.sock"

[[agents]]
name = "my-agent"
process_name = "python3"

[agents.file_access]
default = "deny"
allow = [
    "/home/user/project/**",
    "/tmp/**",
    "/usr/lib/**",
    "/lib/**",
    "/lib64/**",
]
deny = [
    "/home/user/.ssh/**",
    "/home/user/.aws/**",
]
EOF

# 3. Run Guardian Shell (requires root)
sudo RUST_LOG=info target/release/guardian --config my-policy.toml

# 4. In another terminal, use your agent normally
# Guardian will log every file access decision and block denied access
```

### Option B: Cgroup-based isolation (Phase 3 — recommended for production)

```bash
# 1. Build (one-time)
cargo xtask build-ebpf --release
cargo build --release

# 2. Create a policy file with cgroup-based agent
cat > my-policy.toml << 'EOF'
[global]
log_level = "info"
mode = "enforce"
socket_path = "/run/guardian.sock"

[[agents]]
name = "aider"
identity = "cgroup"

[agents.file_access]
default = "deny"
allow = [
    "/home/user/project/**",
    "/tmp/**",
    "/usr/lib/**",
    "/lib/**",
    "/lib64/**",
]
deny = [
    "/home/user/.ssh/**",
    "/home/user/.aws/**",
]
EOF

# 3. Start the Guardian daemon
sudo RUST_LOG=info target/release/guardian --config my-policy.toml

# 4. In another terminal, launch the agent through guardian-launch
sudo target/release/guardian-launch \
    --name aider \
    --memory 4G \
    --pids 200 \
    -- python3 -m aider

# 5. Manage running agents
sudo target/release/guardian-ctl list
sudo target/release/guardian-ctl grant --name aider --path "/home/user/.aws/**" --duration 300
sudo target/release/guardian-ctl stop --name aider
```

---

## Installation

### System Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | Linux only (kernel 5.2+) |
| **Architecture** | x86_64 (aarch64 support planned) |
| **Privileges** | Root or `CAP_BPF` + `CAP_PERFMON` capabilities |
| **Kernel Config** | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_FTRACE=y` |

### Verify Kernel Support

```bash
# Check BPF support (should show CONFIG_BPF=y)
grep CONFIG_BPF /boot/config-$(uname -r)

# Or on systems with /proc/config.gz
zcat /proc/config.gz 2>/dev/null | grep CONFIG_BPF
```

Expected output:
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
```

Most modern distributions (Ubuntu 20.04+, Fedora 33+, Debian 11+, Arch Linux) have these enabled by default.

### Install Rust Toolchain

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install nightly toolchain with rust-src (required for eBPF cross-compilation)
rustup install nightly
rustup component add rust-src --toolchain nightly

# Install the BPF linker
cargo install bpf-linker
```

If `bpf-linker` fails to install, you may need LLVM development headers:

```bash
# Ubuntu/Debian
sudo apt install llvm-dev

# Fedora
sudo dnf install llvm-devel

# Arch Linux
sudo pacman -S llvm
```

---

## Building from Source

Guardian Shell has two components that must be built separately:

```bash
# Step 1: Build the eBPF kernel program (cross-compiles to BPF bytecode)
cargo xtask build-ebpf --release

# Step 2: Build the userspace daemon
cargo build --release
```

**Always use `--release`** for the eBPF program. The BPF verifier in the kernel is more likely to reject unoptimized debug builds because they contain redundant instructions.

### Build Output

```
target/
├── bpfel-unknown-none/release/
│   └── guardian-ebpf              # eBPF program (loaded into kernel)
└── release/
    ├── guardian                    # Userspace daemon
    ├── guardian-launch            # Agent launcher with cgroup isolation (Phase 3)
    └── guardian-ctl               # Agent management CLI (Phase 3)
```

---

## Configuration

Guardian Shell is configured via a TOML file. The configuration defines which processes to monitor and what file access rules to apply.

### Global Settings

```toml
[global]
log_level = "info"
mode = "enforce"                     # "monitor" or "enforce"
pid_rescan_interval = 5              # seconds between /proc scans for comm-based agents
socket_path = "/run/guardian.sock"   # Unix socket for guardian-launch/guardian-ctl IPC
```

| Field | Values | Description |
|-------|--------|-------------|
| `log_level` | `trace`, `debug`, `info`, `warn`, `error` | Default log verbosity (can be overridden with `RUST_LOG` env var) |
| `mode` | `monitor`, `enforce` | `monitor` = log only; `enforce` = kernel-level blocking via LSM |
| `pid_rescan_interval` | Integer (seconds) | How often to rescan `/proc` for new comm-based agent processes |
| `socket_path` | Path string | Unix socket path for IPC with `guardian-launch` and `guardian-ctl` |

### Agent Definitions

Guardian supports two identity modes for agents:

**Comm-based (Phase 1/2)** — Identifies agents by process name. Simple but can be spoofed.

```toml
[[agents]]
name = "claude-code"
process_name = "claude"         # matches /proc/PID/comm

[agents.file_access]
default = "deny"
allow = ["/home/user/project/**"]
deny = ["/home/user/project/.env"]
```

**Cgroup-based (Phase 3)** — Identifies agents by kernel cgroup ID. Cannot be spoofed. Requires launching via `guardian-launch`.

```toml
[[agents]]
name = "aider"
identity = "cgroup"            # no process_name needed

[agents.file_access]
default = "deny"
allow = ["/home/user/project/**"]
deny = ["/home/user/project/.env"]

[agents.resources]             # optional resource limits
memory_max = "4G"
pids_max = 200
cpu_max = "200000 100000"      # 2 CPU cores
```

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Human-readable name displayed in log output |
| `process_name` | For comm-based | Process name to match (from `/proc/PID/comm`, max 15 characters) |
| `identity` | No | `"comm"` (default) or `"cgroup"`. Determines how the agent is identified |
| `file_access.default` | Yes | Default action when no pattern matches: `"allow"` or `"deny"` |
| `file_access.allow` | Yes | List of path patterns that are allowed |
| `file_access.deny` | Yes | List of path patterns that are denied |
| `resources.memory_max` | No | Memory limit for cgroup agents (e.g., `"4G"`, `"512M"`) |
| `resources.pids_max` | No | Max number of processes for cgroup agents |
| `resources.cpu_max` | No | CPU bandwidth limit (e.g., `"200000 100000"` = 2 cores) |

#### Finding the Process Name (comm-based agents)

The `process_name` field must match what the kernel reports in `/proc/PID/comm`. To find it:

```bash
# Method 1: Start your agent, then check
ps aux | grep <agent>
cat /proc/<PID>/comm

# Method 2: Common process names
# Claude Code:  "claude" or "node"
# Python agents: "python3" or "python"
# Node.js agents: "node"
# Custom binaries: the executable name (truncated to 15 chars)
```

Note: The kernel truncates process names to 15 characters. A process named `very-long-agent-name` becomes `very-long-agent` in `/proc/PID/comm`.

### Cgroup-Based Agents (Phase 3)

Cgroup-based agents are the recommended approach for production use. Instead of relying on the process name (which any process can spoof with a single syscall), Guardian assigns each agent a **kernel cgroup** — a process group that the kernel enforces and that no unprivileged process can escape.

**When to use cgroup identity:**
- Running untrusted or semi-trusted LLM agents
- Running multiple agents that share the same binary (e.g., two Python agents)
- Needing resource limits (memory, CPU, process count)
- Wanting automatic child process tracking without relying on fork monitoring

**How it works:**
1. Define the agent in `config.toml` with `identity = "cgroup"`
2. Start the Guardian daemon
3. Launch the agent through `guardian-launch` — it creates a cgroup, registers with the daemon, and exec's the agent
4. All processes the agent spawns inherit the cgroup automatically
5. When the agent exits, the daemon cleans up the cgroup and BPF maps

Existing comm-based configs continue to work unchanged. You can mix both types in the same config.

### File Access Policies

Each agent has a `file_access` section with three fields:

- **`default`** - What to do when no pattern matches (`"allow"` or `"deny"`)
- **`allow`** - List of path patterns the agent is permitted to access
- **`deny`** - List of path patterns the agent is forbidden from accessing

### Pattern Matching

Guardian Shell supports three types of path patterns:

| Pattern | Type | What It Matches | Example |
|---------|------|-----------------|---------|
| `/etc/passwd` | Exact match | Only that exact file path | `/etc/passwd` matches; `/etc/passwd.bak` does not |
| `/home/user/**` | Recursive wildcard | Everything under the directory, including subdirectories | `/home/user/a/b/c/file.txt` matches |
| `/tmp/*` | Single-level wildcard | Files directly in the directory only | `/tmp/file.txt` matches; `/tmp/sub/file.txt` does not |

**Important notes:**
- Patterns must use **absolute paths** (starting with `/`). Relative paths will not match correctly.
- The `/**` wildcard also matches the directory itself (e.g., `/home/user/**` matches `/home/user`).
- The `/*` wildcard does NOT match the directory itself.
- Patterns are matched against the path as captured by the kernel. If a process opens a file using a relative path, the captured path will also be relative and may not match absolute patterns.

### Policy Evaluation Order

When a file access event arrives, Guardian evaluates the policy in this strict order:

```
1. Check DENY patterns  →  If ANY deny pattern matches  →  DENIED  (stop)
2. Check ALLOW patterns  →  If ANY allow pattern matches  →  ALLOWED (stop)
3. Apply DEFAULT action  →  Use the default from config    →  ALLOWED or DENIED
```

**Deny always wins.** If a path matches both an allow pattern and a deny pattern, the access is denied. This prevents accidental over-permissioning.

**Example:**

```toml
[agents.file_access]
default = "deny"
allow = ["/home/user/project/**"]
deny = ["/home/user/project/.env", "/home/user/project/**/.secret"]
```

| File Path | Result | Reason |
|-----------|--------|--------|
| `/home/user/project/main.rs` | ALLOWED | Matches allow pattern, no deny match |
| `/home/user/project/.env` | DENIED | Matches deny pattern (deny wins over allow) |
| `/home/user/project/sub/.secret` | DENIED | Matches deny pattern |
| `/etc/passwd` | DENIED | No pattern matches, default is "deny" |
| `/home/user/project/src/lib.rs` | ALLOWED | Matches recursive allow pattern |

---

## Running Guardian Shell

### CLI Options

```bash
sudo target/release/guardian [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--config <PATH>` | `-c` | `config.toml` | Path to the TOML configuration file |
| `--ebpf-program <PATH>` | | `target/bpfel-unknown-none/release/guardian-ebpf` | Path to the compiled eBPF binary |
| `--validate-config` | | | Validate configuration and exit (Phase 4) |

### Log Levels

Control verbosity with the `RUST_LOG` environment variable:

```bash
# Show ALLOW and DENY events (recommended for normal use)
sudo RUST_LOG=info target/release/guardian --config config.toml

# Show everything including system library accesses
sudo RUST_LOG=debug target/release/guardian --config config.toml

# Maximum detail (raw event data, internal operations)
sudo RUST_LOG=trace target/release/guardian --config config.toml

# Only show DENY events (quietest useful level)
sudo RUST_LOG=warn target/release/guardian --config config.toml
```

| Level | What You See |
|-------|--------------|
| `error` | Only errors (startup failures, crashes) |
| `warn` | DENY events + warnings |
| `info` | ALLOW events + DENY events + startup/shutdown messages |
| `debug` | All of the above + unmatched process events |
| `trace` | All of the above + raw event data |

### Running as a Background Service

```bash
# Run in background, log to file
sudo RUST_LOG=info target/release/guardian --config config.toml >> /var/log/guardian.log 2>&1 &

# Stop Guardian Shell
sudo kill $(pgrep guardian)
```

For production use, consider creating a systemd service:

```ini
# /etc/systemd/system/guardian-shell.service
[Unit]
Description=Guardian Shell - LLM Agent File Access Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/guardian --config /etc/guardian/config.toml
Environment=RUST_LOG=info
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now guardian-shell
sudo journalctl -u guardian-shell -f   # View logs
```

---

## guardian-launch: Launching Agents with Cgroup Isolation

### What guardian-launch Does

`guardian-launch` is a launcher binary that starts an LLM agent inside a dedicated Linux cgroup. It performs six steps in sequence:

1. **Creates a cgroup** at `/sys/fs/cgroup/guardian/<agent-name>-<pid>/`
2. **Enables controllers** (memory, PIDs, CPU) in the cgroup hierarchy
3. **Sets resource limits** (memory cap, process count limit, CPU bandwidth)
4. **Gets the cgroup ID** (inode number, which matches `bpf_get_current_cgroup_id()` in the kernel)
5. **Registers with the Guardian daemon** via Unix socket IPC
6. **exec()'s the agent command** — the launcher process replaces itself with the agent

After step 6, the agent IS the process in the cgroup. There is no wrapper overhead. Every child process the agent spawns (bash, git, curl, pip, etc.) automatically inherits the same cgroup. No process can leave the cgroup without root privileges.

### Why You Need It

Without `guardian-launch`, Guardian identifies agents by their process name (`/proc/PID/comm`). This has three problems:

**Problem 1: Process name spoofing.** Any process can change its own name:
```python
import ctypes
libc = ctypes.CDLL("libc.so.6")
libc.prctl(15, b"systemd\0")  # Now /proc/PID/comm says "systemd"
```
After this call, Guardian stops monitoring the agent. With cgroups, the identity is kernel-enforced and cannot be changed.

**Problem 2: Same-binary ambiguity.** Two Python-based agents (e.g., Aider and OpenClaw) both appear as `python3` in `/proc/PID/comm`. Guardian can't tell them apart. With `guardian-launch`, each gets its own cgroup with separate policy rules.

**Problem 3: No resource control.** A buggy or malicious agent could consume all system memory, fork-bomb the system, or hog the CPU. `guardian-launch` sets hard limits via cgroup controllers.

### guardian-launch Usage

```bash
sudo guardian-launch [OPTIONS] -- <COMMAND> [ARGS...]
```

| Option | Description | Example |
|--------|-------------|---------|
| `--name <NAME>` | Agent name (must match a `[[agents]]` entry in config.toml) | `--name aider` |
| `--memory <LIMIT>` | Memory limit | `--memory 4G`, `--memory 512M` |
| `--pids <MAX>` | Max process count (prevents fork bombs) | `--pids 200` |
| `--cpu <QUOTA>` | CPU bandwidth (`quota period` in microseconds) | `--cpu "200000 100000"` (= 2 cores) |
| `--socket <PATH>` | Guardian daemon socket path | `--socket /run/guardian.sock` |

**Examples:**

```bash
# Launch Aider with 4GB memory and 200 process limit
sudo guardian-launch --name aider --memory 4G --pids 200 \
    -- python3 -m aider

# Launch a Node.js agent with 2 CPU cores
sudo guardian-launch --name codex --memory 8G --cpu "200000 100000" \
    -- npx @openai/codex

# Launch with no resource limits (just cgroup identity)
sudo guardian-launch --name my-agent \
    -- ./my-agent --workspace /home/user/project
```

### Resource Limits

Resource limits are enforced by the Linux kernel via cgroup v2 controllers:

| Limit | Cgroup File | What Happens When Exceeded |
|-------|-------------|---------------------------|
| `--memory` | `memory.max` | Kernel OOM-kills processes in the cgroup |
| `--pids` | `pids.max` | `fork()` returns EAGAIN — agent can't spawn more processes |
| `--cpu` | `cpu.max` | Agent is throttled — still runs but at limited CPU bandwidth |

**CPU limit format**: `"QUOTA PERIOD"` in microseconds. The ratio `QUOTA/PERIOD` gives the number of CPU cores. Examples:
- `"100000 100000"` = 1 core (100% of one CPU)
- `"200000 100000"` = 2 cores
- `"50000 100000"` = 0.5 cores (half a CPU)

---

## guardian-ctl: Managing Running Agents

`guardian-ctl` is a CLI tool that communicates with the running Guardian daemon to manage cgroup-based agents.

### Listing Agents

```bash
sudo guardian-ctl list
```

Output:
```
NAME                 PROCS    CGROUP                                   ID       UPTIME
--------------------------------------------------------------------------------------
aider                3        guardian/aider-12345                      789456   32m 15s
codex                1        guardian/codex-67890                      123789   5m 42s
```

### Stopping Agents

```bash
sudo guardian-ctl stop --name aider
```

This sends `SIGTERM` to every process in the agent's cgroup, then cleans up the cgroup directory and removes the agent from BPF maps.

### Temporary Access Grants

Sometimes an agent needs temporary access to a sensitive resource — for example, reading AWS credentials during a deployment, or accessing an SSH key for a git push.

```bash
# Grant access to AWS credentials for 5 minutes
sudo guardian-ctl grant --name aider --path "/home/user/.aws/**" --duration 300

# Grant access to SSH key for 60 seconds
sudo guardian-ctl grant --name codex --path "/home/user/.ssh/id_rsa" --duration 60
```

After the duration expires, the allow rule is automatically removed from the kernel BPF maps. Access is blocked again without any manual intervention.

**How temporary grants work internally:**
1. `guardian-ctl` sends a grant request to the daemon via Unix socket
2. The daemon adds the path to the ALLOW_EXACT or ALLOW_PREFIXES BPF map
3. The daemon stores the grant with an expiry timestamp
4. A background task checks every 5 seconds and removes expired grants
5. Once removed from the BPF map, the kernel blocks access again immediately

---

## Alerting & Integration (Phase 4)

Phase 4 adds structured logging, real-time notifications, and observability to Guardian Shell. All alerting is configured in the `[alerting]` section of your config file. The entire section is optional — existing configs work unchanged.

### Alerting Configuration

Add an `[alerting]` section to your `config.toml`:

```toml
[alerting]
min_severity = "warning"         # Only alert on "warning" and "critical" events
dedup_window_seconds = 300       # Suppress identical alerts within 5 minutes
rate_limit_per_minute = 100      # Max 100 alerts per minute across all outputs
```

| Field | Default | Description |
|-------|---------|-------------|
| `min_severity` | `"warning"` | Global filter: `"info"` (all events), `"warning"` (denials), `"critical"` (blocks only) |
| `dedup_window_seconds` | `300` | Suppress repeated identical alerts within this window. Set to `0` to disable. |
| `rate_limit_per_minute` | `100` | Cap total alert dispatches per minute (prevents storms) |

**Severity levels:**

| Level | When | Volume |
|-------|------|--------|
| `info` | File access allowed, exec allowed | High (every event) |
| `warning` | File access denied in monitor mode, exec denied | Medium |
| `critical` | File access blocked in enforce mode | Low (policy violations only) |

### JSON Logging for SIEM

Write structured JSON events to a file for ingestion by Elasticsearch, Splunk, Loki, or any SIEM:

```toml
[alerting.json_log]
enabled = true
path = "/var/log/guardian/events.json"  # Omit path for stdout output
max_size_mb = 100                       # Rotate at 100 MB
max_files = 5                           # Keep 5 rotated files
```

Each line is a self-contained JSON object (JSONL format):

```json
{"timestamp":"2026-03-10T14:30:00.123456Z","severity":"critical","event_type":"file_access","action":"blocked","agent":{"name":"claude-code","identity":"cgroup","pid":12345,"comm":"cat"},"file":{"path":"/etc/shadow","flags":"READ"},"policy":{"mode":"enforce"},"host":{"hostname":"myhost"}}
```

**Log rotation** happens automatically when the file exceeds `max_size_mb`. Files are rotated as `events.json.1`, `events.json.2`, etc., up to `max_files`.

**Querying with jq:**

```bash
# Show all blocked events
jq 'select(.action == "blocked")' /var/log/guardian/events.json

# Count events per agent
jq -s 'group_by(.agent.name) | map({agent: .[0].agent.name, count: length})' /var/log/guardian/events.json

# Live tail of critical events
tail -f /var/log/guardian/events.json | jq 'select(.severity == "critical")'
```

### Webhook Alerts

Send alerts to any HTTP endpoint (SIEM, PagerDuty, custom API):

```toml
[alerting.webhook]
enabled = true
url = "https://siem.example.com/api/v1/events"
auth_header = "Bearer your-api-token"    # Optional Authorization header
min_severity = "warning"                  # Only send warnings and critical

# Optional custom headers
[alerting.webhook.headers]
X-Source = "guardian-shell"
X-Environment = "production"
```

The webhook sends an HTTP POST with a JSON body containing all event fields (timestamp, severity, agent, path, action, etc.). The request includes a 10-second timeout.

### Slack Notifications

Send richly-formatted alerts to a Slack channel:

```toml
[alerting.slack]
enabled = true
webhook_url = "https://hooks.slack.com/services/T.../B.../xxx"
channel = "#security-alerts"     # Optional channel override
min_severity = "critical"        # Only critical events
```

**Setting up Slack:**
1. Go to [api.slack.com/apps](https://api.slack.com/apps) → Create New App
2. Enable "Incoming Webhooks" → Add to Workspace
3. Copy the webhook URL into `webhook_url`

Messages use Slack Block Kit with a color-coded sidebar (red=critical, yellow=warning, blue=info) and structured fields showing agent name, event type, path, and PID.

### Email Notifications

Send email alerts via SMTP:

```toml
[alerting.email]
enabled = true
smtp_host = "smtp.gmail.com"
smtp_port = 587                          # STARTTLS
username = "alerts@example.com"
password = "app-password-here"           # Use app password, not account password
from = "Guardian Shell <guardian@example.com>"
to = ["security-team@example.com", "oncall@example.com"]
min_severity = "critical"
```

Emails include a structured plain-text body with severity, event type, agent, path, PID, and timestamp. The subject line includes the severity level and file path for quick scanning.

**Gmail setup:** Use an [App Password](https://support.google.com/accounts/answer/185833) (not your Google account password). Enable 2-Step Verification first.

**Security note:** The SMTP password is stored in plaintext in the config file. Protect the config with file permissions:
```bash
sudo chown root:root /etc/guardian/config.toml
sudo chmod 600 /etc/guardian/config.toml
```

### Prometheus Metrics

Expose event counters via an HTTP `/metrics` endpoint:

```toml
[alerting.prometheus]
enabled = true
listen_address = "127.0.0.1:9090"
endpoint = "/metrics"
```

**Exposed metrics:**

| Metric | Labels | Description |
|--------|--------|-------------|
| `guardian_guardian_file_events_total` | `agent`, `action` | Total file access events |
| `guardian_guardian_exec_events_total` | `agent`, `action` | Total exec events |
| `guardian_guardian_ebpf_events_lost_total` | — | Events lost from perf buffer |
| `guardian_guardian_alerts_sent_total` | `output`, `status` | Alerts sent per output |
| `guardian_guardian_alerts_dropped_total` | — | Alerts dropped (channel full) |

**Querying:**

```bash
curl http://127.0.0.1:9090/metrics
```

**Grafana integration:** Add `http://guardian-host:9090` as a Prometheus data source, then create dashboards:

```promql
# Policy violations per minute
rate(guardian_guardian_file_events_total{action="blocked"}[5m]) * 60

# Alert delivery success rate
sum(rate(guardian_guardian_alerts_sent_total{status="success"}[5m]))
/ sum(rate(guardian_guardian_alerts_sent_total[5m]))
```

### Alert Deduplication & Rate Limiting

Guardian Shell prevents alert storms with two mechanisms:

**Deduplication:** If the same `(agent, event_type, path, action)` tuple fires again within `dedup_window_seconds`, the duplicate is suppressed. This prevents a polling loop hitting a denied path from generating thousands of identical alerts.

**Rate limiting:** A sliding 1-minute window caps total alerts to `rate_limit_per_minute`. Once the cap is hit, remaining events in that minute are dropped (but still counted in Prometheus metrics).

Both mechanisms apply globally before per-output dispatch. Prometheus counters are always updated regardless of dedup/rate limiting.

### Config Validation

Validate your config file without starting the daemon:

```bash
sudo target/release/guardian --config config.toml --validate-config
```

Output:
```
[INFO  guardian] Configuration is valid.
[INFO  guardian] Alerting: configured
[INFO  guardian]   JSON log: enabled
[INFO  guardian]   Prometheus: enabled
```

Checks include:
- TOML syntax and required fields
- Valid severity values (`info`/`warning`/`critical`)
- Enabled outputs have required fields (webhook URL, SMTP host, etc.)
- URL format warnings (missing `http://` or `https://`)
- Overly permissive allow patterns

Useful in CI/CD pipelines and before deploying config changes.

### Config Hot-Reload (SIGHUP)

Reload agent policies without restarting the daemon:

```bash
sudo kill -HUP $(pidof guardian)
```

The daemon re-reads and validates the config file. On success:
```
[INFO  guardian] SIGHUP received — reloading configuration...
[INFO  guardian] Configuration reloaded: 2 agent(s), mode=enforce
```

On failure (invalid config), the previous config is kept:
```
[ERROR guardian] Config reload failed (keeping previous config): ...
```

**What reloads:** Agent policies (file access, exec policies), agent list.

**What requires restart:** Alerting output settings (URLs, credentials), enforcement mode, eBPF programs.

### Preset Configurations

Four ready-to-use configs are in `configs/`:

```bash
# Quick testing — monitor only, no alerting
sudo target/release/guardian --config configs/minimal.toml

# Production — enforce mode, JSON log + Prometheus
sudo target/release/guardian --config configs/recommended.toml

# Maximum security — enforce mode, all alerting outputs
sudo target/release/guardian --config configs/strict.toml

# Development — monitor mode, JSON to stdout, verbose
sudo target/release/guardian --config configs/development.toml
```

| Preset | Mode | Default | Alerting | Use Case |
|--------|------|---------|----------|----------|
| `minimal.toml` | monitor | deny | None | Quick testing |
| `recommended.toml` | enforce | deny | JSON log + Prometheus | Production |
| `strict.toml` | enforce | deny | JSON log + Prometheus (+ commented webhook/Slack/email) | Maximum security |
| `development.toml` | monitor | allow | JSON to stdout + Prometheus + Dashboard | Debugging |

---

## Web Dashboard (Phase 5)

Guardian Shell includes an embedded web dashboard that provides full application control from your browser — real-time event monitoring, agent management, policy editing, and alert configuration.

### Enabling the Dashboard

Add a `[dashboard]` section to your config:

```toml
[dashboard]
enabled = true
listen_address = "127.0.0.1:8080"   # default
```

The dashboard starts as an additional tokio task inside the daemon. No separate process, no additional binary — it's part of the same `guardian` executable.

```bash
# Start the daemon (dashboard starts automatically)
sudo RUST_LOG=info target/release/guardian --config config.toml

# Open in browser
xdg-open http://127.0.0.1:8080
```

On startup you'll see:

```
[INFO  guardian] Starting dashboard on http://127.0.0.1:8080
[INFO  guardian::dashboard] Dashboard available at http://127.0.0.1:8080
```

### Dashboard Pages

The dashboard has six pages accessible from the sidebar navigation:

| Page | Path | Description |
|------|------|-------------|
| **Overview** | `/` | Status cards (mode, agents, events, blocked) + recent events via SSE |
| **Live Events** | `/events` | Full real-time event stream with severity/action filtering |
| **Agents** | `/agents` | Configured agents table + active cgroup agents with stop/grant |
| **Policy Editor** | `/policy` | Per-agent file access and exec policy editing |
| **Alert Config** | `/alerts` | Toggle and configure all alerting outputs |
| **Metrics** | `/metrics` | Prometheus metrics endpoint (text format) |

#### Overview Page

The landing page shows four auto-refreshing status cards:
- **Mode**: `enforce` (red) or `monitor` (blue)
- **Configured Agents**: Total count with active cgroup count
- **File Events**: Total file events from Prometheus counters
- **Blocked**: Total blocked events (enforce mode)

Below the cards, a live event table shows the last 50 events via SSE — events appear instantly as they occur, with no page refresh needed.

#### Live Events Page

A full-screen real-time event feed with client-side filtering:

- **Severity filter**: All / Info / Warning / Critical
- **Action filter**: All / Allow / Deny / Blocked
- **Clear button**: Reset the event buffer
- **Event counter**: Shows total buffered events

Each event row shows: timestamp (ms precision), severity, agent name, event type, action, PID, comm, path, and access mode. The page buffers up to 500 events client-side.

### Live Event Stream (SSE)

The dashboard uses **Server-Sent Events (SSE)** for real-time event delivery. Events flow from the eBPF kernel hook through the alerting pipeline to your browser:

```
eBPF event → perf buffer → event processor → AlertSender.send()
                                                  │
                                                  ├─► broadcast channel ──► SSE endpoint
                                                  │                            │
                                                  │                     EventSource (browser)
                                                  │
                                                  └─► mpsc channel ──► AlertManager
```

The SSE endpoint is at `/events/stream`. Each event is sent as a JSON-encoded `AlertEvent`:

```
event: event
data: {"timestamp":"2026-03-10T14:30:00Z","severity":"critical","event_type":"file_access","action":"blocked","agent_name":"claude-code","pid":12345,"comm":"cat","path":"/etc/shadow","access_mode":"READ","identity_method":"cgroup","policy_mode":"enforce"}
```

Heartbeats are sent every 15 seconds to keep connections alive through proxies. If a client falls behind, missed events are silently skipped (no backpressure on event producers).

You can also consume the SSE stream programmatically:

```bash
# Watch events via curl
curl -N http://127.0.0.1:8080/events/stream

# Parse with jq
curl -sN http://127.0.0.1:8080/events/stream | \
  grep '^data:' | sed 's/^data: //' | jq .
```

### Managing Agents from Dashboard

The **Agents** page (`/agents`) shows two tables:

**Configured Agents** — all agents from `config.toml`:
- Name, identity method (comm/cgroup), default action, rule counts, exec policy status

**Active Cgroup Agents** — agents registered via `guardian-launch`:
- Name, cgroup path, cgroup ID, process count, uptime
- **Stop** button: sends SIGTERM to all processes in the cgroup (with confirmation dialog)
- **Grant** button: opens a form to grant temporary access to a path with a duration in seconds

These actions are equivalent to `guardian-ctl stop` and `guardian-ctl grant` but accessible from the browser.

### Editing Policies from Dashboard

The **Policy Editor** page (`/policy`) provides a visual editor for each agent's security policy:

- Accordion view — one collapsible section per agent
- **File Access Policy**: default action dropdown, allow rules textarea, deny rules textarea
- **Exec Policy**: default action, allow/deny rules (if configured)
- **Save** button per agent

When you save:
1. The in-memory config is updated immediately
2. The full config is written to disk as valid TOML
3. A success/error notification appears

**Important**: Policy changes affect the userspace config (monitor-mode decisions) immediately. To apply changes to kernel-side BPF enforcement maps, click **Reload Config** in the sidebar or restart the daemon.

### Configuring Alerts from Dashboard

The **Alert Config** page (`/alerts`) lets you configure all alerting outputs:

**Global Settings:**
- Minimum severity (info / warning / critical)
- Dedup window (seconds)
- Rate limit (alerts per minute)

**Output Channels** (each with an enable toggle):
- **JSON Log**: file path
- **Webhook**: endpoint URL
- **Slack**: webhook URL
- **Email**: SMTP host
- **Prometheus**: listen address

Changes are saved to the config file on disk. Note: alerting output changes (webhook URLs, SMTP settings, etc.) require a daemon restart to take effect because the `AlertManager` and its connections are initialized once at startup.

### Dashboard Security

The dashboard listens on **localhost only** (`127.0.0.1:8080`) by default. It has **no authentication** — anyone who can reach the port has full control.

**For remote access**, use a reverse proxy with authentication:

```nginx
server {
    listen 443 ssl;
    server_name guardian.internal;

    auth_basic "Guardian Shell";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        # Required for SSE
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        chunked_transfer_encoding off;
        proxy_buffering off;
        proxy_cache off;
    }
}
```

**Best practices:**
- Never bind the dashboard to `0.0.0.0` without authentication
- Use TLS for remote access (nginx/caddy handles this)
- The config file should be owned by root with `chmod 600` (the dashboard can write to it)
- The dashboard provides the same level of control as `guardian-ctl` + editing `config.toml`

---

## Understanding the Output

### Startup Messages

When Guardian Shell starts successfully, you'll see:

```
[INFO  guardian] Loading configuration from: config.toml
[INFO  guardian] Configuration loaded: 2 agent(s) configured
[INFO  guardian]   Agent 'claude-code': watching process 'claude', default=deny, 8 allow rules, 12 deny rules
[INFO  guardian]   Agent 'python-agent': watching process 'python3', default=deny, 5 allow rules, 8 deny rules
[INFO  guardian] Loading eBPF program from: target/bpfel-unknown-none/release/guardian-ebpf
[INFO  guardian] eBPF program loaded successfully
[INFO  guardian] Watching process name 'claude' for agent 'claude-code'
[INFO  guardian] Watching process name 'python3' for agent 'python-agent'
[INFO  guardian] eBPF program attached to syscalls/sys_enter_openat tracepoint
[INFO  guardian] Setting up event readers for 8 CPUs
[INFO  guardian] ==========================================================
[INFO  guardian] Guardian Shell is running. Monitoring 2 agent(s).
[INFO  guardian] Press Ctrl+C to stop.
[INFO  guardian] ==========================================================
```

### ALLOW Events

Logged at `INFO` level when a file access matches an allow pattern:

```
[INFO  guardian] [ALLOW] agent='claude-code' pid=1234 uid=1000 file='/home/user/project/src/main.rs' mode=READ
[INFO  guardian] [ALLOW] agent='claude-code' pid=1234 uid=1000 file='/tmp/scratch.txt' mode=WRITE|CREATE
```

### DENY Events

Logged at `WARN` level when a file access is denied by policy:

```
# In monitor mode:
[WARN  guardian] [DENY] agent='claude-code' pid=1234 uid=1000 file='/home/user/.ssh/id_rsa' mode=READ (monitoring mode - access was NOT actually blocked)

# In enforce mode:
[WARN  guardian] [DENY] agent='claude-code' pid=1234 uid=1000 file='/home/user/.ssh/id_rsa' mode=READ (BLOCKED)
```

**In monitor mode** (`mode = "monitor"`), `[DENY]` means the access *would be denied* under the policy, but the file access still succeeds. Use this to tune your policy.

**In enforce mode** (`mode = "enforce"`), the kernel blocks the access — the agent's `open()` call returns `EACCES` (permission denied). The file is never opened.

### Event Fields

Each log line contains:

| Field | Description | Example |
|-------|-------------|---------|
| `agent` | Name from config `[[agents]]` section | `claude-code` |
| `pid` | Process ID of the agent | `1234` |
| `uid` | User ID running the agent | `1000` |
| `file` | Absolute path of the file being opened | `/home/user/.ssh/id_rsa` |
| `mode` | How the file is being opened | `READ`, `WRITE`, `RDWR` |

**Access Modes:**

| Mode | Meaning |
|------|---------|
| `READ` | Read-only access (`O_RDONLY`) |
| `WRITE` | Write-only access (`O_WRONLY`) |
| `RDWR` | Read-write access (`O_RDWR`) |
| `CREATE` | File will be created if it doesn't exist (`O_CREAT`) |
| `TRUNC` | File will be truncated to zero length (`O_TRUNC`) |
| `APPEND` | Data will be appended (`O_APPEND`) |

Modes can be combined: `WRITE|CREATE`, `RDWR|TRUNC`, `WRITE|CREATE|APPEND`.

---

## Writing Effective Policies

### Principle of Least Privilege

Always start with `default = "deny"` and explicitly allow only what the agent needs:

```toml
[agents.file_access]
default = "deny"    # Block everything by default
allow = [
    # Only allow what's needed
]
deny = [
    # Extra safety: explicitly deny sensitive paths
    # (deny wins even if a future allow rule accidentally matches)
]
```

Using `default = "allow"` is discouraged. It means any file not explicitly denied is accessible, which makes it easy to miss sensitive paths.

### Common Allow Patterns

Most agents need access to system libraries and their project workspace:

```toml
allow = [
    # Agent's project workspace
    "/home/user/project/**",

    # Temporary files
    "/tmp/**",

    # System libraries (needed by most processes)
    "/lib/**",
    "/lib64/**",
    "/usr/lib/**",
    "/usr/lib64/**",

    # Locale data
    "/usr/share/locale/**",

    # Dynamic linker cache
    "/etc/ld.so.cache",

    # SSL certificates (for HTTPS)
    "/etc/ssl/**",
    "/usr/share/ca-certificates/**",

    # Timezone data
    "/usr/share/zoneinfo/**",

    # DNS resolution
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
]
```

### Recommended Deny Patterns

Always deny access to credentials and sensitive system files, even if an allow pattern might accidentally cover them:

```toml
deny = [
    # SSH keys
    "/home/**/.ssh/**",
    "/root/.ssh/**",

    # Cloud credentials
    "/home/**/.aws/**",
    "/home/**/.azure/**",
    "/home/**/.config/gcloud/**",
    "/home/**/.kube/**",

    # GPG keys
    "/home/**/.gnupg/**",

    # Environment files (often contain secrets)
    "/home/**/projects/**/.env",
    "/home/**/projects/**/.env.local",
    "/home/**/projects/**/.env.production",

    # System credentials
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d/**",

    # Docker socket (container escape risk)
    "/var/run/docker.sock",

    # Kernel internals
    "/boot/**",
    "/proc/kcore",
    "/proc/kallsyms",

    # Guardian Shell's own config (prevent agent from reading its rules)
    "/etc/guardian/**",
]
```

### Per-Agent Policies

Different agents can have different policies. A code editor agent might need broader access than a testing agent:

```toml
[[agents]]
name = "code-editor"
process_name = "claude"

[agents.file_access]
default = "deny"
allow = [
    "/home/user/projects/**",
    "/usr/lib/**",
    "/lib/**",
    "/lib64/**",
    "/tmp/**",
]
deny = [
    "/home/user/projects/**/.env",
    "/home/user/.ssh/**",
]

[[agents]]
name = "test-runner"
process_name = "pytest"

[agents.file_access]
default = "deny"
allow = [
    "/home/user/projects/myapp/tests/**",
    "/home/user/projects/myapp/src/**",
    "/usr/lib/**",
    "/lib/**",
    "/lib64/**",
    "/tmp/**",
]
deny = [
    "/home/user/projects/myapp/.env",
    "/home/user/.ssh/**",
]
```

### Tuning Your Policy

The recommended workflow for setting up a new policy:

1. **Start permissive** - Use `default = "allow"` with your deny list, and run with `RUST_LOG=info`
2. **Observe** - Watch which files the agent accesses during normal operation
3. **Build your allow list** - Add the paths the agent legitimately needs
4. **Switch to deny-default** - Change to `default = "deny"` with your allow list
5. **Watch for false denials** - Look for `[DENY]` events on legitimate files you missed
6. **Iterate** - Add missing allow patterns until the agent works normally with no unexpected denials

```bash
# Step 1-2: Permissive mode, observe everything
sudo RUST_LOG=info target/release/guardian --config permissive.toml

# Step 3-5: Strict mode, watch for false denials
sudo RUST_LOG=info target/release/guardian --config strict.toml

# Tip: Grep for DENY events only
sudo RUST_LOG=info target/release/guardian --config strict.toml 2>&1 | grep DENY
```

---

## Real-World Examples

### Monitoring Claude Code (comm-based)

Claude Code runs as a Node.js process. The simplest setup uses comm-based monitoring:

```toml
[global]
log_level = "info"
mode = "enforce"
socket_path = "/run/guardian.sock"

[[agents]]
name = "claude-code"
process_name = "claude"

[agents.file_access]
default = "deny"
allow = [
    # Claude Code's workspace
    "/home/user/projects/my-app/**",

    # System libraries
    "/lib/**",
    "/lib64/**",
    "/usr/lib/**",
    "/usr/share/**",
    "/etc/ld.so.cache",

    # Temp files
    "/tmp/**",

    # Network configuration (for API calls)
    "/etc/ssl/**",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",

    # Rust/Node toolchain (if agent uses these)
    "/home/user/.cargo/**",
    "/home/user/.rustup/**",
    "/home/user/.nvm/**",
    "/home/user/.npm/**",
]
deny = [
    # Credentials
    "/home/user/.ssh/**",
    "/home/user/.aws/**",
    "/home/user/.gnupg/**",

    # Secrets in the project
    "/home/user/projects/my-app/.env",
    "/home/user/projects/my-app/.env.*",
    "/home/user/projects/my-app/secrets/**",

    # Other projects
    "/home/user/projects/other-app/**",

    # System
    "/etc/shadow",
    "/etc/sudoers",
]
```

### Isolating Aider with Cgroups

[Aider](https://github.com/paul-gauthier/aider) is a popular AI coding assistant that runs as a Python process. Since Python-based agents all show up as `python3` in `/proc/PID/comm`, cgroup isolation is the best way to monitor Aider without false positives from other Python processes.

**Config (`config.toml`):**
```toml
[global]
log_level = "info"
mode = "enforce"
socket_path = "/run/guardian.sock"

[[agents]]
name = "aider"
identity = "cgroup"

[agents.file_access]
default = "deny"
allow = [
    # Aider workspace
    "/home/user/projects/my-app/**",

    # Python runtime
    "/usr/lib/python3/**",
    "/home/user/.local/lib/python3/**",
    "/home/user/.virtualenvs/aider/**",

    # System libraries
    "/lib/**",
    "/lib64/**",
    "/usr/lib/**",
    "/etc/ld.so.cache",

    # Temp files and git
    "/tmp/**",
    "/usr/bin/git",
    "/usr/libexec/git-core/**",
]
deny = [
    "/home/user/.ssh/**",
    "/home/user/.aws/**",
    "/home/user/projects/my-app/.env",
]

[agents.resources]
memory_max = "4G"
pids_max = 200
```

**Launching:**
```bash
# Start Guardian daemon
sudo RUST_LOG=info target/release/guardian --config config.toml

# Launch Aider (in another terminal)
sudo target/release/guardian-launch \
    --name aider \
    --memory 4G \
    --pids 200 \
    -- python3 -m aider --model claude-3.5-sonnet

# Aider is now monitored. Every subprocess it spawns (git, shell commands,
# pip installs) is automatically tracked under the same cgroup policy.
```

**Why this matters:** Aider frequently shells out to `git`, runs shell commands for testing, and may install Python packages. All of these child processes inherit the cgroup — Guardian monitors every single one with no extra configuration.

### Running OpenClaw in a Sandbox

[OpenClaw](https://github.com/openclaw-ai/openclaw) (and similar autonomous AI agents) can execute arbitrary code, browse the web, and interact with the filesystem. These agents need strict sandboxing because they operate with minimal human oversight.

**Config:**
```toml
[[agents]]
name = "openclaw"
identity = "cgroup"

[agents.file_access]
default = "deny"
allow = [
    # Agent's dedicated workspace only
    "/home/user/openclaw-workspace/**",
    "/tmp/**",

    # Python runtime
    "/usr/lib/python3/**",
    "/home/user/.local/lib/python3/**",

    # System libraries
    "/lib/**",
    "/lib64/**",
    "/usr/lib/**",
    "/etc/ld.so.cache",

    # Network (for API calls)
    "/etc/ssl/**",
    "/etc/resolv.conf",
]
deny = [
    # All credentials — no exceptions
    "/home/**/.ssh/**",
    "/home/**/.aws/**",
    "/home/**/.gnupg/**",
    "/home/**/.config/gcloud/**",
    "/home/**/.kube/**",

    # No access to other projects
    "/home/user/projects/**",

    # No system modification
    "/etc/shadow",
    "/etc/sudoers",
    "/var/run/docker.sock",

    # No access to Guardian config
    "/etc/guardian/**",
]

[agents.resources]
memory_max = "2G"     # Tight memory limit
pids_max = 100        # Prevent fork bombs
cpu_max = "100000 100000"  # 1 CPU core max
```

**Launching:**
```bash
sudo target/release/guardian-launch \
    --name openclaw \
    --memory 2G \
    --pids 100 \
    --cpu "100000 100000" \
    -- python3 -m openclaw --workspace /home/user/openclaw-workspace

# If the agent needs temporary access to credentials for a deploy:
sudo target/release/guardian-ctl grant \
    --name openclaw \
    --path "/home/user/.aws/credentials" \
    --duration 120  # 2 minutes, then auto-revoked
```

### Securing OpenAI Codex CLI Agent

[OpenAI Codex CLI](https://github.com/openai/codex) is a terminal-based coding agent that can read, write, and execute code. It runs as a Node.js process, similar to Claude Code, but with broader autonomous capabilities.

**The challenge:** Codex runs as `node` in `/proc/PID/comm` — the same as any Node.js application on your system. Comm-based monitoring would catch every Node process, not just Codex.

**Config:**
```toml
[[agents]]
name = "codex"
identity = "cgroup"

[agents.file_access]
default = "deny"
allow = [
    # Codex workspace
    "/home/user/projects/current/**",

    # Node.js runtime
    "/home/user/.nvm/**",
    "/home/user/.npm/**",
    "/usr/lib/node_modules/**",

    # System libraries
    "/lib/**",
    "/lib64/**",
    "/usr/lib/**",
    "/etc/ld.so.cache",

    # Build tools
    "/usr/bin/git",
    "/usr/bin/make",
    "/usr/bin/gcc",

    # Temp and network
    "/tmp/**",
    "/etc/ssl/**",
    "/etc/resolv.conf",
    "/etc/hosts",
]
deny = [
    "/home/user/.ssh/**",
    "/home/user/.aws/**",
    "/home/user/.gnupg/**",
    "/home/user/projects/current/.env",
    "/home/user/projects/current/**/*.key",
    "/etc/shadow",
]

[agents.resources]
memory_max = "8G"
pids_max = 500
cpu_max = "200000 100000"  # 2 cores
```

**Launching:**
```bash
sudo target/release/guardian-launch \
    --name codex \
    --memory 8G \
    --pids 500 \
    --cpu "200000 100000" \
    -- npx @openai/codex

# The agent can write code, run tests, use git — all within its allowed paths.
# Any attempt to read SSH keys or AWS credentials is blocked at the kernel level.
```

### Multiple LLM Agents Side by Side

A common scenario: you're running Aider on one project and Codex on another, simultaneously. Without cgroup isolation, both Python/Node processes would be indistinguishable or receive the same policy.

**Config:**
```toml
[global]
log_level = "info"
mode = "enforce"
socket_path = "/run/guardian.sock"

# Agent 1: Aider on project A (cgroup-based)
[[agents]]
name = "aider"
identity = "cgroup"

[agents.file_access]
default = "deny"
allow = [
    "/home/user/projects/frontend/**",
    "/usr/lib/python3/**",
    "/home/user/.local/lib/python3/**",
    "/lib/**",
    "/lib64/**",
    "/usr/lib/**",
    "/tmp/**",
]
deny = [
    "/home/user/projects/frontend/.env",
    "/home/user/.ssh/**",
]

# Agent 2: Codex on project B (cgroup-based)
[[agents]]
name = "codex"
identity = "cgroup"

[agents.file_access]
default = "deny"
allow = [
    "/home/user/projects/backend/**",
    "/home/user/.nvm/**",
    "/lib/**",
    "/lib64/**",
    "/usr/lib/**",
    "/tmp/**",
]
deny = [
    "/home/user/projects/backend/.env",
    "/home/user/.ssh/**",
]

# Agent 3: Claude Code (comm-based — simple, no launcher needed)
[[agents]]
name = "claude-code"
process_name = "claude"

[agents.file_access]
default = "deny"
allow = ["/home/user/projects/infra/**", "/tmp/**", "/usr/lib/**", "/lib/**", "/lib64/**"]
deny = ["/home/user/.ssh/**", "/home/user/.aws/**"]
```

**Launching (two terminals):**
```bash
# Terminal 1: Launch Aider on the frontend project
sudo target/release/guardian-launch --name aider --memory 4G \
    -- python3 -m aider --model claude-3.5-sonnet

# Terminal 2: Launch Codex on the backend project
sudo target/release/guardian-launch --name codex --memory 8G \
    -- npx @openai/codex

# Terminal 3: Claude Code runs directly (comm-based, no launcher needed)
claude

# Check all running agents:
sudo target/release/guardian-ctl list
```

Each agent can only access its own project directory. Aider cannot read backend code, Codex cannot read frontend code, and neither can read SSH keys or cloud credentials.

### Strict Lockdown Policy

Minimal access for a highly restricted agent:

```toml
[[agents]]
name = "restricted-agent"
process_name = "agent"

[agents.file_access]
default = "deny"
allow = [
    # Only its own workspace, nothing else
    "/home/user/sandbox/**",
]
deny = [
    # Deny secrets even within the sandbox
    "/home/user/sandbox/**/.env",
    "/home/user/sandbox/**/credentials*",
    "/home/user/sandbox/**/*.key",
    "/home/user/sandbox/**/*.pem",
]
```

### Permissive Audit Policy

For initial auditing to see what an agent accesses:

```toml
[[agents]]
name = "audit-agent"
process_name = "agent"

[agents.file_access]
default = "allow"
allow = []
deny = [
    # Only flag access to the most sensitive paths
    "/home/**/.ssh/**",
    "/home/**/.aws/**",
    "/home/**/.gnupg/**",
    "/etc/shadow",
    "/etc/sudoers",
]
```

---

## How It Works

### Architecture Overview

```
                        USER SPACE
 ┌──────────────────────────────────────────────────────────────────┐
 │                                                                  │
 │   guardian-launch                    Guardian Daemon              │
 │   ┌────────────────┐     IPC        ┌──────────────────────┐    │
 │   │ 1. Create cgroup├──────────────>│ Unix socket listener │    │
 │   │ 2. Set limits   │  register     │ /run/guardian.sock    │    │
 │   │ 3. Register     │<─────────────┤                      │    │
 │   │ 4. Move to cgrp │   ACK        │ Populates BPF maps:  │    │
 │   │ 5. exec(agent)  │              │  WATCHED_CGROUPS     │    │
 │   └────────────────┘              │  WATCHED_COMMS       │    │
 │                                    │  ENFORCE_CGROUPS     │    │
 │   guardian-ctl                      │  ALLOW/DENY rules    │    │
 │   ┌────────────────┐     IPC        │                      │    │
 │   │ list / stop /  ├──────────────>│ Background tasks:    │    │
 │   │ grant          │               │  - Cgroup cleanup    │    │
 │   └────────────────┘              │  - Grant expiry      │    │
 │                                    │  - PID rescan        │    │
 │   Cgroup Hierarchy:                └──────────┬───────────┘    │
 │   /sys/fs/cgroup/guardian/                      │                │
 │   ├── aider-1234/     ← PID 1234, 1235        │                │
 │   └── codex-5678/     ← PID 5678              │                │
 │                                                │                │
 │   Alerting Subsystem (Phase 4):                │                │
 │   ┌──────────────────────────────────────┐     │                │
 │   │ Event Processors  ──► AlertSender    │     │                │
 │   │   ├► Prometheus counters (sync)      │     │                │
 │   │   ├► broadcast channel ──► SSE ──────┼─────┼─► Browser      │
 │   │   └► mpsc channel ──► AlertManager   │     │                │
 │   │        ├► JSON Log (file rotation)   │     │                │
 │   │        ├► Webhook (HTTP POST)        │     │                │
 │   │        ├► Slack (Block Kit)          │     │                │
 │   │        └► Email (SMTP)              │     │                │
 │   └──────────────────────────────────────┘     │                │
 │                                                │                │
 │   Dashboard (Phase 5):                         │                │
 │   ┌──────────────────────────────────────┐     │                │
 │   │ axum HTTP :8080                      │     │                │
 │   │   /          Overview + SSE events   │     │                │
 │   │   /events    Live event stream       │     │                │
 │   │   /agents    Agent mgmt (stop/grant) │     │                │
 │   │   /policy    Policy editor           │     │                │
 │   │   /alerts    Alert config            │     │                │
 │   │   /metrics   Prometheus endpoint     │     │                │
 │   └──────────────────────────────────────┘     │                │
 │                                                │                │
 ├════════════════════════════════════════════════╪════════════════┤
 │                                                │                │
 │                        KERNEL SPACE            │                │
 │                                                │                │
 │   eBPF Programs                                │                │
 │   ┌─────────────────────────────────────────────────────────┐  │
 │   │ sys_enter_openat tracepoint:                            │  │
 │   │   cgroup_id = bpf_get_current_cgroup_id()               │  │
 │   │   if WATCHED_CGROUPS[cgroup_id]       ← Priority 1     │  │
 │   │   OR WATCHED_TGIDS[tgid]              ← Priority 2     │  │
 │   │   OR WATCHED_COMMS[comm]              ← Priority 3     │  │
 │   │     → capture event, evaluate policy, set PENDING_DENY  │  │
 │   │                                                          │  │
 │   │ LSM file_open:                                           │  │
 │   │   if PENDING_DENY[pid_tgid] → return -EACCES (blocked) │  │
 │   │                                                          │  │
 │   │ sched_process_fork: child inherits cgroup automatically  │  │
 │   │ sched_process_exit: cleanup CHILD_PIDS                   │  │
 │   └─────────────────────────────────────────────────────────┘  │
 └──────────────────────────────────────────────────────────────────┘
```

### eBPF and Tracepoints

**eBPF** (extended Berkeley Packet Filter) lets you run sandboxed programs inside the Linux kernel. The kernel's BPF verifier checks every program before loading to ensure it:
- Cannot crash the kernel
- Cannot enter infinite loops
- Cannot access invalid memory
- Always terminates

Guardian Shell uses multiple eBPF attachment points:
- **`sys_enter_openat` tracepoint**: Fires on every file open — captures the event and evaluates policy
- **`file_open` LSM hook**: Blocks denied access by returning `-EACCES` (enforce mode)
- **`sched_process_fork`**: Tracks child processes spawned by monitored agents
- **`sched_process_exit`**: Cleans up tracking data when processes exit
- **`sys_enter_execve` tracepoint**: Monitors command execution by agents

### 3-Tier Agent Identification

The eBPF program checks three levels of identity, from strongest to weakest:

```
1. CGROUP ID (Phase 3)    ← cannot be spoofed, kernel-enforced
   bpf_get_current_cgroup_id() → lookup in WATCHED_CGROUPS map

2. TGID / Child PID (Phase 2)  ← tracks process tree
   WATCHED_TGIDS map + CHILD_PIDS map

3. COMM NAME (Phase 1)   ← fallback, can be spoofed
   bpf_get_current_comm() → lookup in WATCHED_COMMS map
```

If any tier matches, the process is monitored. Cgroup-based agents (launched via `guardian-launch`) are identified by tier 1 — the strongest identity that cannot be spoofed by any unprivileged process.

### Event Pipeline

1. **Kernel**: Process calls `openat()` to open a file
2. **Kernel**: `sys_enter_openat` tracepoint fires
3. **Kernel**: eBPF checks cgroup ID → TGID → comm name (3-tier identification)
4. **Kernel**: If watched, evaluates deny/allow rules in-kernel
5. **Kernel**: If denied in enforce mode, marks `PENDING_DENY` map
6. **Kernel**: `file_open` LSM hook reads `PENDING_DENY` → returns `-EACCES` to block access
7. **Kernel**: Event is written to per-CPU perf ring buffer
8. **Userspace**: Async task reads event from perf buffer
9. **Userspace**: Decision is logged as `[ALLOW]` or `[DENY]` (stderr)
10. **Userspace** (Phase 4): AlertEvent is created and sent to AlertManager
11. **Userspace** (Phase 4): Prometheus counters updated synchronously
12. **Userspace** (Phase 4): AlertManager applies dedup/throttle → dispatches to JSON log, webhook, Slack, email
13. **Userspace** (Phase 5): AlertEvent broadcast to SSE subscribers → delivered to dashboard in browser

---

## LLM Agent Security: Why This Matters

Modern LLM-based coding agents are powerful but fundamentally operate by executing code on your machine. Here's why Guardian Shell matters for each type of agent:

### The Core Problem

When you run an LLM agent, you're giving an AI system the ability to:
- **Read any file** your user can access (SSH keys, cloud credentials, environment variables)
- **Write and execute arbitrary code** (including malicious payloads)
- **Spawn child processes** (curl, wget, shell scripts) that inherit the same privileges
- **Exfiltrate data** by reading sensitive files and sending them to external APIs

Most agents run as your user with your full permissions. There is no built-in sandbox.

### Agent-Specific Risks

| Agent | Runtime | Identity Problem | Resource Risk | Guardian Solution |
|-------|---------|-----------------|---------------|-------------------|
| **Claude Code** | Node.js (`node`) | Shares name with all Node apps | Moderate — well-behaved | Comm-based monitoring works; cgroup for strict isolation |
| **Aider** | Python (`python3`) | Shares name with ALL Python scripts | Moderate — spawns git/shell | Cgroup isolation required to distinguish from other Python processes |
| **OpenClaw** | Python (`python3`) | Same as Aider — indistinguishable | High — autonomous, runs arbitrary code | Cgroup isolation + strict resource limits essential |
| **OpenAI Codex CLI** | Node.js (`node`) | Shares name with all Node apps | High — executes commands autonomously | Cgroup isolation to separate from other Node processes |
| **AutoGPT / AgentGPT** | Python (`python3`) | Same binary as any Python script | Very high — fully autonomous with minimal oversight | Cgroup + tight memory/CPU/PID limits |
| **Cursor Agent** | Electron (`electron`) | May share name with other Electron apps | Moderate | Comm-based works if unique; cgroup for certainty |

### What Guardian Shell Provides

1. **Visibility**: See every file access in real time — know exactly what the agent is doing
2. **Enforcement**: Block unauthorized file access at the kernel level — the agent's `open()` call fails
3. **Identity**: Unspoofable cgroup identity — the agent cannot disguise itself as another process
4. **Isolation**: Each agent gets its own policy — Aider can't read Codex's project, and vice versa
5. **Resource limits**: Prevent runaway agents from consuming all memory, CPU, or spawning thousands of processes
6. **Temporary access**: Grant time-limited access to sensitive resources with automatic revocation
7. **Alerting**: Real-time notifications via webhook, Slack, and email when policy violations occur
8. **Observability**: Prometheus metrics for dashboards and alerting rules; structured JSON logs for SIEM
9. **Web dashboard**: Real-time event monitoring, policy editing, agent management, and alert configuration from a browser
10. **Zero overhead**: eBPF runs in the kernel — no process wrapping, no ptrace, no container

---

## Troubleshooting

### "Failed to load eBPF program into kernel"

**Cause**: The eBPF program binary is missing, corrupted, or the BPF verifier rejected it.

```bash
# 1. Rebuild the eBPF program (always use --release)
cargo xtask build-ebpf --release

# 2. Verify the binary exists
ls -la target/bpfel-unknown-none/release/guardian-ebpf

# 3. Make sure you're running as root
sudo target/release/guardian --config config.toml
```

### "Failed to attach to sys_enter_openat tracepoint"

**Cause**: Kernel doesn't support BPF tracepoints.

```bash
# Check if the tracepoint exists
ls /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/

# Check kernel config
grep -E 'CONFIG_BPF|CONFIG_FTRACE' /boot/config-$(uname -r)
```

You need `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, and `CONFIG_FTRACE=y`.

### No events appearing

**Cause**: The process name in config doesn't match the actual process comm.

```bash
# Find the correct process name
ps aux | grep <your-agent>
cat /proc/<PID>/comm
```

Use exactly what `/proc/PID/comm` shows as the `process_name` in your config. Remember it's truncated to 15 characters.

### Too many events / system library noise

**Cause**: Every `openat()` call is captured, including system library loads.

Add common system paths to your allow list to reduce noise:

```toml
allow = [
    "/lib/**",
    "/lib64/**",
    "/usr/lib/**",
    "/usr/share/locale/**",
    "/etc/ld.so.cache",
]
```

Or filter the output:

```bash
# Only show DENY events
sudo RUST_LOG=warn target/release/guardian --config config.toml

# Filter out library noise
sudo RUST_LOG=info target/release/guardian --config config.toml 2>&1 | grep -v '/usr/lib\|/lib64\|ld.so'
```

### "Lost N events on CPU X"

**Cause**: The perf ring buffer is full because events are arriving faster than userspace can process them.

This usually happens with very active agents or when monitoring processes that open many files rapidly. The lost events are dropped and won't be logged. In most cases, a few lost events are acceptable. If you're losing many events consistently, consider:
- Monitoring fewer processes
- Running on a system with faster storage (perf buffers are memory-mapped)

### Permission denied

```bash
# Option 1: Run as root
sudo target/release/guardian --config config.toml

# Option 2: Use capabilities (less privileged)
sudo setcap cap_bpf,cap_perfmon+ep target/release/guardian
target/release/guardian --config config.toml
```

### bpf-linker installation fails

```bash
# Install LLVM development headers first
sudo apt install llvm-dev          # Ubuntu/Debian
sudo dnf install llvm-devel        # Fedora
sudo pacman -S llvm                # Arch

# Then retry
cargo install bpf-linker
```

---

## Security Considerations

### What Guardian Shell Protects Against

- **Visibility**: Real-time view of every file an LLM agent opens
- **Audit trail**: Permanent log of all file access with PID, UID, path, and access mode
- **Kernel-level enforcement**: In enforce mode, denied file access is blocked by the kernel (the `open()` syscall returns EACCES)
- **Unspoofable identity**: Cgroup-based agents cannot change or escape their identity
- **Child process tracking**: All child processes (git, curl, shell commands) are automatically monitored
- **Resource exhaustion prevention**: Memory, CPU, and process count limits via cgroups
- **Credential access detection**: Catch and block agents trying to read SSH keys, cloud credentials, or secrets
- **Temporary access control**: Time-limited grants with automatic revocation

### Best Practices

1. **Config file permissions**: Make the config file readable only by root
   ```bash
   sudo chown root:root /etc/guardian/config.toml
   sudo chmod 600 /etc/guardian/config.toml
   ```

2. **Always use `default = "deny"`** — principle of least privilege

3. **Deny credentials explicitly** — even if allow rules shouldn't cover them, add deny rules as defense-in-depth

4. **Review logs regularly** — unexpected DENY events reveal what agents are trying to access

5. **Don't allow `/**`** — this effectively disables all restrictions for that agent

6. **Start Guardian before agents** — ensures no file access is missed

7. **Enable structured logging** — JSON logs provide an audit trail for incident response and compliance

8. **Set up critical alerts** — configure Slack or email for `critical` severity to get notified of enforcement actions in real time

9. **Monitor Prometheus metrics** — track `alerts_dropped` and `events_lost` to ensure no events are silently dropped

10. **Use `--validate-config` in CI/CD** — catch config errors before deploying to production

11. **Secure the dashboard** — bind to localhost only; use a reverse proxy with auth for remote access

12. **Use the dashboard for incident response** — the live events page with filtering makes it easy to investigate policy violations in real time

---

## Known Limitations

| Limitation | Impact | Planned Fix |
|-----------|--------|-------------|
| **Relative paths** | If agent uses relative paths, pattern matching may fail | Future: Full path resolution in eBPF |
| **Only hooks `openat()`** | Doesn't cover `open()`, `openat2()`, `readlink()`, `stat()` | Future: Additional syscall hooks |
| **x86_64 only** | Tracepoint offsets are hardcoded for x86_64 | Future: Architecture-agnostic offset reading |
| **No network monitoring** | Network access by agents is not tracked | Phase 4: Network policy hooks |
| **Exec monitoring is log-only** | Exec events are logged but not blocked | Future: Exec enforcement via LSM |
| **Max 64 deny/allow rules** | Combined across all agents for BPF map size limits | Future: Larger maps or dynamic sizing |
| **Enforcement requires CONFIG_BPF_LSM** | Kernel must have `CONFIG_BPF_LSM=y` and `bpf` in the LSM list | Falls back to monitor-only if unavailable |
| **5-second grant/cleanup granularity** | Temporary grants and cgroup cleanup are checked every 5 seconds | Acceptable for most use cases |
| **Comm-based agents still spoofable** | Process name can be changed via `prctl(PR_SET_NAME)` | Use cgroup-based identity for untrusted agents |
| **SIGHUP doesn't reload alerting outputs** | Changing webhook URLs, Slack tokens, etc. requires daemon restart | Agent policies reload; output config requires restart |
| **No webhook retry** | Failed webhook/Slack/email sends are logged and dropped | Monitor `alerts_sent{status="error"}` metric |
| **Email password in plaintext** | SMTP password stored in config file | Protect config with `chmod 600` |
| **Dashboard has no authentication** | Anyone who can reach the port has full control | Bind to localhost; use reverse proxy with auth |
| **Dashboard CDN dependency** | First load requires internet for TailwindCSS/htmx/Alpine.js | Bundle libraries locally via rust-embed |
| **Policy edits don't update BPF maps** | Kernel enforcement rules unchanged until reload | Use "Reload Config" button or SIGHUP |
| **Config comments lost on dashboard save** | TOML write-back removes original comments | Use version control for config files |

---

## Roadmap

### Phase 1 - File Access Monitoring ✅
- [x] eBPF tracepoint on `sys_enter_openat`
- [x] Process identification by comm name
- [x] TOML-based policy configuration
- [x] Allow/deny path pattern matching with recursive wildcards
- [x] Real-time event logging with PID, UID, path, and access mode
- [x] Per-CPU async event processing

### Phase 2 - Kernel-Level Enforcement ✅
- [x] LSM (Linux Security Module) BPF hooks for actual file access blocking
- [x] `sys_enter_execve` monitoring for command execution logging
- [x] Process tree tracking via `sched_process_fork` / `sched_process_exit`
- [x] Kernel-side policy evaluation with deny/allow rules in BPF maps
- [x] Periodic PID rescanning via tokio interval

### Phase 3 - Cgroup Identity & Access Control ✅
- [x] Cgroup-based agent identification (kernel-enforced, unspoofable)
- [x] `guardian-launch` — launcher that isolates agents in dedicated cgroups
- [x] `guardian-ctl` — CLI for listing, stopping, and managing agents
- [x] Resource limits (memory, CPU, PID count) via cgroup controllers
- [x] Time-based access grants with automatic expiry
- [x] 3-tier eBPF identification (cgroup → TGID → comm)
- [x] Automatic cgroup lifecycle cleanup
- [x] Unix socket IPC protocol for daemon communication
- [x] Backward compatibility with Phase 1/2 comm-based configs

### Phase 4 - Alerting & Integration ✅
- [x] Structured JSON logging (JSONL) with size-based log rotation
- [x] Webhook alerts (HTTP POST with JSON payload, auth headers, custom headers)
- [x] Slack notifications (Block Kit formatting, severity-colored messages)
- [x] Email notifications (async SMTP via STARTTLS)
- [x] Prometheus metrics endpoint (file events, exec events, alerts sent/dropped)
- [x] Alert deduplication (hash-based, configurable time window)
- [x] Alert rate limiting (per-minute cap)
- [x] Config validation CLI (`--validate-config`)
- [x] Config hot-reload via SIGHUP signal
- [x] Preset configuration templates (minimal, recommended, strict, development)

### Phase 5 - Dashboard & UI ✅ (Current)
- [x] Embedded web dashboard (axum + htmx + Alpine.js + TailwindCSS)
- [x] Real-time event streaming via SSE (Server-Sent Events)
- [x] Live event feed with severity/action filtering
- [x] Agent management UI (view, stop cgroup agents, grant temporary access)
- [x] Visual policy editor (per-agent file access and exec rules)
- [x] Alert configuration editor (all outputs togglable from browser)
- [x] Auto-refreshing status overview (mode, agents, events, blocked)
- [x] Config write-back (save changes to disk as TOML)
- [x] Config reload from dashboard (no SIGHUP needed)
- [x] Prometheus metrics integrated into dashboard server
- [x] Single binary deployment (templates compiled in, static files embedded)
