# Guardian Shell - Usage Guide

Guardian Shell is a Linux security tool that monitors and enforces file access policies for LLM agents (Claude Code, OpenAI Codex, Aider, OpenClaw, Cursor, etc.) using eBPF. It hooks into the kernel's file-open syscall, evaluates every file access against your policy rules in real time, and can block unauthorized access at the kernel level.

**Current mode: Phase 10 — Hardened Cgroup Agents (Defense in Depth)**

Guardian Shell now provides ten layers of protection:
- **Phase 1**: Monitor-only file access logging via eBPF tracepoints
- **Phase 2**: Kernel-level enforcement via LSM BPF hooks (blocks denied access)
- **Phase 3**: Unspoofable cgroup-based agent identity, resource limits, launcher wrapper, and time-based access grants
- **Phase 4**: Structured JSON logging, webhook/Slack/email alerts, Prometheus metrics, and config validation
- **Phase 5**: Web dashboard with real-time event streaming, policy editor, agent management, and full application control
- **Phase 6**: Interactive permission requests — agents can ask for temporary access, humans approve/deny via dashboard in real time
- **Phase 7**: Path normalization, openat2 coverage, risk-based approval workflows, exec enforcement, network monitoring, persistent audit trail
- **Phase 8**: Security hardening — inode protection (rename/unlink/hardlink enforcement), io_uring/memfd_create blocking via seccomp, BPF map capacity 1024, path truncation detection, dynamic linker detection, execveat hook, strict enforcement mode, dashboard authentication, risk-based configurable timeouts, CLI permission approval, grant accumulation limits, weighted justification analysis, anomaly detection, fail-closed mode
- **Phase 9**: Network enforcement — LSM `socket_connect` hook for kernel-level connection blocking, port-based deny/allow BPF maps, per-cgroup network defaults
- **Phase 10**: Hardened cgroup agents — Landlock LSM sandbox (inode-level, symlink-immune file access control), expanded seccomp filter (blocks mount/namespace/chroot escape), PR_SET_NO_NEW_PRIVS (prevents SUID escalation), IPC sandbox config delivery, two security tiers (hardened cgroup vs. legacy comm), Landlock TCP port filtering (kernel 6.7+)

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
   - [Requesting Permissions (Phase 6)](#requesting-permissions-phase-6)
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
   - [Permission Requests (Phase 6)](#permission-requests-phase-6)
   - [Dashboard Security](#dashboard-security)
10. [Security Hardening (Phase 8)](#security-hardening-phase-8)
    - [Seccomp Syscall Blocking](#seccomp-syscall-blocking)
    - [Strict Enforcement Mode](#strict-enforcement-mode)
    - [Dashboard Authentication](#dashboard-authentication)
    - [Risk-Based Timeouts](#risk-based-timeouts)
    - [Grant Accumulation Limits](#grant-accumulation-limits)
    - [Fail-Closed Mode](#fail-closed-mode)
    - [CLI Permission Approval](#cli-permission-approval)
    - [Anomaly Detection](#anomaly-detection)
11. [Hardened Cgroup Agents (Phase 10)](#hardened-cgroup-agents-phase-10)
    - [Two Security Tiers](#two-security-tiers)
    - [Landlock Sandbox](#landlock-sandbox)
    - [Expanded Seccomp Hardening](#expanded-seccomp-hardening)
    - [PR_SET_NO_NEW_PRIVS](#pr_set_no_new_privs)
    - [Kernel Requirements for Landlock](#kernel-requirements-for-landlock)
    - [Disabling Sandbox Layers](#disabling-sandbox-layers)
12. [Understanding the Output](#understanding-the-output)
    - [Startup Messages](#startup-messages)
    - [ALLOW Events](#allow-events)
    - [DENY Events](#deny-events)
    - [Event Fields](#event-fields)
13. [Writing Effective Policies](#writing-effective-policies)
    - [Principle of Least Privilege](#principle-of-least-privilege)
    - [Common Allow Patterns](#common-allow-patterns)
    - [Recommended Deny Patterns](#recommended-deny-patterns)
    - [Per-Agent Policies](#per-agent-policies)
    - [Tuning Your Policy](#tuning-your-policy)
14. [Real-World Examples](#real-world-examples)
    - [Monitoring Claude Code (comm-based)](#monitoring-claude-code-comm-based)
    - [Isolating Aider with Cgroups](#isolating-aider-with-cgroups)
    - [Running OpenClaw in a Sandbox](#running-openclaw-in-a-sandbox)
    - [Securing OpenAI Codex CLI Agent](#securing-openai-codex-cli-agent)
    - [Multiple LLM Agents Side by Side](#multiple-llm-agents-side-by-side)
    - [Hardened Aider with Full Sandbox](#hardened-aider-with-full-sandbox)
    - [Strict Lockdown Policy](#strict-lockdown-policy)
    - [Permissive Audit Policy](#permissive-audit-policy)
15. [How It Works](#how-it-works)
    - [Architecture Overview](#architecture-overview)
    - [eBPF and Tracepoints](#ebpf-and-tracepoints)
    - [3-Tier Agent Identification](#3-tier-agent-identification)
    - [Event Pipeline](#event-pipeline)
16. [LLM Agent Security: Why This Matters](#llm-agent-security-why-this-matters)
17. [Troubleshooting](#troubleshooting)
18. [Security Considerations](#security-considerations)
19. [Known Limitations](#known-limitations)
20. [Roadmap](#roadmap)

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

### Option B: Cgroup-based isolation (Phase 3+10 — recommended for production, full defense-in-depth)

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

`guardian-launch` is a launcher binary that starts an LLM agent inside a dedicated Linux cgroup with full defense-in-depth sandboxing. It performs ten steps in sequence:

1. **Creates a cgroup** at `/sys/fs/cgroup/guardian/<agent-name>-<pid>/`
2. **Enables controllers** (memory, PIDs, CPU) in the cgroup hierarchy
3. **Sets resource limits** (memory cap, process count limit, CPU bandwidth)
4. **Gets the cgroup ID** (inode number, which matches `bpf_get_current_cgroup_id()` in the kernel)
5. **Registers with the Guardian daemon** via Unix socket IPC (receives sandbox config)
6. **Moves self into the cgroup**
7. **Sets PR_SET_NO_NEW_PRIVS** — prevents SUID/capability escalation (Phase 10)
8. **Applies Landlock sandbox** — inode-level file access control, symlink-immune (Phase 10)
9. **Applies seccomp filter** — blocks io_uring, memfd, mount, namespace, chroot (Phase 8+10)
10. **exec()'s the agent command** — the launcher process replaces itself with the agent

After step 10, the agent IS the process in the cgroup with all four defense layers active. There is no wrapper overhead. Every child process the agent spawns (bash, git, curl, pip, etc.) automatically inherits the same cgroup, Landlock sandbox, seccomp filter, and NO_NEW_PRIVS flag. No process can escape any of these restrictions.

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
| `--no-landlock` | Disable Landlock sandbox (Phase 10, not recommended) | `--no-landlock` |
| `--no-seccomp-hardened` | Disable expanded seccomp (Phase 10, not recommended) | `--no-seccomp-hardened` |

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

Sometimes an agent needs temporary access to a sensitive resource — for example, reading AWS credentials during a deployment, accessing an SSH key for a git push, or running a specific command like `grep` or `curl`.

**File access grants:**

```bash
# Grant access to AWS credentials for 5 minutes
sudo guardian-ctl grant --name aider --path "/home/user/.aws/**" --duration 300

# Grant access to SSH key for 60 seconds
sudo guardian-ctl grant --name codex --path "/home/user/.ssh/id_rsa" --duration 60
```

After the duration expires, the allow rule is automatically removed from the kernel BPF maps. Access is blocked again without any manual intervention.

**Exec command grants (via dashboard):**

The dashboard's Agents page supports granting temporary exec access from the browser. Click the **Grant** button on any active cgroup agent and select "Exec Command" as the grant type:

- Select **Exec Command** from the Grant Type dropdown
- Enter the command path (e.g., `/usr/bin/grep`)
- Set the duration (default: 600 seconds / 10 minutes)
- Click **Grant Exec Access**

This adds the command to the agent's exec policy allow list for the specified duration. After expiry, the command is automatically removed from the allow list.

**How temporary grants work internally:**
1. `guardian-ctl` sends a grant request to the daemon via Unix socket (or the dashboard sends via HTTP API)
2. For **file grants**: the daemon adds the path to the ALLOW_EXACT or ALLOW_PREFIXES BPF map
3. For **exec grants**: the daemon adds the command to the agent's exec policy allow list in the config
4. The daemon stores the grant with an expiry timestamp
5. A background task checks every 5 seconds and removes expired grants
6. For file grants: once removed from the BPF map, the kernel blocks access again immediately
7. For exec grants: the command is removed from the config allow list, restoring the original policy

### Requesting Permissions (Phase 6)

Phase 6 adds **interactive permission requests** — an agent can ask the daemon for access to a resource, and the request appears as a real-time notification in the web dashboard for a human to approve or deny.

```bash
# Request permission to run curl (waits for human approval)
sudo guardian-ctl request-permission \
  --name my-agent \
  --resource-type exec \
  --path /usr/bin/curl \
  --justification "Need to fetch config from internal API"
```

Output while waiting:
```
Waiting for human approval via dashboard (up to 120s)...
```

If approved:
```
APPROVED: Approved by user (granted for 600s)
```

If denied or timed out:
```
DENIED: Denied by user
```

**Options:**

| Flag | Short | Required | Default | Description |
|------|-------|----------|---------|-------------|
| `--name` | `-n` | Yes | — | Agent name (must match a configured or registered agent) |
| `--resource-type` | `-t` | No | `exec` | Resource type: `file` or `exec` |
| `--path` | `-p` | Yes | — | Resource path (e.g., `/usr/bin/curl`, `/etc/shadow`) |
| `--justification` | `-j` | No | — | Human-readable reason for the request |

**How it works:**

1. `guardian-ctl` sends a `RequestPermission` IPC message to the daemon
2. The daemon creates a pending request with a risk-based timeout (60-300 seconds depending on risk level)
3. A notification banner appears on the dashboard (all pages) via SSE
4. The human sees the agent name, resource path, justification, and a countdown timer
5. The human selects a grant duration (1 min to 1 hour) and clicks **Approve** or **Deny**
6. The daemon sends the decision back to `guardian-ctl`, which prints the result and exits

**Exit codes:**
- `0`: Approved — the agent now has temporary access for the granted duration
- `1`: Denied or timed out — access was not granted

**Using in scripts:**

```bash
# Request permission, then proceed only if approved
if sudo guardian-ctl request-permission \
    --name my-agent -t exec -p /usr/bin/curl \
    -j "Fetching deployment config"; then
  curl https://internal-api/config > /tmp/config.json
else
  echo "Permission denied, skipping curl"
fi
```

**Requirements:**
- The web dashboard must be enabled (`[dashboard] enabled = true` in config) OR use `guardian-ctl approve/deny` from the CLI
- If the dashboard is disabled and no CLI approval is provided, requests are auto-denied after timeout
- The request times out with an automatic denial if no human responds (timeout varies by risk level: 60s low, 120s medium, 180s high, 300s critical)

### Managing Permissions via CLI (Phase 8)

Phase 8 adds CLI-based permission management, enabling headless environments (no dashboard) to handle permission requests:

```bash
# List all pending permission requests
sudo guardian-ctl pending
```

Output:
```
ID     AGENT              TYPE     RESOURCE                                 RISK       AGE
------------------------------------------------------------------------------------------
42     my-agent           exec     /usr/bin/curl                            medium     15s
       Justification: Need to fetch config from internal API
3      aider              file     /home/user/.aws/credentials              high       45s
       Justification: Deploying to production
```

```bash
# Approve a request (grant access for 5 minutes)
sudo guardian-ctl approve --id 42 --duration 300

# Deny a request with a reason
sudo guardian-ctl deny --id 42 --reason "curl access not authorized"
```

| Command | Flags | Description |
|---------|-------|-------------|
| `pending` | — | List all pending permission requests with risk level and age |
| `approve` | `--id`, `--duration` (default: 300s) | Approve a pending request by ID with grant duration |
| `deny` | `--id`, `--reason` (optional) | Deny a pending request by ID with optional reason |

The `approve` and `deny` commands have the same effect as clicking Approve/Deny in the dashboard — they create temporary grants, update the rate limiter, persist to the SQLite audit trail, and broadcast the resolution via SSE.

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

The dashboard has seven pages accessible from the sidebar navigation:

| Page | Path | Description |
|------|------|-------------|
| **Overview** | `/` | Status cards (mode, agents, events, blocked) + recent events via SSE |
| **Live Events** | `/events` | Full real-time event stream with severity/action filtering |
| **Agents** | `/agents` | Configured agents table + active cgroup agents with stop/grant |
| **Policy Editor** | `/policy` | Per-agent file access and exec policy editing |
| **Requests** | `/requests` | Permission request management — pending requests + resolved history (Phase 6) |
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
- **Grant** button: opens a form to grant temporary access with two grant types:
  - **File Access**: grants access to a file path (added to BPF allow maps). Example: `/home/user/.aws/**` for 5 minutes.
  - **Exec Command**: grants permission to run a command (added to agent's exec policy allow list). Example: `/usr/bin/grep` for 10 minutes.
  - Default duration is 600 seconds (10 minutes). After the duration expires, the grant is automatically removed.

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

### Permission Requests (Phase 6)

Phase 6 adds interactive permission requests to the dashboard. When an agent requests permission (via `guardian-ctl request-permission`), a notification banner appears at the top of **every dashboard page** in real time.

#### Permission Banner

The banner shows:
- **Agent name** — which agent is asking
- **Resource type** — `EXEC` (purple badge) or `FILE` (blue badge)
- **Resource path** — the exact path being requested (e.g., `/usr/bin/curl`)
- **Justification** — the agent's reason for the request
- **Countdown timer** — seconds remaining before auto-denial (120s)
- **Duration selector** — how long to grant access (1 min / 5 min / 10 min / 30 min / 1 hour)
- **Approve** and **Deny** buttons

The banner slides in with an animation and is visible on every page — you don't need to navigate to a specific page to see permission requests.

#### Requests Page

The **Requests** page (`/requests`) provides a dedicated view with two tables:

**Pending Requests:**
- All currently-waiting permission requests with full details
- Approve/deny actions with duration selector
- Shows elapsed waiting time vs timeout

**Resolved History:**
- Last 100 resolved requests (approved, denied, or timed out)
- Shows decision, reason, and grant duration
- Scrollable for audit review

#### Sidebar Badge

The "Requests" navigation link shows a yellow badge with the count of pending requests. The badge appears/disappears in real time as requests arrive and are resolved.

#### How It Works

1. Agent sends `guardian-ctl request-permission --name my-agent --path /usr/bin/curl`
2. The daemon broadcasts a permission event via SSE to all connected browsers
3. The Alpine.js store on every page receives the event and shows the banner
4. The human clicks Approve (with selected duration) or Deny
5. The dashboard sends the decision via API, the daemon relays it to the waiting agent
6. The agent receives the response and either proceeds (approved) or handles denial

Requests that are not resolved within 120 seconds are automatically denied.

### Dashboard Security

The dashboard listens on **localhost only** (`127.0.0.1:8080`) by default.

**Built-in authentication (Phase 8):**

Phase 8 adds optional Bearer token authentication. Add `auth_token` to your dashboard config:

```toml
[dashboard]
enabled = true
listen = "127.0.0.1:8080"
auth_token = "your-secret-token-here"
```

With `auth_token` set, all requests (except `/static/`) require authentication via:
- `Authorization: Bearer <token>` header, or
- `?token=<token>` query parameter (note: token may leak in referer headers and browser history)

Without `auth_token`, the dashboard runs without authentication (backward compatible).

**Security features (when `auth_token` is set):**
- **Constant-time token comparison** — prevents timing attacks that deduce token characters
- **Auth rate limiting** — after 10 consecutive failures, dashboard locks out for 60 seconds (HTTP 429)
- **`/metrics` requires auth** — Prometheus scrapers must include the Bearer token to prevent information disclosure

**For remote access**, use a reverse proxy with TLS:

```nginx
server {
    listen 443 ssl;
    server_name guardian.internal;

    # Optional: Add nginx-level auth on top of Guardian's built-in auth
    # auth_basic "Guardian Shell";
    # auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header Authorization $http_authorization;
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
- Always set `auth_token` when binding to non-localhost addresses
- Use TLS for remote access (nginx/caddy handles this)
- The config file should be owned by root with `chmod 600` (contains the auth token)
- The dashboard provides the same level of control as `guardian-ctl` + editing `config.toml`
- Configure Prometheus scrapers to include `Authorization: Bearer <token>` header when `auth_token` is set

---

## Security Hardening (Phase 8)

Phase 8 implements 16 security fixes addressing known vulnerabilities documented in `docs/security/security-limitations.md`. See `docs/phase_8_implementation.md` for full architectural details.

### Seccomp Syscall Blocking

`guardian-launch` now applies a seccomp BPF filter that blocks dangerous syscalls for all launched agents:

| Blocked Syscall | Number | Why |
|----------------|--------|-----|
| `io_uring_setup` | 425 | io_uring bypasses all eBPF tracepoint monitoring |
| `io_uring_enter` | 426 | io_uring file I/O is invisible to Guardian |
| `io_uring_register` | 427 | io_uring registration for async operations |
| `memfd_create` | 319 | Creates in-memory files for fileless code execution |

Blocked syscalls return `EPERM`. All other syscalls are allowed. The filter is inherited by all child processes. If seccomp is not available, a warning is logged and the agent launches without the filter.

### Strict Enforcement Mode

A new `strict` mode ensures Guardian never runs without enforcement:

```toml
[global]
mode = "strict"  # exit immediately if LSM hooks fail to load
```

| Mode | LSM Failure Behavior |
|------|---------------------|
| `monitor` | No LSM hooks loaded (monitoring only) |
| `enforce` | Warning logged, continues in monitor-only mode |
| `strict` | **Daemon exits with error** — refuses to run without enforcement |

Use `strict` in production where you cannot accept silent degradation to monitoring-only.

### Dashboard Authentication

See [Dashboard Security](#dashboard-security) above. Add `auth_token` to `[dashboard]` config to require Bearer token authentication.

### Risk-Based Timeouts

Permission request timeouts now vary by risk level instead of using a fixed 120-second window:

```toml
[permissions.timeouts]
low = 60        # 1 minute for low-risk (e.g., /tmp files)
medium = 120    # 2 minutes for medium-risk
high = 180      # 3 minutes for high-risk (e.g., SSH keys)
critical = 300  # 5 minutes for critical (e.g., /etc/shadow)
```

If `[permissions.timeouts]` is not configured, the defaults above are used automatically.

### Grant Accumulation Limits

Prevents agents from accumulating unlimited grant time through repeated requests:

```toml
[permissions]
max_grant_total_secs = 3600  # max 1 hour of accumulated grants per resource per 24h
```

When an agent's total accumulated grant time for a specific resource exceeds this limit within a 24-hour window, a warning is logged. This helps detect patient agents that maintain permanent access through repeated short-duration grants.

### Fail-Closed Mode

By default, eBPF errors cause Guardian to allow access (fail-open). For high-security agents, enable fail-closed mode to deny access on any eBPF error:

```toml
[[agents]]
name = "high-security-agent"
identity = "cgroup"
fail_closed = true  # deny on eBPF error instead of allowing

[agents.file_access]
default = "deny"
```

This is a per-agent setting — development agents can remain fail-open while security-critical agents use fail-closed.

### CLI Permission Approval

See [Managing Permissions via CLI (Phase 8)](#managing-permissions-via-cli-phase-8) above. Use `guardian-ctl pending`, `approve`, and `deny` to manage permissions without the dashboard.

### Anomaly Detection

An automated background task runs hourly to detect suspicious approval patterns:

| Pattern | Detection | Threshold |
|---------|-----------|-----------|
| Rubber-stamping | >90% approval rate in 24h | 10+ total requests |
| High-volume agent | Agent submits excessive requests | >20 requests in 24h |
| Persistence attack | Agent denied then approved for same resource | Any occurrence in 24h |

Findings are logged as warnings and dispatched through configured alerting outputs (Slack, webhook, email, JSON log).

---

## Hardened Cgroup Agents (Phase 10)

Phase 10 adds **defense-in-depth** for cgroup-based agents by layering three additional security mechanisms on top of eBPF monitoring. See `docs/phase_10_implementation.md` for full architectural details.

**The problem:** eBPF tracepoints see path strings from userspace, not kernel inodes. This makes eBPF enforcement vulnerable to symlink bypass, TOCTOU races, and io_uring bypass — all of which are architectural and cannot be fixed within eBPF.

**The solution:** Use **Landlock LSM** (inode-level, symlink-immune enforcement) as the primary enforcement layer for cgroup agents. eBPF becomes the audit and visibility layer.

### Two Security Tiers

Phase 10 establishes two explicit security tiers:

| | Tier 1: Hardened Cgroup | Tier 2: Legacy Comm |
|---|---|---|
| **Launch method** | `guardian-launch` | Direct process |
| **Enforcement layers** | Cgroup + Landlock + Seccomp + eBPF | eBPF only |
| **Symlink bypass** | **SOLVED** | Vulnerable |
| **TOCTOU race** | **SOLVED** | Vulnerable |
| **io_uring bypass** | **SOLVED** | Vulnerable |
| **Mount/namespace escape** | **SOLVED** | Vulnerable |
| **SUID escalation** | **SOLVED** | Vulnerable |
| **Network exfiltration** | **SOLVED** (TCP, kernel 6.7+) | Phase 9 only |
| **Recommendation** | Production use | Testing/legacy only |

**For production security, always use cgroup-based agents with `guardian-launch`.**

### Landlock Sandbox

Landlock is a Linux Security Module (kernel 5.13+) that controls file access at the **inode level**. Unlike eBPF tracepoints that see path strings, Landlock checks are performed after the kernel resolves all symlinks, mounts, and path indirection.

**How it defeats symlink attacks:**

```
Without Landlock (eBPF only):
  Agent:  ln -s /etc/shadow /tmp/innocent
  Agent:  cat /tmp/innocent
  eBPF:   openat("/tmp/innocent") → matches /tmp/** → ALLOW
  Result: Agent reads /etc/shadow contents

With Landlock (Phase 10):
  Agent:  ln -s /etc/shadow /tmp/innocent
  Agent:  cat /tmp/innocent
  VFS:    Resolves /tmp/innocent → inode of /etc/shadow
  Landlock: Is /etc/shadow under an allowed hierarchy? → NO
  Result: -EACCES (Permission denied)
```

**Landlock rules are derived automatically from your existing agent config:**

```toml
[[agents]]
name = "my-agent"
identity = "cgroup"

[agents.file_access]
default = "deny"                          # Landlock requires default-deny
allow = ["/tmp/**", "/home/user/project/**"]  # → Landlock PathBeneath rules

[agents.exec]
default = "deny"
allow = ["/usr/bin/python3", "/usr/bin/git"]  # → Landlock Execute rights

[agents.network_policy]
default = "deny"
allow_ports = [443, 53]                       # → Landlock NetPort rules (kernel 6.7+)
```

No additional configuration needed — `guardian-launch` translates your existing file/exec/network policy into Landlock rules automatically.

**Important:** Landlock is inherently default-deny. Agents with `file_access.default = "allow"` cannot use Landlock — the sandbox is skipped with a warning, and the agent falls back to eBPF-only enforcement.

**Important:** Landlock rules are irreversible once applied. Temporary grants via `guardian-ctl grant` only update eBPF maps, not the Landlock sandbox. The Landlock sandbox provides a baseline that cannot be weakened, even by the daemon.

### Expanded Seccomp Hardening

Phase 10 expands the seccomp filter (originally 4 syscalls in Phase 8) to block additional dangerous syscalls:

| Category | Syscalls Blocked | Why |
|----------|-----------------|-----|
| **io_uring** (Phase 8) | `io_uring_setup`, `io_uring_enter`, `io_uring_register` | Bypasses all eBPF tracepoints |
| **memfd** (Phase 8) | `memfd_create` | Fileless code execution |
| **Mount manipulation** (NEW) | `mount`, `umount2` | Mount namespace escape |
| **New mount API** (NEW) | `open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr` | Modern mount API escape |
| **Root escape** (NEW) | `pivot_root`, `chroot` | Container/chroot breakout |
| **Namespace escape** (NEW) | `setns`, `unshare` | Namespace manipulation |

The expanded filter is controlled by `seccomp_hardened` in the sandbox config (default: `true`). The base io_uring + memfd filter is always applied regardless of this setting.

### PR_SET_NO_NEW_PRIVS

Phase 10 sets `PR_SET_NO_NEW_PRIVS` on the agent process before applying Landlock. This prevents:

- **SUID escalation** — setuid binaries (like `sudo`) cannot gain elevated privileges
- **Capability escalation** — file capabilities on binaries are ignored
- **Seccomp bypass** — cannot load a more permissive seccomp filter

The flag is inherited by all child processes and cannot be cleared.

### Kernel Requirements for Landlock

| Kernel Version | Landlock ABI | Filesystem | Network | Notes |
|-------|-----|------------|---------|----------|
| < 5.13 | none | NO | NO | Landlock skipped. eBPF-only. |
| 5.13+ | v1 | YES | NO | Filesystem sandbox active. |
| 5.19+ | v2 | YES + rename/link | NO | Rename/link control added. |
| 6.7+ | v4 | YES | YES (TCP) | Full sandbox: files + network. |

**Check if Landlock is available on your system:**

```bash
# Check LSM list
cat /sys/kernel/security/lsm
# Should include "landlock"

# Check kernel version
uname -r
# 6.7+ for full filesystem + network support
```

Most modern distributions (Ubuntu 22.04+, RHEL 9+, Fedora 36+, Debian 12+) have Landlock support enabled by default. The sandbox gracefully degrades on older kernels — a warning is logged and the agent falls back to eBPF-only enforcement.

### Disabling Sandbox Layers

For debugging or compatibility, individual sandbox layers can be disabled:

```bash
# Disable Landlock (falls back to eBPF-only enforcement)
sudo guardian-launch --name my-agent --no-landlock -- python3 -m aider

# Disable expanded seccomp (only base io_uring/memfd filter applied)
sudo guardian-launch --name my-agent --no-seccomp-hardened -- python3 -m aider
```

These flags are for debugging only. **Do not use them in production.**

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

### Hardened Aider with Full Sandbox

Phase 10's defense-in-depth applied to Aider — Landlock + seccomp + cgroup + eBPF:

**Config:**
```toml
[global]
mode = "enforce"
socket_path = "/run/guardian.sock"

[dashboard]
enabled = true
listen = "127.0.0.1:8080"

[[agents]]
name = "aider"
identity = "cgroup"
fail_closed = true       # deny on any eBPF error

[agents.file_access]
default = "deny"         # required for Landlock sandbox
allow = [
    "/home/user/project/**",
    "/tmp/**",
    "/proc/self/**",
    "/usr/lib/python3/**",
    "/home/user/.local/lib/python3/**",
    "/usr/lib/**", "/lib/**", "/lib64/**",
    "/etc/ssl/**", "/etc/resolv.conf", "/etc/hosts",
    "/usr/libexec/git-core/**",
]
deny = [
    "/home/user/project/.env",
    "/home/user/.ssh/**",
    "/home/user/.aws/**",
]

[agents.exec]
default = "deny"
allow = ["/usr/bin/python3", "/usr/bin/git", "/usr/bin/grep", "/usr/bin/find"]

[agents.network_policy]
default = "deny"
allow_ports = [443, 53]  # HTTPS and DNS only
```

**Launching (all four defense layers activate automatically):**
```bash
sudo target/release/guardian-launch \
    --name aider --memory 4G --pids 200 \
    -- python3 -m aider --model claude-3.5-sonnet

# Output:
# [INFO] PR_SET_NO_NEW_PRIVS set: SUID escalation blocked
# [INFO] Landlock: fully enforced (all requested rights controlled)
# [INFO] Seccomp filter applied: io_uring, memfd, mount, namespace, chroot blocked
```

**What's protected:**

| Attack | Defense Layer | Result |
|--------|-------------|--------|
| `ln -s /etc/shadow /tmp/x && cat /tmp/x` | Landlock (inode-level) | Permission denied |
| `python3 -c "import io_uring"` | Seccomp | EPERM |
| `sudo cat /etc/shadow` | PR_SET_NO_NEW_PRIVS | sudo can't escalate |
| `unshare -n bash` | Seccomp | EPERM |
| `mount -t tmpfs none /tmp` | Seccomp | EPERM |
| `curl http://evil.com:8080` | Landlock (TCP port) | EACCES (port 8080 not allowed) |
| `cat /home/user/.ssh/id_rsa` | Landlock + eBPF | Permission denied (both layers) |

All attempts are also logged by eBPF and visible in the dashboard with risk classification.

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
 │   │ 4. Move to cgrp │  ACK+sandbox │ Populates BPF maps:  │    │
 │   │ 5. NO_NEW_PRIVS │              │  WATCHED_CGROUPS     │    │
 │   │ 6. Landlock     │              │  WATCHED_COMMS       │    │
 │   │ 7. Seccomp      │              │                      │    │
 │   │ 8. exec(agent)  │              │                      │    │
 │   └────────────────┘              │                      │    │
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
10. **Defense-in-depth**: Four-layer security for cgroup agents (cgroup + Landlock + seccomp + eBPF) — symlink-immune, TOCTOU-immune, io_uring-immune
11. **Zero overhead**: eBPF runs in the kernel — no process wrapping, no ptrace, no container

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
- **io_uring/memfd blocking**: Seccomp filter blocks io_uring and memfd_create syscalls that bypass eBPF monitoring
- **Symlink-immune enforcement**: Landlock LSM enforces file access at the inode level — symlinks are resolved before access checks (Phase 10)
- **TOCTOU immunity**: Landlock checks happen at VFS layer after path resolution — no race condition between check and use (Phase 10)
- **Mount/namespace/chroot escape prevention**: Expanded seccomp blocks mount, umount2, pivot_root, chroot, setns, unshare (Phase 10)
- **SUID escalation prevention**: PR_SET_NO_NEW_PRIVS prevents privilege escalation via setuid binaries (Phase 10)
- **Landlock TCP port filtering**: Outbound TCP connections restricted to allowed ports on kernel 6.7+ (Phase 10)
- **Irreversible sandbox**: Landlock ruleset cannot be relaxed once applied, even if the daemon is compromised (Phase 10)
- **Inode protection**: Rename, unlink, and hardlink operations on denied resources are blocked via LSM hooks
- **File manipulation defense**: Agents cannot move or copy denied files to allowed directories
- **Dynamic linker detection**: Direct invocation of ld-linux to bypass exec policy is detected and blocked
- **Anomaly detection**: Automatic detection of rubber-stamping, persistence attacks, and approval flooding
- **Fail-closed option**: Per-agent configuration to deny access on any eBPF error (instead of default fail-open)
- **Dashboard authentication**: Optional Bearer token auth with constant-time comparison and rate limiting
- **IPC socket authentication**: Only root (UID 0) can connect to the Unix domain socket (`SO_PEERCRED` verification)
- **IPC connection limiting**: Maximum 64 concurrent connections to prevent resource exhaustion
- **SSRF prevention**: Webhook and Slack URLs validated against private/loopback IP ranges
- **Email injection prevention**: Subject line inputs sanitized to strip newline characters
- **CDN integrity**: SRI (Subresource Integrity) hashes on all CDN-loaded scripts prevent supply chain attacks

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

11. **Secure the dashboard** — set `auth_token` in dashboard config; use a reverse proxy with TLS for remote access

12. **Use the dashboard for incident response** — the live events page with filtering makes it easy to investigate policy violations in real time

13. **Use strict mode in production** — set `mode = "strict"` to prevent silent degradation to monitor-only when LSM hooks fail

14. **Enable fail-closed for sensitive agents** — set `fail_closed = true` on agents handling critical resources to deny access on eBPF errors

15. **Configure grant accumulation limits** — set `max_grant_total_secs` to prevent agents from accumulating unlimited access through repeated grants

16. **Monitor anomaly detection alerts** — configure alerting outputs to receive notifications about rubber-stamping and persistence attack patterns

17. **Use external webhook URLs only** — webhook and Slack URLs targeting private IPs (127.0.0.1, 10.x.x.x, 192.168.x.x) are rejected to prevent SSRF

18. **Don't use `?token=` in production** — prefer `Authorization: Bearer <token>` header; query parameter tokens leak in referer headers and browser history

19. **Use cgroup agents for production** — cgroup agents (launched via `guardian-launch`) get Landlock + seccomp + PR_SET_NO_NEW_PRIVS + eBPF (four defense layers). Comm-based agents only get eBPF (one layer).

20. **Use `default = "deny"` for Landlock protection** — Landlock is inherently default-deny. Agents with `file_access.default = "allow"` skip Landlock entirely, falling back to eBPF-only enforcement with known symlink/TOCTOU vulnerabilities.

21. **Don't use `--no-landlock` or `--no-seccomp-hardened` in production** — these flags disable critical security layers. Use them only for debugging.

---

## Known Limitations

| Limitation | Impact | Planned Fix |
|-----------|--------|-------------|
| **Relative paths** | If agent uses relative paths, pattern matching may fail | Future: Full path resolution in eBPF |
| **Symlinks not resolved in eBPF** | Userspace `normalize_path()` handles `/proc/self/root/` and `..` but not arbitrary symlinks. **Mitigated for cgroup agents** by Landlock (Phase 10) | Use cgroup agents with `guardian-launch` for symlink-immune enforcement |
| **x86_64 only** | Tracepoint offsets are hardcoded for x86_64 | Future: Architecture-agnostic offset reading |
| **Network enforcement requires CONFIG_BPF_LSM** | LSM `socket_connect` hook needs kernel LSM support. Falls back to log-only if unavailable | Ensure kernel has `CONFIG_BPF_LSM=y` and `bpf` in LSM list |
| **Enforcement requires CONFIG_BPF_LSM** | Kernel must have `CONFIG_BPF_LSM=y` and `bpf` in the LSM list | In strict mode, daemon exits if LSM unavailable; otherwise falls back to monitor-only |
| **5-second grant/cleanup granularity** | Temporary grants and cgroup cleanup are checked every 5 seconds | Acceptable for most use cases |
| **Comm-based agents still spoofable** | Process name can be changed via `prctl(PR_SET_NAME)` | Use cgroup-based identity for untrusted agents |
| **No webhook retry** | Failed webhook/Slack/email sends are logged and dropped | Monitor `alerts_sent{status="error"}` metric |
| **Email password in plaintext** | SMTP password stored in config file | Protect config with `chmod 600` |
| **Dashboard CDN dependency** | First load requires internet for TailwindCSS/htmx/Alpine.js; SRI hashes prevent tampering | Bundle libraries locally via rust-embed |
| **Policy edits don't update BPF maps** | Kernel enforcement rules unchanged until reload | Use "Reload Config" button or SIGHUP |
| **Config comments lost on dashboard save** | TOML write-back removes original comments | Use version control for config files |
| **openat2 requires kernel 5.6+** | `sys_enter_openat2` tracepoint not available on older kernels | Gracefully skipped; `openat` and `open` hooks still active |
| **Seccomp filter is x86_64 syscall numbers** | `io_uring`/`memfd_create` blocking uses hardcoded x86_64 syscall numbers | Future: Per-arch syscall number mapping |
| **Anomaly detection is hourly** | Rubber-stamping and persistence attacks detected on 1-hour cycle | Acceptable; alerts fire within the hour |
| **No `mmap_file` LSM hook** | Agents can `mmap()` a file to bypass `file_open` enforcement | Future: LSM `mmap_file` hook |
| **No content hashing** | Policy is path-based; moved/copied file content not tracked | Future: Inode-based or content-hash policy |
| **Landlock requires kernel 5.13+** | Landlock sandbox unavailable on older kernels. Falls back to eBPF-only | Most production distros (Ubuntu 22.04+, RHEL 9+) have 5.13+ |
| **Landlock network requires kernel 6.7+** | TCP port filtering unavailable on older kernels. Falls back to eBPF network enforcement | Filesystem sandbox still works on 5.13+ |
| **Landlock incompatible with default-allow** | Landlock is inherently default-deny. Agents with `file_access.default = "allow"` skip Landlock | Use `default = "deny"` for full Landlock protection |
| **Landlock grants are irreversible** | `guardian-ctl grant` only updates eBPF maps, not Landlock sandbox. Landlock baseline cannot be relaxed | Agent must be relaunched for truly expanded access |
| **UDP not enforced by Landlock** | Landlock only filters TCP connect/bind. UDP `sendto()` unrestricted | Requires network namespace for UDP control |
| **Comm-based agents lack Landlock/seccomp** | Tier 2 agents don't go through `guardian-launch` | Use cgroup agents for production security |

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

### Phase 5 - Dashboard & UI ✅
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

### Phase 6 - Interactive Permission Requests ✅
- [x] Interactive permission request protocol (`guardian-ctl request-permission`)
- [x] Long-poll IPC with oneshot channels (agent blocks while waiting for human)
- [x] Real-time permission notification banner on all dashboard pages
- [x] Dedicated `/requests` page with pending requests and resolved history
- [x] Approve/deny with configurable grant duration (1 min to 1 hour)
- [x] 120-second auto-deny timeout (fail-secure)
- [x] SSE stream merging (alert events + permission events on single connection)
- [x] Alpine.js global permission store with countdown timer
- [x] Sidebar badge showing pending request count
- [x] Exec grant type support (in addition to file access grants)
- [x] Resolved permission audit trail (last 100 entries)

### Phase 7 - Security Hardening (Partial) ✅
- [x] Userspace path normalization (`normalize_path()` strips `/proc/self/root/`, resolves `..`)
- [x] `openat2` tracepoint hook (closes openat2 syscall bypass, Linux 5.6+)
- [x] Legacy `open()` syscall tracepoint (belt-and-suspenders coverage)
- [x] Per-agent permission rate limiting (3/min, 15/hr, exponential backoff)
- [x] 4-tier risk classification (Low/Medium/High/Critical) with path patterns
- [x] Auto-deny for never-approve resources (`/etc/shadow`, SSH keys, etc.)
- [x] Auto-approve for low-risk resources (`/tmp/**`, `/proc/self/**`)
- [x] Justification text analysis (urgency, security bypass, reassurance, authority claims)
- [x] UI friction: mandatory wait timers (0/3/5/10s by risk level), type-to-confirm for CRITICAL
- [x] Persistent SQLite audit trail for all permission decisions
- [x] Exec enforcement via LSM `bprm_check_security` hook with `PENDING_EXEC_DENY` map
- [x] Network monitoring via `sys_enter_connect` tracepoint (AF_INET/AF_INET6, port-based policy)
- [x] Network enforcement via LSM `socket_connect` hook (blocks denied connections at kernel level)
- [x] SSE single shared EventSource with custom DOM events

### Phase 8 - Security Hardening (Complete) ✅

**8a: Critical Security Fixes**
- [x] BPF map capacity increase (256 → 1024 entries per policy map)
- [x] io_uring + memfd_create seccomp blocking via `seccompiler` crate
- [x] Inode LSM hooks for rename/unlink/hardlink enforcement (`PENDING_RENAME/UNLINK/LINK_DENY` maps)
- [x] Path truncation detection (`EVENT_FLAG_TRUNCATED` status flag, deny-on-truncation)

**8b: Exec Hardening + Dashboard Security**
- [x] Dynamic linker detection (`DYNAMIC_LINKERS` map + `argv[1]` inspection)
- [x] `execveat` tracepoint with `AT_EMPTY_PATH` detection (blocks memfd-based exec)
- [x] Strict enforcement mode (daemon exits if LSM hooks fail to attach)
- [x] Default `/memfd:` prefix in exec deny maps
- [x] Dashboard Bearer token authentication middleware (`auth_token` config)

**8c: Approval Hardening**
- [x] Risk-based configurable timeouts (`RiskTimeoutConfig`: 60/120/180/300s per tier)
- [x] CLI permission approval (`guardian-ctl pending/approve/deny`)
- [x] Grant accumulation limits (`max_grant_total_secs` per resource per 24h)
- [x] Weighted justification analysis (graduated risk bumps: score ≥8 → +2 tiers, ≥3 → +1)

**8d: Polish**
- [x] Per-cgroup fail-closed mode (`FAIL_CLOSED_CGROUPS` BPF map, deny on eBPF errors)
- [x] Full SIGHUP reload including alerting outputs (`Arc<RwLock<AlertSender>>`)
- [x] Anomaly detection (rubber-stamping >90% approval, persistence attacks, flood detection)

**8e: Userspace Security Hardening**
- [x] IPC `SO_PEERCRED` authentication (only root UID 0 can connect)
- [x] IPC socket permissions restricted to 0o600 (owner-only)
- [x] IPC connection rate limiting (semaphore, max 64 concurrent)
- [x] Cgroup path traversal prevention (rejects `..` and absolute paths)
- [x] PID validation before `kill()` (rejects negative/zero PIDs)
- [x] Grant type validation (rejects invalid values)
- [x] Resource path null byte and control character validation
- [x] IPC error message sanitization (no BPF internals leaked to clients)
- [x] Constant-time auth token comparison (prevents timing attacks)
- [x] Dashboard auth rate limiting (10 failures → 60s lockout)
- [x] `/metrics` endpoint requires auth when `auth_token` is configured
- [x] SSRF prevention for webhook/Slack URLs (blocks private/loopback IPs)
- [x] Email subject header injection prevention (newline sanitization)
- [x] CDN SRI (Subresource Integrity) hashes on all dashboard scripts

### Phase 9 - Network Enforcement ✅

- [x] LSM `socket_connect` hook for kernel-level connection blocking (returns -ECONNREFUSED)
- [x] Port-based deny/allow BPF maps (`NET_DENY_PORTS`, `NET_ALLOW_PORTS`) evaluated in-kernel
- [x] `PENDING_NET_DENY` map follows same tracepoint→LSM pattern as file/exec/inode enforcement
- [x] Per-cgroup and per-comm network default action maps
- [x] Graceful fallback to monitor-only when LSM `socket_connect` unavailable
- [x] BPF stack overflow fix: dynamic linker detection reads directly into per-CPU buffer

### Phase 10 - Hardened Cgroup Agents (Defense in Depth) ✅

- [x] Landlock LSM sandbox in `guardian-launch` (inode-level, symlink-immune file access control)
- [x] Landlock filesystem rights: ReadFile, WriteFile, Execute, MakeReg, MakeDir, RemoveFile, RemoveDir, ReadDir per allowed path
- [x] Landlock network rights: ConnectTcp per allowed port (ABI v4, kernel 6.7+)
- [x] System read paths always allowed (dynamic linking: `/usr/lib`, `/lib`, `/lib64`, `/etc/ld.so.cache`, etc.)
- [x] Landlock graceful degradation: FullyEnforced / PartiallyEnforced / NotEnforced with logging
- [x] Landlock skipped for `file_access.default = "allow"` agents (incompatible with default-deny model)
- [x] Expanded seccomp filter: mount (165, 166), new mount API (428-433, 442), pivot_root (155), chroot (161), setns (308), unshare (272)
- [x] `seccomp_hardened` toggle: base filter always applied, expanded filter controlled by config
- [x] `PR_SET_NO_NEW_PRIVS` prevents SUID/capability escalation, required by Landlock
- [x] IPC `SandboxConfig` delivery: daemon sends agent policy to launcher in registration Ack response
- [x] `--no-landlock` and `--no-seccomp-hardened` CLI flags for debugging
- [x] Two security tiers documented: Tier 1 (hardened cgroup) vs Tier 2 (legacy comm)
- [x] `strip_glob()` converts path patterns (`/tmp/**`) to Landlock PathBeneath base directories (`/tmp`)
