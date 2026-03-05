# Guardian Shell - Usage Guide

Guardian Shell is a Linux security tool that monitors file access by LLM agents (Claude Code, AutoGPT, Aider, Cursor, etc.) using eBPF. It hooks into the kernel's file-open syscall and evaluates every file access against your policy rules in real time.

**Current mode: Monitor-only (Phase 1)**
Guardian logs ALLOW/DENY decisions but does not block file access yet. Use it to audit what your agents are doing and tune your policy before enforcement mode arrives in Phase 2.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Building from Source](#building-from-source)
4. [Configuration](#configuration)
   - [Global Settings](#global-settings)
   - [Agent Definitions](#agent-definitions)
   - [File Access Policies](#file-access-policies)
   - [Pattern Matching](#pattern-matching)
   - [Policy Evaluation Order](#policy-evaluation-order)
5. [Running Guardian Shell](#running-guardian-shell)
   - [CLI Options](#cli-options)
   - [Log Levels](#log-levels)
6. [Understanding the Output](#understanding-the-output)
   - [Startup Messages](#startup-messages)
   - [ALLOW Events](#allow-events)
   - [DENY Events](#deny-events)
   - [Event Fields](#event-fields)
7. [Writing Effective Policies](#writing-effective-policies)
   - [Principle of Least Privilege](#principle-of-least-privilege)
   - [Common Allow Patterns](#common-allow-patterns)
   - [Recommended Deny Patterns](#recommended-deny-patterns)
   - [Per-Agent Policies](#per-agent-policies)
   - [Tuning Your Policy](#tuning-your-policy)
8. [Real-World Examples](#real-world-examples)
   - [Monitoring Claude Code](#monitoring-claude-code)
   - [Monitoring a Python Agent](#monitoring-a-python-agent)
   - [Monitoring Multiple Agents](#monitoring-multiple-agents)
   - [Strict Lockdown Policy](#strict-lockdown-policy)
   - [Permissive Audit Policy](#permissive-audit-policy)
9. [How It Works](#how-it-works)
   - [Architecture Overview](#architecture-overview)
   - [eBPF and Tracepoints](#ebpf-and-tracepoints)
   - [Process Name Matching](#process-name-matching)
   - [Event Pipeline](#event-pipeline)
10. [Troubleshooting](#troubleshooting)
11. [Security Considerations](#security-considerations)
12. [Known Limitations](#known-limitations)
13. [Roadmap](#roadmap)

---

## Quick Start

```bash
# 1. Build (one-time)
cargo xtask build-ebpf --release
cargo build --release

# 2. Create a policy file
cat > my-policy.toml << 'EOF'
[global]
log_level = "info"

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
# Guardian will log every file access decision
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
    └── guardian                    # Userspace daemon
```

---

## Configuration

Guardian Shell is configured via a TOML file. The configuration defines which processes to monitor and what file access rules to apply.

### Global Settings

```toml
[global]
log_level = "info"
```

| Field | Values | Description |
|-------|--------|-------------|
| `log_level` | `trace`, `debug`, `info`, `warn`, `error` | Default log verbosity (can be overridden with `RUST_LOG` env var) |

### Agent Definitions

Each `[[agents]]` section defines a process to monitor:

```toml
[[agents]]
name = "claude-code"
process_name = "claude"

[agents.file_access]
default = "deny"
allow = ["/home/user/project/**"]
deny = ["/home/user/project/.env"]
```

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Human-readable name displayed in log output |
| `process_name` | Yes | Process name to match (from `/proc/PID/comm`, max 15 characters) |
| `file_access.default` | Yes | Default action when no pattern matches: `"allow"` or `"deny"` |
| `file_access.allow` | Yes | List of path patterns that are allowed |
| `file_access.deny` | Yes | List of path patterns that are denied |

#### Finding the Process Name

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
[WARN  guardian] [DENY] agent='claude-code' pid=1234 uid=1000 file='/home/user/.ssh/id_rsa' mode=READ (monitoring mode - access was NOT actually blocked)
[WARN  guardian] [DENY] agent='claude-code' pid=1234 uid=1000 file='/etc/shadow' mode=READ (monitoring mode - access was NOT actually blocked)
```

**Important:** In Phase 1 (current), `[DENY]` means the access *would be denied* under the policy, but the file access still succeeds. The agent is not actually blocked. This changes in Phase 2.

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

### Monitoring Claude Code

```toml
[global]
log_level = "info"

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

### Monitoring a Python Agent

```toml
[[agents]]
name = "autogpt"
process_name = "python3"

[agents.file_access]
default = "deny"
allow = [
    # Python and its packages
    "/usr/lib/python3/**",
    "/usr/lib64/python3/**",
    "/home/user/.local/lib/python3/**",
    "/home/user/venvs/autogpt/**",

    # Agent workspace
    "/home/user/autogpt-workspace/**",

    # System libraries
    "/lib/**",
    "/lib64/**",
    "/usr/lib/**",
    "/etc/ld.so.cache",
    "/usr/share/locale/**",

    # Temp files
    "/tmp/**",
]
deny = [
    "/home/user/.ssh/**",
    "/home/user/.aws/**",
    "/home/user/autogpt-workspace/.env",
]
```

### Monitoring Multiple Agents

```toml
[global]
log_level = "info"

# Agent 1: Claude Code
[[agents]]
name = "claude"
process_name = "claude"

[agents.file_access]
default = "deny"
allow = ["/home/user/project-a/**", "/tmp/**", "/usr/lib/**", "/lib/**", "/lib64/**"]
deny = ["/home/user/project-a/.env", "/home/user/.ssh/**"]

# Agent 2: Aider (Python-based)
[[agents]]
name = "aider"
process_name = "python3"

[agents.file_access]
default = "deny"
allow = ["/home/user/project-b/**", "/tmp/**", "/usr/lib/**", "/lib/**", "/lib64/**"]
deny = ["/home/user/project-b/.env", "/home/user/.ssh/**"]

# Agent 3: Custom agent
[[agents]]
name = "custom-bot"
process_name = "mybot"

[agents.file_access]
default = "deny"
allow = ["/home/user/bot-workspace/**", "/tmp/**", "/usr/lib/**", "/lib/**", "/lib64/**"]
deny = ["/home/user/.ssh/**", "/home/user/.aws/**"]
```

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
 ┌─────────────────────────────────────────────────────────────┐
 │                       USER SPACE                             │
 │                                                              │
 │  config.toml ──→ [Config Parser] ──→ [Policy Engine]        │
 │                                            │                 │
 │                                    ┌───────┴───────┐        │
 │                                    │  eBPF Loader  │        │
 │                                    └───────┬───────┘        │
 │                                            │                 │
 │                             ┌──────────────┴──────────────┐ │
 │                             │   Async Event Processor     │ │
 │                             │   (one task per CPU core)   │ │
 │                             └──────────────┬──────────────┘ │
 │                                            │                 │
 │ ──── perf buffer ──────────────────────────┼──────────────── │
 │                                            │                 │
 │                       KERNEL SPACE         │                 │
 │                                            │                 │
 │           ┌────────────────────────────────┴──────┐         │
 │           │          eBPF Program                  │         │
 │           │   tracepoint/sys_enter_openat          │         │
 │           │                                        │         │
 │           │   1. Get process comm name             │         │
 │           │   2. Lookup in WATCHED_COMMS map       │         │
 │           │   3. If watched → capture event:       │         │
 │           │      - PID, UID, filename, flags       │         │
 │           │   4. Send to userspace via perf buffer │         │
 │           └────────────────────────────────────────┘         │
 └──────────────────────────────────────────────────────────────┘
```

### eBPF and Tracepoints

**eBPF** (extended Berkeley Packet Filter) lets you run sandboxed programs inside the Linux kernel. The kernel's BPF verifier checks every program before loading to ensure it:
- Cannot crash the kernel
- Cannot enter infinite loops
- Cannot access invalid memory
- Always terminates

**Tracepoints** are static instrumentation points in the kernel. Guardian Shell hooks into `sys_enter_openat`, which fires every time any process on the system opens a file. The eBPF program runs at this point, checks if the process is one we're monitoring, and if so, captures the event.

### Process Name Matching

Guardian Shell matches processes by their **comm name** — the process name stored in the kernel's task struct and visible at `/proc/PID/comm`.

The matching happens directly inside the eBPF program in the kernel. When any process calls `openat()`:

1. The eBPF program reads the calling process's comm name
2. It looks up the name in the `WATCHED_COMMS` hash map
3. If the name is there, it captures the event
4. If not, it returns immediately (near-zero overhead)

This approach catches even short-lived processes because the check happens during the syscall itself — the process cannot exit before the eBPF program runs.

### Event Pipeline

1. **Kernel**: Process calls `openat()` to open a file
2. **Kernel**: `sys_enter_openat` tracepoint fires
3. **Kernel**: eBPF program checks if process comm is in `WATCHED_COMMS`
4. **Kernel**: If watched, eBPF captures PID, UID, filename, flags into a `FileAccessEvent`
5. **Kernel**: Event is written to a per-CPU perf ring buffer
6. **Userspace**: Async task reads event from perf buffer
7. **Userspace**: Event is parsed and matched to an agent config by comm name
8. **Userspace**: Policy engine evaluates file path against allow/deny rules
9. **Userspace**: Decision is logged as `[ALLOW]` or `[DENY]`

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

### What Guardian Shell Protects Against (Phase 1)

- **Visibility**: Real-time view of every file an LLM agent opens
- **Audit trail**: Permanent log of all file access with PID, UID, path, and access mode
- **Policy violation detection**: Immediate alerts when agents access files outside their scope
- **Credential access detection**: Catch agents trying to read SSH keys, cloud credentials, or secrets

### What It Does NOT Do Yet

- **Block access**: Phase 1 is monitor-only. The agent still succeeds in opening the file, even if the log says `[DENY]`.
- **Prevent execution**: Command execution (`execve`) is not monitored.
- **Track child processes**: If a monitored agent spawns a child process with a different name, the child is not tracked.

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

---

## Known Limitations

| Limitation | Impact | Planned Fix |
|-----------|--------|-------------|
| **Monitor-only** | Logs violations but doesn't block access | Phase 2: LSM BPF hooks for kernel-level blocking |
| **Process name spoofing** | Agent could call `prctl(PR_SET_NAME)` to change its comm | Phase 3: Cgroup-based identification |
| **Relative paths** | If agent uses relative paths, pattern matching may fail | Phase 2: Full path resolution |
| **Only hooks `openat()`** | Doesn't cover `open()`, `openat2()`, `readlink()`, `stat()` | Phase 2: Additional syscall hooks |
| **x86_64 only** | Tracepoint offsets are hardcoded for x86_64 | Future: Architecture-agnostic offset reading |
| **No child process tracking** | Child processes with different names aren't monitored | Phase 2: Process tree tracking via `execve` |
| **No network monitoring** | Network access by agents is not tracked | Future phases |

---

## Roadmap

### Phase 1 (Current) - File Access Monitoring
- [x] eBPF tracepoint on `sys_enter_openat`
- [x] Process identification by comm name
- [x] TOML-based policy configuration
- [x] Allow/deny path pattern matching with recursive wildcards
- [x] Real-time event logging with PID, UID, path, and access mode
- [x] Per-CPU async event processing

### Phase 2 - Kernel-Level Enforcement
- [ ] LSM (Linux Security Module) BPF hooks for actual file access blocking
- [ ] `sys_enter_execve` monitoring for command restrictions
- [ ] Process tree tracking (automatically monitor child processes)
- [ ] Full path resolution for relative paths

### Phase 3 - Advanced Identity & Access
- [ ] Cgroup-based agent identification (robust, not spoofable)
- [ ] Launcher wrapper to automatically isolate agents in cgroups
- [ ] Time-based access windows ("allow /etc/hosts for 5 minutes")
- [ ] Interactive user consent flow for elevated permissions

### Phase 4 - Alerting & Integration
- [ ] Webhook alerts for policy violations
- [ ] Slack/email notifications
- [ ] Structured JSON logging for SIEM integration
- [ ] Prometheus metrics export

### Phase 5 - Dashboard & UI
- [ ] Web-based real-time monitoring dashboard
- [ ] Visual policy editor
- [ ] Agent activity timeline and replay
- [ ] Alert management and incident response
