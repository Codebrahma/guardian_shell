# Guardian Shell

**Kernel-level security for LLM agents on Linux.**

Guardian Shell uses eBPF, Landlock, seccomp, and cgroup isolation to monitor and restrict what AI coding agents can access on your system. It operates at the kernel level — no shell syntax tricks, prompt injections, or sandbox toggles can bypass it.

> Unlike application-layer sandboxes that parse shell commands (vulnerable to process substitution, backticks, eval), Guardian Shell intercepts at the syscall level. See [Snowflake Cortex comparison](docs/security/snowflake-cortex-sandbox-escape-analysis.md).

## Features

- **6-layer defense for cgroup agents**: PR_SET_NO_NEW_PRIVS + privilege dropping + seccomp + Landlock + eBPF LSM + cgroup isolation
- **Kernel-level enforcement**: eBPF tracepoints + LSM hooks intercept execve, file_open, connect at the syscall level
- **Landlock sandbox**: Inode-level file access control — immune to symlinks, TOCTOU, path tricks
- **Seccomp hardening**: Blocks io_uring, memfd_create, mount, namespace escape, chroot, pivot_root
- **Web dashboard**: Real-time event stream, agent management, policy editor, permission approval
- **Interactive permissions**: Agents can request access, humans approve/deny with risk-based friction
- **Alerting**: Structured JSON logs, Slack, email, webhooks, Prometheus metrics
- **Network enforcement**: Port-based outbound TCP control via eBPF LSM socket_connect
- **Auto-config**: New cgroup agents get sensible defaults automatically
- **Multi-distro**: Tested on Fedora 43 (SELinux) and supports Debian/Ubuntu

## Quick Start

### Prerequisites

```bash
# Rust nightly + BPF toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker

# Verify kernel support
cat /boot/config-$(uname -r) | grep CONFIG_BPF
```

### Build

```bash
cargo xtask build-ebpf --release
cargo build --release
```

### Run

```bash
# Copy a preset config
cp configs/recommended.toml my-config.toml
# Edit paths for your environment
vi my-config.toml

# Start the daemon
sudo RUST_LOG=info target/release/guardian --config my-config.toml

# Open dashboard
open http://127.0.0.1:8080

# Launch a sandboxed agent (in another terminal)
sudo target/release/guardian-launch --name my-agent -- bash
```

### Validate Config

```bash
# Check config without starting the daemon
target/release/guardian --config my-config.toml --validate-config
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Kernel                                                   │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────┐ │
│  │ eBPF         │  │ Landlock LSM  │  │ Seccomp BPF  │ │
│  │ Tracepoints  │  │ (inode-level) │  │ (syscall     │ │
│  │ + LSM hooks  │  │               │  │  filter)     │ │
│  └──────┬───────┘  └───────────────┘  └──────────────┘ │
│         │                                                │
│  ┌──────┴───────┐                                       │
│  │ Cgroup v2    │                                       │
│  │ (isolation)  │                                       │
│  └──────────────┘                                       │
└─────────────────────────────────────────────────────────┘
          │ perf events
┌─────────┴───────────────────────────────────────────────┐
│ Userspace                                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Guardian     │  │ Dashboard    │  │ Alerting     │  │
│  │ Daemon       │  │ (axum+htmx)  │  │ (Slack,email │  │
│  │              │  │              │  │  webhook,log)│  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│  ┌──────────────┐  ┌──────────────┐                     │
│  │ guardian-    │  │ guardian-ctl │                     │
│  │ launch      │  │ (CLI)        │                     │
│  └──────────────┘  └──────────────┘                     │
└─────────────────────────────────────────────────────────┘
```

## Enforcement Modes

| Mode | Behavior | LSM Failure |
|------|----------|-------------|
| `monitor` | Log-only, no blocking | No LSM hooks loaded |
| `enforce` | Kernel-level blocking via LSM | Warning logged, continues in monitor-only |
| `strict` | Kernel-level blocking, no degradation | **Daemon exits** — refuses to run without enforcement |

```toml
[global]
mode = "strict"  # recommended for production
```

## Security Tiers

| Tier | Identity | Layers | Use Case |
|------|----------|--------|----------|
| **Tier 1** (recommended) | Cgroup | Landlock + seccomp + eBPF + cgroup + NNP + privilege drop | Production agents |
| **Tier 2** (legacy) | Comm | eBPF monitoring only | Quick testing |

## Preset Configs

| Config | Mode | Description |
|--------|------|-------------|
| `configs/minimal.toml` | monitor | Bare minimum, logging only |
| `configs/recommended.toml` | enforce | Production defaults with deny-all |
| `configs/strict.toml` | strict | Maximum security, fails on any LSM error |
| `configs/development.toml` | monitor | Verbose debug logging |

```bash
# Start with recommended config
cp configs/recommended.toml my-config.toml
sudo target/release/guardian --config my-config.toml
```

## Agent Configuration

Each agent has four policy sections (all except `file_access` are optional):

```toml
[[agents]]
name = "my-agent"
identity = "cgroup"          # "comm" or "cgroup"
watch_children = true         # track child processes (default: true)
fail_closed = true            # deny on eBPF error (default: false)

[agents.file_access]
default = "deny"
allow = ["/home/user/project/**", "/tmp/**"]
deny = ["/home/user/.ssh/**"]
read_only = ["/etc/passwd", "/var/log/**"]  # read OK, write/delete blocked

[agents.exec_policy]
default = "deny"
allow = ["/usr/bin/git", "/usr/bin/python3"]
deny = ["/usr/bin/curl", "/usr/bin/ssh"]

[agents.network_policy]
default = "deny"
allow_ports = [443, 53]       # HTTPS + DNS
deny_ports = [22, 25]         # SSH, SMTP

[agents.resources]
memory_max = "4G"
pids_max = 200
```

See [USAGE.md](USAGE.md) for full configuration reference with examples.

## Dashboard

The web dashboard runs at `http://127.0.0.1:8080` (configurable):

- **Overview**: Agent status, event counts, mode indicator
- **Events**: Live SSE stream with filtering by severity/action/agent
- **Agents**: Create, configure, stop, grant temporary access
- **Policy**: Edit file/exec/network rules per agent
- **Requests**: Approve/deny permission requests with risk-based friction
- **Alerts**: Configure JSON logs, Slack, email, webhooks, Prometheus

Enable with `auth_token` in config for production:
```toml
[dashboard]
enabled = true
listen_address = "127.0.0.1:8080"
auth_token = "your-secret-token-here"
```

## Documentation

- **[USAGE.md](USAGE.md)** -- Comprehensive usage guide (all features, examples)
- **[ARCHITECTURE.md](ARCHITECTURE.md)** -- Technical deep dive (eBPF, design decisions)
- **[CLAUDE.md](CLAUDE.md)** -- Development handoff document
- **[docs/security/](docs/security/)** -- Security analyses and incident comparisons
- **[docs/phase_11_security_hardening.md](docs/phase_11_security_hardening.md)** -- Latest changes

## Project Status

| Phase | Status | Description |
|-------|--------|-------------|
| 1 | Done | eBPF monitoring + comm-based agents |
| 2 | Done | LSM enforcement + exec monitoring |
| 3 | Done | Cgroup isolation + guardian-launch + guardian-ctl |
| 4 | Done | Alerting (Slack, email, webhooks, Prometheus, JSON logs) |
| 5 | Done | Web dashboard (axum + htmx + Alpine.js) |
| 6 | Done | Interactive permission requests |
| 7 | Done | Path normalization, openat2, approval hardening |
| 8 | Done | Seccomp, inode hooks, dynamic linker detection, dashboard auth |
| 9 | Done | Network enforcement (socket_connect LSM) |
| 10 | Done | Landlock sandbox, expanded seccomp, IPC sandbox config |
| 11 | Done | Security hardening, privilege dropping, CSRF, perf fixes |
| 12 | Planned | Resilience & lifecycle (orphaned cgroup cleanup, daemon watchdog) |
| 13 | Planned | OpenShell features (L7 inspection, credential isolation, binary integrity) |

## Requirements

- **Linux kernel 5.13+** (Landlock). 5.6+ for openat2 hook. 6.7+ for Landlock TCP filtering.
- **BPF support**: `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`
- **Rust nightly** (required for eBPF cross-compilation)
- **Root access** (for eBPF loading, cgroup creation)
- **x86_64** (syscall numbers hardcoded for x86_64; aarch64 offsets may differ)

## Troubleshooting

### Build fails with "linker not found"

```bash
cargo install bpf-linker

# If that fails, install LLVM:
# Ubuntu/Debian: sudo apt install llvm-dev
# Fedora: sudo dnf install llvm-devel
```

### "Failed to load eBPF program"

```bash
# Build the eBPF program first
cargo xtask build-ebpf --release

# Verify the binary exists
ls -la target/bpfel-unknown-none/release/guardian-ebpf

# Must run as root
sudo target/release/guardian --config config.toml
```

### "Failed to attach to tracepoint"

```bash
# Check kernel tracepoint support
ls /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/

# Check kernel config
cat /boot/config-$(uname -r) | grep -E 'CONFIG_BPF|CONFIG_FTRACE'
```

### Landlock + exec returns EACCES on Fedora/RHEL

This is a known interaction between Landlock and SELinux when running as root.
Guardian Shell automatically drops privileges to the invoking user (via `SUDO_UID`).
If the issue persists, use `--user <uid>` or see `docs/landlock-exec-investigation.md`.

### Grant approved but agent still gets EACCES

Cgroup agents with `file_access.default = "deny"` have an immutable Landlock sandbox
applied at launch. Grants approved via the dashboard or `guardian-ctl` only update
eBPF maps — Landlock cannot be modified after `restrict_self()`.

**File grants:** Only work for paths in `file_access.allow` that are NOT also in
`file_access.read_only`. `read_only` takes precedence over `allow` — Landlock layer 2
blocks writes even when a parent allow glob matches (e.g. `allow = ["/project/**"]` with
`read_only = ["/project/config.txt"]` means `config.txt` is write-blocked). Permission
requests for `read_only` or system read paths are **denied immediately** by the daemon
(no dashboard prompt). `guardian-ctl` receives: `DENIED: '<path>' is Landlock read-only protected`.
Paths outside any Landlock set are also denied immediately as unreachable.

**Exec grants:** Landlock does **not** handle `AccessFs::Execute` — exec enforcement is
eBPF-only. However, to exec a binary the kernel must first **read** it. Binaries in
standard system paths (`/usr/bin`, `/usr/sbin`, `/sbin`, `/usr/local`, `/lib`, etc.)
are always readable because `guardian-launch` includes them as system read paths in
the Landlock ruleset. Binaries in the agent's `exec_allow` config also get Landlock
read access. But a binary at a non-standard path (e.g. `/opt/custom/tool`) that is
not in `system_read_paths`, `file_allow`, or `exec_allow` will be blocked by Landlock
at the read level — and an exec grant cannot fix that.

**To permanently allow a new path**, add it to the agent's config and restart.

## Permission Request System

When an agent hits EACCES, it can request temporary access via `guardian-ctl request-permission`.
The request goes through several checks before reaching a human:

### Auto-Deny (instant, no human prompt)

Resources on the `auto_deny` list are rejected immediately. No dashboard notification,
no waiting. Configure in `config.toml`:

```toml
[agents.permissions]
auto_deny = [
  "/etc/shadow",
  "/home/user/.ssh/**",
  "/home/user/.gnupg/**",
  "/home/user/.aws/**",
]
```

### Auto-Approve (instant, no human prompt)

Low-risk resources on the `auto_approve` list are granted immediately with a capped
duration. No human approval needed:

```toml
[[agents.permissions.auto_approve]]
pattern = "/tmp/**"
max_duration_secs = 300    # 5 minutes max
```

### Rate Limiting

Prevents agents from flooding the approval queue:

| Limit | Default | Effect |
|-------|---------|--------|
| Per-minute | 3 requests | 4th request in same minute is rejected |
| Per-hour | 15 requests | 16th request in same hour is rejected |
| Max pending | 2 per agent | 3rd concurrent request is rejected |
| Same-resource cooldown | 5 minutes | Re-requesting a denied resource is blocked |
| Grant accumulation | 3600s (1hr) / 24h | Total granted time per resource capped |

### Exponential Backoff After Denials

Each consecutive denial doubles the cooldown before the agent can request again:

| Consecutive denials | Cooldown (base 30s) | Effect |
|---------------------|---------------------|--------|
| 1 | 30s | Agent must wait 30s before next request |
| 2 | 60s | |
| 3 | 120s | |
| 4 | 240s | |
| 5+ | 600s (max) | Capped at 10 minutes |

An approval resets the consecutive denial counter to zero.

### Risk Classification

Every request is scored on a 4-tier risk scale that determines UI friction:

| Risk | Score | Wait timer | Type-to-confirm | Timeout | Examples |
|------|-------|------------|-----------------|---------|----------|
| Low | 0-25 | 0s | No | 60s | `/tmp/**`, `/proc/self/status` |
| Medium | 26-50 | 3s | No | 120s | Most paths (base score) |
| High | 51-75 | 5s | No | 180s | `/etc/passwd`, `/var/log/**`, execs like `curl` |
| Critical | 76+ | 10s | Yes ("CONFIRM") | 300s | `/etc/shadow`, `/root/**` |

Score modifiers: exec type (1.5x), post-denial retry (2x), high request rate (1.3x).

### Justification Analysis

If the agent provides a `--justification`, the text is scanned for social engineering
patterns. Suspicious patterns bump the risk score:

- **Urgency**: "urgent", "immediately", "emergency", "asap"
- **Security bypass**: "disable security", "bypass", "override", "skip check"
- **Reassurance**: "trust me", "don't worry", "it's safe", "it's harmless"
- **Authority claims**: "admin told", "supervisor", "authorized by"
- **Sensitive mentions**: "ssh key", "password", "credential", "secret"

Score >= 3 bumps risk by one tier. Score >= 8 bumps by two tiers.

### Configuration Reference

```toml
[agents.permissions]
auto_deny = ["/etc/shadow", "/home/user/.ssh/**"]
rate_limit_per_minute = 3
rate_limit_per_hour = 15
deny_cooldown_secs = 30
max_pending_per_agent = 2
max_grant_total_secs = 3600

[[agents.permissions.auto_approve]]
pattern = "/tmp/**"
max_duration_secs = 300

[agents.permissions.timeouts]
low = 60
medium = 120
high = 180
critical = 300
```

## Contributing

Contributions are welcome. Please open an issue to discuss your idea before
submitting a pull request.

**Development setup:**
```bash
# Clone and build
git clone https://github.com/anthropics/guardian-shell.git
cd guardian-shell
cargo xtask build-ebpf --release
cargo build --release

# Run tests (Linux only)
cargo test --workspace
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for internals and [CLAUDE.md](CLAUDE.md)
for the full development handoff document.

## License

Apache License 2.0. See [LICENSE](LICENSE).
