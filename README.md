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

## License

Apache License 2.0. See [LICENSE](LICENSE).
