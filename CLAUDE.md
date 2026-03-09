# Guardian Shell - Claude Agent Handoff Document

This document provides everything a Claude agent needs to continue development
on this project on a Linux machine.

## Project Summary

Guardian Shell is a Linux security tool that uses eBPF to monitor and restrict
LLM agent activities. It's built with Rust and the Aya eBPF framework.

**Current state: Phase 3 - Cgroup Identity + Guardian Launcher (compiled on Linux)**

Phase 3 adds (on top of Phase 2):
- **Cgroup-based agent identification**: `bpf_get_current_cgroup_id()` in eBPF for unspoofable identity
- **Guardian Launcher** (`guardian-launch`): Creates cgroups, sets resource limits, registers with daemon
- **Unix socket IPC**: Daemon accepts agent registrations from launcher at `/run/guardian.sock`
- **Agent lifecycle management**: `guardian-ctl` CLI for list/stop/grant operations
- **Time-based access windows**: Temporary grants with automatic expiry
- **Resource limits**: Memory, PIDs, CPU limits via cgroup v2 controllers
- **Backward compatibility**: Comm-based agents (Phase 1/2) still work alongside cgroup agents

Architecture: 3-tier identification in eBPF: cgroup ID (strongest) -> TGID/child PID -> comm name (fallback).
The `guardian-launch` binary creates a cgroup, registers with the daemon via IPC, then exec's the agent.
All child processes inherit the cgroup and are automatically monitored.

## Project Structure

```
guardian_shell/
├── Cargo.toml                  # Workspace root
├── .cargo/config.toml          # BPF linker config
├── rust-toolchain.toml         # Nightly Rust (required for eBPF)
├── config.toml                 # Example security policy
├── README.md                   # User-facing docs
├── CLAUDE.md                   # This file
│
├── guardian-common/            # Shared types (no_std for eBPF, std for userspace)
│   ├── Cargo.toml
│   └── src/lib.rs              # FileAccessEvent, IPC protocol types, constants
│
├── guardian-ebpf/              # eBPF kernel program (BPF bytecode)
│   ├── Cargo.toml              # Target: bpfel-unknown-none
│   └── src/main.rs             # Tracepoints + LSM hook + cgroup identification
│
├── guardian/                   # Userspace daemon
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs             # Entry point, eBPF loading, event loop, IPC server
│       ├── config.rs           # TOML parsing, policy engine, path matching
│       └── ipc.rs              # IPC server, agent registration, cgroup lifecycle
│
├── guardian-launch/            # Agent launcher with cgroup isolation (Phase 3)
│   ├── Cargo.toml
│   └── src/main.rs             # Creates cgroup, registers, exec's agent
│
├── guardian-ctl/               # CLI for managing agents (Phase 3)
│   ├── Cargo.toml
│   └── src/main.rs             # list/stop/grant commands
│
└── xtask/                      # Build tooling
    ├── Cargo.toml
    └── src/main.rs             # Cross-compiles eBPF program
```

## How It Works

### Comm-based agents (Phase 1/2 — backward compatible)
1. **Userspace daemon** reads `config.toml` to learn which processes to monitor
2. **Daemon scans `/proc/`** to find PIDs matching configured `process_name` values
3. **Daemon loads eBPF program** and populates `WATCHED_COMMS` + `WATCHED_TGIDS` maps
4. **eBPF program** hooks syscalls + LSM to monitor and enforce policy

### Cgroup-based agents (Phase 3 — recommended)
1. **`guardian-launch --name <agent> -- <command>`** creates a cgroup, registers via IPC, exec's agent
2. **Daemon receives registration**, populates `WATCHED_CGROUPS` BPF map with cgroup ID
3. **eBPF program** uses `bpf_get_current_cgroup_id()` — strongest, unspoofable identification
4. **All child processes** automatically inherit the cgroup — no PID tracking needed
5. **Resource limits** (memory, PIDs, CPU) enforced via cgroup controllers
6. **`guardian-ctl`** provides list/stop/grant commands for agent management

## First Steps on Linux

### 1. Install Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install nightly toolchain + rust-src (needed for eBPF)
rustup install nightly
rustup component add rust-src --toolchain nightly

# Install BPF linker
cargo install bpf-linker

# Verify kernel BPF support
cat /boot/config-$(uname -r) | grep CONFIG_BPF
# Should show CONFIG_BPF=y and CONFIG_BPF_SYSCALL=y
```

### 2. Build

```bash
# Build eBPF kernel program (cross-compile to BPF target)
cargo xtask build-ebpf --release

# Build userspace daemon
cargo build --release
```

### 3. Test with Comm-Based Agent (Phase 1/2)

Edit `config.toml` to watch a common process like `cat`:

```toml
[global]
log_level = "info"
mode = "enforce"
pid_rescan_interval = 5
socket_path = "/run/guardian.sock"

[[agents]]
name = "test-cat"
process_name = "cat"
watch_children = true

[agents.file_access]
default = "deny"
allow = ["/tmp/**"]
deny = ["/etc/shadow"]
```

```bash
# Terminal 1:
sudo RUST_LOG=debug target/release/guardian --config config.toml

# Terminal 2:
cat /tmp/somefile       # Should show [ALLOW]
cat /etc/passwd         # In enforce mode: BLOCKED (returns EACCES)
cat /etc/shadow         # Blocked (explicit deny rule)
```

### 3b. Test with Cgroup-Based Agent (Phase 3)

Add a cgroup agent to config.toml:
```toml
[[agents]]
name = "test-agent"
identity = "cgroup"

[agents.file_access]
default = "deny"
allow = ["/tmp/**", "/proc/**", "/usr/lib/**", "/lib/**", "/lib64/**"]
deny = ["/etc/shadow"]
```

```bash
# Terminal 1: Start the daemon
sudo RUST_LOG=info target/release/guardian --config config.toml

# Terminal 2: Launch a process with cgroup isolation
sudo target/release/guardian-launch --name test-agent --memory 1G --pids 50 -- bash

# Inside the launched bash shell:
cat /tmp/somefile       # ALLOWED — in the allow list
cat /etc/shadow         # BLOCKED — in the deny list

# Terminal 3: Manage agents
sudo target/release/guardian-ctl list                    # List agents
sudo target/release/guardian-ctl grant -n test-agent \
    -p "/etc/shadow" -d 60                              # Temporary 60s grant
sudo target/release/guardian-ctl stop -n test-agent     # Stop the agent
```

### 4. Potential Build Issues to Watch For

- **bpf-linker fails to install**: May need `llvm-dev` package
  (`sudo apt install llvm-dev` on Ubuntu)
- **eBPF verifier rejects program**: Build with `--release` flag (optimized code
  passes verifier more reliably). Check error message for specific rejection reason.
- **"Failed to attach to tracepoint"**: Kernel needs `CONFIG_FTRACE=y` and
  `CONFIG_BPF=y`. Most modern distros (Ubuntu 20.04+, Fedora 33+) have these.
- **Permission denied**: Must run as root or with `CAP_BPF` + `CAP_PERFMON`.
- **Tracepoint offsets wrong on non-x86_64**: The offsets in `guardian-ebpf/src/main.rs`
  (lines 219-231) are for x86_64. Verify on your arch by reading:
  `cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format`

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Tracepoint + LSM hybrid | Tracepoint captures filename from syscall args (easy). LSM hook blocks access (enforcement). Tracepoint sets PENDING_DENY map entry, LSM reads it. Avoids complex path reading in LSM context. |
| 3-tier identification (cgroup > TGID > comm) | Cgroup is unspoofable (kernel-enforced). TGID tracking catches children. Comm is the fallback. All three checked in eBPF for maximum coverage. |
| Kernel-side policy evaluation | Deny/allow rules stored in BPF Array maps. Tracepoint evaluates policy in-kernel with bounded loops. Eliminates userspace round-trip for enforcement decisions. |
| Per-CPU array scratch buffer | eBPF has 512-byte stack limit. `FileAccessEvent` is 292 bytes. Using `PerCpuArray` as a pre-allocated buffer is the standard pattern. |
| `PerfEventArray` (not `RingBuf`) | Compatible with Linux 5.2+. `RingBuf` is more efficient but needs 5.8+. |
| Deny-takes-precedence policy | Security best practice. Even if a path matches an allow rule, a deny rule overrides it. Prevents accidental over-permissioning. |
| `#[repr(C)]` on shared structs | Ensures identical memory layout between BPF target and native target. Without it, Rust may reorder fields differently per target. |
| Graceful LSM fallback | If LSM attachment fails (kernel doesn't support it), daemon falls back to monitor-only mode instead of crashing. |
| Cgroup v2 for agent isolation | Unspoofable identity, automatic child tracking via inheritance, resource limits via controllers. Process cannot escape its cgroup. |
| Launcher + IPC registration | `guardian-launch` creates cgroup, registers with daemon via Unix socket, then exec's agent. Clean separation of concerns. |
| Length-prefixed JSON IPC | Simple, debuggable protocol over Unix domain socket. Supports agent registration, listing, stopping, and temporary grants. |
| Temporary grants with expiry | Allow rules added to BPF maps with automatic removal after duration. Enables time-bounded access to sensitive resources. |

## Known Limitations (Phase 3)

1. **Relative paths not resolved**: eBPF captures whatever path the syscall receives
2. **Only hooks `openat`**: Doesn't cover `open` (rare on modern Linux), `openat2`,
   or `readlink`/`stat` (for detecting path enumeration)
3. **x86_64 offsets hardcoded**: Tracepoint field offsets may differ on aarch64/arm
4. **Max 256 deny/allow rules**: Per BPF map entry limits
5. **Enforcement requires CONFIG_BPF_LSM**: Kernel must have `CONFIG_BPF_LSM=y`
   and `bpf` in the LSM list. Falls back to monitor-only if unavailable.
6. **Exec monitoring is log-only**: Exec events are logged but not blocked
7. **Tracepoint-LSM timing dependency**: Enforcement relies on the `sys_enter_openat`
   tracepoint firing before the LSM `file_open` hook in the same syscall
8. **Cgroup requires root**: Creating cgroups and running guardian-launch needs root
9. **Cgroup v2 required**: Cgroup-based identification requires cgroup v2 (default on modern distros)
10. **Process name still spoofable for comm-based agents**: Use cgroup identity for unspoofable identification

## Build Notes

- The `log_level` field in `GlobalConfig` triggers a dead_code warning since
  env_logger uses `RUST_LOG` env var. This is intentional for future use.

## Roadmap for Future Phases

### Phase 2: Enforcement + Exec Monitoring ✅ DONE
- LSM BPF `file_open` hook for kernel-level blocking
- `sys_enter_execve` tracepoint for command execution monitoring
- Process tree tracking via `sched_process_fork` / `sched_process_exit`
- Periodic PID rescanning via tokio interval
- Kernel-side policy evaluation with deny/allow rules in BPF maps

### Phase 3: Advanced Identity & Access ✅ DONE
- **Cgroup-based agent identification** via `bpf_get_current_cgroup_id()` in eBPF
- **Guardian Launcher** (`guardian-launch`): cgroup creation, resource limits, IPC registration
- **Guardian Ctl** (`guardian-ctl`): list/stop/grant CLI for agent management
- **Unix socket IPC** for launcher-daemon communication (`/run/guardian.sock`)
- **Time-based access windows** with automatic BPF map cleanup on expiry
- **Resource limits** via cgroup v2 controllers (memory, PIDs, CPU)
- **3-tier eBPF identification**: cgroup ID → TGID → comm name (backward compatible)
- **Cgroup lifecycle**: automatic cleanup when agent exits (cgroup becomes empty)

### Phase 4: Alerting & Integration
- Webhook alerts for policy violations
- Slack/email notifications
- Structured JSON logging for SIEM
- Prometheus metrics export

### Phase 5: Dashboard & UI
- Web-based real-time dashboard
- Visual policy editor
- Agent activity timeline
- Alert management

## Dependency Versions

| Crate | Version | Purpose |
|-------|---------|---------|
| aya | 0.13 | eBPF userspace library |
| aya-ebpf | 0.1 | eBPF kernel-side library |
| aya-log | 0.2 | Log forwarding from eBPF to userspace |
| aya-log-ebpf | 0.1 | Log macros for eBPF programs |
| tokio | 1 | Async runtime for event processing |
| serde | 1 | Config deserialization + IPC |
| serde_json | 1 | IPC message serialization |
| toml | 0.8 | TOML config parsing |
| clap | 4 | CLI argument parsing |
| anyhow | 1 | Error handling with context |
| bytes | 1 | Perf buffer byte management |
| log | 0.4 | Logging facade |
| env_logger | 0.11 | Log output |
| libc | 0.2 | Unix system calls (kill, etc.) |

## Code Quality Notes

- All source files have extensive inline comments explaining eBPF concepts,
  Rust patterns, and security rationale - the user is learning all three simultaneously
- `guardian/src/config.rs` has 6 unit tests covering path matching and policy evaluation
- `guardian/src/main.rs` has 3 unit tests for flag decoding
- The tests in `guardian/` can only run on Linux (aya dependency)
- `guardian-common` tests pass on any platform

## Security Best Practices Implemented

- Default-deny policy model
- Deny rules override allow rules
- Config validation warns about overly permissive patterns
- Sensitive paths (SSH keys, cloud creds, .env) in default deny list
- eBPF program never blocks syscalls in Phase 1 (fail-open for safety)
- Error in eBPF program returns 0 (don't interfere with system)
- Documented that config file should be root-owned and not world-writable
