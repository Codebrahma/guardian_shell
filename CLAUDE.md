# Guardian Shell - Claude Agent Handoff Document

This document provides everything a Claude agent needs to continue development
on this project on a Linux machine.

## Project Summary

Guardian Shell is a Linux security tool that uses eBPF to monitor and restrict
LLM agent activities. It's built with Rust and the Aya eBPF framework.

**Current state: Phase 1 - File Access Monitoring (code complete, not yet compiled on Linux)**

The code was written on macOS and needs to be built and tested on Linux.
The `aya` crate (eBPF userspace library) is Linux-only, so only `guardian-common`
and `xtask` have been verified to compile. The full build and first test run
need to happen on Linux.

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
├── guardian-common/            # Shared types (no_std, works in kernel + userspace)
│   ├── Cargo.toml
│   └── src/lib.rs              # FileAccessEvent struct, constants, helpers
│
├── guardian-ebpf/              # eBPF kernel program (BPF bytecode)
│   ├── Cargo.toml              # Target: bpfel-unknown-none
│   └── src/main.rs             # Tracepoint on sys_enter_openat
│
├── guardian/                   # Userspace daemon
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs             # Entry point, eBPF loading, event loop
│       └── config.rs           # TOML parsing, policy engine, path matching
│
└── xtask/                      # Build tooling
    ├── Cargo.toml
    └── src/main.rs             # Cross-compiles eBPF program
```

## How It Works

1. **Userspace daemon** reads `config.toml` to learn which processes to monitor
   and what file access rules to apply
2. **Daemon scans `/proc/`** to find PIDs matching configured `process_name` values
3. **Daemon loads the eBPF program** into the kernel and populates the `WATCHED_PIDS` map
4. **eBPF program** hooks into the `sys_enter_openat` tracepoint (fires on every file open)
5. **On each openat()**, the eBPF program checks if the PID is watched; if yes, it
   captures the event (PID, UID, filename, flags) and sends it to userspace via perf buffer
6. **Userspace receives events** and evaluates them against policy rules (deny > allow > default)
7. **Phase 1 is monitor-only** - it logs ALLOW/DENY decisions but does NOT block access

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

### 3. Test with a Simple Process

Edit `config.toml` to watch a common process like `cat`:

```toml
[[agents]]
name = "test-cat"
process_name = "cat"

[agents.file_access]
default = "deny"
allow = ["/tmp/**"]
deny = ["/etc/shadow"]
```

Then in one terminal:
```bash
sudo RUST_LOG=debug target/release/guardian --config config.toml
```

In another terminal:
```bash
cat /tmp/somefile       # Should show [ALLOW]
cat /etc/passwd         # Should show [DENY] (not in allow list, default=deny)
cat /etc/shadow         # Should show [DENY] (explicit deny)
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
| Tracepoint (not LSM BPF) | Phase 1 is monitor-only. LSM hooks can enforce (block access) but require `CONFIG_BPF_LSM` which not all kernels have. Tracepoints work everywhere. |
| Process name matching | Simplest identification. Scans `/proc/PID/comm`. Limitation: point-in-time scan, agents started after daemon aren't detected. |
| Per-CPU array scratch buffer | eBPF has 512-byte stack limit. `FileAccessEvent` is 292 bytes. Using `PerCpuArray` as a pre-allocated buffer is the standard pattern. |
| `PerfEventArray` (not `RingBuf`) | Compatible with Linux 5.2+. `RingBuf` is more efficient but needs 5.8+. |
| Deny-takes-precedence policy | Security best practice. Even if a path matches an allow rule, a deny rule overrides it. Prevents accidental over-permissioning. |
| `#[repr(C)]` on shared structs | Ensures identical memory layout between BPF target and native target. Without it, Rust may reorder fields differently per target. |

## Known Limitations (Phase 1)

1. **Monitor-only**: Logs violations but doesn't actually block file access
2. **Point-in-time PID scan**: Agents started after Guardian aren't detected until restart
3. **Process name spoofable**: Agent could `prctl(PR_SET_NAME)` to change its comm
4. **Relative paths not resolved**: eBPF captures whatever path the syscall receives
5. **Only hooks `openat`**: Doesn't cover `open` (rare on modern Linux), `openat2`,
   or `readlink`/`stat` (for detecting path enumeration)
6. **x86_64 offsets hardcoded**: Tracepoint field offsets may differ on aarch64/arm

## Unused Import Warning

`guardian/src/main.rs:60` imports `AgentConfig` which is currently unused in that
file (it's used indirectly through the `Config` struct). If the compiler warns,
either remove the import or add `#[allow(unused_imports)]`.

## Roadmap for Future Phases

### Phase 2: Enforcement + Exec Monitoring
- Replace tracepoint with **LSM BPF hooks** (`file_open`) for kernel-level blocking
- Add `sys_enter_execve` tracepoint for command execution monitoring
- Add process tree tracking (watch child processes of agents)
- Add periodic PID rescanning or exec-based auto-discovery

### Phase 3: Advanced Identity & Access
- **Cgroup-based agent identification** (robust, can't be spoofed)
- Launcher wrapper that puts agents in dedicated cgroups
- Time-based access windows ("allow /etc/hosts for 5 minutes")
- User consent flow for elevated permissions

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
| serde | 1 | Config deserialization |
| toml | 0.8 | TOML config parsing |
| clap | 4 | CLI argument parsing |
| anyhow | 1 | Error handling with context |
| bytes | 1 | Perf buffer byte management |
| log | 0.4 | Logging facade |
| env_logger | 0.11 | Log output |

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
