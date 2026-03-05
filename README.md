# Guardian Shell

A Linux security tool that monitors and restricts LLM agent activities using eBPF. Built with Rust and the [Aya](https://aya-rs.dev/) framework.

## What Problem Does This Solve?

LLM agents (Claude Code, AutoGPT, Aider, etc.) run commands and access files on your system. Without guardrails, they could:

- Read your SSH keys, cloud credentials, or API tokens
- Modify system configuration files
- Access sensitive data outside their workspace
- Execute destructive commands

Guardian Shell uses eBPF to monitor agent behavior at the kernel level - there's no way for the agent to bypass it (unlike userspace sandboxes).

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        USER SPACE                            │
│                                                              │
│  ┌──────────┐     ┌──────────────────────────────────────┐  │
│  │  config   │────▶│         Guardian Daemon               │  │
│  │  (TOML)   │     │                                      │  │
│  └──────────┘     │  ┌────────────┐  ┌────────────────┐  │  │
│                    │  │ PID        │  │ Policy Engine  │  │  │
│  ┌──────────┐     │  │ Discovery  │  │ (allow/deny    │  │  │
│  │  /proc/   │────▶│  │ (/proc/)   │  │  path rules)   │  │  │
│  └──────────┘     │  └──────┬─────┘  └───────┬────────┘  │  │
│                    │         │                 │            │  │
│                    │  ┌──────┴─────────────────┴────────┐  │  │
│                    │  │       Event Processor            │  │  │
│                    │  │  (one async task per CPU core)   │  │  │
│                    │  └──────────────┬──────────────────┘  │  │
│                    └─────────────────┼──────────────────────┘  │
│                                      │ perf buffer             │
│ ─────────────────────────────────────┼──────────────────────── │
│                        KERNEL SPACE  │                          │
│                    ┌─────────────────┴──────────────────────┐  │
│                    │         eBPF Program                    │  │
│                    │   (tracepoint/sys_enter_openat)         │  │
│                    │                                         │  │
│                    │   1. Get PID of calling process          │  │
│                    │   2. Lookup in WATCHED_PIDS map          │  │
│                    │   3. If watched → capture event          │  │
│                    │   4. Send to userspace via perf buffer   │  │
│                    └─────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

## Key Concepts

### eBPF (extended Berkeley Packet Filter)
A technology that lets you run sandboxed programs in the Linux kernel without modifying kernel source code or loading kernel modules. The kernel's BPF verifier ensures these programs are safe (can't crash the kernel, infinite loop, or access invalid memory).

### Tracepoints
Static instrumentation points in the Linux kernel. We hook into `sys_enter_openat` which fires every time any process opens a file. Our eBPF program filters events to only capture those from watched processes.

### BPF Maps
Shared data structures between kernel and userspace:
- **WATCHED_PIDS** (HashMap): Userspace writes PIDs to watch; eBPF reads to filter
- **EVENT_BUF** (PerCpuArray): Scratch buffer for building events (eBPF has 512-byte stack limit)
- **EVENTS** (PerfEventArray): Ring buffer for sending events from kernel to userspace

### Aya Framework
A Rust library for writing eBPF programs. Unlike C-based eBPF tools (like BCC or libbpf), Aya lets you write both the kernel and userspace code in Rust with full type safety.

## Prerequisites

**This tool runs on Linux only.** If you're on macOS/Windows, use a Linux VM.

### System Requirements
- Linux kernel 5.2+ (for BPF tracepoint support)
- Root access (or `CAP_BPF` + `CAP_PERFMON` capabilities)

### Development Tools

```bash
# 1. Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Install nightly toolchain (required for eBPF compilation)
rustup install nightly
rustup component add rust-src --toolchain nightly

# 3. Install bpf-linker (links eBPF object files)
cargo install bpf-linker

# 4. Verify kernel supports BPF
# This should output kernel config options - look for CONFIG_BPF=y
zcat /proc/config.gz 2>/dev/null | grep CONFIG_BPF || grep CONFIG_BPF /boot/config-$(uname -r)
```

## Building

```bash
# Step 1: Build the eBPF kernel program
# This cross-compiles Rust to BPF bytecode
cargo xtask build-ebpf --release

# Step 2: Build the userspace daemon
cargo build --release
```

### Build Output

```
target/
├── bpfel-unknown-none/release/
│   └── guardian-ebpf          # eBPF kernel program (BPF bytecode)
└── release/
    └── guardian                # Userspace daemon (native binary)
```

## Configuration

Create a `config.toml` file (see the included example):

```toml
[global]
log_level = "info"

[[agents]]
name = "my-agent"
process_name = "python3"    # Match against /proc/PID/comm

[agents.file_access]
default = "deny"            # Deny everything not explicitly allowed

allow = [
    "/home/user/workspace/**",   # Allow project directory (recursive)
    "/tmp/**",                   # Allow temp files
    "/usr/lib/**",               # Allow system libraries
]

deny = [
    "/home/user/.ssh/**",        # Never allow SSH key access
    "/home/user/.aws/**",        # Never allow cloud credentials
    "/home/user/workspace/.env", # Deny .env even though workspace is allowed
]
```

### Pattern Matching Rules

| Pattern | Matches | Doesn't Match |
|---------|---------|---------------|
| `/etc/passwd` | Exact file only | `/etc/passwd.bak` |
| `/home/user/**` | Everything under `/home/user/` recursively | `/home/other/file` |
| `/tmp/*` | Files directly in `/tmp/` | `/tmp/sub/file` |

### Policy Evaluation Order

1. **Deny patterns** checked first (deny ALWAYS wins)
2. **Allow patterns** checked next
3. **Default action** applied if no pattern matches

## Running

```bash
# Start your LLM agent first, then run Guardian Shell:
sudo target/release/guardian --config config.toml

# With debug logging to see all file access events:
sudo RUST_LOG=debug target/release/guardian --config config.toml

# With trace logging for maximum detail:
sudo RUST_LOG=trace target/release/guardian --config config.toml
```

### Example Output

```
[INFO] Loading configuration from: config.toml
[INFO] Configuration loaded: 1 agent(s) configured
[INFO]   Agent 'claude-code': watching process 'claude', default=deny, 8 allow rules, 12 deny rules
[INFO] Loading eBPF program from: target/bpfel-unknown-none/release/guardian-ebpf
[INFO] eBPF program loaded successfully
[INFO] Watching PID 1234 (process: 'claude', agent: 'claude-code')
[INFO] eBPF program attached to syscalls/sys_enter_openat tracepoint
[INFO] ==========================================================
[INFO] Guardian Shell is running. Monitoring 1 agent(s).
[INFO] Press Ctrl+C to stop.
[INFO] ==========================================================
[WARN] [DENY] agent='claude-code' pid=1234 uid=1000 file='/home/user/.ssh/id_rsa' mode=READ
[WARN] [DENY] agent='claude-code' pid=1234 uid=1000 file='/etc/shadow' mode=READ
```

## Project Structure

```
guardian_shell/
├── Cargo.toml               # Workspace definition
├── .cargo/config.toml       # Cargo config (BPF linker setup)
├── rust-toolchain.toml       # Nightly Rust requirement
├── config.toml               # Example security policy configuration
│
├── guardian-common/          # Shared types (kernel + userspace)
│   ├── Cargo.toml
│   └── src/lib.rs            # FileAccessEvent struct, constants
│
├── guardian-ebpf/            # eBPF kernel program
│   ├── Cargo.toml
│   └── src/main.rs           # Tracepoint handler for sys_enter_openat
│
├── guardian/                 # Userspace daemon
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs           # Daemon entry point, event processing
│       └── config.rs         # TOML config parsing, policy engine
│
└── xtask/                    # Build tooling
    ├── Cargo.toml
    └── src/main.rs           # eBPF cross-compilation logic
```

## Security Considerations

### What This Protects Against (Phase 1)
- **Visibility**: See every file an LLM agent accesses in real-time
- **Audit trail**: Log all file access attempts with PID, UID, path, and access mode
- **Policy violations**: Identify when agents access files outside their allowed scope

### Current Limitations (Will Be Addressed in Future Phases)
- **Monitor-only**: Phase 1 logs violations but doesn't block access. The agent still succeeds in opening the file.
- **Point-in-time PID scan**: Agents started after Guardian Shell won't be detected until restart.
- **Process name spoofing**: Agents could theoretically change their comm name. Cgroup-based tracking (planned) prevents this.
- **Relative paths**: The eBPF program captures paths as provided by the syscall, which may be relative. Full path resolution is planned.

### Best Practices
1. **Always use `default = "deny"`** - principle of least privilege
2. **Be specific with allow patterns** - `/home/user/project/**` not `/**`
3. **Always deny credential paths** - `.ssh`, `.aws`, `.gnupg`, `.kube`
4. **Run Guardian Shell before starting agents** - ensures all file access is captured
5. **Monitor logs for unexpected DENY events** - indicates the agent is trying to access something it shouldn't

## Roadmap

### Phase 1 (Current) - File Access Monitoring
- [x] eBPF tracepoint on sys_enter_openat
- [x] Process identification by name
- [x] TOML-based policy configuration
- [x] Allow/deny path pattern matching
- [x] Event logging with PID, UID, path, flags

### Phase 2 - Kernel-Level Enforcement
- [ ] LSM (Linux Security Module) BPF hooks for actual file access blocking
- [ ] Exec monitoring (sys_enter_execve) for command restrictions
- [ ] Process tree tracking (monitor child processes)

### Phase 3 - Advanced Identity & Access
- [ ] Cgroup-based agent identification (robust, can't be spoofed)
- [ ] Launcher wrapper that automatically puts agents in cgroups
- [ ] Time-based access windows (allow privileged access for N minutes)
- [ ] User consent flow for elevated permissions

### Phase 4 - Alerting & Integration
- [ ] Webhook alerts for policy violations
- [ ] Slack/email notifications
- [ ] Structured JSON logging for SIEM integration
- [ ] Metrics export (Prometheus format)

### Phase 5 - Dashboard & UI
- [ ] Web-based real-time dashboard
- [ ] Visual policy editor
- [ ] Agent activity timeline
- [ ] Alert management interface

## Troubleshooting

### "Failed to load eBPF program"
```bash
# 1. Make sure you built the eBPF program first:
cargo xtask build-ebpf --release

# 2. Verify the binary exists:
ls -la target/bpfel-unknown-none/release/guardian-ebpf

# 3. Ensure you're running as root:
sudo target/release/guardian --config config.toml
```

### "No running processes found matching..."
The agent must be running BEFORE Guardian Shell starts. Start your agent first, then run Guardian Shell. Verify the process name:
```bash
ps aux | grep <your-agent>
cat /proc/<PID>/comm
```

### "Failed to attach to tracepoint"
```bash
# Check if your kernel supports BPF tracepoints:
ls /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/

# Check kernel config:
zcat /proc/config.gz | grep -E 'CONFIG_BPF|CONFIG_FTRACE'
```

### eBPF build fails with "linker not found"
```bash
# Install the BPF linker:
cargo install bpf-linker

# If that fails, you may need LLVM:
# Ubuntu/Debian: sudo apt install llvm-dev
# Fedora: sudo dnf install llvm-devel
```

## Learning Resources

- [Aya Book](https://aya-rs.dev/book/) - Official Aya tutorial
- [eBPF.io](https://ebpf.io/) - eBPF overview and documentation
- [Linux BPF documentation](https://docs.kernel.org/bpf/) - Kernel docs
- [The Rust Programming Language](https://doc.rust-lang.org/book/) - Rust basics
