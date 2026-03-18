# Guardian Shell - Claude Agent Handoff Document

This document provides everything a Claude agent needs to continue development
on this project on a Linux machine.

## Project Summary

Guardian Shell is a Linux security tool that uses eBPF to monitor and restrict
LLM agent activities. It's built with Rust and the Aya eBPF framework.

**Current state: Phase 10 - Hardened Cgroup Agents (compiled on Linux)**

Phase 10 introduces **defense-in-depth for cgroup agents** — a creative architectural shift that solves all CRITICAL and HIGH security vulnerabilities by using the right enforcement tool for each layer:

- **Landlock LSM sandbox** (Linux 5.13+): Inode-level file access control applied in `guardian-launch` before exec. Resolves symlinks at kernel VFS layer — completely immune to the #1 CRITICAL symlink bypass. Default-deny model mirrors agent policy.
- **Expanded seccomp filter**: Blocks mount (165-166), namespace escape (setns 308, unshare 272), chroot (161), pivot_root (155), and new mount API (428-433, 442) in addition to existing io_uring and memfd_create blocks.
- **PR_SET_NO_NEW_PRIVS**: Prevents SUID privilege escalation. Required by Landlock, good practice regardless.
- **IPC sandbox config**: Daemon sends agent policy to launcher during registration via `SandboxConfig` in IPC response. Launcher builds Landlock rules + seccomp filter from it.
- **Two security tiers**: Cgroup agents (Tier 1, hardened: Landlock+seccomp+eBPF+cgroup) vs comm-based agents (Tier 2, limited: eBPF monitoring only).
- **Landlock TCP network filtering** (kernel 6.7+): Port-based outbound TCP control as additional layer alongside eBPF LSM socket_connect.

Key insight: eBPF tracepoints operate on path strings (vulnerable to symlinks, TOCTOU). Landlock operates on inodes (immune). Phase 10 makes Landlock the primary enforcement layer for cgroup agents, with eBPF as the audit/visibility layer.

Phase 9 adds kernel-level network enforcement, upgrading from Phase 7's log-only network monitoring to actual connection blocking:

- **Network enforcement**: LSM `socket_connect` hook blocks denied connections at kernel level (returns -ECONNREFUSED)
- **Network policy maps**: Port-based deny/allow BPF maps (`NET_DENY_PORTS`, `NET_ALLOW_PORTS`) evaluated in-kernel by `sys_enter_connect` tracepoint
- **PENDING_NET_DENY map**: Same tracepoint→PENDING_MAP→LSM pattern as file_open, inode_rename, etc.
- **Per-cgroup network defaults**: `NET_CGROUP_DEFAULT_ACTION` map for cgroup-based agents
- **BPF stack fix**: Dynamic linker detection reads argv[1] directly into event buffer (eliminates 256-byte stack allocation that exceeded BPF 512-byte limit)

Phase 8 adds security hardening (IPC auth, rate limiting, SSRF prevention, SRI hashes, etc.). Phase 7 adds:

- **Path canonicalization**: `normalize_path()` strips `/proc/self/root/`, `/proc/<pid>/root/`, resolves `..` components
- **openat2 tracepoint**: `sys_enter_openat2` eBPF hook closes the openat2 syscall bypass (Linux 5.6+)
- **Permission rate limiting**: Per-agent rate limits (3/min, 15/hr), exponential backoff after denials, same-resource cooldown
- **Risk classification**: 4-tier risk scoring (Low/Medium/High/Critical) with path patterns, exec multiplier, post-denial multiplier
- **Auto-deny**: Configurable never-approve list for critical resources (`/etc/shadow`, SSH keys, etc.)
- **Auto-approve**: Configurable auto-approve for low-risk resources (`/tmp/**`, `/proc/self/**`)
- **Justification analysis**: Pattern matching for suspicious text (urgency, security bypass, reassurance, authority claims)
- **UI friction**: Mandatory wait timers (0/3/5/10s by risk level), type-to-confirm for CRITICAL risk, risk-colored banners
- **Persistent audit trail**: SQLite `permission_audit` table with full metadata for all permission decisions
- **Risk display**: Risk level badges, justification warnings, and risk flags shown in banners and requests page
- **Exec enforcement**: LSM `bprm_check_security` hook with `PENDING_EXEC_DENY` map for kernel-side binary blocking
- **Network monitoring**: `sys_enter_connect` tracepoint with sockaddr parsing (AF_INET/AF_INET6) and port-based policy
- **Legacy open hook**: `sys_enter_open` tracepoint as belt-and-suspenders for rare code paths using legacy `open()` syscall
- **SSE connection fix**: Single shared EventSource with custom DOM events prevents browser connection pool exhaustion

Architecture: Permission requests use oneshot channels for long-poll IPC. Agent sends request
via Unix socket, daemon creates oneshot channel and broadcasts to dashboard via `tokio::sync::broadcast`.
Human approves/denies in browser, decision sent back via oneshot, agent unblocks immediately.
SSE endpoint uses `tokio_stream::StreamExt::merge` to combine two broadcast streams.
Security hardening adds `permissions.rs` module with rate limiter, risk classifier, auto-deny/approve,
and justification analyzer. All evaluated before the oneshot channel is created.
Exec enforcement uses a separate `PENDING_EXEC_DENY` map (not shared with file `PENDING_DENY`) because
during execve, the kernel internally opens the binary, triggering `file_open` LSM which would consume a
shared pending entry. Network enforcement uses the same tracepoint→PENDING_MAP→LSM pattern:
`sys_enter_connect` evaluates port-based policy and sets `PENDING_NET_DENY`, then LSM `socket_connect`
consumes the entry and returns -ECONNREFUSED to block the connection.

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
│   └── src/lib.rs              # FileAccessEvent, NetworkEvent, IPC protocol types, constants
│
├── guardian-ebpf/              # eBPF kernel program (BPF bytecode)
│   ├── Cargo.toml              # Target: bpfel-unknown-none
│   └── src/main.rs             # Tracepoints (openat/open/openat2/execve/connect) + LSM hooks (file_open/bprm_check_security) + cgroup identification
│
├── guardian/                   # Userspace daemon
│   ├── Cargo.toml
│   ├── askama.toml             # Template config
│   ├── templates/              # Phase 5/6: Askama HTML templates
│   │   ├── base.html           # Base layout (nav, head, TailwindCSS/htmx/Alpine.js, permission banner)
│   │   ├── index.html          # Dashboard overview with status cards + recent events
│   │   ├── events.html         # Live SSE event stream with filtering
│   │   ├── agents.html         # Agent management (list, stop, grant with exec type)
│   │   ├── policy.html         # Policy editor (per-agent allow/deny rules)
│   │   ├── alerts.html         # Alert configuration editor
│   │   └── requests.html       # Phase 6: Permission requests (pending + resolved history)
│   ├── static/                 # Phase 5: Static assets (embedded via rust-embed)
│   │   ├── app.js              # Custom JavaScript
│   │   └── app.css             # Custom CSS
│   └── src/
│       ├── main.rs             # Entry point, eBPF loading, event loop, IPC server
│       ├── config.rs           # TOML parsing, policy engine, path normalization, alerting + dashboard config
│       ├── permissions.rs      # Permission hardening: rate limiting, risk classification, auto-deny/approve, justification analysis
│       ├── ipc.rs              # IPC server, agent registration, cgroup lifecycle, permission requests
│       ├── alerting/           # Phase 4: Alerting & Integration
│       │   ├── mod.rs          # AlertManager, AlertSender, dedup, dispatch, broadcast
│       │   ├── json_log.rs     # Structured JSONL logging with rotation
│       │   ├── webhook.rs      # Generic HTTP POST webhook
│       │   ├── slack.rs        # Slack Block Kit notifications
│       │   ├── email.rs        # SMTP email alerts
│       │   └── metrics.rs      # Prometheus metrics + HTTP server
│       └── dashboard/          # Phase 5: Web Dashboard
│           ├── mod.rs          # Axum router, static file handler, server startup
│           ├── state.rs        # DashboardState (shared refs to IPC, alerts, event bus)
│           └── routes/
│               ├── mod.rs      # Route module declarations
│               ├── pages.rs    # Page handlers (/, /agents, /policy, /alerts, /events, /requests)
│               ├── api.rs      # API handlers (stop, grant, policy update, alerts, reload, permissions)
│               └── sse.rs      # SSE event stream endpoint (merged alert + permission streams)
│
├── guardian-launch/            # Agent launcher with cgroup isolation (Phase 3)
│   ├── Cargo.toml
│   └── src/main.rs             # Creates cgroup, registers, exec's agent
│
├── guardian-ctl/               # CLI for managing agents (Phase 3+6)
│   ├── Cargo.toml
│   └── src/main.rs             # list/stop/grant/request-permission commands
│
├── configs/                    # Preset configuration templates (Phase 4)
│   ├── minimal.toml            # Bare minimum, monitor-only
│   ├── recommended.toml        # Production defaults
│   ├── strict.toml             # Maximum security
│   └── development.toml        # Verbose debugging
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
6. **`guardian-ctl`** provides list/stop/grant (file & exec)/request-permission commands

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
    -p "/etc/shadow" -d 60                              # Temporary 60s file grant
sudo target/release/guardian-ctl grant -n test-agent \
    -p "/usr/bin/curl" -d 60 -t exec                   # Temporary 60s exec grant
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
| Temporary grants with expiry | Allow rules added to BPF maps (file) or exec policy (exec) with automatic removal after duration. Both `guardian-ctl grant -t exec` and dashboard support exec grants. |
| Async alert dispatch | AlertManager runs as tokio task with mpsc channel. Event processors never block on I/O. |
| Synchronous Prometheus metrics | Counters updated atomically in event processors. Accurate even when alert channel is full. |
| Per-output severity filters | Webhook gets warnings, Slack/email get critical only. Reduces noise per channel. |
| JSONL format (one JSON per line) | Easy to grep, tail, pipe to SIEM. No parser state between lines. Industry standard. |
| Simple TCP metrics server | Avoids axum dependency for Phase 4. Serves Prometheus text format directly. |
| Hash-based dedup | Same (agent, event_type, path, action) suppressed within window. Prevents alert storms. |
| Preset config templates | Inspired by Falco: ship working configs for common scenarios. Reduces onboarding friction. |
| axum + htmx + Alpine.js | Server-rendered HTML with htmx for partial updates, Alpine.js for client-side filtering. No JS build step. ~30KB total frontend. |
| askama templates | Compile-time template checking catches errors at build time. Zero-allocation rendering. |
| rust-embed for static files | Single binary deployment. No external file dependencies. |
| broadcast channel for SSE | Standard tokio pattern. Lagged SSE clients skip events rather than blocking producers. |
| Manual TOML serialization | Preserves readable config format. serde_toml round-trips lose comments and ordering. |
| Dashboard behind `enabled` flag | Zero overhead when disabled. No axum server spawned. |
| Oneshot channel for permission long-poll | Agent blocks on `oneshot::Receiver`, dashboard resolves via `oneshot::Sender`. No polling loops. |
| SSE stream merging | `tokio_stream::StreamExt::merge` combines alert + permission broadcast streams into single SSE endpoint. |
| Alpine.js global permission store | Defined in `base.html`, available on every page. Banners appear everywhere without code duplication. |
| 120s auto-deny timeout | Fail-secure: unanswered requests are denied. Prevents agents from hanging indefinitely. |
| Dual data sources (fetch + SSE) | HTTP fetch catches pre-existing pending requests; SSE delivers new ones in real time. |
| Userspace path normalization | Quick win for `/proc/self/root/` and `..` bypasses without kernel changes. Not full canonicalization (no symlinks). |
| Risk-based approval friction | 4-tier risk scoring with mandatory wait timers prevents reflexive rubber-stamping of high-risk requests. |
| Justification pattern matching | Simple string matching flags social engineering patterns (urgency, authority claims). Low false positive rate. |
| Per-agent rate limiting | Prevents approval fatigue via flood attacks. Exponential backoff on consecutive denials. |
| SQLite permission audit | Persistent trail survives daemon restarts. Enables future anomaly detection on approval patterns. |
| openat2 graceful fallback | `load_tracepoint` failure is non-fatal — daemon continues without openat2 coverage on kernels < 5.6. |
| Separate PENDING_EXEC_DENY map | During execve, kernel internally opens the binary triggering `file_open` LSM. A shared PENDING map would be consumed by the file_open check, so exec enforcement needs its own map. |
| sys_enter_connect + LSM socket_connect for network enforcement | Tracepoint parses sockaddr, evaluates port-based policy, sets PENDING_NET_DENY. LSM socket_connect blocks with -ECONNREFUSED. Same pattern as file_open enforcement. |
| Single shared SSE connection | Browser HTTP/1.1 limits (~6 connections per origin). Multiple EventSource instances per page exhausted the pool. Single shared SSE with custom DOM events fixes this. |
| Legacy `sys_enter_open` hook | Belt-and-suspenders: most code uses `openat`, but rare binaries or direct syscalls may use legacy `open`. Reuses PENDING_DENY and EVENT_BUF maps. |
| Landlock as primary enforcement for cgroup agents | eBPF tracepoints see path strings (vulnerable to symlinks, TOCTOU). Landlock operates on inodes (immune). Use the right tool for each job: Landlock enforces, eBPF audits. |
| IPC sandbox config delivery | Daemon sends agent policy to launcher in registration Ack. Avoids config parsing duplication and keeps single source of truth. |
| Landlock default-deny only | Landlock has no deny rules — it's inherently default-deny. Agents with `file_access.default = "allow"` skip Landlock (incompatible model). |
| System read paths in Landlock | Common paths (/usr/lib, /etc/resolv.conf, /dev/null, etc.) get read+execute for dynamic linking. Without these, most binaries can't start. |
| Two security tiers | Cgroup agents get 4-layer defense (Landlock+seccomp+eBPF+cgroup). Comm-based agents get eBPF only. Clear documentation prevents false sense of security. |

## Known Limitations (Phase 10)

1. **Symlinks bypass eBPF enforcement**: eBPF tracepoints see raw path strings, not resolved inodes. **Mitigated for cgroup agents by Landlock** (inode-level, symlink-immune). Comm-based agents remain vulnerable.
2. **openat2 tracepoint requires kernel 5.6+**: Gracefully skipped on older kernels
3. **x86_64 offsets hardcoded**: Tracepoint field offsets may differ on aarch64/arm
4. **BPF LSM enforcement optional for cgroup agents**: Landlock provides primary enforcement. BPF LSM (`CONFIG_BPF_LSM=y`) adds a second enforcement layer but is no longer required for security.
5. **Tracepoint-LSM timing dependency**: eBPF enforcement relies on tracepoint firing before LSM hook. **Not applicable to Landlock** (separate enforcement path).
6. **Cgroup requires root**: Creating cgroups and running guardian-launch needs root
7. **Cgroup v2 required**: Cgroup-based identification requires cgroup v2 (default on modern distros)
8. **Comm-based agents have limited security**: No Landlock, no seccomp hardening. Use cgroup agents for production.
9. **SIGHUP reload doesn't update alerting outputs**: Alerting config changes still require daemon restart
10. **No webhook retry logic**: Failed webhook/Slack/email sends are logged and dropped
11. **Email password stored in plaintext config**: Use file permissions to protect config
12. **Dashboard policy changes don't update BPF maps**: Require daemon restart or SIGHUP
13. **Config write-back loses comments**: Dashboard saves config as clean TOML
14. **TailwindCSS/htmx/Alpine.js loaded from CDN**: Dashboard requires internet access
15. **Landlock requires Linux 5.13+**: Gracefully skipped on older kernels. Network filtering requires 6.7+.
16. **Landlock incompatible with `default = "allow"`**: Agents with permissive default skip Landlock sandbox.
17. **Seccomp filter is x86_64 only**: Syscall numbers hardcoded for x86_64 in guardian-launch
18. **UDP not enforced by Landlock**: Only TCP connect is filtered. UDP `sendto()` without prior `connect()` bypasses both Landlock and eBPF.
19. **DNS unmonitored**: DNS resolution happens before `connect()`. No domain-based policy possible.

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
- **Time-based access windows** (file and exec) with automatic cleanup on expiry
- **Resource limits** via cgroup v2 controllers (memory, PIDs, CPU)
- **3-tier eBPF identification**: cgroup ID → TGID → comm name (backward compatible)
- **Cgroup lifecycle**: automatic cleanup when agent exits (cgroup becomes empty)

### Phase 4: Alerting & Integration ✅ DONE
- **Structured JSON logging** with SIEM-compatible JSONL format and size-based rotation
- **Webhook alerts** via HTTP POST with JSON payload and auth headers
- **Slack notifications** with Block Kit formatting and severity-colored messages
- **Email notifications** via async SMTP (lettre) with STARTTLS
- **Prometheus metrics** on HTTP endpoint (file events, exec events, alerts sent/dropped)
- **Alert dedup/throttling** with configurable time window and rate limits
- **Config validation CLI** (`--validate-config`) for pre-deployment checks
- **SIGHUP config reload** for hot-reloading agent policies
- **Preset configs** in `configs/` (minimal, recommended, strict, development)

### Phase 5: Dashboard & UI ✅ DONE
- **Web dashboard** embedded in guardian binary (axum + htmx + Alpine.js + TailwindCSS)
- **Live event stream** via SSE with severity/action filtering
- **Agent management**: view configured agents, stop cgroup agents, grant temporary access
- **Policy editor**: edit file access and exec rules per agent, save to disk
- **Alert configuration**: toggle and configure all alerting outputs from browser
- **Status overview**: auto-refreshing mode/agent/event/blocked cards
- **Config reload**: reload config from dashboard UI
- **Prometheus metrics** endpoint integrated into dashboard server (`/metrics`)
- **Single binary**: templates compiled in, static files embedded via rust-embed

### Phase 6: Interactive Permission Requests ✅ DONE
- **Interactive permission requests** via `guardian-ctl request-permission`
- **Long-poll IPC** with `tokio::sync::oneshot` channels (agent blocks waiting for human)
- **Real-time dashboard notifications**: permission banners on every page via SSE
- **Dedicated `/requests` page**: pending requests table + resolved history audit trail
- **SSE stream merging**: alert events + permission events on single SSE connection
- **Approve/deny with grant duration**: 1 min to 1 hour configurable grant duration
- **120-second auto-deny timeout**: fail-secure, unanswered requests denied
- **Exec grant support**: temporary grants for both file access and exec commands
- **Alpine.js permission store**: global store with countdown timer, badge counter
- **Resolved history**: last 100 resolved requests with full metadata

### Phase 7: Security Hardening (Partial) ✅ DONE
Based on `docs/security-improvements-research.md`:

**7a: Critical Security Fixes (partial):**
- Userspace path normalization (`normalize_path()`) in config.rs + main.rs event loop
- `openat2` tracepoint hook in eBPF (closes openat2 syscall bypass)
- *Not yet implemented:* LSM `file_open` with `bpf_d_path()`, LSM `bprm_check_security`, dynamic linker detection, `inode_rename`/`inode_unlink` hooks

**7c: Approval Hardening (complete):**
- Per-agent rate limiting (3/min, 15/hr, exponential backoff, same-resource cooldown)
- Risk classification with 4-tier scoring (Low/Medium/High/Critical)
- Auto-deny for never-approve resources
- Auto-approve for low-risk resources with configurable duration
- Justification text analysis (urgency, security bypass, reassurance, authority claims)
- Mandatory wait timers in UI (0/3/5/10s by risk level)
- Type-to-confirm for CRITICAL risk resources
- Risk-colored permission banners with justification warnings
- Persistent SQLite audit trail for all permission decisions
- `/api/permissions/audit` endpoint for querying audit history

**Not yet implemented:** Phase 7b (network monitoring), Phase 7d (advanced hardening: inode deny map, content hashing, io_uring blocking, mmap_file LSM, anomaly detection)

### Phase 8: Security Fixes ✅ DONE
Based on `docs/security/security-fixes.md` and `docs/security/security-limitations.md`:

**8a: Critical Security (P0+P1):**
- BPF map capacity increased from 256 to 1024 entries (`MAX_POLICY_RULES = 1024`)
- Seccomp filter in `guardian-launch` blocks io_uring (syscalls 425-427) and memfd_create (319) with EPERM
- Inode LSM hooks: `inode_rename`, `inode_unlink`, `inode_link` with PENDING maps and tracepoints for rename/unlink/hardlink enforcement
- Path truncation handling: `status_flags` field in `FileAccessEvent`, `EVENT_FLAG_TRUNCATED` flag, deny-by-default for truncated paths

**8b: Exec Hardening + Dashboard Security (P2):**
- Dynamic linker detection: `DYNAMIC_LINKERS` BPF map, reads `argv[1]` for real binary behind ld-linux
- `execveat` tracepoint: detects `AT_EMPTY_PATH` flag (memfd_create + execveat attack vector)
- Strict enforcement mode: `mode = "strict"` bails on any LSM load/attach failure
- Default `/memfd:` exec deny: unconditionally blocks exec of memfd paths
- Dashboard authentication: optional `auth_token` in config, Bearer header or `?token=` query param

**8c: Approval Hardening (P3):**
- Risk-based configurable timeouts: `RiskTimeoutConfig` with per-level timeout settings (60/120/180/300s defaults)
- CLI permission approval: `guardian-ctl pending/approve/deny` commands + IPC message handlers
- Grant accumulation limits: `GrantAccumulator` tracking 24h cumulative grant durations, `max_grant_total_secs` config
- Improved justification analysis: weighted scoring (per-pattern weights), graduated risk bumps (score >= 8 -> +2, >= 3 -> +1)

**8d: Polish (P4):**
- Configurable fail-closed mode: `fail_closed: true` per agent, `FAIL_CLOSED_CGROUPS` BPF map
- SIGHUP reload: agent policies and permissions config reloaded (alerting outputs still require restart)
- Anomaly detection: hourly background task checking rubber-stamping (>90% approval), high-volume agents, deny-then-approve persistence patterns
- SQLite query methods: `approval_rate_24h()`, `high_volume_agents_24h()`, `agents_with_deny_then_approve()`

### Phase 9: Network Enforcement ✅ DONE
- LSM `socket_connect` hook blocks denied connections at kernel level (-ECONNREFUSED)
- Port-based BPF maps: `NET_DENY_PORTS`, `NET_ALLOW_PORTS`, `NET_DEFAULT_ACTION`, `NET_CGROUP_DEFAULT_ACTION`
- `PENDING_NET_DENY` map: tracepoint→PENDING→LSM pattern for network enforcement
- `populate_net_enforcement_maps()` loads port policy from config into BPF maps
- BLOCKED status in `process_net_event()` for enforce mode

### Phase 10: Hardened Cgroup Agents ✅ DONE
Creative architectural shift: use Landlock LSM as primary enforcement, eBPF as audit layer.

- **Landlock sandbox** in `guardian-launch`: inode-level file access control (Linux 5.13+). Resolves symlinks at VFS layer. Default-deny model. TCP connect filtering (kernel 6.7+).
- **Expanded seccomp**: Blocks mount (165-166), namespace escape (setns, unshare), chroot, pivot_root, new mount API (428-433, 442)
- **PR_SET_NO_NEW_PRIVS**: Prevents SUID escalation, required by Landlock
- **IPC SandboxConfig**: Daemon sends agent policy in registration Ack response. Launcher builds Landlock + seccomp from it.
- **Two security tiers**: Cgroup = hardened (Landlock+seccomp+eBPF+cgroup), Comm = limited (eBPF only)
- Every CRITICAL and HIGH vulnerability (symlinks, TOCTOU, io_uring, rename/hardlink) is mitigated for cgroup agents

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
| reqwest | 0.12 | HTTP client for webhook/Slack alerts |
| lettre | 0.11 | Async SMTP email transport |
| chrono | 0.4 | ISO 8601 timestamps |
| prometheus | 0.13 | Prometheus metrics counters + encoding |
| axum | 0.8 | HTTP framework for dashboard |
| askama | 0.12 | Compile-time HTML templates |
| askama_axum | 0.4 | Askama + axum integration |
| rust-embed | 8 | Embed static files in binary |
| tower-http | 0.6 | HTTP middleware (CORS) |
| seccompiler | 0.4 | Seccomp BPF filter for blocking io_uring/memfd_create/mount/namespace |
| landlock | 0.4 | Landlock LSM for inode-level file access control (symlink-immune) |
| tokio-stream | 0.1 | Stream adapters for SSE broadcast |

## Code Quality Notes

- All source files have extensive inline comments explaining eBPF concepts,
  Rust patterns, and security rationale - the user is learning all three simultaneously
- `guardian/src/config.rs` has 15 unit tests covering path matching, policy evaluation, identity, and path normalization
- `guardian/src/permissions.rs` has 6 unit tests for rate limiting, risk classification, auto-deny/approve, and justification analysis
- `guardian/src/main.rs` has 4 unit tests for flag decoding and comm conversion
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
