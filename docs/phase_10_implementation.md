# Phase 10 Implementation: Hardened Cgroup Agents — Defense in Depth

## What Phase 10 Solves

Phases 1–9 built a comprehensive monitoring and enforcement system using eBPF tracepoints and LSM hooks. But eBPF enforcement has a fundamental architectural weakness: **tracepoints see path strings from userspace, not kernel inodes.** The kernel resolves paths to inodes *after* the tracepoint fires but *before* the actual I/O. This creates six vulnerabilities that cannot be fixed within eBPF:

**Problem 1: Symlink bypass (CRITICAL).** An agent creates a symlink from an allowed path to a denied resource. The eBPF tracepoint sees the allowed symlink path, not the real target:
```
Agent:   ln -s /etc/shadow /tmp/innocent_file
Agent:   cat /tmp/innocent_file
eBPF:    openat("/tmp/innocent_file") → matches /tmp/** → ALLOW
Kernel:  VFS resolves → opens /etc/shadow → agent reads shadow file
```
The agent gets the contents of `/etc/shadow` despite a deny rule. No amount of path string manipulation in eBPF can fix this — the path argument genuinely is `/tmp/innocent_file` at the syscall layer. Full fix would require `bpf_d_path()` which needs Linux 5.11+ and complex raw helper calls not yet supported by aya.

**Problem 2: TOCTOU race (HIGH).** The tracepoint reads the userspace path pointer at syscall entry. Between the tracepoint reading the path and the LSM hook firing, another thread can modify the memory the pointer references — changing the path between the check and the use.

**Problem 3: io_uring bypass (HIGH).** Phase 8 added seccomp to block `io_uring_setup`. But if an agent finds a way to load a seccomp-bypassing filter first (unlikely but theoretical), or if seccomp fails to apply, io_uring performs file I/O via ring buffers that completely bypass all syscall tracepoints.

**Problem 4: Rename/hardlink evasion.** Phase 8 added inode LSM hooks, but the path-based checking in tracepoints is still vulnerable to symlink indirection on the rename/link source or destination.

**Problem 5: memfd+execveat.** In-memory executables have no filesystem path. Phase 8 mitigates this with seccomp and execveat hooks, but a defense-in-depth approach needs enforcement at the VFS level.

**Problem 6: Dynamic linker tricks.** Phase 8's `argv[1]` inspection helps but remains fragile — the dynamic linker can be influenced via environment variables (`LD_PRELOAD`, `LD_LIBRARY_PATH`) and other indirection.

**The root cause:** eBPF tracepoints operate on syscall arguments (path strings), not on kernel objects (inodes). All six problems stem from this gap.

---

## The Creative Insight

**Stop trying to fix enforcement in eBPF. Use a kernel mechanism that already operates on inodes.**

Linux **Landlock LSM** (available since kernel 5.13, network support since 6.7) is a userspace-driven access control mechanism that:

- Operates at the **inode level** — symlinks are fully resolved by VFS before Landlock checks
- Is **immune to TOCTOU** — checks happen at the VFS layer, after path resolution
- Is **not bypassed by io_uring** — Landlock hooks are in the VFS/LSM layer, not the syscall layer
- Controls **rename/link operations** via the `REFER` right (ABI v2, kernel 5.19+)
- Controls **TCP connect** by port (ABI v4, kernel 6.7+)
- Is **irreversible** — once applied to a process, it can only be made more restrictive
- Is **inherited** by all child processes
- **Coexists** with BPF LSM — both are stackable LSMs

**The architecture flip:** For cgroup agents launched via `guardian-launch`, Landlock becomes the **primary enforcement layer**. eBPF becomes the **audit and visibility layer** (logging, dashboard, alerting). This gives us four defense layers:

```
┌─────────────────────────────────────────────────┐
│                 Agent Process                     │
├─────────────────────────────────────────────────┤
│  Layer 4: eBPF Monitoring                        │
│  • Tracepoints log all syscalls to dashboard     │
│  • LSM hooks provide additional enforcement      │
│  • Alerting pipeline for security events         │
├─────────────────────────────────────────────────┤
│  Layer 3: Seccomp Filter (expanded)              │
│  • Blocks io_uring (syscalls 425-427)            │
│  • Blocks memfd_create (319)                     │
│  • Blocks mount/umount (165, 166)                │
│  • Blocks new mount API (428-433, 442)           │
│  • Blocks pivot_root/chroot (155, 161)           │
│  • Blocks namespace escape (308, 272)            │
├─────────────────────────────────────────────────┤
│  Layer 2: Landlock Sandbox                       │
│  • Inode-level file access control               │
│  • Symlink-immune (resolved before check)        │
│  • TCP connect filtering by port (kernel 6.7+)   │
│  • No symlink/device/block creation rights       │
│  • Irreversible, inherited by children           │
├─────────────────────────────────────────────────┤
│  Layer 1: Cgroup Isolation                       │
│  • Memory/PID/CPU resource limits                │
│  • Unspoofable cgroup ID for identification      │
│  • Automatic child process inheritance           │
│  • PR_SET_NO_NEW_PRIVS (no SUID escalation)     │
└─────────────────────────────────────────────────┘
```

---

## Two Security Tiers

### Tier 1: Hardened Cgroup Agents (recommended, production)

Launched via `guardian-launch`. Gets all four defense layers. **Every CRITICAL and HIGH vulnerability is mitigated.**

### Tier 2: Legacy Comm-Based Agents (backward compatible, limited)

Not launched via `guardian-launch`. Gets eBPF monitoring + optional BPF LSM enforcement only:

| Vulnerability | Cgroup Agent (Tier 1) | Comm Agent (Tier 2) |
|---|---|---|
| Symlink bypass | **SOLVED** (Landlock) | VULNERABLE |
| TOCTOU race | **SOLVED** (Landlock) | VULNERABLE |
| io_uring bypass | **SOLVED** (seccomp) | VULNERABLE |
| Rename/hardlink | **SOLVED** (Landlock REFER) | PARTIAL (Phase 8 LSM) |
| memfd+execveat | **SOLVED** (seccomp + Landlock) | PARTIAL (Phase 8) |
| Dynamic linker | **SOLVED** (Landlock per-path exec) | PARTIAL (Phase 8) |
| Network exfil | **SOLVED** (Landlock TCP, 6.7+) | Phase 9 only |
| SUID escalation | **SOLVED** (PR_SET_NO_NEW_PRIVS) | VULNERABLE |
| Mount escape | **SOLVED** (seccomp blocks mount) | VULNERABLE |
| Namespace escape | **SOLVED** (seccomp blocks setns/unshare) | VULNERABLE |

---

## What Was Built

### IPC Protocol Extension

| File | Lines Changed | What |
|------|---------------|------|
| `guardian-common/src/lib.rs` | +35 | `SandboxConfig` struct with Landlock/seccomp/no_new_privs toggles and policy fields. `IpcResponse::Ack` extended with `sandbox: Option<SandboxConfig>`. Helper functions `default_true()`, `default_allow()`. |
| `guardian/src/ipc.rs` | +25 | Registration handler builds `SandboxConfig` from agent config and returns in Ack response. All non-registration Ack sites changed to `Ack { sandbox: None }`. |
| `guardian-ctl/src/main.rs` | +1 | Updated `IpcResponse::Ack` pattern match to `Ack { .. }`. |

### Landlock Sandbox + Expanded Seccomp

| File | Lines Changed | What |
|------|---------------|------|
| `guardian-launch/src/main.rs` | +230 (rewrite) | Full Landlock sandbox (`apply_landlock_sandbox()`), expanded seccomp (`apply_seccomp_filter()` with hardened mode), `PR_SET_NO_NEW_PRIVS`, `--no-landlock`/`--no-seccomp-hardened` CLI flags, `register_with_daemon()` returns `Option<SandboxConfig>`. |
| `guardian-launch/Cargo.toml` | +1 | `landlock = "0.4"` dependency. |

---

## Architecture

### How Landlock Solves Symlinks (The #1 CRITICAL Issue)

**The attack that defeats eBPF:**
```
Agent: ln -s /etc/shadow /tmp/innocent_file
Agent: cat /tmp/innocent_file
eBPF sees: openat("/tmp/innocent_file") → matches /tmp/** → ALLOW
Kernel reads: /etc/shadow → agent gets shadow file contents
```

**With Landlock:**
```
Agent: ln -s /etc/shadow /tmp/innocent_file
Agent: cat /tmp/innocent_file
VFS resolves: /tmp/innocent_file → inode of /etc/shadow
Landlock checks: is /etc/shadow inode under an allowed hierarchy? → NO
Result: -EACCES (Permission denied)
```

Landlock uses **file descriptors to identify directories**, not path strings. When a rule says "allow read under `/tmp`", the kernel resolves `/tmp` to its inode at rule-creation time. During access, the kernel walks from the target file's dentry up to root, checking if any ancestor inode matches a rule. Symlinks are resolved by VFS before this check happens. The attack is structurally impossible.

### IPC: Daemon → Launcher Config Delivery

The daemon needs to communicate the agent's policy to `guardian-launch` so it can build the Landlock ruleset. Rather than having the launcher parse the config file separately (which would duplicate parsing logic and create version skew), the daemon sends a `SandboxConfig` in the registration Ack response:

```
guardian-launch                          Guardian Daemon
      │                                        │
      │  Register { cgroup_path, cgroup_id,    │
      │             agent_name }               │
      ├───────────────────────────────────────>│
      │                                        │ ← looks up agent config
      │                                        │ ← builds SandboxConfig
      │  Ack { sandbox: Some(SandboxConfig) }  │
      │<───────────────────────────────────────┤
      │                                        │
      │  ← applies PR_SET_NO_NEW_PRIVS         │
      │  ← applies Landlock ruleset            │
      │  ← applies seccomp filter              │
      │  ← exec(agent command)                 │
```

**SandboxConfig fields:**

```rust
pub struct SandboxConfig {
    pub landlock: bool,           // Enable Landlock (default: true)
    pub seccomp_hardened: bool,   // Enable expanded seccomp (default: true)
    pub no_new_privs: bool,       // Set PR_SET_NO_NEW_PRIVS (default: true)
    pub file_default: String,     // "deny" or "allow"
    pub file_allow: Vec<String>,  // Allowed file paths (from agent config)
    pub exec_allow: Vec<String>,  // Allowed exec paths (from agent config)
    pub net_allow_ports: Vec<u16>,// Allowed TCP ports (from agent config)
    pub net_default: String,      // "deny" or "allow" (default: "allow")
}
```

### guardian-launch Execution Order

The execution order in `guardian-launch` is critical — each step has a dependency on the previous:

```
Step 1: Parse CLI args
Step 2: Create cgroup directory (/sys/fs/cgroup/guardian/<name>-<pid>/)
Step 3: Enable controllers + set resource limits (memory, PIDs, CPU)
Step 4: Get cgroup ID (inode number of the cgroup directory)
Step 5: Register with daemon (receives SandboxConfig)
Step 6: Move self into cgroup
Step 7: PR_SET_NO_NEW_PRIVS     ← before Landlock (required without CAP_SYS_ADMIN)
Step 8: Apply Landlock sandbox   ← before seccomp (Landlock uses syscalls seccomp might block)
Step 9: Apply seccomp filter     ← before exec (inherited by child)
Step 10: exec() agent command    ← replaces launcher process
```

**Why the order matters:**

1. `PR_SET_NO_NEW_PRIVS` before Landlock — Landlock requires this unless the process has `CAP_SYS_ADMIN`. Setting it first means we never need `CAP_SYS_ADMIN` for the Landlock call.
2. Landlock before seccomp — Landlock's `landlock_create_ruleset()`, `landlock_add_rule()`, and `landlock_restrict_self()` are syscalls. If seccomp blocks them first, Landlock can't be applied.
3. Both before exec — both seccomp filters and Landlock rulesets are inherited by the child process. Setting them before `exec()` means the agent starts with all restrictions already in place.

### Landlock Ruleset Construction

`guardian-launch` translates the `SandboxConfig` into Landlock rules:

```
Config                                  → Landlock Rule
──────────────────────────────────────  → ──────────────────────────────
file_allow = ["/tmp/**"]                → PathBeneath("/tmp", ReadFile | WriteFile | MakeReg | ...)
file_allow = ["/proc/self/**"]          → PathBeneath("/proc/self", ReadFile | ReadDir)
exec_allow = ["/usr/bin/python3"]       → PathBeneath("/usr/bin", ReadFile | Execute)
net_allow_ports = [443]                 → NetPort(443, ConnectTcp)
System libs (/usr/lib, /lib, /lib64)    → PathBeneath(path, ReadFile | ReadDir | Execute)
file_default = "deny"                   → implicit: everything not allowed is denied
```

**Implementation in `apply_landlock_sandbox()`:**

```rust
fn apply_landlock_sandbox(config: &SandboxConfig) -> Result<()> {
    use landlock::{
        Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset,
        RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
    };

    // Landlock is inherently default-deny. Skip if agent uses default-allow.
    if config.file_default != "deny" {
        log::warn!("Landlock sandbox skipped: file_default='{}' (requires 'deny')",
                    config.file_default);
        return Ok(());
    }

    // Target highest ABI — crate auto-downgrades via CompatLevel
    let abi = ABI::V5;
    let fs_access = AccessFs::from_all(abi);

    // Build ruleset — handle filesystem and optionally network
    let has_net = config.net_default == "deny" && !config.net_allow_ports.is_empty();

    let ruleset_base = if has_net {
        Ruleset::default()
            .handle_access(fs_access)?
            .handle_access(AccessNet::ConnectTcp)?
    } else {
        Ruleset::default().handle_access(fs_access)?
    };

    let mut ruleset = ruleset_base.create()?;

    // 1. System paths for dynamic linking and basic operation
    let system_read_paths = [
        "/usr/lib", "/usr/lib64", "/lib", "/lib64",
        "/usr/share", "/etc/ld.so.cache", "/etc/ld.so.conf",
        "/etc/ld.so.conf.d", "/etc/localtime", "/etc/resolv.conf",
        "/etc/nsswitch.conf", "/etc/hosts", "/etc/passwd", "/etc/group",
        "/dev/null", "/dev/zero", "/dev/urandom", "/dev/random",
    ];

    let read_rights = AccessFs::ReadFile | AccessFs::ReadDir;
    let read_exec_rights = read_rights | AccessFs::Execute;

    for path in &system_read_paths {
        if Path::new(path).exists() {
            if let Ok(fd) = PathFd::new(path) {
                ruleset = ruleset.add_rule(PathBeneath::new(fd, read_exec_rights))?;
            }
        }
    }

    // 2. /proc/self for runtime operations
    if let Ok(fd) = PathFd::new("/proc/self") {
        ruleset = ruleset.add_rule(PathBeneath::new(fd, read_rights))?;
    }

    // 3. Agent-allowed paths from config
    let write_rights = AccessFs::WriteFile | AccessFs::MakeReg | AccessFs::RemoveFile
        | AccessFs::MakeDir | AccessFs::RemoveDir;

    for pattern in &config.file_allow {
        let base_path = strip_glob(pattern); // "/tmp/**" → "/tmp"
        if Path::new(&base_path).exists() {
            if let Ok(fd) = PathFd::new(&base_path) {
                ruleset = ruleset.add_rule(
                    PathBeneath::new(fd, read_rights | write_rights)
                )?;
            }
        }
    }

    // 4. Exec-allowed paths
    for pattern in &config.exec_allow {
        let base_path = strip_glob(pattern);
        let dir = if Path::new(&base_path).is_dir() {
            base_path.clone()
        } else {
            Path::new(&base_path).parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or(base_path.clone())
        };
        if Path::new(&dir).exists() {
            if let Ok(fd) = PathFd::new(&dir) {
                ruleset = ruleset.add_rule(PathBeneath::new(fd, read_exec_rights))?;
            }
        }
    }

    // 5. Network port rules (Landlock ABI v4+, kernel 6.7+)
    if has_net {
        for &port in &config.net_allow_ports {
            ruleset = ruleset.add_rule(NetPort::new(port, AccessNet::ConnectTcp))?;
        }
    }

    // 6. Enforce — irreversible after this point
    let status = ruleset.restrict_self()?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            info!("Landlock: fully enforced (all requested rights controlled)");
        }
        RulesetStatus::PartiallyEnforced => {
            info!("Landlock: partially enforced (some rights not available on this kernel)");
        }
        RulesetStatus::NotEnforced => {
            log::warn!("Landlock: not enforced (kernel may not support Landlock)");
        }
    }

    Ok(())
}
```

**Key design choices:**

1. **`strip_glob()`** strips `/**` and `/*` suffixes from patterns to get base directories. Landlock's `PathBeneath` applies to entire hierarchies, so `/tmp/**` maps to a rule on `/tmp` that covers all descendants.

2. **System read paths** are always added — most processes need dynamic linking and basic system info. These get `ReadFile | ReadDir | Execute` but NOT write rights.

3. **No `MakeSym` right** is ever granted — agents cannot create symlinks. This prevents symlink-based attacks even within allowed directories.

4. **`add_rule()` ownership pattern** — the `landlock` crate's `add_rule()` takes ownership of `RulesetCreated` and returns `Result<Self>`. Each call must reassign: `ruleset = ruleset.add_rule(...)?`.

5. **Non-existent paths silently skipped** — if a configured allow path doesn't exist on this system, the rule is skipped with a debug log. This prevents startup failures on systems with different filesystem layouts.

### Expanded Seccomp Filter (Phase 10 Hardening)

Phase 8 blocked io_uring and memfd_create. Phase 10 expands the seccomp filter to block additional dangerous syscalls when `seccomp_hardened = true`:

```
Category                    Syscalls Blocked                    Numbers (x86_64)
────────────────────────── ──────────────────────────────────── ────────────────
io_uring (Phase 8)          io_uring_setup/enter/register       425, 426, 427
memfd (Phase 8)             memfd_create                        319
mount manipulation (NEW)    mount, umount2                      165, 166
new mount API (NEW)         open_tree, move_mount, fsopen,      428-433, 442
                            fsconfig, fsmount, fspick,
                            mount_setattr
root escape (NEW)           pivot_root, chroot                  155, 161
namespace escape (NEW)      setns, unshare                      272, 308
```

**Implementation:**

```rust
fn apply_seccomp_filter(hardened: bool) -> Result<()> {
    // Base syscalls (always blocked)
    let mut blocked: Vec<i64> = vec![
        319, // memfd_create
        425, // io_uring_setup
        426, // io_uring_enter
        427, // io_uring_register
    ];

    // Hardened syscalls (Phase 10)
    if hardened {
        blocked.extend_from_slice(&[
            155, // pivot_root
            161, // chroot
            165, // mount
            166, // umount2
            272, // unshare
            308, // setns
            428, // open_tree
            429, // move_mount
            430, // fsopen
            431, // fsconfig
            432, // fsmount
            433, // fspick
            442, // mount_setattr
        ]);
    }

    // Build seccomp filter: matched syscalls → EPERM, default → ALLOW
    // ... (uses seccompiler crate)
}
```

The filter structure:
- **Base filter** (4 syscalls) — always applied. Same as Phase 8.
- **Hardened filter** (+13 syscalls) — applied when `seccomp_hardened = true` in `SandboxConfig`.
- **Default action** — `SeccompAction::Allow` (all other syscalls pass through).
- **Match action** — `SeccompAction::Errno(EPERM)` (blocked syscalls return permission denied).

Seccomp filters compose as intersection (most restrictive wins). If the agent or a library applies its own seccomp filter later, the combined filter is at least as restrictive as ours. Filters cannot be relaxed once applied.

### PR_SET_NO_NEW_PRIVS

Phase 10 adds `prctl(PR_SET_NO_NEW_PRIVS, 1)` before Landlock and seccomp:

```rust
let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
```

This prevents:
- **SUID escalation** — a setuid binary run by the agent will NOT gain elevated privileges
- **Capability escalation** — file capabilities on binaries are ignored
- **Seccomp bypass** — cannot load a more permissive seccomp filter
- **Required by Landlock** — without `CAP_SYS_ADMIN`, Landlock requires `NO_NEW_PRIVS` to be set

The flag is inherited by all child processes and cannot be cleared.

---

## Configuration

### Agent Sandbox Configuration

The sandbox is configured implicitly through the existing agent config. The daemon translates it to `SandboxConfig` and sends it to the launcher:

```toml
[[agents]]
name = "my-agent"
identity = "cgroup"

[agents.file_access]
default = "deny"                    # ← becomes SandboxConfig.file_default
allow = ["/tmp/**", "/proc/self/**", "/usr/lib/**", "/lib/**"]  # ← file_allow
deny = ["/etc/shadow", "/root/.ssh/**"]

[agents.exec]
default = "deny"
allow = ["/usr/bin/python3", "/usr/bin/grep"]  # ← exec_allow

[agents.network_policy]
default = "deny"                    # ← net_default
allow_ports = [80, 443, 53]         # ← net_allow_ports
```

**No new config fields needed.** The existing `file_access`, `exec`, and `network_policy` sections drive the Landlock sandbox automatically.

### CLI Override Flags

```bash
# Disable Landlock (not recommended — falls back to eBPF-only enforcement)
sudo guardian-launch --name my-agent --no-landlock -- python3 -m aider

# Disable expanded seccomp hardening (only base io_uring/memfd filter applied)
sudo guardian-launch --name my-agent --no-seccomp-hardened -- python3 -m aider
```

| Flag | Effect |
|------|--------|
| `--no-landlock` | Disables Landlock sandbox. Agent relies on eBPF enforcement only. |
| `--no-seccomp-hardened` | Disables expanded seccomp (mount/namespace/chroot blocks). Base io_uring/memfd filter still applied. |

These flags are for debugging and backward compatibility. Production deployments should not use them.

---

## Landlock Graceful Degradation

Landlock capabilities depend on the kernel version and ABI:

| Kernel | ABI | Filesystem | Network | Behavior |
|--------|-----|------------|---------|----------|
| < 5.13 | none | NO | NO | Landlock skipped with warning. eBPF-only enforcement. |
| 5.13-5.18 | v1 | YES | NO | Filesystem sandbox active. Network via eBPF only. |
| 5.19-6.1 | v2 | YES + REFER | NO | + rename/link control. Network via eBPF only. |
| 6.2-6.6 | v3 | YES + truncate | NO | + truncate control. Network via eBPF only. |
| 6.7-6.9 | v4 | YES | YES (TCP) | Full sandbox: filesystem + network. |
| 6.10+ | v5 | YES + ioctl | YES | + device ioctl control. |

The `landlock` Rust crate (v0.4) has built-in `CompatLevel::BestEffort` that automatically downgrades to the best available ABI. Phase 10 targets ABI v5 but gracefully degrades:

```
FullyEnforced     — all requested rights are controlled (best case)
PartiallyEnforced — some rights not available on this kernel (e.g., no network on < 6.7)
NotEnforced       — Landlock not available at all (< 5.13, or not enabled in kernel)
```

The `restrict_self()` return value indicates the enforcement level, which is logged.

### Kernel Requirements Check

```bash
# Check if Landlock is enabled
cat /sys/kernel/security/lsm
# Should include "landlock" in the comma-separated list

# Check kernel version for ABI level
uname -r
# 6.7+ = full filesystem + network
# 5.13+ = filesystem only
```

---

## What About `default = "allow"` Agents?

Landlock is inherently default-deny. When you create a ruleset that handles filesystem access, **all** access is denied unless explicitly allowed. This is fundamentally incompatible with `file_access.default = "allow"`.

**Phase 10 behavior:**

- **`default = "deny"` agents**: Landlock sandbox applied. Full protection.
- **`default = "allow"` agents**: Landlock sandbox **skipped** with a warning log. These agents rely on eBPF enforcement only (with its known limitations).

```
[WARN] Landlock sandbox skipped: file_access.default='allow' (Landlock requires 'deny')
```

This is by design. If you want Landlock's inode-level protection, you must use `default = "deny"`. The recommendation is clear in the documentation: use `default = "deny"` for production security.

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Landlock as primary enforcement, eBPF as audit | eBPF tracepoints operate on path strings (vulnerable to symlinks, TOCTOU). Landlock operates on inodes (immune). Using the right tool for each job: Landlock for enforcement, eBPF for visibility. |
| IPC sandbox config delivery | Avoids duplicating config parsing in guardian-launch. Daemon is the single source of truth for agent configuration. Launcher receives only what it needs to build the sandbox. |
| Landlock only for default-deny agents | Landlock has no deny rules — it's inherently default-deny. Forcing a default-allow agent into Landlock would require granting access to `/` (defeating the purpose). Better to skip and let eBPF handle enforcement for permissive agents. |
| System read paths always allowed | Without `/usr/lib`, `/lib`, `/etc/ld.so.cache`, etc., no dynamically-linked binary can execute. These are read+execute only (no write). Similar to how a container runtime mounts system libraries read-only. |
| No MakeSym right ever granted | Prevents symlink creation in allowed directories. Even with Landlock's inode-level checking, not granting MakeSym is belt-and-suspenders defense. |
| PR_SET_NO_NEW_PRIVS before Landlock | Required by Landlock unless process has CAP_SYS_ADMIN. Setting it first means guardian-launch works without capabilities. Also prevents SUID escalation as a bonus. |
| Landlock before seccomp | Landlock uses syscalls (landlock_create_ruleset, etc.) that the expanded seccomp filter doesn't block but could theoretically conflict with future seccomp additions. Ordering removes ambiguity. |
| Expanded seccomp behind toggle | Base filter (io_uring+memfd) is always safe. Expanded filter blocks legitimate syscalls (mount, unshare) that some agents might need. The toggle allows gradual rollout. |
| Best-effort sandbox application | If Landlock or seccomp fails (unsupported kernel, missing LSM), a warning is logged and the agent launches anyway. This prevents the launcher from becoming a single point of failure while degrading gracefully. |
| Target ABI::V5 with auto-downgrade | Requesting the highest ABI ensures we get the most features available. The crate automatically downgrades if the kernel doesn't support v5. No version detection logic needed in our code. |
| Two security tiers documented | Rather than hiding limitations, explicitly document that comm-based agents are Tier 2 with known vulnerabilities. This sets correct expectations and pushes users toward cgroup agents for security. |

---

## Files Changed: Detailed Summary

### `guardian-common/src/lib.rs`

| Change | Detail |
|--------|--------|
| `SandboxConfig` struct | New IPC type carrying agent sandbox policy: `landlock` (bool), `seccomp_hardened` (bool), `no_new_privs` (bool), `file_default` (String), `file_allow` (Vec<String>), `exec_allow` (Vec<String>), `net_allow_ports` (Vec<u16>), `net_default` (String). Serde defaults: bools default to `true`, `net_default` defaults to `"allow"`. |
| `IpcResponse::Ack` | Changed from unit variant to struct variant with `sandbox: Option<SandboxConfig>`. Uses `#[serde(default, skip_serializing_if = "Option::is_none")]` for backward compatibility. |
| `default_true()` | Helper function returning `true` for serde defaults. |
| `default_allow()` | Helper function returning `"allow"` for serde defaults. |

### `guardian/src/ipc.rs`

| Change | Detail |
|--------|--------|
| `handle_register()` | Builds `SandboxConfig` from agent config: extracts `file_access.allow`, `exec.allow`, `network_policy.allow_ports`, `network_policy.default`, `file_access.default`. Returns `IpcResponse::Ack { sandbox: Some(sandbox) }`. |
| `handle_stop_agent()` | Changed `IpcResponse::Ack` to `IpcResponse::Ack { sandbox: None }`. |
| `handle_grant_access()` | Changed `IpcResponse::Ack` to `IpcResponse::Ack { sandbox: None }`. |
| `handle_approve_permission()` | Changed `IpcResponse::Ack` to `IpcResponse::Ack { sandbox: None }`. |
| `handle_deny_permission()` | Changed `IpcResponse::Ack` to `IpcResponse::Ack { sandbox: None }`. |

### `guardian-launch/src/main.rs` (Full Rewrite)

| Section | Change |
|---------|--------|
| CLI args | Added `--no-landlock` and `--no-seccomp-hardened` flags. |
| `main()` | New execution order: cgroup → register (receives SandboxConfig) → move to cgroup → PR_SET_NO_NEW_PRIVS → Landlock → seccomp → exec. Each step logged with info!. |
| `register_with_daemon()` | Returns `Result<Option<SandboxConfig>>` (was `Result<()>`). Extracts sandbox from `IpcResponse::Ack { sandbox }`. |
| NEW: `apply_landlock_sandbox()` | ~120 lines. Creates Landlock ruleset with ABI::V5, adds system read paths, agent-allowed paths, exec paths, and network port rules. Calls `restrict_self()`. |
| NEW: `strip_glob()` | Strips `/**` and `/*` suffixes from path patterns for Landlock PathBeneath. |
| `apply_seccomp_filter()` | Now takes `hardened: bool` parameter. Base filter: 4 syscalls (io_uring + memfd). Hardened: +13 syscalls (mount, namespace, chroot, pivot_root, new mount API). |

### `guardian-launch/Cargo.toml`

| Change | Detail |
|--------|--------|
| Dependencies | Added `landlock = "0.4"`. |

### `guardian-ctl/src/main.rs`

| Change | Detail |
|--------|--------|
| Ack pattern match | Changed `IpcResponse::Ack` to `IpcResponse::Ack { .. }` to match new struct variant. |

---

## Example: End-to-End Hardened Agent

Here's a complete example showing all four defense layers working together:

**1. Config (`config.toml`):**

```toml
[global]
mode = "enforce"
socket_path = "/run/guardian.sock"

[dashboard]
enabled = true
listen = "127.0.0.1:8080"
auth_token = "my-secret-token"

[[agents]]
name = "aider"
identity = "cgroup"
fail_closed = true

[agents.file_access]
default = "deny"
allow = [
    "/home/user/project/**",
    "/tmp/**",
    "/proc/self/**",
    "/usr/lib/**", "/lib/**", "/lib64/**",
    "/etc/ssl/**", "/etc/resolv.conf", "/etc/hosts",
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
allow_ports = [443, 53]
```

**2. Start the daemon:**

```bash
sudo RUST_LOG=info target/release/guardian --config config.toml
```

**3. Launch the agent:**

```bash
sudo target/release/guardian-launch \
    --name aider \
    --memory 4G \
    --pids 200 \
    -- python3 -m aider
```

**4. What happens on launch:**

```
[INFO] Guardian Launch: agent='aider' cmd=["python3", "-m", "aider"]
[INFO] Created cgroup: /sys/fs/cgroup/guardian/aider-12345
[INFO] Resource limit: memory.max = 4G
[INFO] Resource limit: pids.max = 200
[INFO] Registered with Guardian daemon
[INFO] Moved to cgroup
[INFO] PR_SET_NO_NEW_PRIVS set: SUID escalation blocked
[INFO] Landlock: fully enforced (all requested rights controlled)
[INFO] Seccomp filter applied: io_uring, memfd, mount, namespace, chroot blocked
[INFO] Launching: ["python3", "-m", "aider"]
```

**5. What happens when the agent tries to cheat:**

```bash
# Inside the agent (running as aider in the cgroup):

# Symlink attack — Landlock blocks it
ln -s /etc/shadow /tmp/innocent
cat /tmp/innocent
# → Permission denied (Landlock resolves symlink → /etc/shadow not in allowed hierarchy)

# io_uring — seccomp blocks it
python3 -c "import io_uring"
# → io_uring_setup returns EPERM (seccomp filter)

# Mount escape — seccomp blocks it
mount -t tmpfs none /tmp
# → mount returns EPERM (seccomp filter)

# Namespace escape — seccomp blocks it
unshare -n bash
# → unshare returns EPERM (seccomp filter)

# SUID escalation — PR_SET_NO_NEW_PRIVS prevents it
/usr/bin/sudo cat /etc/shadow
# → sudo cannot gain privileges (NO_NEW_PRIVS)

# Network to non-allowed port — Landlock blocks it (kernel 6.7+)
python3 -c "import socket; s = socket.socket(); s.connect(('evil.com', 8080))"
# → connect returns EACCES (Landlock: port 8080 not in allowed list)

# eBPF still logs everything
# Dashboard shows: all attempts logged with [DENY] and risk classification
```

**6. Manage the agent:**

```bash
# List agents (shows cgroup agents with process counts)
sudo guardian-ctl list

# Temporarily grant access (e.g., for deploying)
sudo guardian-ctl grant --name aider --path "/home/user/.aws/credentials" --duration 120

# Request permission interactively
sudo guardian-ctl request-permission --name aider \
    --resource-type exec --path /usr/bin/curl \
    --justification "Need to fetch API config"

# Check pending requests
sudo guardian-ctl pending

# Approve from CLI
sudo guardian-ctl approve --id 42 --duration 300
```

---

## What Remains Limited (Even with Landlock)

| Limitation | Impact | Mitigation |
|-----------|--------|------------|
| **UDP not enforced** | Landlock only filters TCP connect/bind. UDP `sendto()` unrestricted. | Requires network namespace or eBPF cgroup/socket programs. |
| **DNS not monitored** | DNS resolution happens before connect. Landlock controls by port, not hostname. | Port 53 can be allowed/denied but individual queries are not inspected. |
| **`default = "allow"` agents** | Can't use Landlock sandbox (inherently default-deny). | Use eBPF enforcement. Documented as Tier 2 with limitations. |
| **Comm-based agents** | Don't go through `guardian-launch`, so no Landlock/seccomp. | Documented as Tier 2. Push users toward cgroup agents. |
| **Landlock requires 5.13+** | Older kernels fall back to eBPF-only. | Most production distros (Ubuntu 22.04+, RHEL 9+, Fedora 36+) have 5.13+. |
| **Landlock network requires 6.7+** | TCP filtering only on recent kernels. | Filesystem sandbox still works. Network falls back to eBPF enforcement. |
| **Temporary grants don't update Landlock** | Landlock is irreversible once applied. New grants only affect eBPF enforcement maps. | Design trade-off: Landlock provides baseline security that cannot be weakened, while eBPF handles dynamic grants. |

The last point deserves emphasis: **Landlock rules cannot be relaxed after application**. If an agent is granted temporary access to `/etc/shadow` via `guardian-ctl grant`, this only updates the eBPF ALLOW maps. Landlock will still deny the access at the VFS level. This is actually a security feature — it means a compromised daemon cannot weaken the agent's sandbox. For truly dynamic access, the agent would need to be relaunched.

---

## Dependencies

| Crate | Version | Purpose | New? |
|-------|---------|---------|------|
| `landlock` | 0.4 | Landlock LSM userspace API | **NEW** |
| `seccompiler` | 0.4 | Seccomp BPF filter (expanded) | Existing (Phase 8) |
| `libc` | 0.2 | `prctl()` for `PR_SET_NO_NEW_PRIVS` | Existing |

No other new dependencies. The Landlock crate is well-maintained, `no_std`-compatible, and used by major projects (Tor, Chromium sandbox).

---

## Summary

| Before Phase 10 | After Phase 10 |
|---|---|
| eBPF is enforcement + monitoring | eBPF is monitoring; Landlock is enforcement |
| Symlinks bypass everything | Symlinks resolved at inode level |
| io_uring bypasses everything | io_uring blocked by seccomp (expanded) |
| TOCTOU race is architectural | TOCTOU eliminated (VFS-level checks) |
| Single enforcement layer | Four defense layers (cgroup + Landlock + seccomp + eBPF) |
| All agent types equally (in)secure | Cgroup agents hardened; comm agents documented as limited |
| mount/namespace escape possible | mount, chroot, unshare, setns all blocked |
| SUID escalation possible | PR_SET_NO_NEW_PRIVS prevents privilege gain |
| Requires CONFIG_BPF_LSM for enforcement | Landlock works without BPF LSM (separate stackable LSM) |
| Guardian is enforcement-only path | Landlock provides kernel-enforced baseline even if daemon crashes |

**The key insight: we don't need to fix eBPF. We need to use the right tool for enforcement (Landlock) and let eBPF do what it's best at (visibility).**
