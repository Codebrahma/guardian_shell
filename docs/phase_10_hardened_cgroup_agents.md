# Phase 10: Hardened Cgroup Agents — Defense in Depth

## The Problem

Guardian Shell's eBPF-based enforcement has fundamental limitations that can't be fixed within the eBPF layer:

| # | Vulnerability | Severity | Why eBPF Can't Fix It |
|---|---|---|---|
| 1 | **Symlink bypass** | CRITICAL | eBPF tracepoints see raw userspace path strings, not resolved inodes. `bpf_d_path()` requires Linux 5.11+ and complex raw helper calls in aya. |
| 2 | **TOCTOU race** | HIGH | Tracepoint reads userspace pointer at syscall entry; another thread can change it before LSM fires. Architectural to the tracepoint→LSM pattern. |
| 3 | **io_uring bypass** | HIGH | io_uring operations don't go through syscall tracepoints at all. No tracepoint = no PENDING map = no LSM enforcement. |
| 4 | **Rename/hardlink** | HIGH | Even with Phase 8 LSM hooks, path-based checking is still vulnerable to symlink indirection. |
| 5 | **memfd+execveat** | MEDIUM-HIGH | In-memory executables have no filesystem path for policy matching. |
| 6 | **Dynamic linker** | MEDIUM | Phase 8 argv[1] inspection helps but is fragile (environment variables, multiple indirection). |

All six stem from the same root cause: **eBPF tracepoints operate on syscall arguments (path strings), not on kernel objects (inodes)**. The kernel resolves paths to inodes *after* the tracepoint fires but *before* the actual I/O happens.

## The Creative Insight

**Stop trying to fix enforcement in eBPF. Use a kernel mechanism that already operates on inodes.**

Linux **Landlock LSM** (available since 5.13, network since 6.7) is a userspace-driven access control mechanism that:

- Operates at the **inode level** — symlinks are fully resolved by VFS before Landlock checks
- Is **immune to TOCTOU** — checks happen at the VFS layer, after path resolution
- Is **not bypassed by io_uring** — Landlock hooks are in the VFS/LSM layer, not the syscall layer
- Controls **rename/link operations** via `REFER` right (ABI v2)
- Controls **TCP connect** by port (ABI v4, kernel 6.7+)
- Is **irreversible** — once applied, can only be made more restrictive
- Is **inherited** by all child processes
- **Coexists** with BPF LSM — both are stackable LSMs

**The architecture flip:** For cgroup agents launched via `guardian-launch`, Landlock becomes the **primary enforcement layer**. eBPF becomes the **audit and visibility layer** (logging, dashboard, alerting). This gives us:

- **Landlock**: Enforces what the agent can access (inode-level, symlink-immune)
- **Seccomp**: Blocks dangerous syscalls (io_uring, memfd_create, namespace escape)
- **eBPF**: Monitors and logs everything for the audit trail and dashboard
- **Cgroup**: Resource limits and unspoofable identity

## Two Security Tiers

### Tier 1: Hardened Cgroup Agents (recommended, production)

Launched via `guardian-launch`. Gets all four defense layers:

```
┌─────────────────────────────────────────────────┐
│                 Agent Process                     │
├─────────────────────────────────────────────────┤
│  Layer 4: eBPF Monitoring                        │
│  • Tracepoints log all syscalls to dashboard     │
│  • LSM hooks provide additional enforcement      │
│  • Alerting pipeline for security events         │
├─────────────────────────────────────────────────┤
│  Layer 3: Seccomp Filter                         │
│  • Blocks io_uring (syscalls 425-427)            │
│  • Blocks memfd_create (319)                     │
│  • Blocks mount/namespace/chroot manipulation    │
│  • Blocks ptrace for anti-debugging              │
├─────────────────────────────────────────────────┤
│  Layer 2: Landlock Sandbox                       │
│  • Inode-level file access control               │
│  • Symlink-immune (resolved before check)        │
│  • TCP connect filtering by port                 │
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

**Security guarantee:** Every CRITICAL and HIGH vulnerability is mitigated.

### Tier 2: Legacy Comm-Based Agents (backward compatible, limited)

Not launched via `guardian-launch`. Gets eBPF monitoring + optional BPF LSM enforcement only:

- Symlink bypass: **VULNERABLE**
- TOCTOU race: **VULNERABLE**
- io_uring bypass: **VULNERABLE**
- Rename/hardlink: **PARTIALLY MITIGATED** (Phase 8 LSM hooks, path-based)

**Documentation clearly states:** Comm-based agents provide monitoring and best-effort enforcement. For production security, use cgroup agents with `guardian-launch`.

---

## Vulnerability Coverage Matrix

| Vulnerability | Severity | Landlock | Seccomp | eBPF LSM | Cgroup Agent | Comm Agent |
|---|---|---|---|---|---|---|
| Symlink bypass | CRITICAL | **SOLVED** (inode-level) | — | — | SOLVED | VULNERABLE |
| TOCTOU race | HIGH | **SOLVED** (VFS-level) | — | — | SOLVED | VULNERABLE |
| io_uring bypass | HIGH | — | **SOLVED** (blocks syscall) | — | SOLVED | VULNERABLE |
| Rename/hardlink | HIGH | **SOLVED** (REFER right) | belt-and-suspenders | Phase 8 | SOLVED | PARTIAL |
| memfd+execveat | MEDIUM-HIGH | — | **SOLVED** (blocks memfd) | Phase 8 | SOLVED | PARTIAL |
| Dynamic linker | MEDIUM | **SOLVED** (execute per-path) | — | Phase 8 | SOLVED | PARTIAL |
| Network exfil | CRITICAL | **SOLVED** (TCP connect, 6.7+) | — | Phase 9 | SOLVED | Phase 9 only |
| SUID escalation | — | requires no_new_privs | **PR_SET_NO_NEW_PRIVS** | — | SOLVED | VULNERABLE |
| Mount escape | — | — | **SOLVED** (blocks mount) | — | SOLVED | VULNERABLE |
| Namespace escape | — | — | **SOLVED** (blocks setns/unshare) | — | SOLVED | VULNERABLE |

---

## How Landlock Solves Symlinks (The #1 CRITICAL Issue)

The symlink attack that defeats eBPF:
```
Agent: ln -s /etc/shadow /tmp/innocent_file
Agent: cat /tmp/innocent_file
eBPF sees: openat("/tmp/innocent_file") → matches /tmp/** → ALLOW
Kernel reads: /etc/shadow → agent gets shadow file contents
```

With Landlock:
```
Agent: ln -s /etc/shadow /tmp/innocent_file
Agent: cat /tmp/innocent_file
VFS resolves: /tmp/innocent_file → inode of /etc/shadow
Landlock checks: is /etc/shadow inode under an allowed hierarchy? → NO
Result: -EACCES (Permission denied)
```

**Landlock uses file descriptors to identify directories, not path strings.** When a rule says "allow read under /tmp", the kernel resolves `/tmp` to its inode at rule-creation time. During access, the kernel walks from the target file's dentry up to root, checking if any ancestor inode matches a rule. Symlinks are resolved by VFS before this check happens.

---

## Implementation Design

### Config Changes

Add `sandbox` section to agent config:

```toml
[[agents]]
name = "my-agent"
identity = "cgroup"

# NEW: Sandbox configuration for hardened cgroup agents
[agents.sandbox]
# Enable Landlock filesystem sandbox (default: true for cgroup agents)
landlock = true
# Enable expanded seccomp filter (default: true for cgroup agents)
seccomp = true
# Set PR_SET_NO_NEW_PRIVS (default: true)
no_new_privs = true

[agents.file_access]
default = "deny"
allow = ["/tmp/**", "/proc/self/**", "/usr/lib/**", "/lib/**", "/lib64/**"]
deny = ["/etc/shadow", "/root/.ssh/**"]

[agents.exec]
default = "deny"
allow = ["/usr/bin/python3", "/usr/bin/grep", "/usr/bin/cat"]

[agents.network_policy]
default = "deny"
allow_ports = [80, 443, 53]
```

### Landlock Ruleset Construction

`guardian-launch` translates Guardian config into Landlock rules:

```
Config                          → Landlock Rule
────────────────────────────── → ──────────────────────────────
file_access.allow = ["/tmp/**"] → PathBeneath("/tmp", ReadFile | WriteFile | MakeReg | RemoveFile)
file_access.allow = ["/proc/**"]→ PathBeneath("/proc", ReadFile | ReadDir)
exec.allow = ["/usr/bin/python3"]→ PathBeneath("/usr/bin", Execute) [filtered to specific files]
network_policy.allow_ports=[443]→ NetPort(443, ConnectTcp)
default = "deny"                → (implicit: Landlock denies everything not explicitly allowed)
```

**Key mapping rules:**
1. `file_access.allow` paths → `ReadFile | WriteFile | ReadDir` under those directories
2. `exec.allow` paths → `Execute` right for those directories
3. System library paths (`/usr/lib`, `/lib`, `/lib64`) → `ReadFile | Execute` (needed for dynamic linking)
4. `network_policy.allow_ports` → `ConnectTcp` for those ports
5. **Never grant:** `MakeSym` (no symlink creation), `MakeBlock`, `MakeChar` (no device creation)
6. `default = "deny"` → all unspecified access denied (Landlock's natural model)
7. `default = "allow"` → Landlock sandbox disabled with a warning (incompatible with deny-by-default sandbox)

### Expanded Seccomp Filter

Block dangerous syscalls beyond the existing io_uring/memfd_create:

```
Category                    Syscalls Blocked                    Numbers (x86_64)
────────────────────────── ──────────────────────────────────── ────────────────
io_uring (existing)         io_uring_setup/enter/register       425, 426, 427
memfd (existing)            memfd_create                        319
mount manipulation (NEW)    mount, umount2                      165, 166
new mount API (NEW)         open_tree, move_mount, fsopen,      428-433, 442
                            fsconfig, fsmount, fspick,
                            mount_setattr
root escape (NEW)           pivot_root, chroot                  155, 161
namespace escape (NEW)      setns, unshare                      308, 272
```

### guardian-launch Execution Order

```
1. Create cgroup                     (existing)
2. Enable controllers + limits       (existing)
3. Get cgroup ID                     (existing)
4. Register with daemon              (existing)
   ↳ Daemon responds with agent config (NEW: include sandbox + policy)
5. Move self to cgroup               (existing)
6. prctl(PR_SET_NO_NEW_PRIVS, 1)    (NEW)
7. Apply Landlock ruleset            (NEW)
   ↳ Create ruleset with handled access rights
   ↳ Add PathBeneath rules for allowed dirs
   ↳ Add NetPort rules for allowed ports
   ↳ landlock_restrict_self()
8. Apply seccomp filter              (existing, expanded)
9. exec() agent command              (existing)
```

**Order matters:**
- `PR_SET_NO_NEW_PRIVS` before Landlock (required unless CAP_SYS_ADMIN)
- Landlock before seccomp (Landlock uses syscalls that seccomp might block)
- Both before exec (inherited by child)

### IPC Protocol Change

The daemon must send the agent's config back to `guardian-launch` during registration so it can build the Landlock ruleset:

```json
// Current response:
{"type": "ack"}

// New response:
{
  "type": "ack",
  "config": {
    "file_access": {"default": "deny", "allow": ["/tmp/**"], "deny": ["/etc/shadow"]},
    "exec": {"default": "deny", "allow": ["/usr/bin/python3"]},
    "network_policy": {"default": "deny", "allow_ports": [80, 443]},
    "sandbox": {"landlock": true, "seccomp": true, "no_new_privs": true}
  }
}
```

---

## Landlock Graceful Degradation

| Kernel | ABI | Filesystem | Network | Behavior |
|--------|-----|------------|---------|----------|
| < 5.13 | none | NO | NO | Landlock skipped with warning. eBPF-only enforcement. |
| 5.13-5.18 | v1 | YES | NO | Filesystem sandbox active. Network via eBPF LSM only. |
| 5.19-6.1 | v2 | YES + REFER | NO | + rename/link control. Network via eBPF LSM only. |
| 6.2-6.6 | v3 | YES + truncate | NO | + truncate control. Network via eBPF LSM only. |
| 6.7+ | v4 | YES | YES (TCP) | Full sandbox: filesystem + network. |
| 6.10+ | v5 | YES + ioctl | YES | + device ioctl control. |

The `landlock` Rust crate (v0.4.4) has built-in `CompatLevel::BestEffort` that automatically downgrades to the best available ABI.

---

## What About `default = "allow"` Agents?

Landlock is inherently default-deny. When you create a ruleset that handles filesystem access, **all** access is denied unless explicitly allowed. This means:

- **`default = "deny"` agents**: Perfect match. Landlock naturally enforces this.
- **`default = "allow"` agents**: Incompatible with Landlock's model. Options:
  1. Skip Landlock for these agents (they're permissive by design, less security needed)
  2. Convert to deny-only rules (add PathBeneath for `/` with broad rights, minus denied paths — but Landlock has no deny rules)
  3. **Recommended**: Require `default = "deny"` for hardened mode. Log a warning if `sandbox.landlock = true` with `default = "allow"`.

---

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `landlock` | 0.4 | Landlock LSM userspace API |

The `seccompiler` dependency already exists. No other new dependencies needed.

---

## What Remains Limited (Even with Landlock)

1. **UDP not enforced**: Landlock only filters TCP connect/bind. UDP `sendto()` is unrestricted. Would need eBPF or network namespace.
2. **DNS unmonitored**: DNS resolution happens before connect. Landlock controls connect by port, not by hostname.
3. **`default = "allow"` agents**: Can't use Landlock sandbox (inherently default-deny).
4. **Comm-based agents**: Don't go through `guardian-launch`, so no Landlock/Seccomp layers.
5. **Landlock requires 5.13+**: Older kernels fall back to eBPF-only. Most production distros (Ubuntu 22.04+, RHEL 9+, Fedora 36+) have 5.13+.

---

## Summary

| Before Phase 10 | After Phase 10 |
|---|---|
| eBPF is enforcement + monitoring | eBPF is monitoring; Landlock is enforcement |
| Symlinks bypass everything | Symlinks resolved at inode level |
| io_uring bypasses everything | io_uring blocked by seccomp |
| TOCTOU race is architectural | TOCTOU eliminated (VFS-level checks) |
| Single enforcement layer | Four defense layers (cgroup + Landlock + seccomp + eBPF) |
| All agent types equally (in)secure | Cgroup agents hardened; comm agents documented as limited |
| Requires CONFIG_BPF_LSM for enforcement | Landlock works without BPF LSM |

**The key insight: we don't need to fix eBPF. We need to use the right tool for enforcement (Landlock) and let eBPF do what it's best at (visibility).**
