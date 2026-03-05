# Phase 3: Robust Agent Identity with Cgroups & Guardian Launcher

## Why Phase 3 Is Needed

Even with Phase 2's enforcement and process tree tracking, two critical weaknesses remain:

**Weakness 1: Process name spoofing.** Any process can change its own comm name:
```python
import ctypes
libc = ctypes.CDLL("libc.so.6")
libc.prctl(15, b"systemd\0")  # Now /proc/PID/comm says "systemd"
```
After this, Guardian stops monitoring the agent. The agent walks free.

**Weakness 2: Same-runtime ambiguity.** Two Python agents both appear as `python3`. Phase 2's process tree tracking helps (separate trees), but the initial identification still relies on a spoofable name.

Phase 3 solves both by using **Linux cgroups** — a kernel-enforced isolation mechanism that a process **cannot escape or spoof**, no matter what. Every process in a cgroup is tracked automatically, including all children, grandchildren, and any process the agent ever spawns.

---

## Table of Contents

1. [What Are Cgroups?](#what-are-cgroups)
   - [Cgroups v1 vs v2](#cgroups-v1-vs-v2)
   - [Why Cgroups for Agent Identity](#why-cgroups-for-agent-identity)
   - [How Cgroup Inheritance Works](#how-cgroup-inheritance-works)
2. [The Guardian Launcher](#the-guardian-launcher)
   - [User Experience](#user-experience)
   - [What the Launcher Does](#what-the-launcher-does)
   - [Launcher Implementation Plan](#launcher-implementation-plan)
3. [eBPF Cgroup Identification](#ebpf-cgroup-identification)
   - [bpf_get_current_cgroup_id()](#bpf_get_current_cgroup_id)
   - [WATCHED_CGROUPS Map](#watched_cgroups-map)
   - [Implementation Plan](#implementation-plan-cgroup-ebpf)
4. [Configuration Changes](#configuration-changes)
5. [Agent Lifecycle Management](#agent-lifecycle-management)
6. [Architecture Diagram: Phase 3](#architecture-diagram-phase-3)
7. [Comparison: Phase 1 → 2 → 3](#comparison-phase-1--2--3)
8. [Implementation Roadmap](#implementation-roadmap)
9. [Advanced Features](#advanced-features)
   - [Time-Based Access Windows](#time-based-access-windows)
   - [User Consent Flow](#user-consent-flow)
   - [Resource Limits](#resource-limits)

---

## What Are Cgroups?

### The Basics

**Cgroups** (control groups) are a Linux kernel feature for organizing processes into hierarchical groups. Originally designed for resource management (CPU limits, memory limits), they've become the foundation for container isolation in Docker, Podman, and Kubernetes.

Every process on Linux belongs to a cgroup. You can see yours:

```bash
cat /proc/self/cgroup
# Output (cgroup v2):
# 0::/user.slice/user-1000.slice/session-2.scope

# The hierarchy:
# /sys/fs/cgroup/
# └── user.slice/
#     └── user-1000.slice/
#         └── session-2.scope/
#             └── cgroup.procs → contains your shell's PID
```

### Cgroups v1 vs v2

| Feature | v1 | v2 |
|---------|----|----|
| **Hierarchy** | Multiple separate trees (one per resource) | Single unified tree |
| **Process membership** | Process can be in different cgroups per resource | Process is in exactly one cgroup |
| **API** | Complex, inconsistent | Clean, single interface |
| **Default on modern distros** | Legacy | Default since ~2022 |
| **Used by** | Older Docker, legacy systems | Docker 20.10+, Podman, Kubernetes, systemd |

**Guardian Shell will use cgroup v2** (the modern unified hierarchy). Most current Linux distributions default to v2.

```bash
# Check if your system uses cgroup v2
mount | grep cgroup2
# If you see: cgroup2 on /sys/fs/cgroup type cgroup2 → v2 is active

# Or check:
stat -f /sys/fs/cgroup/ | grep Type
# Type: cgroup2fs → v2
```

### Why Cgroups for Agent Identity

Cgroups provide **the strongest possible identity** for processes on Linux:

| Property | Process Name (comm) | PID | Cgroup |
|----------|-------------------|-----|--------|
| **Unique per agent?** | No (multiple python3) | Yes but ephemeral | Yes and persistent |
| **Spoofable?** | Yes (prctl) | No but dies with process | No (kernel-enforced) |
| **Tracks children?** | No | No | Yes (automatic inheritance) |
| **Survives exec?** | No (new binary = new comm) | Yes | Yes |
| **Who controls it?** | The process itself | Kernel | Root / cgroup owner |

When you place a process in a cgroup:
- The process **cannot move itself** to a different cgroup
- All **children automatically inherit** the parent's cgroup
- The cgroup exists **until explicitly removed** by the owner
- The kernel guarantees these properties — no userspace code can override them

### How Cgroup Inheritance Works

```
1. Guardian Launcher creates cgroup:
   /sys/fs/cgroup/guardian/aider-abc123/

2. Launcher places itself in the cgroup:
   echo $$ > /sys/fs/cgroup/guardian/aider-abc123/cgroup.procs

3. Launcher exec's the agent (agent inherits cgroup):
   exec python3 -m aider

4. Agent spawns bash (bash inherits cgroup):
   subprocess.run(["bash", "-c", "cat /etc/shadow"])

5. Bash spawns cat (cat inherits cgroup):
   exec cat /etc/shadow

Result:
/sys/fs/cgroup/guardian/aider-abc123/cgroup.procs contains:
  PID 2000 (python3 / aider)
  PID 2001 (bash)
  PID 2002 (cat)

ALL of them are in the same cgroup.
NONE of them can leave.
Guardian identifies ALL of them as "aider".
```

Even if the agent renames itself:
```python
# Agent tries to hide:
libc.prctl(15, b"systemd\0")  # Changes comm to "systemd"

# Doesn't matter:
# /proc/2000/cgroup still shows: 0::/guardian/aider-abc123
# Guardian identifies it by cgroup, not by name
```

---

## The Guardian Launcher

### User Experience

Today (Phase 1):
```bash
# User must: find process name, edit config, start Guardian, then start agent
vim config.toml          # Add process_name = "python3"
sudo guardian --config config.toml
python3 -m aider        # Hope the name matches
```

Phase 3:
```bash
# One command. Everything automatic.
guardian-launch --name "aider" --policy strict -- python3 -m aider
```

Or with a pre-configured policy file:
```bash
guardian-launch --config /etc/guardian/aider.toml -- python3 -m aider
```

### What the Launcher Does

```
guardian-launch --name "aider" -- python3 -m aider
         │
         ▼
Step 1: Create cgroup
         /sys/fs/cgroup/guardian/aider-<uuid>/
         │
         ▼
Step 2: Set resource limits (optional)
         memory.max = 4G
         pids.max = 200
         │
         ▼
Step 3: Register with Guardian daemon
         Send IPC message: {
           cgroup_id: 12345,
           cgroup_path: "guardian/aider-<uuid>",
           agent_name: "aider",
           policy: "strict"   (or inline policy from config)
         }
         │
         ▼
Step 4: Move self into the cgroup
         echo $$ > /sys/fs/cgroup/guardian/aider-<uuid>/cgroup.procs
         │
         ▼
Step 5: exec() the agent
         exec python3 -m aider "$@"
         │
         ▼
         The agent process replaces the launcher.
         The agent is now in the cgroup.
         All children will inherit the cgroup.
         Guardian daemon monitors this cgroup.
```

### Launcher Implementation Plan

**New binary: `guardian-launch` (Rust)**

```rust
// guardian-launch/src/main.rs (conceptual)

fn main() -> Result<()> {
    let args = parse_args();  // --name, --policy, --config, -- <command>

    // Step 1: Create cgroup
    let cgroup_path = format!("guardian/{}-{}", args.name, uuid());
    let cgroup_dir = format!("/sys/fs/cgroup/{}", cgroup_path);
    fs::create_dir_all(&cgroup_dir)?;

    // Step 2: Resource limits (if configured)
    if let Some(mem) = args.memory_limit {
        fs::write(format!("{}/memory.max", cgroup_dir), mem)?;
    }
    if let Some(pids) = args.pid_limit {
        fs::write(format!("{}/pids.max", cgroup_dir), pids)?;
    }

    // Step 3: Register with Guardian daemon via Unix socket
    let socket = UnixStream::connect("/run/guardian.sock")?;
    let registration = AgentRegistration {
        cgroup_path: cgroup_path.clone(),
        agent_name: args.name.clone(),
        policy_name: args.policy.clone(),
    };
    send_message(&socket, &registration)?;
    wait_for_ack(&socket)?;

    // Step 4: Move self into cgroup
    let pid = std::process::id();
    fs::write(format!("{}/cgroup.procs", cgroup_dir), pid.to_string())?;

    // Step 5: exec the agent (replaces this process)
    let err = exec::execvp(&args.command[0], &args.command);
    // exec only returns on error
    Err(anyhow!("Failed to exec {:?}: {}", args.command, err))
}
```

**Communication with Guardian daemon:**

The launcher communicates with the running Guardian daemon via a Unix domain socket (`/run/guardian.sock`):

```
Launcher → Daemon:  "Register cgroup guardian/aider-abc123 as agent 'aider' with policy 'strict'"
Daemon → Launcher:  "ACK. Monitoring active."
Launcher:           exec(agent)
...
Agent exits.
Daemon detects empty cgroup → removes cgroup → logs "Agent 'aider' stopped"
```

---

## eBPF Cgroup Identification

### bpf_get_current_cgroup_id()

The BPF helper `bpf_get_current_cgroup_id()` returns a unique 64-bit identifier for the current process's cgroup. This is available in the eBPF program and is the key to cgroup-based identification.

```rust
// In the eBPF program:
let cgroup_id = bpf_get_current_cgroup_id();
if WATCHED_CGROUPS.get(&cgroup_id).is_some() {
    // This process is in a watched cgroup → capture event
}
```

### WATCHED_CGROUPS Map

```rust
// New BPF map in guardian-ebpf
#[map]
static WATCHED_CGROUPS: HashMap<u64, AgentInfo> = HashMap::with_max_entries(256, 0);

// AgentInfo stores the agent identity for logging
#[repr(C)]
struct AgentInfo {
    agent_id: u32,      // Index into userspace agent config
    flags: u32,         // Enforcement flags
}
```

### Implementation Plan: Cgroup eBPF {#implementation-plan-cgroup-ebpf}

**Step 1: Add cgroup checking to the eBPF program**

The check order becomes:
1. Check `WATCHED_CGROUPS` (cgroup ID) — **strongest, preferred**
2. Check `WATCHED_PIDS` (PID) — from Phase 2 process tree tracking
3. Check `WATCHED_COMMS` (comm name) — Phase 1 fallback

If any match, capture the event. Priority determines the agent identity used for policy evaluation.

**Step 2: Userspace populates WATCHED_CGROUPS**

When the launcher registers a new agent:
```rust
// In guardian daemon
fn handle_agent_registration(reg: AgentRegistration) -> Result<()> {
    // Get the cgroup ID from the filesystem
    let cgroup_id = get_cgroup_id(&reg.cgroup_path)?;

    // Insert into eBPF map
    let info = AgentInfo { agent_id: find_agent_index(&reg.agent_name), flags: 0 };
    watched_cgroups.insert(cgroup_id, info, 0)?;

    info!("Agent '{}' registered with cgroup ID {}", reg.agent_name, cgroup_id);
    Ok(())
}
```

**Step 3: Cleanup when agent exits**

When all processes in a cgroup exit, the cgroup becomes empty:
```rust
// Periodic check or inotify on cgroup.events
fn cleanup_empty_cgroups() {
    for (cgroup_path, agent_name) in &registered_agents {
        let procs = fs::read_to_string(format!("/sys/fs/cgroup/{}/cgroup.procs", cgroup_path))?;
        if procs.trim().is_empty() {
            // Remove from eBPF map
            watched_cgroups.remove(&cgroup_id)?;
            // Remove the cgroup directory
            fs::remove_dir(format!("/sys/fs/cgroup/{}", cgroup_path))?;
            info!("Agent '{}' stopped. Cgroup removed.", agent_name);
        }
    }
}
```

---

## Configuration Changes

### Phase 3 Config Format

```toml
[global]
log_level = "info"
enforcement = "enforce"
socket_path = "/run/guardian.sock"   # NEW: IPC socket for launcher

# ─── Cgroup-based agent (recommended) ───────────────────────
[[agents]]
name = "claude-code"
identity = "cgroup"                  # NEW: identity method
launcher_name = "claude-code"        # Matches guardian-launch --name

[agents.file_access]
default = "deny"
allow = ["/home/user/project/**", "/tmp/**", "/usr/lib/**"]
deny = ["/home/user/.ssh/**"]

[agents.exec_access]
default = "allow"
deny = ["curl", "wget", "ssh"]

[agents.resources]                   # NEW: resource limits
memory_max = "4G"
pids_max = 200
cpu_max = "200000 100000"           # 200ms per 100ms period (2 CPUs)

# ─── Comm-based agent (Phase 1 compatibility) ───────────────
[[agents]]
name = "legacy-agent"
identity = "comm"                    # Backward compatible
process_name = "my-agent"

[agents.file_access]
default = "deny"
allow = ["/home/user/project/**"]
deny = ["/home/user/.ssh/**"]
```

### Policy Templates

Pre-built policies for common security postures:

```toml
# /etc/guardian/policies/strict.toml
[file_access]
default = "deny"
allow = []      # Only what the launcher config specifies
deny = [
    "/home/**/.ssh/**",
    "/home/**/.aws/**",
    "/home/**/.gnupg/**",
    "/home/**/.kube/**",
    "/etc/shadow",
    "/etc/sudoers",
]

[exec_access]
default = "deny"
allow = ["git", "ls", "cat", "head", "tail", "grep", "find"]
deny = ["curl", "wget", "ssh", "scp", "nc", "rm", "dd"]

[resources]
memory_max = "2G"
pids_max = 100
```

```bash
# Use a policy template
guardian-launch --name "aider" --policy strict -- python3 -m aider
```

---

## Agent Lifecycle Management

### Full Lifecycle: Launch → Monitor → Stop

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AGENT LIFECYCLE                               │
│                                                                      │
│  1. LAUNCH                                                           │
│     guardian-launch --name "aider" -- python3 -m aider              │
│     ├── Create cgroup: /sys/fs/cgroup/guardian/aider-abc123         │
│     ├── Register with daemon via /run/guardian.sock                  │
│     ├── Daemon adds cgroup ID to WATCHED_CGROUPS map                │
│     └── exec(python3 -m aider) inside cgroup                       │
│                                                                      │
│  2. MONITOR                                                          │
│     Agent runs, spawns children, opens files                        │
│     ├── All processes in cgroup → tracked by eBPF                   │
│     ├── File access → LSM hook checks policy → allow/block          │
│     ├── Command exec → execve hook logs + checks policy             │
│     └── Denied access → logged + blocked (enforcement mode)         │
│                                                                      │
│  3. STOP                                                             │
│     Agent exits (Ctrl+C, crash, or guardian-stop)                   │
│     ├── All child processes exit (cgroup becomes empty)             │
│     ├── Daemon detects empty cgroup                                  │
│     ├── Daemon removes cgroup ID from WATCHED_CGROUPS               │
│     ├── Daemon removes cgroup directory                              │
│     └── Daemon logs: "Agent 'aider' session ended"                  │
│                                                                      │
│  Optional: FORCE STOP                                                │
│     guardian-stop --name "aider"                                     │
│     ├── Sends SIGTERM to all processes in cgroup                    │
│     ├── Waits 5 seconds                                              │
│     ├── Sends SIGKILL if still running                               │
│     └── Cleanup as in step 3                                         │
└─────────────────────────────────────────────────────────────────────┘
```

### Guardian CLI Commands (Phase 3)

```bash
# Launch an agent with monitoring
guardian-launch --name "aider" -- python3 -m aider

# List running agents
guardian-list
# Output:
# NAME          PID    CGROUP                        PROCS  POLICY   UPTIME
# claude-code   1000   guardian/claude-code-abc123    4      strict   2h 15m
# aider         2000   guardian/aider-def456          2      strict   45m

# View an agent's activity
guardian-logs --name "aider"
# Output: real-time stream of [ALLOW]/[DENY] events for this agent

# Stop an agent
guardian-stop --name "aider"
# Output: Agent 'aider' stopped. 2 processes terminated.
```

---

## Architecture Diagram: Phase 3

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                               USER SPACE                                      │
│                                                                               │
│  ┌─────────────────┐    ┌──────────────────────────────────────────────────┐ │
│  │ guardian-launch  │    │              Guardian Daemon                     │ │
│  │                  │    │                                                  │ │
│  │ Creates cgroup   │───>│  /run/guardian.sock (IPC)                       │ │
│  │ Registers agent  │    │                                                  │ │
│  │ exec(agent)      │    │  Manages:                                       │ │
│  └─────────────────┘    │  • Agent registrations                          │ │
│                          │  • WATCHED_CGROUPS map                          │ │
│  ┌─────────────────┐    │  • Policy evaluation                            │ │
│  │ guardian-list    │───>│  • Event logging                                │ │
│  │ guardian-logs    │    │  • Cgroup lifecycle                             │ │
│  │ guardian-stop    │    │                                                  │ │
│  └─────────────────┘    └──────────────────────┬───────────────────────────┘ │
│                                                  │                            │
│  ┌────── Cgroup Hierarchy ─────────────────────────────────────────────────┐ │
│  │ /sys/fs/cgroup/guardian/                                                 │ │
│  │ ├── claude-code-abc123/  ← PID 1000, 1001, 1002, 1003                  │ │
│  │ ├── aider-def456/        ← PID 2000, 2001                              │ │
│  │ └── openclaw-ghi789/     ← PID 3000                                    │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
│                                                                               │
│ ═════════════════════════════════════════════════════════════════════════════ │
│                                                                               │
│                          KERNEL SPACE                                         │
│                                                                               │
│  ┌──────────────────────────────────────────────────────────────────────────┐ │
│  │  eBPF Programs:                                                          │ │
│  │                                                                          │ │
│  │  LSM: security_file_open                                                 │ │
│  │  ├── bpf_get_current_cgroup_id() → check WATCHED_CGROUPS               │ │
│  │  ├── If watched → check policy → return 0 or -EPERM                    │ │
│  │  └── If not watched → return 0 (allow, zero overhead)                   │ │
│  │                                                                          │ │
│  │  Tracepoint: sys_enter_openat (logging)                                  │ │
│  │  Tracepoint: sys_enter_execve (exec monitoring)                          │ │
│  │  Tracepoint: sched_process_exit (cleanup)                                │ │
│  │                                                                          │ │
│  │  BPF Maps:                                                               │ │
│  │  ├── WATCHED_CGROUPS: HashMap<u64, AgentInfo>   ← primary identity      │ │
│  │  ├── WATCHED_COMMS:   HashMap<[u8;16], u8>      ← fallback              │ │
│  │  ├── WATCHED_PIDS:    HashMap<u32, u32>          ← process tree          │ │
│  │  ├── DENY_PATTERNS:   HashMap<[u8;256], u8>     ← kernel-side deny      │ │
│  │  └── EVENTS:          PerfEventArray              ← event output         │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Comparison: Phase 1 → 2 → 3

| Feature | Phase 1 | Phase 2 | Phase 3 |
|---------|---------|---------|---------|
| **Enforcement** | Monitor only | Kernel blocks access | Kernel blocks access |
| **Identity** | Process name (comm) | Process name + PID tree | **Cgroup (unspoofable)** |
| **Child tracking** | None | execve-based | **Cgroup inheritance** |
| **Spoofing** | Vulnerable | Partially resistant | **Immune** |
| **Multi-agent** | Only if different names | Better with PID trees | **Perfect isolation** |
| **Setup** | Edit config, find name | Edit config, find name | **`guardian-launch`** |
| **Resource limits** | None | None | **Memory, CPU, PID limits** |
| **Cleanup** | Manual | Process exit hooks | **Automatic cgroup cleanup** |
| **Agent management** | Manual | Manual | **CLI: list, logs, stop** |

---

## Implementation Roadmap

### Phase 3a: Cgroup eBPF Matching (2 weeks)

| Week | Task |
|------|------|
| 1 | Add `bpf_get_current_cgroup_id()` to eBPF program |
| 1 | Add `WATCHED_CGROUPS` BPF map |
| 1 | Implement 3-tier check: cgroup → PID → comm |
| 2 | Userspace: read cgroup IDs from filesystem |
| 2 | Userspace: populate WATCHED_CGROUPS from config |
| 2 | Testing with manually created cgroups |

### Phase 3b: Guardian Launcher (2-3 weeks)

| Week | Task |
|------|------|
| 1 | New crate: `guardian-launch` |
| 1 | Cgroup creation and process placement |
| 1 | Unix socket IPC with daemon |
| 2 | Daemon: handle registrations, populate eBPF maps |
| 2 | Daemon: detect empty cgroups, cleanup |
| 3 | Policy templates (strict, permissive, custom) |
| 3 | CLI tools: `guardian-list`, `guardian-logs`, `guardian-stop` |

### Phase 3c: Advanced Features (2-3 weeks)

| Week | Task |
|------|------|
| 1 | Resource limits via cgroup controllers |
| 1 | Time-based access windows |
| 2 | User consent flow (interactive permission prompts) |
| 2 | Agent session recording (full audit trail) |
| 3 | Integration testing with real agents |

---

## Advanced Features

### Time-Based Access Windows

Sometimes an agent needs temporary access to a sensitive resource:

```bash
# Grant 5-minute access to AWS credentials for deployment
guardian-grant --name "claude-code" --path "/home/user/.aws/**" --duration 5m
```

Implementation: the daemon adds a temporary allow rule with an expiry timestamp. After the duration, it's automatically removed.

```toml
# Or in config:
[[agents.file_access.temporary]]
path = "/home/user/.aws/**"
duration = "5m"
requires_consent = true    # Ask user before granting
```

### User Consent Flow

For sensitive operations, Guardian can pause and ask the user:

```
[CONSENT REQUIRED] Agent 'claude-code' wants to read /home/user/.aws/credentials
  Reason: Agent is running 'aws s3 cp' command
  Options:
    [A] Allow once
    [T] Allow for 5 minutes
    [D] Deny
    [B] Block agent (kill all processes)
  >
```

Implementation: the daemon sends a notification via desktop notification (libnotify), terminal prompt, or web UI, and waits for user input before allowing/denying the LSM hook.

### Resource Limits

Cgroups provide natural resource isolation:

```toml
[agents.resources]
memory_max = "4G"           # Agent + children can't use more than 4GB
pids_max = 200              # Max 200 processes (prevents fork bombs)
cpu_max = "200000 100000"   # 2 CPU cores maximum
io_max = "8:0 wbps=10485760"  # 10 MB/s write to disk
```

This prevents agents from:
- **Memory bombing**: Allocating all system memory
- **Fork bombing**: Spawning thousands of processes
- **CPU hogging**: Consuming all CPU cores
- **Disk thrashing**: Writing huge amounts of data

If an agent exceeds its limits, the kernel's OOM killer terminates it — Guardian logs the event.
