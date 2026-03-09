# Phase 3 Implementation: Cgroup Identity, Guardian Launcher & Time-Based Access

## What Phase 3 Solves

Phase 2 gave us kernel-level enforcement (blocking denied file access) and process tree tracking. But two critical weaknesses remained:

**Weakness 1: Process name spoofing.** Any process can change its own comm name with a single syscall:

```python
import ctypes
libc = ctypes.CDLL("libc.so.6")
libc.prctl(15, b"systemd\0")  # Now /proc/PID/comm says "systemd"
```

After this, Guardian stops monitoring the agent. It walks free.

**Weakness 2: Same-runtime ambiguity.** Two Python agents (e.g., Aider and OpenClaw) both appear as `python3`. Phase 2's process tree tracking helps (separate trees), but the initial identification still relies on a spoofable name.

**Weakness 3: No resource control.** A malicious or buggy agent could consume all system memory, spawn thousands of processes (fork bomb), or hog the CPU.

Phase 3 solves all three by using **Linux cgroups** — a kernel-enforced isolation mechanism that a process **cannot escape or spoof**, no matter what.

---

## What Was Built

### New Binaries

| Binary | Purpose |
|--------|---------|
| `guardian-launch` | Launches an agent inside a dedicated cgroup with resource limits, registers it with the Guardian daemon |
| `guardian-ctl` | CLI tool to list running agents, stop them, and grant temporary file access |

### New/Modified Source Files

| File | What Changed |
|------|-------------|
| `guardian-ebpf/src/main.rs` | Added 3 new BPF maps (`WATCHED_CGROUPS`, `ENFORCE_CGROUPS`, `CGROUP_DEFAULT_ACTION`). Added `bpf_get_current_cgroup_id()` call. Implemented 3-tier identification: cgroup → TGID → comm. |
| `guardian-common/src/lib.rs` | Changed from unconditional `#![no_std]` to conditional `#![cfg_attr(not(feature = "user"), no_std)]`. Added IPC protocol types (`IpcRequest`, `IpcResponse`, `AgentStatus`) behind the `user` feature. Added length-prefixed JSON send/recv helpers. |
| `guardian-common/Cargo.toml` | Added `serde` and `serde_json` as optional dependencies behind the `user` feature. |
| `guardian/src/main.rs` | Added IPC server startup, cgroup BPF map management, cgroup cleanup background task, temporary grant expiry task. Modified event processing to work with both comm-based and cgroup-based agents. |
| `guardian/src/config.rs` | Added `socket_path` to `GlobalConfig`. Added `identity` field to `AgentConfig` ("comm" or "cgroup"). Made `process_name` optional. Added `ResourceLimits` struct. Added backward-compatible `effective_identity()` and `effective_process_name()` methods. |
| `guardian/src/ipc.rs` | **New file.** Complete IPC server: Unix socket listener, agent registration handler, list/stop/grant handlers, cgroup lifecycle cleanup, temporary grant expiry. |
| `guardian/Cargo.toml` | Added `serde_json` and `libc` dependencies. |
| `guardian-launch/` | **New crate.** The launcher binary. |
| `guardian-ctl/` | **New crate.** The management CLI. |
| `Cargo.toml` | Added `guardian-launch` and `guardian-ctl` to workspace members and default-members. |
| `config.toml` | Added `socket_path`. Added commented cgroup-based agent example with resource limits. |

---

## Architecture

### How the Pieces Fit Together

```
                        USER SPACE
 ┌──────────────────────────────────────────────────────────────────┐
 │                                                                  │
 │   guardian-launch                    Guardian Daemon              │
 │   ┌────────────────┐     IPC        ┌──────────────────────┐    │
 │   │ 1. Create cgroup├──────────────>│ Unix socket listener │    │
 │   │ 2. Set limits   │  register     │ /run/guardian.sock    │    │
 │   │ 3. Register     │<─────────────┤                      │    │
 │   │ 4. Move to cgrp │   ACK        │ Populates BPF maps:  │    │
 │   │ 5. exec(agent)  │              │  WATCHED_CGROUPS     │    │
 │   └────────────────┘              │  ENFORCE_CGROUPS     │    │
 │                                    │  CGROUP_DEFAULT_ACTION│    │
 │   guardian-ctl                      │                      │    │
 │   ┌────────────────┐     IPC        │ Background tasks:    │    │
 │   │ list / stop /  ├──────────────>│  - Cgroup cleanup    │    │
 │   │ grant          │               │  - Grant expiry      │    │
 │   └────────────────┘              │  - PID rescan        │    │
 │                                    └──────────┬───────────┘    │
 │                                                │                │
 │   Cgroup Hierarchy:                            │                │
 │   /sys/fs/cgroup/guardian/                      │                │
 │   ├── aider-1234/     ← PID 1234, 1235        │                │
 │   └── openclaw-5678/  ← PID 5678              │                │
 │                                                │                │
 ├════════════════════════════════════════════════╪════════════════┤
 │                                                │                │
 │                        KERNEL SPACE            │                │
 │                                                │                │
 │   eBPF Programs                                │                │
 │   ┌─────────────────────────────────────────────────────────┐  │
 │   │ sys_enter_openat tracepoint:                            │  │
 │   │   cgroup_id = bpf_get_current_cgroup_id()               │  │
 │   │   if WATCHED_CGROUPS[cgroup_id]       ← Priority 1     │  │
 │   │   OR WATCHED_TGIDS[tgid]              ← Priority 2     │  │
 │   │   OR WATCHED_COMMS[comm]              ← Priority 3     │  │
 │   │     → capture event, evaluate policy, set PENDING_DENY  │  │
 │   │                                                          │  │
 │   │ LSM file_open:                                           │  │
 │   │   if PENDING_DENY[pid_tgid] → return -EACCES (blocked) │  │
 │   │                                                          │  │
 │   │ sched_process_fork: child inherits cgroup automatically  │  │
 │   │ sched_process_exit: cleanup CHILD_PIDS                   │  │
 │   └─────────────────────────────────────────────────────────┘  │
 └──────────────────────────────────────────────────────────────────┘
```

### 3-Tier Identification in eBPF

The eBPF program now checks three levels of identity, from strongest to weakest:

```
1. CGROUP ID (Phase 3)    ← cannot be spoofed, kernel-enforced
   bpf_get_current_cgroup_id() → lookup in WATCHED_CGROUPS map

2. TGID / Child PID (Phase 2)  ← tracks process tree
   WATCHED_TGIDS map + CHILD_PIDS map

3. COMM NAME (Phase 1)   ← fallback, can be spoofed
   bpf_get_current_comm() → lookup in WATCHED_COMMS map
```

If any tier matches, the process is monitored. The same pattern applies for enforcement checking — if the cgroup, TGID, or comm is in the enforcement maps, policy evaluation runs in-kernel and can block access.

---

## IPC Protocol

The Guardian daemon listens on a Unix domain socket (default: `/run/guardian.sock`). Messages use a **length-prefixed JSON** format:

```
┌──────────┬──────────────────────────────────┐
│ 4 bytes  │ N bytes                          │
│ (u32 BE) │ (JSON payload)                   │
│ length   │                                  │
└──────────┴──────────────────────────────────┘
```

### Request Types

**Register** — sent by `guardian-launch` when starting an agent:
```json
{
  "type": "register",
  "cgroup_path": "guardian/aider-1234",
  "cgroup_id": 789456,
  "agent_name": "aider"
}
```

**ListAgents** — sent by `guardian-ctl list`:
```json
{ "type": "list" }
```

**StopAgent** — sent by `guardian-ctl stop`:
```json
{ "type": "stop", "agent_name": "aider" }
```

**GrantAccess** — sent by `guardian-ctl grant`:
```json
{
  "type": "grant",
  "agent_name": "aider",
  "path": "/home/user/.aws/**",
  "duration_secs": 300
}
```

### Response Types

```json
{ "type": "ack" }

{ "type": "error", "message": "No agent config found for 'unknown'" }

{
  "type": "agents",
  "agents": [
    {
      "name": "aider",
      "cgroup_path": "guardian/aider-1234",
      "cgroup_id": 789456,
      "num_processes": 3,
      "uptime_secs": 1847
    }
  ]
}
```

---

## guardian-launch: Step-by-Step Flow

When you run:
```bash
sudo guardian-launch --name aider --memory 4G --pids 200 -- python3 -m aider
```

Here is what happens internally:

### Step 1: Create Cgroup
```
mkdir /sys/fs/cgroup/guardian/              ← base directory (if not exists)
mkdir /sys/fs/cgroup/guardian/aider-54321/  ← unique per launch (name + PID)
```

### Step 2: Enable Controllers
```
echo "+memory +pids +cpu" > /sys/fs/cgroup/guardian/cgroup.subtree_control
```
This enables memory, PID, and CPU controllers for child cgroups. Best-effort — if a controller is not available, it's silently skipped.

### Step 3: Set Resource Limits
```
echo "4G" > /sys/fs/cgroup/guardian/aider-54321/memory.max
echo "200" > /sys/fs/cgroup/guardian/aider-54321/pids.max
```

### Step 4: Get Cgroup ID
The cgroup ID is the **inode number** of the cgroup directory. This is what `bpf_get_current_cgroup_id()` returns in the kernel:
```rust
let metadata = std::fs::metadata("/sys/fs/cgroup/guardian/aider-54321")?;
let cgroup_id = metadata.ino();  // e.g., 789456
```

### Step 5: Register with Daemon
Connect to `/run/guardian.sock` and send a registration message. The daemon:
1. Finds the matching agent config in `config.toml`
2. Inserts `cgroup_id` into the `WATCHED_CGROUPS` BPF map
3. If enforce mode: also inserts into `ENFORCE_CGROUPS` and `CGROUP_DEFAULT_ACTION`
4. Stores the registration in memory for lifecycle management
5. Responds with `ACK`

### Step 6: Move to Cgroup
```
echo $$ > /sys/fs/cgroup/guardian/aider-54321/cgroup.procs
```
The launcher process is now in the cgroup.

### Step 7: exec() the Agent
```rust
Command::new("python3").args(&["-m", "aider"]).exec();
```
`exec()` replaces the launcher process with the agent. The agent inherits:
- The cgroup (kernel-enforced, cannot escape)
- All resource limits
- Guardian monitoring via the WATCHED_CGROUPS BPF map

Every child process the agent spawns (bash, git, curl, etc.) automatically inherits the same cgroup. **No process can leave the cgroup without root privileges.**

---

## Cgroup Lifecycle Management

### Automatic Cleanup

The daemon runs a background task every 5 seconds that:

1. **Checks for empty cgroups**: reads `/sys/fs/cgroup/guardian/<name>/cgroup.procs`. If empty (all processes exited), the agent is cleaned up:
   - Removes cgroup ID from `WATCHED_CGROUPS`, `ENFORCE_CGROUPS`, `CGROUP_DEFAULT_ACTION` BPF maps
   - Removes the cgroup directory
   - Logs: `Agent 'aider' cleaned up (uptime=1847s)`

2. **Expires temporary grants**: checks each grant's expiry time. When expired:
   - Removes the allow rule from `ALLOW_EXACT` or `ALLOW_PREFIXES` BPF maps
   - Logs: `Temporary grant expired: agent='aider' path='/home/user/.aws/**'`

### Force Stop

When `guardian-ctl stop --name aider` is run:
1. Reads PIDs from `/sys/fs/cgroup/guardian/aider-54321/cgroup.procs`
2. Sends `SIGTERM` to each process
3. Cleans up BPF maps and cgroup directory immediately

---

## Time-Based Access Windows

Sometimes an agent needs temporary access to a sensitive resource — for example, reading AWS credentials during a deployment.

### How It Works

1. **Grant request** arrives via IPC (from `guardian-ctl grant`)
2. **Daemon adds the path** to the `ALLOW_EXACT` or `ALLOW_PREFIXES` BPF maps
3. **Daemon stores** the grant with an expiry timestamp
4. **Agent can now access** the previously-denied path
5. **After the duration**, the cleanup task removes the rule from BPF maps
6. **Access is blocked again** automatically

### Example

```bash
# Agent needs to deploy using AWS credentials for 5 minutes
sudo guardian-ctl grant --name claude-code --path "/home/user/.aws/**" --duration 300

# After 300 seconds, access is automatically revoked
# Daemon logs: "Temporary grant expired: agent='claude-code' path='/home/user/.aws/**'"
```

The grant modifies the kernel-side BPF maps directly, so enforcement takes effect immediately — no round-trip to userspace needed for each file access.

---

## Configuration Changes

### New Fields

```toml
[global]
log_level = "info"
mode = "enforce"
pid_rescan_interval = 5
socket_path = "/run/guardian.sock"    # ← NEW: IPC socket path

# Cgroup-based agent (Phase 3 — recommended)
[[agents]]
name = "aider"
identity = "cgroup"                  # ← NEW: "cgroup" or "comm" (default: "comm")

[agents.file_access]
default = "deny"
allow = ["/tmp/**"]
deny = ["/etc/shadow"]

[agents.resources]                   # ← NEW: resource limits for cgroup agents
memory_max = "4G"
pids_max = 200
cpu_max = "200000 100000"            # 2 CPU cores

# Comm-based agent (Phase 1/2 — still works)
[[agents]]
name = "claude-code"
process_name = "claude"              # identity defaults to "comm" when process_name is set

[agents.file_access]
default = "deny"
allow = ["/tmp/**"]
deny = ["/etc/shadow"]
```

### Backward Compatibility

| Config Pattern | Identity Method |
|---------------|----------------|
| `process_name = "claude"` (no `identity` field) | `comm` — works exactly like Phase 1/2 |
| `identity = "comm"`, `process_name = "claude"` | `comm` — explicit, same behavior |
| `identity = "cgroup"` (no `process_name`) | `cgroup` — requires `guardian-launch` |

Existing Phase 1/2 configs work without any changes. The `identity` field and `resources` section are optional.

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Cgroup ID = inode number** | `bpf_get_current_cgroup_id()` returns the cgroup directory's inode number. We read the same value via `stat()` in userspace. Guaranteed to match. |
| **Length-prefixed JSON IPC** | Simple, debuggable, no external dependencies. Works well for our low-frequency request/response pattern. |
| **Launcher exec()'s the agent** | The launcher replaces itself with the agent process. No wrapper process overhead. The agent IS the process in the cgroup. |
| **Cgroup name = agent-PID** | Unique per launch. Multiple instances of the same agent get separate cgroups with separate monitoring. |
| **Controllers enabled best-effort** | Not all kernels have all cgroup controllers enabled. Failing to enable a controller logs a warning but doesn't block the launch. |
| **Temporary grants in BPF maps** | Grants are added directly to the kernel-side allow maps, so enforcement/evaluation happens at kernel speed with no userspace round-trip. |
| **5-second cleanup interval** | Balances responsiveness with overhead. Empty cgroups are detected within 5 seconds. Grants expire within 5 seconds of their deadline. |
| **Separate guardian-ctl binary** | Keeps the launcher focused on one job (launch). Management operations (list, stop, grant) are separate concerns with different argument patterns. |

---

## Comparison: Phase 1 → 2 → 3

| Feature | Phase 1 | Phase 2 | Phase 3 |
|---------|---------|---------|---------|
| **Enforcement** | Monitor only (log) | Kernel blocks access (LSM) | Kernel blocks access (LSM) |
| **Identity** | Process name (comm) | Process name + PID tree | **Cgroup (unspoofable)** |
| **Child tracking** | None | Fork-based (`sched_process_fork`) | **Cgroup inheritance (automatic)** |
| **Spoofing** | Vulnerable | Partially resistant | **Immune** |
| **Multi-agent** | Only if different names | Better with PID trees | **Perfect isolation** |
| **Setup** | Edit config, find name | Edit config, find name | **`guardian-launch` one command** |
| **Resource limits** | None | None | **Memory, CPU, PID limits** |
| **Cleanup** | Manual | Process exit hooks | **Automatic cgroup cleanup** |
| **Agent management** | Manual | Manual | **CLI: list, stop, grant** |
| **Temporary access** | Not supported | Not supported | **Time-based grants** |
