# Phase 2: Enforcement & Process Tree Tracking

## Why Phase 2 Is Needed

Phase 1 has two fundamental gaps that make it unsuitable for real security:

**Gap 1: Monitor-only.** Guardian logs `[DENY]` but the agent still reads the file. It's like a security camera that watches someone walk through the door but never locks it. An agent can read your SSH keys, and all you get is a log line after the fact.

**Gap 2: No child process tracking.** When Claude Code runs `cat /etc/shadow`, Guardian only monitors the `claude` process — not the `cat` it spawned. The agent can access any file by spawning a child process with a different name. This completely bypasses monitoring.

Phase 2 fixes both: **kernel-level blocking** so denied files can't be opened, and **execve tracking** so every process spawned by an agent is automatically monitored.

---

## Table of Contents

1. [What Changes in Phase 2](#what-changes-in-phase-2)
2. [LSM BPF Hooks: Kernel-Level Enforcement](#lsm-bpf-hooks-kernel-level-enforcement)
   - [Why Tracepoints Can't Block](#why-tracepoints-cant-block)
   - [How LSM Hooks Work](#how-lsm-hooks-work)
   - [The security_file_open Hook](#the-security_file_open-hook)
   - [Implementation Plan](#implementation-plan-lsm)
   - [Kernel Requirements](#kernel-requirements)
   - [Fallback Strategy](#fallback-strategy)
3. [Process Tree Tracking via execve](#process-tree-tracking-via-execve)
   - [The Child Process Problem](#the-child-process-problem)
   - [How execve Tracking Works](#how-execve-tracking-works)
   - [Implementation Plan](#implementation-plan-execve)
   - [Process Lifecycle Management](#process-lifecycle-management)
4. [Policy Engine Changes](#policy-engine-changes)
   - [Enforcement Mode Configuration](#enforcement-mode-configuration)
   - [Read vs Write Policies](#read-vs-write-policies)
5. [New Architecture Diagram](#new-architecture-diagram)
6. [Implementation Roadmap](#implementation-roadmap)
7. [Risk Assessment](#risk-assessment)
8. [Testing Strategy](#testing-strategy)

---

## What Changes in Phase 2

| Component | Phase 1 (Current) | Phase 2 (Planned) |
|-----------|-------------------|-------------------|
| **File access** | Monitor only (log) | **Block at kernel level** |
| **eBPF program type** | Tracepoint | **LSM BPF** (+ tracepoint for logging) |
| **Denied files** | Agent reads them successfully | **Agent gets EPERM, can't read** |
| **Child processes** | Not tracked | **Auto-discovered via execve** |
| **Spawned commands** | Invisible to Guardian | **Inherit parent's policy** |
| **Syscalls monitored** | `openat` only | `openat` + **`execve`** |
| **Policy model** | Allow/deny file paths | Allow/deny file paths + **command allowlist** |

---

## LSM BPF Hooks: Kernel-Level Enforcement

### Why Tracepoints Can't Block

In Phase 1, our eBPF program is attached to a **tracepoint** (`sys_enter_openat`). Tracepoints are observation points — they fire when an event happens, but they have no mechanism to prevent the event from completing. The return value of a tracepoint program is ignored by the kernel.

```
Phase 1 (tracepoint):
  Process calls openat("/etc/shadow")
    → Tracepoint fires, eBPF program runs
    → eBPF returns 0 (kernel ignores this)
    → openat() SUCCEEDS ← agent reads the file
    → Guardian logs [DENY] after the fact
```

This is by design — tracepoints are meant for passive observation, not enforcement.

### How LSM Hooks Work

Linux Security Modules (LSM) is a framework that provides hooks at security-critical points in the kernel. When a process tries to open a file, the kernel calls the LSM hook **before** completing the operation. If any LSM module returns an error, the operation is denied.

BPF LSM (added in Linux 5.7) lets you write eBPF programs that act as LSM hooks. Your eBPF program can return `-EPERM` (permission denied) to block the operation.

```
Phase 2 (LSM BPF):
  Process calls openat("/etc/shadow")
    → Kernel calls security_file_open() hook
    → Our eBPF LSM program runs
    → eBPF checks WATCHED_COMMS + policy
    → eBPF returns -EPERM
    → openat() FAILS with "Permission denied" ← agent can't read the file
    → Guardian logs [BLOCKED]
```

The key difference: the LSM hook runs **before** the file is opened, and its return value **controls whether the operation succeeds**.

### The security_file_open Hook

The LSM framework provides dozens of hooks. For file access control, the primary hook is `security_file_open`:

```rust
// Pseudo-code for the Phase 2 eBPF LSM program
#[lsm(hook = "file_open")]
pub fn guardian_file_open(ctx: LsmContext) -> i32 {
    let comm = bpf_get_current_comm()?;

    // Not a watched process → allow
    if WATCHED_COMMS.get(&comm).is_none() {
        return 0;  // Allow
    }

    // Read the file path from the LSM context
    // (LSM hooks provide structured access to the file object)
    let path = read_file_path_from_context(&ctx)?;

    // Check policy (deny patterns checked in eBPF for performance)
    if matches_deny_pattern(&path) {
        return -1;  // -EPERM: deny the open
    }

    // Send event to userspace for detailed policy check
    EVENTS.output(&ctx, &event, 0);

    // Allow by default (userspace logs the decision)
    return 0;
}
```

**What the hook provides that tracepoints don't:**
- Direct access to the kernel `file` struct (resolved path, not just the user-provided string)
- The ability to return an error code that blocks the operation
- Access to the inode, dentry, and mount point for accurate path resolution

### Implementation Plan: LSM {#implementation-plan-lsm}

**Step 1: Detect LSM BPF support**
```rust
// In userspace daemon startup
fn check_lsm_support() -> bool {
    // Check if CONFIG_BPF_LSM is enabled
    // Read /sys/kernel/security/lsm and check for "bpf"
    let lsm_list = std::fs::read_to_string("/sys/kernel/security/lsm")
        .unwrap_or_default();
    lsm_list.contains("bpf")
}
```

**Step 2: Write the LSM eBPF program**
- New file: `guardian-ebpf/src/lsm.rs`
- Program type: `BPF_PROG_TYPE_LSM`
- Attach to: `security_file_open`
- Move critical deny patterns into a BPF map (`DENY_PATTERNS`) for kernel-side checking
- Return `-EPERM` for denied paths, `0` for everything else

**Step 3: Dual-mode operation**
- If LSM BPF is available → use LSM hooks (enforcement mode)
- If not → fall back to tracepoints (monitor-only mode)
- Log which mode is active at startup

**Step 4: Keep tracepoint for logging**
- The tracepoint program continues running for detailed event logging
- LSM program handles enforcement (fast, simple deny patterns)
- Tracepoint program handles observability (detailed logging with full context)

**Step 5: Path resolution**
- LSM hooks provide access to the kernel's `struct file`, which has the resolved absolute path
- This fixes the relative path problem from Phase 1
- No more "id_rsa" instead of "/home/user/.ssh/id_rsa"

### Kernel Requirements

```bash
# Check if your kernel supports BPF LSM
cat /sys/kernel/security/lsm
# Should include "bpf" in the comma-separated list

# If not, you may need to add it to the kernel boot parameters
# Edit /etc/default/grub:
# GRUB_CMDLINE_LINUX="lsm=lockdown,capability,yama,apparmor,bpf"
# Then: sudo update-grub && reboot

# Check kernel config
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
# Should show: CONFIG_BPF_LSM=y
```

**Distribution support:**

| Distribution | BPF LSM Available | Notes |
|-------------|-------------------|-------|
| Ubuntu 22.04+ | Yes (needs boot param) | Add `bpf` to LSM list |
| Fedora 37+ | Yes (usually enabled) | Check with `cat /sys/kernel/security/lsm` |
| Debian 12+ | Yes (needs boot param) | Add `bpf` to LSM list |
| Arch Linux | Yes (usually enabled) | Recent kernels have it |
| Amazon Linux 2023 | Varies | Check kernel config |

### Fallback Strategy

Not all kernels support BPF LSM. Phase 2 must handle this gracefully:

```
Startup:
  1. Check /sys/kernel/security/lsm for "bpf"
  2. If found:
     → Load LSM program → enforcement mode
     → Log: "Enforcement mode active. Denied files WILL be blocked."
  3. If not found:
     → Load tracepoint program → monitor mode
     → Log: "WARNING: BPF LSM not available. Running in monitor-only mode."
     → Log: "To enable enforcement, add 'bpf' to kernel LSM list."
```

---

## Process Tree Tracking via execve

### The Child Process Problem

This is the biggest security gap in Phase 1. Here's how an agent bypasses monitoring:

```
Scenario: Guardian watches process_name = "claude"

Claude (PID 1000, comm="claude")
  │
  ├── Guardian sees this process ✓
  │
  └── Claude runs: subprocess.run(["cat", "/home/user/.ssh/id_rsa"])
      │
      └── bash (PID 1001, comm="bash")
          │
          └── cat (PID 1002, comm="cat")
              │
              └── Reads /home/user/.ssh/id_rsa
                  │
                  └── Guardian does NOT see this ✗
                      (comm="cat" is not in WATCHED_COMMS)
```

The agent simply spawns a child process to do the dirty work. The child has a different comm name, so Guardian ignores it.

### How execve Tracking Works

We hook the `sys_enter_execve` tracepoint (or the `sched_process_exec` tracepoint). When any process calls `execve()` to start a new program, our eBPF program checks if the **parent** is watched. If so, the child is automatically added to the watch list.

```
Phase 2 execve tracking:

sys_enter_execve fires:
  1. Get current PID (this is the NEW process being exec'd)
  2. Get parent PID from task_struct
  3. Check: is parent PID in WATCHED_PIDS map?
     ├── No  → ignore
     └── Yes →
         4. Add NEW PID to WATCHED_PIDS
         5. Copy parent's agent identity to child
         6. Send "new_process" event to userspace
```

Now the attack is neutralized:

```
Claude (PID 1000, comm="claude") → in WATCHED_PIDS ✓
  │
  └── execve("bash") → PID 1001
      │  eBPF: parent 1000 is watched → add 1001 to WATCHED_PIDS ✓
      │
      └── execve("cat") → PID 1002
          │  eBPF: parent 1001 is watched → add 1002 to WATCHED_PIDS ✓
          │
          └── openat("/home/user/.ssh/id_rsa")
              │  eBPF: PID 1002 is in WATCHED_PIDS → CAPTURE EVENT ✓
              │  LSM: return -EPERM → BLOCKED ✓
              └── cat gets "Permission denied"
```

### Implementation Plan: execve {#implementation-plan-execve}

**Step 1: Add a second eBPF program for execve**

```rust
// New tracepoint program in guardian-ebpf
#[tracepoint]
pub fn guardian_exec_monitor(ctx: TracePointContext) -> u32 {
    match try_guardian_exec_monitor(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_exec_monitor(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    // Check if THIS process is already watched (by comm)
    let comm = bpf_get_current_comm()?;
    let self_watched = WATCHED_COMMS.get(&comm).is_some();

    // Check if PARENT is watched (by PID)
    let parent_tgid = get_parent_tgid()?;  // Read from task_struct
    let parent_watched = WATCHED_PIDS.get(&parent_tgid).is_some();

    if self_watched || parent_watched {
        // Add this new PID to WATCHED_PIDS
        WATCHED_PIDS.insert(&tgid, &1, 0)?;

        // Send event to userspace: "new process in agent tree"
        let event = build_exec_event(tgid, parent_tgid, &comm)?;
        EXEC_EVENTS.output(ctx, &event, 0);
    }

    Ok(0)
}
```

**Step 2: Add WATCHED_PIDS back (alongside WATCHED_COMMS)**

In Phase 1 we removed `WATCHED_PIDS` in favor of `WATCHED_COMMS`. Phase 2 uses both:
- `WATCHED_COMMS`: Initial matching by process name (catches the agent when it starts)
- `WATCHED_PIDS`: Runtime tracking of the entire process tree (populated by execve hook)

**Step 3: Attach to the execve tracepoint**

```rust
// In userspace daemon, after attaching the file_open program
let exec_program: &mut TracePoint = bpf
    .program_mut("guardian_exec_monitor")?
    .try_into()?;
exec_program.load()?;
exec_program.attach("syscalls", "sys_enter_execve")?;
```

**Step 4: Handle process exit (cleanup)**

Dead PIDs must be removed from `WATCHED_PIDS` to prevent the map from filling up:

```rust
// Option A: Hook sched_process_exit to remove PIDs in eBPF
#[tracepoint]
pub fn guardian_process_exit(ctx: TracePointContext) -> u32 {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    WATCHED_PIDS.remove(&tgid);
    Ok(0)
}

// Option B: Periodic cleanup in userspace
// Every 30 seconds, scan WATCHED_PIDS and remove entries
// where /proc/PID doesn't exist anymore
```

### Process Lifecycle Management

The full lifecycle of a tracked process tree:

```
1. Agent starts
   └── comm="claude" matches WATCHED_COMMS
   └── eBPF adds PID to WATCHED_PIDS
   └── Userspace logs: "Agent 'claude-code' started (PID 1000)"

2. Agent spawns child
   └── execve tracepoint fires
   └── Parent PID 1000 is in WATCHED_PIDS
   └── Child PID 1001 added to WATCHED_PIDS
   └── Userspace logs: "Child process 'bash' (PID 1001) tracked under agent 'claude-code'"

3. Child spawns grandchild
   └── Same as step 2, recursive
   └── PID 1002 added, inherits agent identity

4. Grandchild opens a file
   └── PID 1002 is in WATCHED_PIDS → event captured
   └── LSM hook evaluates policy → blocked or allowed

5. Process exits
   └── sched_process_exit fires
   └── PID removed from WATCHED_PIDS
   └── Userspace logs: "Process 'cat' (PID 1002) exited"

6. Agent exits
   └── PID 1000 removed from WATCHED_PIDS
   └── All children already cleaned up (or cleaned up by periodic sweep)
   └── Userspace logs: "Agent 'claude-code' (PID 1000) stopped"
```

---

## Policy Engine Changes

### Enforcement Mode Configuration

Phase 2 adds an `enforcement` field to the config:

```toml
[global]
log_level = "info"
enforcement = "enforce"    # "enforce" (block access) or "monitor" (log only)

[[agents]]
name = "claude-code"
process_name = "claude"
track_children = true      # NEW: auto-discover child processes

[agents.file_access]
default = "deny"
allow = ["/home/user/project/**", "/tmp/**"]
deny = ["/home/user/.ssh/**"]

# NEW: Command execution policy
[agents.exec_access]
default = "allow"
allow = ["git", "cargo", "npm", "node", "rustc"]
deny = ["curl", "wget", "ssh", "scp", "nc", "ncat"]
```

### Read vs Write Policies

Phase 2 enables separate policies for read and write access:

```toml
[agents.file_access]
default = "deny"

# Read access (O_RDONLY)
allow_read = [
    "/home/user/project/**",
    "/usr/lib/**",
    "/etc/ssl/**",
]

# Write access (O_WRONLY, O_RDWR, O_CREAT, O_TRUNC)
allow_write = [
    "/home/user/project/**",
    "/tmp/**",
]
deny_write = [
    "/home/user/project/.git/**",    # Agent can read .git but not modify it
    "/home/user/project/package-lock.json",
]
```

---

## New Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER SPACE                                      │
│                                                                              │
│  config.toml ──→ [Config Parser] ──→ [Policy Engine]                        │
│                                           │                                  │
│                                   ┌───────┴───────┐                         │
│                                   │  eBPF Loader  │                         │
│                                   └───────┬───────┘                         │
│                                           │                                  │
│                            ┌──────────────┴──────────────┐                  │
│                            │     Event Processor          │                  │
│                            │  • File access events        │                  │
│                            │  • Exec events (new)         │                  │
│                            │  • Process exit events (new) │                  │
│                            └──────────────┬──────────────┘                  │
│                                           │                                  │
│ ══════════════════════════════════════════╪══════════════════════════════════ │
│                                           │                                  │
│                         KERNEL SPACE      │                                  │
│                                           │                                  │
│  ┌────────────────────────────────────────┴──────────────────────────────┐  │
│  │                                                                       │  │
│  │  ┌─── LSM Hook (NEW) ──────────────────────────────────────────┐     │  │
│  │  │  security_file_open                                          │     │  │
│  │  │  • Check WATCHED_COMMS + WATCHED_PIDS                       │     │  │
│  │  │  • Check deny patterns                                      │     │  │
│  │  │  • Return -EPERM to BLOCK access                            │     │  │
│  │  └──────────────────────────────────────────────────────────────┘     │  │
│  │                                                                       │  │
│  │  ┌─── Tracepoint: sys_enter_openat ────────────────────────────┐     │  │
│  │  │  • Capture event details (PID, filename, flags)              │     │  │
│  │  │  • Send to userspace for logging                            │     │  │
│  │  └──────────────────────────────────────────────────────────────┘     │  │
│  │                                                                       │  │
│  │  ┌─── Tracepoint: sys_enter_execve (NEW) ──────────────────────┐     │  │
│  │  │  • Detect child process creation                             │     │  │
│  │  │  • If parent is watched → add child to WATCHED_PIDS         │     │  │
│  │  │  • Inherit agent identity                                    │     │  │
│  │  └──────────────────────────────────────────────────────────────┘     │  │
│  │                                                                       │  │
│  │  ┌─── Tracepoint: sched_process_exit (NEW) ────────────────────┐     │  │
│  │  │  • Clean up WATCHED_PIDS when process exits                  │     │  │
│  │  └──────────────────────────────────────────────────────────────┘     │  │
│  │                                                                       │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  BPF Maps:                                                                   │
│  ┌──────────────┬──────────────┬──────────────┬──────────────────────────┐  │
│  │WATCHED_COMMS │WATCHED_PIDS  │DENY_PATTERNS │ EVENTS / EXEC_EVENTS    │  │
│  │(comm→flag)   │(pid→agent_id)│(path prefixes)│ (perf ring buffers)     │  │
│  └──────────────┴──────────────┴──────────────┴──────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Roadmap

### Phase 2a: Process Tree Tracking (2-3 weeks)

This is the lower-risk change and can be done without LSM support.

| Week | Task | Details |
|------|------|---------|
| 1 | Add `WATCHED_PIDS` map back | Alongside existing `WATCHED_COMMS`. Both maps checked. |
| 1 | Write execve tracepoint program | New eBPF program: `guardian_exec_monitor` |
| 1 | Write process exit handler | Clean up WATCHED_PIDS on process exit |
| 2 | Userspace: process tree state | Track parent-child relationships, agent identity inheritance |
| 2 | Config: `track_children` option | Per-agent toggle for child process tracking |
| 2 | Logging: exec events | Log child process discovery: "New process 'bash' tracked under 'claude-code'" |
| 3 | Testing | Test with Claude Code, Aider, multi-level process trees |
| 3 | Edge cases | Fork bombs (map full), rapid spawn/exit, orphan processes |

### Phase 2b: LSM Enforcement (2-3 weeks)

This requires BPF LSM kernel support.

| Week | Task | Details |
|------|------|---------|
| 1 | LSM support detection | Check `/sys/kernel/security/lsm` at startup, choose mode |
| 1 | Write LSM eBPF program | `security_file_open` hook, deny pattern matching in kernel |
| 1 | DENY_PATTERNS BPF map | Move critical deny patterns (SSH keys, cloud creds) into eBPF map |
| 2 | Dual-mode daemon | Load LSM if available, fall back to tracepoint. Log mode clearly. |
| 2 | Path resolution | Use LSM hook's file struct for resolved absolute paths |
| 2 | Config: enforcement mode | `enforcement = "enforce"` or `"monitor"` |
| 3 | Testing | Verify blocked files return EPERM, unblocked files work normally |
| 3 | Safety testing | Ensure system processes aren't affected, only watched agents |

### Phase 2c: Command Execution Policy (1-2 weeks)

| Week | Task | Details |
|------|------|---------|
| 1 | exec policy config | `[agents.exec_access]` section with allow/deny command lists |
| 1 | exec event evaluation | Check executed command against policy |
| 2 | Logging and alerting | Log blocked commands: "[EXEC BLOCKED] agent='claude' command='curl'" |

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| LSM hook blocks system process | Low | Critical | Check WATCHED_COMMS/PIDS first. Never block unwatched processes. |
| WATCHED_PIDS map fills up | Medium | Medium | Cap at 4096 entries, periodic cleanup, LRU eviction |
| BPF verifier rejects LSM program | Medium | High | Keep LSM program minimal. Complex logic in userspace. |
| Performance regression | Low | Medium | LSM hook only does map lookups + prefix match. Benchmark. |
| Kernel doesn't support BPF LSM | High | High | Graceful fallback to monitor mode. Document how to enable. |

---

## Testing Strategy

### Unit Tests
- Policy evaluation with enforcement mode
- Read vs write policy separation
- Command execution policy matching

### Integration Tests
```bash
# Test 1: File blocking works
sudo guardian --config enforce.toml  # enforcement = "enforce"
cat /etc/shadow                       # As watched process → should get EPERM

# Test 2: Child process tracking
sudo guardian --config track.toml     # track_children = true
# Start agent, run cat from agent → should be tracked and logged

# Test 3: Fallback mode
# On kernel without BPF LSM:
sudo guardian --config enforce.toml
# Should log: "WARNING: BPF LSM not available. Running in monitor-only mode."

# Test 4: Process tree cleanup
# Start agent, spawn children, kill agent
# Verify WATCHED_PIDS entries are cleaned up
```

### Stress Tests
- Rapid process spawn/exit (fork-bomb style) — verify map cleanup
- High-throughput file access — verify LSM hook performance
- Multiple agents with overlapping children — verify identity isolation
