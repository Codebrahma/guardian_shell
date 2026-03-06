# Phase 2 Implementation: Enforcement + Exec Monitoring

## Overview

Phase 2 adds kernel-level file access blocking, command execution monitoring,
process tree tracking, and periodic PID rescanning to Guardian Shell. The key
advancement over Phase 1 (monitor-only) is that Guardian can now **actually
prevent** an LLM agent from reading or writing files it shouldn't access.

## Architecture

### Hybrid Tracepoint + LSM Design

Phase 2 uses a two-stage approach for enforcement:

```
┌─────────────────────────────────────────────────────────────┐
│  Process calls openat("/home/user/secret/file.txt")         │
│                                                             │
│  Stage 1: sys_enter_openat tracepoint fires                 │
│    → Checks WATCHED_COMMS / WATCHED_TGIDS / CHILD_PIDS     │
│    → Reads filename from userspace memory                   │
│    → Evaluates deny/allow rules via LPM Trie + HashMap      │
│    → If denied: sets PENDING_DENY[pid_tgid] = 1             │
│    → Sends event to userspace via perf buffer                │
│                                                             │
│  Stage 2: LSM file_open hook fires (same syscall)           │
│    → Checks PENDING_DENY[pid_tgid]                          │
│    → If found: removes entry, returns -EACCES (blocked!)    │
│    → If not found: returns 0 (allowed)                      │
│                                                             │
│  Result: Process gets EACCES error, file is never opened    │
└─────────────────────────────────────────────────────────────┘
```

**Why this hybrid?** The tracepoint has easy access to the filename from syscall
arguments (userspace pointer). The LSM hook has the authority to block the
syscall. Reading the filename inside LSM context is complex and unreliable, so
we use the tracepoint for policy evaluation and the LSM hook for enforcement.

### BPF Programs (5 total)

| Program | Hook | Purpose |
|---------|------|---------|
| `guardian_file_open` | `syscalls/sys_enter_openat` | Captures file access, evaluates policy, sets PENDING_DENY |
| `guardian_enforce_file_open` | LSM `file_open` | Reads PENDING_DENY, returns -EACCES to block |
| `guardian_exec_monitor` | `syscalls/sys_enter_execve` | Captures command execution events |
| `guardian_fork_track` | `sched/sched_process_fork` | Tracks child processes of watched agents |
| `guardian_exit_track` | `sched/sched_process_exit` | Cleans up tracked PIDs on process exit |

### BPF Maps (14 total)

| Map | Type | Purpose |
|-----|------|---------|
| `WATCHED_COMMS` | HashMap<[u8;16], u8> | Process comm names to monitor |
| `WATCHED_TGIDS` | HashMap<u32, u8> | Process TGIDs to monitor (catches worker threads) |
| `ENFORCE_COMMS` | HashMap<[u8;16], u8> | Comms with enforcement enabled |
| `ENFORCE_TGIDS` | HashMap<u32, u8> | TGIDs with enforcement enabled (catches worker threads) |
| `PENDING_DENY` | HashMap<u64, u8> | Pending deny decisions (key=pid_tgid) |
| `DENY_PREFIXES` | LpmTrie<[u8;256], u8> | Deny rules for prefix/glob matching |
| `DENY_EXACT` | HashMap<[u8;256], u8> | Deny rules for exact path matching |
| `ALLOW_PREFIXES` | LpmTrie<[u8;256], u8> | Allow rules for prefix/glob matching |
| `ALLOW_EXACT` | HashMap<[u8;256], u8> | Allow rules for exact path matching |
| `DEFAULT_ACTION` | HashMap<[u8;16], u8> | Per-comm default action (0=deny, 1=allow) |
| `CHILD_PIDS` | HashMap<u32, u32> | Child→parent PID mapping |
| `EVENT_BUF` | PerCpuArray | Scratch buffer for file events (512-byte stack limit) |
| `EXEC_BUF` | PerCpuArray | Scratch buffer for exec events |
| `EVENTS` / `EXEC_EVENTS` | PerfEventArray | Perf buffers for events to userspace |

## Policy Evaluation (Kernel-Side)

Policy is evaluated entirely in-kernel with zero loops using O(1) map lookups:

```
1. Check DENY_EXACT[filename]     → if match: DENY
2. Check DENY_PREFIXES[filename]  → if match: DENY  (LPM trie prefix match)
3. Check ALLOW_EXACT[filename]    → if match: ALLOW
4. Check ALLOW_PREFIXES[filename] → if match: ALLOW (LPM trie prefix match)
5. Check DEFAULT_ACTION[comm]     → 0=deny, 1=allow
6. Fail-open if no default configured
```

Deny rules always take precedence over allow rules.

## Test Configuration: Blocking Claude Code Agent

### Test Setup

Created two test folders:
- `/home/suren/codebrahma/llm_allowed/` — Claude should be able to read files here
- `/home/suren/codebrahma/llm_not_allowed/` — Claude should be BLOCKED from reading here

### config.toml

```toml
[global]
log_level = "info"
mode = "enforce"
pid_rescan_interval = 5

[[agents]]
name = "claude-code"
process_name = "claude"
watch_children = true

[agents.file_access]
default = "deny"
allow = [
    "/home/suren/codebrahma/llm_allowed/**",
    "/home/suren/codebrahma/guardian_shell/**",
    "/home/suren/**",
    "/tmp/**",
    "/proc/**",
    "/sys/**",
    "/dev/**",
    "/usr/lib/**",
    "/usr/lib64/**",
    "/usr/share/**",
    "/usr/local/**",
    "/usr/bin/**",
    "/lib/**",
    "/lib64/**",
    "/bin/**",
    "/etc/ld.so.cache",
    "/etc/ssl/**",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/passwd",
    "/etc/nsswitch.conf",
    "/etc/localtime",
    "/etc/claude-code/**",
    "/run/**",
    "/var/tmp/**",
]
deny = [
    "/home/suren/codebrahma/llm_not_allowed/**",
    "/etc/shadow",
    "/etc/gshadow",
    "/home/suren/.ssh/**",
    "/home/suren/.gnupg/**",
    "/home/suren/.aws/**",
]

[agents.exec_policy]
default = "allow"
allow = ["/usr/bin/**", "/usr/local/bin/**", "/bin/**"]
deny = []
```

**Key point**: Deny rules override allow rules. Even though `/home/suren/**` is
in the allow list, `/home/suren/codebrahma/llm_not_allowed/**` in the deny list
takes precedence and blocks access.

### Running the Test

Terminal 1 (Guardian):
```bash
sudo RUST_LOG=info target/release/guardian --config config.toml
```

Terminal 2 (Claude Code agent — separate session):
```bash
claude  # Start a new Claude Code session
# Ask Claude to read a file in /home/suren/codebrahma/llm_not_allowed/
```

### Expected Guardian Output

```
[BLOCKED|ENFORCE] agent='claude-code' pid=82458 comm='libuv-worker' \
  file='/home/suren/codebrahma/llm_not_allowed/secret_file.txt' mode=READ
```

The Claude agent receives an EACCES (Permission denied) error and cannot read
the file. Files in `/home/suren/codebrahma/llm_allowed/` work normally.

### Log Format

```
[ACTION|MODE] agent='name' pid=TGID comm='thread_name' file='path' mode=FLAGS
```

- **ACTION**: `ALLOW`, `BLOCKED`, `DENY`
- **MODE**: `ENFORCE` (actually blocked) or `MONITOR` (logged only)
- **mode**: `READ`, `WRITE`, `RDWR`, with optional `|CREATE`, `|TRUNC`, `|APPEND`

## Issues Faced and Solutions

### Issue 1: Map FD Invalidation (os error 9)

**Symptom**: `Failed to load 'guardian_file_open': Bad file descriptor (os error 9)`

**Root cause**: `take_map()` was called before `program.load()`. In Aya, BPF
programs reference maps by file descriptor. `take_map()` transfers ownership of
the map out of the `Ebpf` object, invalidating the FD that the program expects.
When the program is then loaded into the kernel, the BPF verifier rejects it
because the map FDs are invalid.

**Fix**: Split program management into `load_tracepoint()` and
`attach_tracepoint()`. Load ALL programs first, THEN call `take_map()`:

```rust
// Step 3: Load all programs FIRST
load_tracepoint(&mut bpf, "guardian_file_open")?;
load_tracepoint(&mut bpf, "guardian_exec_monitor")?;
load_tracepoint(&mut bpf, "guardian_fork_track")?;
load_tracepoint(&mut bpf, "guardian_exit_track")?;
load_lsm(&mut bpf)?;

// Step 4: NOW safe to take_map()
populate_watched_comms(&mut bpf, &config)?;
populate_enforcement_maps(&mut bpf, &config)?;

// Step 5: Attach programs
attach_tracepoint(&mut bpf, "guardian_file_open", "syscalls", "sys_enter_openat")?;
```

### Issue 2: BPF Verifier 1M Instruction Limit

**Symptom**: `program is too large. Processed 1000001 insn`

**Root cause**: The initial implementation stored deny/allow rules in BPF Array
maps and iterated over them with bounded loops:

```rust
// OLD APPROACH (REJECTED BY VERIFIER):
for i in 0..MAX_POLICY_RULES {  // 64 rules
    let rule = DENY_RULES.get(i);
    // Compare 256 bytes of path...
}
```

The BPF verifier explores all possible execution paths. With 64 rules x 256
bytes of comparison, the state space exploded past 1,000,001 instructions.

**Fix**: Replaced Array-based loops with **LPM Trie** (Longest Prefix Match) for
prefix patterns (`/**`) and **HashMap** for exact path matches. Both are O(1)
lookups with zero loops:

```rust
// NEW APPROACH (ZERO LOOPS):
fn evaluate_policy(filename: &[u8; 256], filename_len: usize, comm: &[u8; 16]) -> bool {
    let lpm_key = Key::new((filename_len as u32) * 8, *filename);

    if unsafe { DENY_EXACT.get(filename) }.is_some() { return false; }
    if DENY_PREFIXES.get(&lpm_key).is_some() { return false; }
    if unsafe { ALLOW_EXACT.get(filename) }.is_some() { return true; }
    if ALLOW_PREFIXES.get(&lpm_key).is_some() { return true; }

    // Fall through to default action
    match unsafe { DEFAULT_ACTION.get(comm) } {
        Some(&action) => action == 1,
        None => true,
    }
}
```

### Issue 3: Claude Code Uses Bun Runtime — Worker Thread Problem

**Symptom**: Guardian logged events for the main `claude` process but completely
missed file accesses from the Claude agent. Files in the blocked folder were
read successfully without any BLOCKED log entries.

**Root cause**: Claude Code is built on the **Bun** JavaScript runtime (NOT
Node.js). Bun spawns multiple worker threads for I/O operations, and these
threads have **different comm names** than the main process:

```
Main process:   comm = "claude"
Worker threads: comm = "Bun Pool 0", "Bun Pool 1", "HeapHelper",
                       "File Watcher", "HTTP Client", "libuv-worker"
```

All actual file I/O happens on the worker threads ("Bun Pool *" and
"libuv-worker"), not the main "claude" thread. The original implementation only
matched by comm name, so worker threads were invisible to Guardian.

**Fix (3 parts)**:

**Part A — WATCHED_TGIDS map**: Added a new BPF HashMap keyed by TGID (thread
group ID). In Linux, all threads of a process share the same TGID. The
userspace daemon scans `/proc` for processes named "claude", gets their PIDs
(which equal TGID for the main thread), and inserts them into `WATCHED_TGIDS`.
The eBPF program checks this map in addition to comm matching:

```rust
fn is_process_watched(comm: &[u8; 16], tgid: u32) -> bool {
    unsafe { WATCHED_COMMS.get(comm) }.is_some()       // Match by name
        || unsafe { WATCHED_TGIDS.get(&tgid) }.is_some() // Match by TGID
        || unsafe { CHILD_PIDS.get(&tgid) }.is_some()    // Match children
}
```

**Part B — ENFORCE_TGIDS map**: The enforcement check originally only checked
`ENFORCE_COMMS`, which again only matched the "claude" comm. Added
`ENFORCE_TGIDS` so enforcement triggers for any thread of a watched process:

```rust
let is_enforcing = unsafe { ENFORCE_COMMS.get(&comm) }.is_some()
    || unsafe { ENFORCE_TGIDS.get(&tgid) }.is_some();
```

**Part C — Periodic PID Rescan**: The WATCHED_TGIDS and ENFORCE_TGIDS maps need
to be updated when new Claude processes start. The maps are wrapped in
`Arc<Mutex<>>` and a tokio task rescans `/proc` every N seconds:

```rust
type SharedBpfMap = Arc<Mutex<HashMap<MapData, u32, u8>>>;

// In the rescan loop:
if let Ok(mut map) = rescan_watched.lock() {
    for pid in &pids {
        let _ = map.insert(*pid, 1, 0);
    }
}
```

### Issue 4: WATCHED_TGIDS Map Dropped After Population

**Symptom**: TGID-based matching worked at startup but stopped working after a
few seconds. New Claude processes were not detected.

**Root cause**: `take_map()` returns an owned `HashMap<MapData, ...>`. In the
initial implementation, this was a local variable in `populate_watched_tgids()`.
When the function returned, the map was dropped, closing its file descriptor.
The kernel kept the map alive (programs still reference it), but userspace could
no longer update it.

**Fix**: Return the maps from `populate_watched_tgids()` wrapped in
`Arc<Mutex<>>` and pass them to the periodic rescan task:

```rust
fn populate_watched_tgids(bpf, config, enforce_mode)
    -> Result<(SharedBpfMap, Option<SharedBpfMap>)>
{
    // ... populate maps ...
    let watched = Arc::new(Mutex::new(watched_tgids));
    let enforce = enforce_tgids.map(|et| Arc::new(Mutex::new(et)));
    Ok((watched, enforce))
}
```

### Issue 5: Userspace Agent Matching for Worker Threads

**Symptom**: Events from worker threads (comm="Bun Pool 0") were logged as
`[CHILD]` with no policy evaluation, even though they were legitimate agent
threads.

**Root cause**: `process_file_event()` matched agents by exact comm name:
```rust
let agent_config = config.agents.iter().find(|a| a.process_name == comm);
```
"Bun Pool 0" != "claude", so it fell through to the `None` branch.

**Fix**: Added `find_agent_for_event()` that falls back to the first configured
agent when no exact match is found:

```rust
fn find_agent_for_event<'a>(config: &'a Config, comm: &str) -> Option<&'a AgentConfig> {
    if let Some(agent) = config.agents.iter().find(|a| a.process_name == comm) {
        return Some(agent);
    }
    // Fall back to first agent for worker threads
    config.agents.first()
}
```

### Issue 6: /etc/claude-code/managed-settings.json Blocked

**Symptom**: Repeated BLOCKED logs for `/etc/claude-code/managed-settings.json`
even though it's a harmless config file.

**Root cause**: The `default = "deny"` policy blocks everything not explicitly
allowed. `/etc/claude-code/` was not in the allow list.

**Fix**: Added `/etc/claude-code/**` to the allow list in config.toml.

### Issue 7: Pod Trait Orphan Rule

**Symptom**: Compile error when trying to implement `aya::Pod` for
`FileAccessEvent` and `ExecEvent` in the guardian (userspace) crate.

**Root cause**: Rust's orphan rule prevents implementing a foreign trait
(`aya::Pod`) on a foreign type (`FileAccessEvent` from `guardian-common`) in a
third crate (`guardian`).

**Fix**: Added `aya` as an optional dependency to `guardian-common` behind a
`user` feature flag, and implemented Pod there:

```toml
# guardian-common/Cargo.toml
[features]
user = ["aya"]

[dependencies]
aya = { version = "0.13", optional = true }
```

```rust
// guardian-common/src/lib.rs
#[cfg(feature = "user")]
unsafe impl aya::Pod for FileAccessEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}
```

## Files Modified in Phase 2

### guardian-common/src/lib.rs
- Added `ExecEvent` struct for execve monitoring
- Added `PolicyRule` struct for config conversion
- Added BPF map name constants
- Added `aya::Pod` implementations behind `user` feature

### guardian-common/Cargo.toml
- Added `aya` as optional dependency with `user` feature gate

### guardian-ebpf/src/main.rs
- Added 14 BPF maps (up from 4 in Phase 1)
- Added `evaluate_policy()` using LPM Trie + HashMap (zero loops)
- Added `is_process_watched()` with TGID-based matching
- Added LSM `file_open` hook for enforcement
- Added `sys_enter_execve` tracepoint for exec monitoring
- Added `sched_process_fork` tracepoint for child tracking
- Added `sched_process_exit` tracepoint for cleanup

### guardian/src/main.rs
- Added LSM program load/attach with graceful fallback
- Added enforcement map population (LPM Trie, HashMap, default actions)
- Added `WATCHED_TGIDS` and `ENFORCE_TGIDS` with `Arc<Mutex<>>` lifecycle
- Added periodic PID rescan that updates BPF maps
- Added `find_agent_for_event()` with worker thread fallback
- Added exec event processing
- Changed ALLOW events to debug level to reduce log noise

### guardian/src/config.rs
- Added `mode` field to GlobalConfig ("monitor" or "enforce")
- Added `pid_rescan_interval` field
- Added `ExecPolicy` struct
- Added `watch_children` to AgentConfig
- Added `check_exec_policy()` function
- Added config validation for mode and exec policy

### config.toml
- Added `mode = "enforce"`
- Added `pid_rescan_interval = 5`
- Added `watch_children = true`
- Added `exec_policy` section
- Added `/etc/claude-code/**` to allow list
- Added deny rules for sensitive paths

## Kernel Requirements for Enforcement

The LSM BPF enforcement requires:
- `CONFIG_BPF_LSM=y` in kernel config
- `bpf` listed in the LSM order (check `/sys/kernel/security/lsm`)
- If unavailable, Guardian falls back to monitor-only mode gracefully

To check:
```bash
cat /sys/kernel/security/lsm
# Should include "bpf" in the comma-separated list

cat /boot/config-$(uname -r) | grep CONFIG_BPF_LSM
# Should show CONFIG_BPF_LSM=y
```

## Running Guardian

```bash
# Build eBPF program
cargo xtask build-ebpf --release

# Build userspace daemon
cargo build --release

# Run (requires root for eBPF)
sudo RUST_LOG=info target/release/guardian --config config.toml

# For verbose output (includes ALLOW events):
sudo RUST_LOG=debug target/release/guardian --config config.toml
```
