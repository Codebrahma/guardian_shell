# Guardian Shell - Agent Identity & Identification Guide

How to find, identify, and name LLM agents running on your Linux system so you can add them to Guardian Shell's allow/deny policies.

---

## Table of Contents

1. [The Problem: Which Process Is Which Agent?](#the-problem-which-process-is-which-agent)
2. [Quick Reference: Finding Your Agent's Process Name](#quick-reference-finding-your-agents-process-name)
3. [Known Agent Process Names](#known-agent-process-names)
4. [Step-by-Step: Identifying Any Agent](#step-by-step-identifying-any-agent)
5. [The Process Tree Problem](#the-process-tree-problem)
6. [Multiple Agents, Same Runtime](#multiple-agents-same-runtime)
7. [Identification Methods Explained](#identification-methods-explained)
   - [Level 1: Process Name (comm) — Current](#level-1-process-name-comm--current)
   - [Level 2: Command Line Arguments](#level-2-command-line-arguments)
   - [Level 3: Process Tree Tracking (execve)](#level-3-process-tree-tracking-execve)
   - [Level 4: Cgroup-Based Isolation](#level-4-cgroup-based-isolation)
   - [Level 5: Launcher Wrapper](#level-5-launcher-wrapper)
8. [How Agents Actually Run on Linux](#how-agents-actually-run-on-linux)
   - [Node.js Agents (Claude Code, Cursor)](#nodejs-agents-claude-code-cursor)
   - [Python Agents (Aider, AutoGPT, Open Interpreter, OpenClaw)](#python-agents-aider-autogpt-open-interpreter-openclaw)
   - [Rust/Go Agents](#rustgo-agents)
9. [Writing Policies for Multiple Agents](#writing-policies-for-multiple-agents)
10. [Spoofing and Evasion](#spoofing-and-evasion)
11. [Future: Robust Identity with Cgroups](#future-robust-identity-with-cgroups)
12. [Future: The Guardian Launcher](#future-the-guardian-launcher)

---

## The Problem: Which Process Is Which Agent?

When you have multiple LLM agents running on one system — Claude Code, Aider, OpenClaw, Open Interpreter, AutoGPT — they all look like regular Linux processes. The challenge is:

1. **Finding them**: What process name does each agent use?
2. **Distinguishing them**: Two Python agents both show up as `python3`
3. **Tracking children**: An agent spawns `bash`, which spawns `grep` — are those the agent too?
4. **Preventing evasion**: Can an agent rename itself to avoid monitoring?

This guide covers how to solve each of these problems.

---

## Quick Reference: Finding Your Agent's Process Name

The fastest way to find any agent's process name:

```bash
# Step 1: Start your agent normally

# Step 2: In another terminal, find it
ps aux | grep -i <agent-name>

# Step 3: Get the exact comm name (this is what Guardian uses)
cat /proc/<PID>/comm
```

The `comm` name is what you put in `process_name` in your Guardian config. It's limited to 15 characters.

---

## Known Agent Process Names

Here's a reference table for popular LLM agents. **Always verify on your system** — names can change between versions.

| Agent | How to Install | Main Process Name | Child Processes | How to Verify |
|-------|---------------|-------------------|-----------------|---------------|
| **Claude Code** | `npm install -g @anthropic-ai/claude-code` | `claude` or `node` | `node`, `bash`, `git`, agent-spawned commands | `ps aux \| grep claude` |
| **Cursor** | AppImage / .deb | `cursor` or `electron` | `node`, `bash`, agent-spawned commands | `ps aux \| grep cursor` |
| **Aider** | `pip install aider-chat` | `python3` or `aider` | `git`, `bash`, spawned commands | `ps aux \| grep aider` |
| **AutoGPT** | `git clone` + `pip install` | `python3` | `bash`, `curl`, various spawned commands | `ps aux \| grep autogpt` |
| **Open Interpreter** | `pip install open-interpreter` | `python3` or `interpreter` | `bash`, `python3`, spawned commands | `ps aux \| grep interpreter` |
| **OpenClaw** | varies | `python3` or custom | `bash`, spawned commands | `ps aux \| grep openclaw` |
| **GPT Engineer** | `pip install gpt-engineer` | `python3` | `bash`, spawned commands | `ps aux \| grep gpt-engineer` |
| **Cline** | VS Code extension | `node` | `bash`, `git`, spawned commands | `ps aux \| grep cline` |
| **Continue.dev** | VS Code/JetBrains extension | `node` | `bash`, spawned commands | `ps aux \| grep continue` |
| **Devin** | Cloud-based (local runner) | `python3` or `node` | Various | Check docs |

**Important**: Python-based agents often show up as `python3` or `python3.12` (truncated to 15 chars in comm). Node.js-based agents often show up as `node`. This creates the "same name, different agent" problem — addressed below.

---

## Step-by-Step: Identifying Any Agent

### Method 1: Watch It Start

```bash
# Terminal 1: Start watching for new processes
# This shows every new process that starts on the system
sudo bpftrace -e 'tracepoint:sched:sched_process_exec { printf("%s (pid=%d, ppid=%d)\n", comm, pid, curtask->parent->pid); }'

# If you don't have bpftrace, use:
watch -n 0.5 'ps -eo pid,ppid,comm,args --sort=-start_time | head -20'

# Terminal 2: Start your agent
aider --model claude-3.5-sonnet
```

You'll see the agent's process name and all child processes it spawns.

### Method 2: Find a Running Agent

```bash
# Find by name (case-insensitive search through all process command lines)
ps aux | grep -i "claude\|aider\|autogpt\|interpreter\|openclaw"

# Get detailed info for a specific PID
PID=12345
echo "Comm name:  $(cat /proc/$PID/comm)"
echo "Full command: $(cat /proc/$PID/cmdline | tr '\0' ' ')"
echo "Executable: $(readlink /proc/$PID/exe)"
echo "Cgroup:     $(cat /proc/$PID/cgroup)"
echo "Parent PID: $(grep PPid /proc/$PID/status | awk '{print $2}')"
```

### Method 3: Trace the Entire Process Tree

```bash
# See the full process tree of a running agent
pstree -p <agent-PID>

# Example output for Claude Code:
# claude(1234)─┬─node(1235)───bash(1240)───grep(1245)
#              └─node(1236)

# Example output for Aider:
# python3(2000)───git(2010)
```

### Method 4: Use Guardian in Audit Mode

Run Guardian with `default = "allow"` and watch what shows up:

```toml
[[agents]]
name = "discover-python"
process_name = "python3"

[agents.file_access]
default = "allow"
allow = []
deny = ["/home/**/.ssh/**"]  # Just flag the dangerous stuff
```

```bash
sudo RUST_LOG=info target/release/guardian --config audit.toml
```

This tells you what files each process accesses — helping you build the right policy.

---

## The Process Tree Problem

LLM agents don't just run as one process. They spawn child processes:

```
Claude Code session:
├── claude (PID 1000)           ← main agent process
│   ├── node (PID 1001)         ← Node.js worker
│   ├── bash (PID 1002)         ← shell for running commands
│   │   ├── git (PID 1003)      ← agent ran: git status
│   │   ├── cat (PID 1004)      ← agent ran: cat file.txt
│   │   └── npm (PID 1005)      ← agent ran: npm install
│   └── node (PID 1006)         ← another worker

Aider session:
├── python3 (PID 2000)          ← main agent process
│   ├── git (PID 2001)          ← aider ran: git diff
│   └── bash (PID 2002)         ← shell commands
│       └── pytest (PID 2003)   ← aider ran: pytest
```

**The problem**: Guardian Phase 1 monitors by process name. If you watch `claude`, you catch the main process. But when Claude spawns `bash` which spawns `cat`, those child processes have different comm names — Guardian doesn't know they belong to the agent.

**Current workaround**: Add all known child process names to your config:

```toml
# Watch the main agent AND its common children
[[agents]]
name = "claude-code"
process_name = "claude"
[agents.file_access]
default = "deny"
allow = ["/home/user/project/**", "/tmp/**", "/usr/lib/**", "/lib/**", "/lib64/**"]
deny = ["/home/user/.ssh/**"]

[[agents]]
name = "claude-shells"
process_name = "bash"
[agents.file_access]
default = "deny"
allow = ["/home/user/project/**", "/tmp/**", "/usr/lib/**", "/lib/**", "/lib64/**"]
deny = ["/home/user/.ssh/**"]

[[agents]]
name = "claude-git"
process_name = "git"
[agents.file_access]
default = "deny"
allow = ["/home/user/project/**", "/tmp/**", "/usr/lib/**", "/lib/**", "/lib64/**"]
deny = ["/home/user/.ssh/**"]
```

**Phase 2 solution**: Track `execve` in eBPF to automatically detect child processes and inherit the parent's policy. (See [Level 3](#level-3-process-tree-tracking-execve) below.)

**Phase 3 solution**: Use cgroups — all processes in a cgroup are tracked automatically, including children. (See [Level 4](#level-4-cgroup-based-isolation) below.)

---

## Multiple Agents, Same Runtime

When two Python agents run simultaneously:

```
python3 (PID 2000) → Aider
python3 (PID 3000) → OpenClaw
```

Both have comm name `python3`. Guardian can't tell them apart with process name alone.

### Workaround 1: Custom Process Names via Wrapper Scripts

Create wrapper scripts that give each agent a unique process name:

```bash
#!/bin/bash
# /usr/local/bin/aider-agent
# This script renames the process before running aider
exec -a "aider-agent" python3 -m aider "$@"
```

```bash
#!/bin/bash
# /usr/local/bin/openclaw-agent
exec -a "openclaw-agt" python3 -m openclaw "$@"
```

The `exec -a "name"` flag sets the process name (argv[0]). Now you can configure:

```toml
[[agents]]
name = "aider"
process_name = "aider-agent"
[agents.file_access]
default = "deny"
allow = ["/home/user/project-a/**"]

[[agents]]
name = "openclaw"
process_name = "openclaw-agt"
[agents.file_access]
default = "deny"
allow = ["/home/user/project-b/**"]
```

Note: `exec -a` changes `argv[0]` but not always `comm`. For a more reliable rename, use a Python wrapper:

```python
#!/usr/bin/env python3
# /usr/local/bin/aider-named
import ctypes, sys, os

# Set the process comm name (what /proc/PID/comm shows)
libc = ctypes.CDLL("libc.so.6")
PR_SET_NAME = 15
libc.prctl(PR_SET_NAME, b"aider-agent\0")

# Now run the actual agent
os.execvp("python3", ["aider-agent", "-m", "aider"] + sys.argv[1:])
```

### Workaround 2: Shared Policy for Same Runtime

If you can't rename, apply the same policy to all `python3` processes:

```toml
[[agents]]
name = "all-python-agents"
process_name = "python3"
[agents.file_access]
default = "deny"
allow = [
    "/home/user/project-a/**",  # Aider's workspace
    "/home/user/project-b/**",  # OpenClaw's workspace
    "/usr/lib/python3/**",
    "/tmp/**",
]
deny = ["/home/user/.ssh/**", "/home/user/.aws/**"]
```

This is less precise but still protects sensitive paths.

### Future Solution: Cgroup Isolation

In Phase 3, each agent will run in its own cgroup:

```bash
# Each agent gets its own cgroup
/sys/fs/cgroup/guardian/aider/cgroup.procs     → contains Aider's PIDs
/sys/fs/cgroup/guardian/openclaw/cgroup.procs   → contains OpenClaw's PIDs
```

Even if both are `python3`, Guardian identifies them by cgroup path, not process name.

---

## Identification Methods Explained

### Level 1: Process Name (comm) — Current

**What Guardian Phase 1 uses.**

```
/proc/PID/comm → "python3" (max 15 chars)
```

The eBPF program calls `bpf_get_current_comm()` in the kernel and checks it against the `WATCHED_COMMS` hash map.

| Pros | Cons |
|------|------|
| Simple, fast (~50ns lookup) | Truncated to 15 characters |
| Works for all processes | Spoofable via `prctl(PR_SET_NAME)` |
| Catches short-lived processes | Can't distinguish same-named processes |
| No setup required | Doesn't track child processes |

**Best for**: Single-agent systems, agents with unique binary names.

### Level 2: Command Line Arguments

**Planned enhancement.**

```
/proc/PID/cmdline → "python3\0-m\0aider\0--model\0claude-3.5\0"
```

The full command line can distinguish `python3 -m aider` from `python3 -m openclaw`.

| Pros | Cons |
|------|------|
| More specific than comm name | Harder to read from eBPF (longer string) |
| Can distinguish same-runtime agents | Can be modified by the process |
| No setup required | Arguments may vary between invocations |

**Implementation idea**: Userspace reads `/proc/PID/cmdline` for watched PIDs and matches against patterns like `python3.*aider`.

### Level 3: Process Tree Tracking (execve)

**Planned for Phase 2.**

Hook the `sys_enter_execve` tracepoint to detect when a watched process spawns children:

```
Agent starts: python3 (PID 2000) → add to watch list
Agent spawns: bash (PID 2001, parent=2000) → auto-add to watch list
Bash spawns: git (PID 2002, parent=2001) → auto-add to watch list
```

How it works in eBPF:

```
sys_enter_execve fires:
  1. Get parent PID (bpf_get_current_pid_tgid)
  2. Check: is parent in WATCHED_PIDS?
  3. If yes → add NEW child PID to WATCHED_PIDS
  4. Child inherits parent's agent identity
```

| Pros | Cons |
|------|------|
| Tracks entire process tree | More complex eBPF program |
| Child processes auto-discovered | Need to clean up dead PIDs |
| Works with any spawn pattern | Fork bombs could fill the map |

**Best for**: Agents that spawn many child processes (Claude Code, AutoGPT).

### Level 4: Cgroup-Based Isolation

**Planned for Phase 3. The most robust approach.**

Linux cgroups (control groups) are a kernel mechanism for grouping processes. A process placed in a cgroup cannot escape it, and all child processes automatically inherit the parent's cgroup.

```
/sys/fs/cgroup/guardian/
├── claude-code/
│   └── cgroup.procs → 1000, 1001, 1002, 1003 (all Claude processes)
├── aider/
│   └── cgroup.procs → 2000, 2001 (all Aider processes)
└── openclaw/
    └── cgroup.procs → 3000 (all OpenClaw processes)
```

**Key properties:**
- **Cannot be spoofed**: Only root can move processes between cgroups
- **Inherits to children**: `fork()` and `exec()` preserve cgroup membership
- **Unique per agent**: Each agent instance gets its own cgroup
- **Kernel-enforced**: The cgroup membership is part of the task struct

The eBPF program would read the cgroup ID (available via `bpf_get_current_cgroup_id()`) and check it against a `WATCHED_CGROUPS` map.

| Pros | Cons |
|------|------|
| Cannot be spoofed by the agent | Requires cgroup setup (launcher) |
| All children automatically tracked | Needs root or delegated cgroup |
| Unique identity per agent instance | Slightly more complex config |
| Works with any process name | Requires cgroup v2 for best experience |

**Best for**: Production deployments, multi-agent systems, security-critical environments.

### Level 5: Launcher Wrapper

**Planned for Phase 3. The easiest user experience.**

Instead of manually creating cgroups, Guardian provides a launcher command:

```bash
# Instead of running the agent directly:
aider --model claude-3.5-sonnet

# Run it through Guardian's launcher:
guardian-launch --name "aider" --policy strict -- aider --model claude-3.5-sonnet
```

The launcher:
1. Creates a dedicated cgroup: `/sys/fs/cgroup/guardian/aider-<uuid>/`
2. Places itself in the cgroup
3. Executes the agent (which inherits the cgroup)
4. Guardian daemon detects the cgroup and applies the matching policy
5. All child processes are automatically tracked

```toml
# Config references the launcher name, not a process name
[[agents]]
name = "aider"
launcher_name = "aider"    # Matches --name from guardian-launch

[agents.file_access]
default = "deny"
allow = ["/home/user/project/**"]
deny = ["/home/user/.ssh/**"]
```

| Pros | Cons |
|------|------|
| Zero-setup for users | Requires using the launcher |
| Automatic cgroup creation | Agent must be started through guardian-launch |
| Works with any agent | Adds a startup step |
| Unique identity guaranteed | Not transparent to existing workflows |

---

## How Agents Actually Run on Linux

### Node.js Agents (Claude Code, Cursor)

```
┌─────────────────────────────────────────────────┐
│ Claude Code                                      │
│                                                  │
│  claude (main process)                           │
│    ├── node (language server / worker)            │
│    ├── node (API client for Anthropic)           │
│    └── bash (shell for executing commands)       │
│         ├── git status                           │
│         ├── cat src/main.rs                      │
│         ├── cargo build                          │
│         │    └── rustc (compiler)                │
│         └── npm install                          │
│              └── node (npm scripts)              │
│                                                  │
│  Process names seen: claude, node, bash, git,    │
│  cat, cargo, rustc, npm                          │
└─────────────────────────────────────────────────┘
```

**How to identify**: Look for `claude` in comm. The main process is usually named `claude` if installed via npm globally. If running from source, it might be `node`.

```bash
# Find Claude Code
ps aux | grep -E 'claude|@anthropic'
# Get the comm name
cat /proc/$(pgrep -f claude)/comm
```

**Guardian config**:
```toml
[[agents]]
name = "claude-code"
process_name = "claude"

[agents.file_access]
default = "deny"
allow = [
    # Project workspace
    "/home/user/myproject/**",

    # System libraries (Node.js needs these)
    "/lib/**", "/lib64/**", "/usr/lib/**",
    "/etc/ld.so.cache",
    "/usr/share/locale/**",

    # Node.js runtime
    "/home/user/.nvm/**",
    "/home/user/.npm/**",
    "/usr/local/lib/node_modules/**",

    # Temp files
    "/tmp/**",

    # SSL (for API calls)
    "/etc/ssl/**",
    "/usr/share/ca-certificates/**",

    # Git (Claude uses git heavily)
    "/usr/libexec/git-core/**",
    "/usr/share/git-core/**",
]
deny = [
    "/home/user/.ssh/**",
    "/home/user/.aws/**",
    "/home/user/.gnupg/**",
    "/home/user/myproject/.env",
    "/home/user/myproject/.env.*",
]
```

### Python Agents (Aider, AutoGPT, Open Interpreter, OpenClaw)

```
┌─────────────────────────────────────────────────┐
│ Aider                                            │
│                                                  │
│  python3 (main process: python3 -m aider)       │
│    ├── git diff                                  │
│    ├── git log                                   │
│    └── bash -c "..."                             │
│         └── user commands                        │
│                                                  │
│  Process names seen: python3, git, bash          │
│                                                  │
├─────────────────────────────────────────────────┤
│ AutoGPT                                          │
│                                                  │
│  python3 (main process)                          │
│    ├── bash (shell commands)                     │
│    │    ├── curl (web requests)                  │
│    │    ├── cat, ls, grep (file operations)      │
│    │    └── python3 (spawned scripts)            │
│    └── python3 (sub-agents)                      │
│                                                  │
│  Process names seen: python3, bash, curl, etc.   │
│                                                  │
├─────────────────────────────────────────────────┤
│ Open Interpreter                                 │
│                                                  │
│  python3 (main process: interpreter)             │
│    ├── python3 (code execution sandbox)          │
│    ├── bash (shell commands)                     │
│    │    └── any command the agent decides to run │
│    └── node (if running JavaScript)              │
│                                                  │
│  Process names seen: python3, bash, node, etc.   │
└─────────────────────────────────────────────────┘
```

**The Python problem**: All Python agents show up as `python3`. To distinguish them:

```bash
# See the full command line (shows the module being run)
ps aux | grep python3
# Output:
# user  2000  python3 -m aider --model claude-3.5
# user  3000  python3 -m openclaw serve

# Or check each one
cat /proc/2000/cmdline | tr '\0' ' '
# → python3 -m aider --model claude-3.5-sonnet
```

**Workaround with wrapper scripts** (recommended until Phase 3):

```bash
# /usr/local/bin/run-aider
#!/bin/bash
exec -a "aider" python3 -m aider "$@"

# /usr/local/bin/run-openclaw
#!/bin/bash
exec -a "openclaw" python3 -m openclaw "$@"
```

Now use them:
```bash
run-aider --model claude-3.5-sonnet    # Shows as "aider" in comm
run-openclaw serve                      # Shows as "openclaw" in comm
```

Guardian config:
```toml
[[agents]]
name = "aider"
process_name = "aider"
[agents.file_access]
default = "deny"
allow = ["/home/user/project-a/**", "/tmp/**", "/usr/lib/**", "/lib/**", "/lib64/**"]
deny = ["/home/user/.ssh/**"]

[[agents]]
name = "openclaw"
process_name = "openclaw"
[agents.file_access]
default = "deny"
allow = ["/home/user/project-b/**", "/tmp/**", "/usr/lib/**", "/lib/**", "/lib64/**"]
deny = ["/home/user/.ssh/**"]
```

### Rust/Go Agents

Agents written in Rust or Go compile to native binaries with unique names:

```bash
# The binary name IS the process name
./my-rust-agent        # comm = "my-rust-agent" (truncated to 15: "my-rust-agent")
./custom-go-bot        # comm = "custom-go-bot"
```

These are the easiest to identify — just use the binary name.

---

## Writing Policies for Multiple Agents

### Scenario: Developer Workstation with 3 Agents

```
System:
├── Claude Code → editing project-frontend
├── Aider → editing project-backend
└── OpenClaw → running experiments in sandbox
```

```toml
[global]
log_level = "info"

# ─────────────────────────────────────────────
# Agent 1: Claude Code (Node.js-based)
# ─────────────────────────────────────────────
[[agents]]
name = "claude-code"
process_name = "claude"

[agents.file_access]
default = "deny"
allow = [
    # Its workspace only
    "/home/dev/project-frontend/**",

    # Shared dependencies
    "/home/dev/.nvm/**",
    "/home/dev/.npm/**",

    # System
    "/lib/**", "/lib64/**", "/usr/lib/**",
    "/etc/ld.so.cache", "/etc/ssl/**",
    "/usr/share/**", "/tmp/**",
]
deny = [
    # Never access other projects
    "/home/dev/project-backend/**",
    "/home/dev/sandbox/**",

    # Credentials
    "/home/dev/.ssh/**",
    "/home/dev/.aws/**",
    "/home/dev/.gnupg/**",
    "/home/dev/project-frontend/.env",
    "/home/dev/project-frontend/.env.*",
]

# ─────────────────────────────────────────────
# Agent 2: Aider (Python-based, using wrapper)
# Run with: run-aider --model claude-3.5-sonnet
# ─────────────────────────────────────────────
[[agents]]
name = "aider"
process_name = "aider"

[agents.file_access]
default = "deny"
allow = [
    # Its workspace only
    "/home/dev/project-backend/**",

    # Python runtime
    "/usr/lib/python3/**",
    "/home/dev/.local/lib/python3/**",
    "/home/dev/venvs/backend/**",

    # System
    "/lib/**", "/lib64/**", "/usr/lib/**",
    "/etc/ld.so.cache", "/etc/ssl/**",
    "/usr/share/**", "/tmp/**",
]
deny = [
    # Never access other projects
    "/home/dev/project-frontend/**",
    "/home/dev/sandbox/**",

    # Credentials
    "/home/dev/.ssh/**",
    "/home/dev/.aws/**",
    "/home/dev/project-backend/.env",
]

# ─────────────────────────────────────────────
# Agent 3: OpenClaw (Python-based, using wrapper)
# Run with: run-openclaw
# ─────────────────────────────────────────────
[[agents]]
name = "openclaw"
process_name = "openclaw"

[agents.file_access]
default = "deny"
allow = [
    # Restricted to sandbox only
    "/home/dev/sandbox/**",

    # Python runtime
    "/usr/lib/python3/**",
    "/home/dev/venvs/openclaw/**",

    # System (minimal)
    "/lib/**", "/lib64/**", "/usr/lib/**",
    "/etc/ld.so.cache", "/tmp/**",
]
deny = [
    # Cannot access any real project
    "/home/dev/project-frontend/**",
    "/home/dev/project-backend/**",

    # Credentials
    "/home/dev/.ssh/**",
    "/home/dev/.aws/**",
    "/home/dev/.gnupg/**",
    "/home/dev/.kube/**",
]

# ─────────────────────────────────────────────
# Catch-all: Monitor any bash/git spawned by agents
# (Until Phase 2 adds process tree tracking)
# ─────────────────────────────────────────────
[[agents]]
name = "agent-shells"
process_name = "bash"

[agents.file_access]
default = "deny"
allow = [
    "/home/dev/project-frontend/**",
    "/home/dev/project-backend/**",
    "/home/dev/sandbox/**",
    "/lib/**", "/lib64/**", "/usr/lib/**",
    "/etc/ld.so.cache", "/tmp/**", "/usr/share/**",
]
deny = [
    "/home/dev/.ssh/**",
    "/home/dev/.aws/**",
    "/home/dev/.gnupg/**",
    "/home/dev/**/.env",
    "/home/dev/**/.env.*",
]

[[agents]]
name = "agent-git"
process_name = "git"

[agents.file_access]
default = "deny"
allow = [
    "/home/dev/project-frontend/**",
    "/home/dev/project-backend/**",
    "/home/dev/sandbox/**",
    "/lib/**", "/lib64/**", "/usr/lib/**",
    "/etc/ld.so.cache", "/tmp/**", "/usr/share/**",
    "/usr/libexec/git-core/**",
]
deny = [
    "/home/dev/.ssh/**",
    "/home/dev/.aws/**",
]
```

---

## Spoofing and Evasion

### How an Agent Could Evade Detection

A malicious or compromised agent could:

**1. Rename its process** (trivial):
```c
// C code inside the agent
prctl(PR_SET_NAME, "systemd");  // Now /proc/PID/comm says "systemd"
```

```python
# Python code inside the agent
import ctypes
libc = ctypes.CDLL("libc.so.6")
libc.prctl(15, b"innocent\0")  # PR_SET_NAME = 15
```

After this, Guardian's comm-based matching no longer catches the process.

**2. Spawn a child with a different name**:
```python
import subprocess
subprocess.run(["cat", "/home/user/.ssh/id_rsa"])
# "cat" is not watched → Guardian doesn't see it (Phase 1)
```

**3. Use relative paths**:
```python
os.chdir("/home/user/.ssh")
open("id_rsa")  # eBPF captures "id_rsa", not "/home/user/.ssh/id_rsa"
# Pattern "/home/user/.ssh/**" doesn't match "id_rsa"
```

### Current Mitigations

| Attack | Phase 1 Status | Future Fix |
|--------|---------------|------------|
| Process name spoofing | Vulnerable | Phase 3: Cgroup-based ID (can't be spoofed) |
| Child process evasion | Vulnerable | Phase 2: execve tracking (auto-discover children) |
| Relative path bypass | Vulnerable | Phase 2: Full path resolution in eBPF or userspace |

### Detection Heuristic (Can Implement Now)

You can add a discrepancy check in userspace: if `/proc/PID/comm` doesn't match `/proc/PID/exe`, something is suspicious:

```bash
# Normal:
# /proc/1234/comm → "python3"
# /proc/1234/exe  → /usr/bin/python3.12  ← matches

# Suspicious (spoofed):
# /proc/1234/comm → "systemd"
# /proc/1234/exe  → /usr/bin/python3.12  ← mismatch!
```

---

## Future: Robust Identity with Cgroups

### How Cgroup Identification Will Work (Phase 3)

```
                    ┌─────────────────────────┐
                    │    /sys/fs/cgroup/       │
                    │         guardian/         │
                    └─────────┬───────────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
      ┌───────┴──────┐ ┌─────┴──────┐ ┌──────┴──────┐
      │ claude-code/ │ │   aider/   │ │  openclaw/  │
      │              │ │            │ │             │
      │ PID 1000     │ │ PID 2000   │ │ PID 3000    │
      │ PID 1001     │ │ PID 2001   │ │             │
      │ PID 1002     │ │            │ │             │
      │ PID 1003     │ │            │ │             │
      └──────────────┘ └────────────┘ └─────────────┘
```

**Properties:**
- Agent `claude-code` spawns bash (PID 1001) → automatically in `claude-code` cgroup
- Bash spawns git (PID 1002) → automatically in `claude-code` cgroup
- Git spawns sub-process (PID 1003) → automatically in `claude-code` cgroup
- **No process can escape** its cgroup without root
- **No spoofing possible** — cgroup is kernel-managed
- **All processes identified** regardless of their comm name

**eBPF implementation:**

```rust
// In the eBPF program (Phase 3):
let cgroup_id = bpf_get_current_cgroup_id();
if WATCHED_CGROUPS.get(&cgroup_id).is_none() {
    return Ok(0);  // Not in any watched cgroup
}
// → Catches ALL processes in the agent's cgroup tree
```

**Config (Phase 3):**

```toml
[[agents]]
name = "claude-code"
cgroup = "guardian/claude-code"    # Instead of process_name

[agents.file_access]
default = "deny"
allow = ["/home/user/project/**"]
deny = ["/home/user/.ssh/**"]
```

---

## Future: The Guardian Launcher

### The Vision

```bash
# Today (Phase 1): Must manually find process name, add to config
aider --model claude-3.5-sonnet

# Future (Phase 3): One command to launch with full isolation
guardian-launch --name aider --policy /etc/guardian/aider-policy.toml \
    -- aider --model claude-3.5-sonnet
```

### What the Launcher Does

```
guardian-launch --name aider -- aider --model claude-3.5
        │
        ▼
┌─────────────────────────────────────────────────────┐
│ 1. Create cgroup: /sys/fs/cgroup/guardian/aider-xxx │
│ 2. Move self into the cgroup                         │
│ 3. Set resource limits (optional):                   │
│    - Memory: 4GB max                                 │
│    - CPU: 200% (2 cores)                             │
│    - PIDs: 100 max (prevent fork bombs)              │
│ 4. Notify Guardian daemon: "aider-xxx is starting"  │
│ 5. exec() the agent (inherits cgroup)               │
│                                                      │
│ Agent runs inside cgroup:                            │
│   aider (PID 2000) ─┬─ git (PID 2001)              │
│                      └─ bash (PID 2002)              │
│                           └─ grep (PID 2003)         │
│                                                      │
│ ALL processes tracked by Guardian via cgroup ID      │
│ NO process can escape the cgroup                     │
│ NO process name spoofing matters                     │
└─────────────────────────────────────────────────────┘
```

### Comparison: Today vs Future

| Aspect | Phase 1 (Today) | Phase 3 (Future) |
|--------|-----------------|-------------------|
| **Identity** | Process comm name | Cgroup path |
| **Child tracking** | Manual config per name | Automatic (cgroup inheritance) |
| **Spoofing** | Vulnerable (prctl) | Immune (kernel cgroup) |
| **Setup** | Find process name, add to config | `guardian-launch --name X -- command` |
| **Multiple same-name** | Can't distinguish | Separate cgroups |
| **Enforcement** | Monitor only (log) | Kernel blocks access (LSM) |
| **Scope** | Single process name | Entire process tree |

---

## Summary: How to Set Up Guardian for Your Agents Today

**Step 1**: Find each agent's process name:
```bash
# Start the agent, then:
ps aux | grep -i <agent>
cat /proc/<PID>/comm
```

**Step 2**: For Python agents with the same name, create wrapper scripts:
```bash
#!/bin/bash
# /usr/local/bin/run-aider
exec -a "aider" python3 -m aider "$@"
```

**Step 3**: Add each agent to your config:
```toml
[[agents]]
name = "descriptive-name"
process_name = "comm-name"    # From step 1 or 2

[agents.file_access]
default = "deny"
allow = ["agent's workspace", "system libs"]
deny = ["credentials", "other projects"]
```

**Step 4**: Also add entries for common child process names (`bash`, `git`, `node`) with appropriate policies.

**Step 5**: Run Guardian and iterate:
```bash
sudo RUST_LOG=info target/release/guardian --config config.toml
```

Watch for unexpected `[DENY]` events and add missing allow rules. Watch for suspicious `[ALLOW]` events on sensitive paths and add deny rules.
