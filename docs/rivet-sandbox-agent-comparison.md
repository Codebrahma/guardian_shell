# Rivet Sandbox Agent vs Guardian Shell — Deep Comparison

> **Last Updated:** 2026-03-20
> **Purpose:** Understand how Rivet's Sandbox Agent SDK works, its architecture, strengths,
> limitations, and how it compares to Guardian Shell for LLM agent security.

---

## Table of Contents

1. [What Is Rivet Sandbox Agent?](#1-what-is-rivet-sandbox-agent)
2. [Rivet Architecture Deep Dive](#2-rivet-architecture-deep-dive)
3. [Guardian Shell Architecture Recap](#3-guardian-shell-architecture-recap)
4. [Side-by-Side Comparison](#4-side-by-side-comparison)
5. [Security Model Comparison](#5-security-model-comparison)
6. [Use Case Scenarios](#6-use-case-scenarios)
7. [Strengths and Weaknesses](#7-strengths-and-weaknesses)
8. [Can They Work Together?](#8-can-they-work-together)
9. [Summary](#9-summary)

---

## 1. What Is Rivet Sandbox Agent?

Rivet Sandbox Agent is an **API adapter layer** that lets you control different coding agents
(Claude Code, Codex, OpenCode, Cursor, Amp, Pi) through a single unified HTTP/SSE interface.

### The Problem Rivet Solves

Every coding agent has its own protocol:

```
Claude Code  →  JSONL over stdout
Codex        →  JSON-RPC
OpenCode     →  HTTP server with SSE
Cursor       →  Proprietary protocol
Amp          →  Its own format
```

If you're building a platform that uses coding agents, you'd need to write separate
integration code for each agent. Rivet eliminates this:

```
Your App
   │
   ▼
Sandbox Agent (single HTTP API)
   │
   ├── Claude Code adapter  →  translates to JSONL/stdout
   ├── Codex adapter        →  translates to JSON-RPC
   ├── OpenCode adapter     →  translates to HTTP/SSE
   └── Amp adapter          →  translates to Amp's format
```

**One API. Swap agents with a config change.**

### What Rivet Is NOT

Rivet Sandbox Agent does **not** provide security sandboxing itself. Despite the word "sandbox"
in its name, it is designed to run **inside** an existing sandbox (Docker, E2B, Vercel Sandboxes,
etc.). It does not:

- Block file access at the kernel level
- Filter syscalls
- Monitor or restrict network connections
- Detect evasion attacks (symlinks, TOCTOU, etc.)
- Provide human-in-the-loop approval with risk scoring

The "sandbox" in its name refers to the **environment** it runs in, not something it provides.

---

## 2. Rivet Architecture Deep Dive

### 2.1 Three-Layer Design

```
┌─────────────────────────────────────────────────────────────────┐
│                        YOUR APPLICATION                          │
│  (TypeScript SDK, CLI, or any HTTP client)                       │
└─────────────────┬───────────────────────────────────────────────┘
                  │ HTTP / SSE
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                     SANDBOX AGENT SERVER                         │
│  (Rust binary, ~15MB, no dependencies)                          │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Router Layer (HTTP endpoints)                            │   │
│  │    GET  /agents              — list available agents      │   │
│  │    POST /sessions            — create new session         │   │
│  │    POST /sessions/{id}/messages — send prompt to agent    │   │
│  │    GET  /sessions/{id}/events   — stream events (SSE)     │   │
│  │    GET  /sessions/{id}          — get session status      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Agent Adapters (one per supported agent)                 │   │
│  │    claude-code-adapter.rs   — JSONL/stdout translation    │   │
│  │    codex-adapter.rs         — JSON-RPC translation        │   │
│  │    opencode-adapter.rs      — HTTP/SSE translation        │   │
│  │    amp-adapter.rs           — Amp protocol translation    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Agent Processes (spawned as subprocesses)                │   │
│  │    PID 100: claude-code --jsonl                           │   │
│  │    PID 200: codex                                         │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 How a Session Works (Step by Step)

Here's what happens when you ask an agent to write code via Rivet:

```
Step 1: Your app creates a session
────────────────────────────────
POST /sessions
{
  "agent": "claude-code",
  "agentMode": "default"
}

→ Sandbox Agent spawns Claude Code as a subprocess
→ Returns session ID: "sess_abc123"

Step 2: Your app sends a prompt
────────────────────────────────
POST /sessions/sess_abc123/messages
{
  "message": "Create a REST API with Express.js"
}

→ Sandbox Agent translates this to Claude Code's JSONL format
→ Writes to Claude Code's stdin

Step 3: Your app streams events
────────────────────────────────
GET /sessions/sess_abc123/events  (SSE connection)

→ Events flow back in a NORMALIZED format:

  data: {"type": "message_received", "content": "I'll create an Express API..."}
  data: {"type": "tool_call_started", "tool": "write_file", "path": "server.js"}
  data: {"type": "file_created", "path": "server.js"}
  data: {"type": "tool_call_completed", "tool": "write_file"}
  data: {"type": "command_executed", "command": "npm install express"}
  data: {"type": "session_completed"}
```

The key insight: **every agent produces the same event format**. Whether you're using
Claude Code or Codex, your app sees identical event types.

### 2.3 Deployment Modes

**Embedded Mode (Development):**

```typescript
// Runs sandbox-agent as a local subprocess
const client = await SandboxAgent.start();
const session = await client.createSession("my-session", {
  agent: "claude-code",
});
```

Your app spawns the Sandbox Agent binary directly. Good for local development.

**Server Mode (Production):**

```bash
# Inside a Docker container, E2B sandbox, or Vercel Sandbox:
sandbox-agent server --token "$SECRET_TOKEN" --host 0.0.0.0 --port 2468
```

```typescript
// Your app connects remotely:
const client = await SandboxAgent.connect({
  baseUrl: "http://sandbox-ip:2468",
  token: process.env.SANDBOX_TOKEN,
});
```

The agent runs inside an isolated environment. Your app controls it over HTTP.

### 2.4 Rivet Actors Integration

Rivet also offers **Actors** — a stateful compute primitive. Combined with Sandbox Agent:

```
┌──────────────────────────────────────────────────────┐
│  Rivet Actor (persistent, durable)                    │
│                                                       │
│  - Stores session transcript in SQLite                │
│  - Survives crashes (state persisted)                 │
│  - Broadcasts tool_call events to connected clients   │
│  - Hibernates when idle ($0 cost)                     │
│  - ~20ms cold start                                   │
│                                                       │
│  ┌─────────────────────────────────────────────────┐ │
│  │  Sandbox Agent (inside the actor)                │ │
│  │  Controls Claude Code / Codex / etc.             │ │
│  └─────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
        ▲                ▲                ▲
        │                │                │
   Browser 1        Browser 2        Mobile App
   (watches live)   (watches live)   (gets updates)
```

Actors provide the **persistence and real-time broadcasting** that Sandbox Agent itself
doesn't handle.

### 2.5 Event Types

Rivet normalizes all agent events into these categories:

| Event Type | Description | Example |
|-----------|-------------|---------|
| `message_sent` | Your prompt was delivered | "Create a REST API" |
| `message_received` | Agent is responding | "I'll create an Express..." |
| `tool_call_started` | Agent is using a tool | write_file("server.js") |
| `tool_call_completed` | Tool execution finished | server.js written |
| `file_created` | A new file was created | server.js |
| `file_modified` | An existing file changed | package.json |
| `command_executed` | A shell command ran | npm install express |
| `permission.requested` | Agent wants approval | "Run npm install?" |
| `permission.resolved` | Approval decision made | approved / denied |
| `session_completed` | Session is done | — |

### 2.6 Authentication

Rivet uses a simple bearer token model:

```bash
# Start server with a token
sandbox-agent server --token "my-secret-token"

# All HTTP requests must include it
curl -H "Authorization: Bearer my-secret-token" \
  http://localhost:2468/agents
```

This authenticates the **client** (your app) to the Sandbox Agent server.
It does NOT enforce per-file or per-command permissions.

---

## 3. Guardian Shell Architecture Recap

For context, here's what Guardian Shell does differently:

```
┌──────────────────────────────────────────────────────────────────┐
│  Linux Kernel                                                     │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  eBPF Programs (loaded by Guardian)                       │    │
│  │    sys_enter_openat  → captures file open attempts        │    │
│  │    sys_enter_execve  → captures command execution         │    │
│  │    sys_enter_connect → captures network connections       │    │
│  │    file_open LSM     → BLOCKS file access (kernel-level)  │    │
│  │    bprm_check LSM    → BLOCKS exec (kernel-level)         │    │
│  │    socket_connect    → BLOCKS connections (kernel-level)   │    │
│  │    inode_rename LSM  → BLOCKS renames of protected files  │    │
│  │    inode_unlink LSM  → BLOCKS deletion of protected files │    │
│  │    inode_link LSM    → BLOCKS hardlinks to protected files│    │
│  └──────────────────────────────────────────────────────────┘    │
│                              ▲                                    │
│                              │ policy maps                        │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  Landlock LSM (applied by guardian-launch)                │    │
│  │    Inode-level file access control (symlink-immune)       │    │
│  │    TCP port filtering (kernel 6.7+)                       │    │
│  └──────────────────────────────────────────────────────────┘    │
│                              ▲                                    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  Seccomp Filter (applied by guardian-launch)              │    │
│  │    Blocks: io_uring, memfd_create, mount, unshare,        │    │
│  │           chroot, pivot_root, setns, new mount API        │    │
│  └──────────────────────────────────────────────────────────┘    │
│                              ▲                                    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  Cgroup v2 (created by guardian-launch)                   │    │
│  │    Resource limits: memory, PIDs, CPU                     │    │
│  │    Identity: unspoofable cgroup ID                        │    │
│  └──────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
                               ▲
                               │ events + policy
┌──────────────────────────────────────────────────────────────────┐
│  Userspace Daemon (guardian)                                      │
│    Policy engine, event processing, IPC server                   │
│    Human approval workflow with risk scoring                     │
│    Web dashboard, alerting, audit trail                          │
│    Anomaly detection on approval patterns                        │
└──────────────────────────────────────────────────────────────────┘
```

Guardian operates at the **kernel level**. It doesn't care what agent you're running —
it monitors and restricts the actual Linux syscalls the agent makes.

---

## 4. Side-by-Side Comparison

### 4.1 Core Identity

| Aspect | Rivet Sandbox Agent | Guardian Shell |
|--------|-------------------|----------------|
| **What it is** | API adapter + agent controller | Kernel-level security enforcer |
| **One-line summary** | "One API for any coding agent" | "eBPF + Landlock sandbox for LLM agents" |
| **Primary value** | Developer experience | Security enforcement |
| **Written in** | Rust (server) + TypeScript (SDK) | Rust + eBPF C (kernel programs) |
| **Binary size** | ~15MB | ~5MB (daemon + eBPF + launcher) |
| **Runs as** | HTTP server inside a sandbox | Root-level daemon with kernel programs |
| **Target user** | Platform builders (SaaS, IDE plugins) | Security engineers, ops teams |

### 4.2 Feature Comparison

| Feature | Rivet | Guardian | Notes |
|---------|-------|----------|-------|
| **Multi-agent support** | Claude Code, Codex, OpenCode, Amp, Cursor, Pi | Any Linux process | Rivet: protocol adapters. Guardian: monitors syscalls |
| **Unified API** | Yes (single HTTP/SSE) | No (each agent managed separately) | Rivet's core strength |
| **Session management** | Yes (create/stream/complete) | No | Guardian doesn't manage agent sessions |
| **Event streaming** | Yes (normalized JSON via SSE) | Yes (SSE via dashboard) | Different event types |
| **File access control** | None | Kernel-level (Landlock + eBPF LSM) | Rivet delegates to host sandbox |
| **Exec blocking** | None | Kernel-level (bprm_check_security) | — |
| **Network control** | None | Port-based (eBPF + Landlock TCP) | — |
| **Symlink protection** | None | Landlock inode-level (immune) | — |
| **Syscall filtering** | None | Seccomp (17 syscalls blocked) | — |
| **Resource limits** | None (host sandbox) | Cgroup v2 (memory, PIDs, CPU) | — |
| **Human approval** | Basic (permission.requested event) | Advanced (risk scoring, wait timers, type-to-confirm) | — |
| **Audit trail** | Event stream (no built-in storage) | SQLite persistent log | — |
| **Anomaly detection** | None | Rubber-stamping, flood, persistence pattern detection | — |
| **Dashboard** | Inspector UI (debugging) | Full web UI (monitoring + management) | — |
| **Authentication** | Bearer token for API | Bearer token for dashboard + IPC auth | — |
| **Agent swapping** | Config change | Config change (different mechanism) | — |
| **Requires root** | No | Yes (eBPF + cgroups) | — |
| **Requires Linux** | Any Linux | Linux with eBPF + Landlock support | — |
| **Cloud-native** | Yes (E2B, Vercel, Docker, etc.) | No (bare metal / VM focused) | — |

### 4.3 Security Layer Comparison

```
Rivet Sandbox Agent — Security Layers:
┌───────────────────────────────────────┐
│  Bearer token authentication          │  ← 1 layer
│  (who can call the HTTP API)          │
│                                       │
│  ... that's it.                       │
│  Everything else is the host sandbox. │
└───────────────────────────────────────┘

Guardian Shell — Security Layers:
┌───────────────────────────────────────┐
│  Layer 7: Anomaly detection           │  ← detects suspicious approval patterns
│  Layer 6: Human approval + risk score │  ← mandatory human decision with UI friction
│  Layer 5: Rate limiting + auto-deny   │  ← prevents approval fatigue attacks
│  Layer 4: Landlock (inode-level)      │  ← symlink-immune file control
│  Layer 3: Seccomp (syscall filter)    │  ← blocks io_uring, memfd, mount, etc.
│  Layer 2: eBPF LSM hooks             │  ← kernel-level file/exec/network blocking
│  Layer 1: Cgroup v2 isolation         │  ← resource limits + identity
└───────────────────────────────────────┘
```

---

## 5. Security Model Comparison

### 5.1 How Rivet Handles Security

Rivet's approach: **"Security is someone else's problem."**

```
Example: Agent tries to read /etc/shadow

┌──────────────────────────────────────────────────────┐
│  E2B Sandbox (or Docker, Vercel, etc.)                │
│                                                       │
│  Sandbox Agent receives: "read /etc/shadow"           │
│  Sandbox Agent tells Claude Code to do it             │
│  Claude Code calls: cat /etc/shadow                   │
│                                                       │
│  What prevents this?                                  │
│    → E2B's container isolation (if configured)        │
│    → Docker's volume mounts (if configured)           │
│    → The agent's own safety rules (unreliable)        │
│                                                       │
│  Rivet itself? Does nothing. It's an API adapter.     │
└──────────────────────────────────────────────────────┘
```

Rivet does emit `permission.requested` events when an agent asks for approval, but it's
up to your application to:
1. Receive the event
2. Decide whether to approve
3. Send back the decision

There's no built-in risk scoring, rate limiting, or anomaly detection.

### 5.2 How Guardian Handles Security

Guardian's approach: **"We are the enforcement layer."**

```
Example: Agent tries to read /etc/shadow

┌──────────────────────────────────────────────────────┐
│  Linux Kernel                                         │
│                                                       │
│  Agent calls: openat("/etc/shadow")                   │
│                                                       │
│  1. Landlock check: Is inode of /etc/shadow in allow  │
│     set? NO → BLOCKED (-EACCES)                       │
│     (Even if agent used a symlink, Landlock sees the  │
│     real inode after kernel resolves the path)         │
│                                                       │
│  2. eBPF tracepoint: Logs the attempt with full       │
│     metadata (PID, cgroup, raw path, timestamp)       │
│                                                       │
│  3. eBPF LSM file_open: Checks PENDING_DENY map      │
│     Returns -EACCES (double enforcement)              │
│                                                       │
│  4. Daemon: Sends alert to dashboard + Slack          │
│     Records in SQLite audit trail                     │
│     Increments agent's risk score                     │
│                                                       │
│  Result: Agent gets EACCES error. File never opened.  │
│  Four independent layers had to all fail for the      │
│  attack to succeed.                                   │
└──────────────────────────────────────────────────────┘
```

### 5.3 Specific Attack Scenarios

#### Symlink Attack

```
Attack: ln -s /etc/shadow /tmp/harmless && cat /tmp/harmless

Rivet:
  Agent asks Sandbox Agent: "read /tmp/harmless"
  Sandbox Agent tells Claude Code to read it
  Claude Code reads /tmp/harmless → follows symlink → reads /etc/shadow
  Result: DATA LEAKED (unless host sandbox blocks it)
  Rivet's role: None. It forwarded the request.

Guardian:
  Agent calls openat("/tmp/harmless")
  Landlock: resolves inode → /etc/shadow → NOT in allow set → BLOCKED
  eBPF: logs "raw path /tmp/harmless, attempted by agent X"
  Result: BLOCKED at kernel level. Agent gets EACCES.
```

#### Dynamic Linker Bypass

```
Attack: /lib/ld-linux.so.2 /usr/bin/curl http://evil.com
        (Runs curl through the dynamic linker to bypass exec policy)

Rivet:
  Agent asks to execute: /lib/ld-linux.so.2 /usr/bin/curl http://evil.com
  Sandbox Agent forwards to Claude Code
  Claude Code runs the command
  Result: curl executes (unless host sandbox blocks it)
  Rivet's role: Emits command_executed event. No blocking.

Guardian:
  Agent calls execve("/lib/ld-linux.so.2", ["/usr/bin/curl", "http://evil.com"])
  eBPF: recognizes ld-linux as a dynamic linker
  eBPF: reads argv[1] → /usr/bin/curl → evaluates exec policy → DENIED
  LSM bprm_check_security: returns -EPERM
  Result: BLOCKED. Agent cannot use dynamic linker to bypass exec rules.
```

#### Approval Fatigue Attack

```
Attack: Agent floods with 100 permission requests hoping human rubber-stamps one

Rivet:
  100 permission.requested events emitted
  Your app receives them all
  No built-in rate limiting, risk scoring, or throttling
  Human sees 100 popups → clicks "approve" on #47 out of fatigue
  Result: Sensitive operation approved

Guardian:
  Request 1-3: Normal processing with risk scoring
  Request 4: Rate limit hit (3/min) → auto-denied, agent gets cooldown
  If agent retries: Exponential backoff (30s → 60s → 120s → 240s)
  If same resource: 5-minute cooldown before re-requesting
  Risk scoring: repeated requests bump risk from MEDIUM to HIGH
  Anomaly detection: flags "flood pattern" and alerts ops team
  Result: Attack mitigated by multiple layers
```

#### io_uring Bypass

```
Attack: Use io_uring to read files, bypassing openat monitoring

Rivet:
  Agent runs io_uring_setup() + io_uring_enter()
  Reads /etc/shadow via io_uring (never calls openat)
  Result: DATA LEAKED (io_uring bypasses most monitoring)
  Rivet's role: Might emit command_executed for the binary. No file-level visibility.

Guardian:
  Agent calls io_uring_setup()
  Seccomp filter: syscall 425 → returns EPERM
  Result: BLOCKED before the syscall even enters the kernel.
  io_uring cannot be used at all.
```

---

## 6. Use Case Scenarios

### 6.1 When to Use Rivet Sandbox Agent

**Building a coding agent platform (SaaS):**

You're building a product where users can choose between Claude Code, Codex, or OpenCode.
You don't want to maintain separate integrations for each.

```
Your SaaS Platform
  │
  ├── User A prefers Claude Code
  │     └── Sandbox Agent → Claude Code adapter
  │
  ├── User B prefers Codex
  │     └── Sandbox Agent → Codex adapter
  │
  └── User C prefers OpenCode
        └── Sandbox Agent → OpenCode adapter

All three use the SAME API from your platform's perspective.
```

**Building an IDE plugin:**

You want your VS Code extension to work with multiple agents:

```typescript
const client = await SandboxAgent.connect({ baseUrl, token });

// User picks their preferred agent in settings
const session = await client.createSession("task-1", {
  agent: userSettings.preferredAgent,  // "claude-code" or "codex" or "opencode"
});

// Same code regardless of agent:
await client.postMessage(session.id, { message: "Fix the failing test" });

for await (const event of client.streamEvents(session.id)) {
  if (event.type === "file_modified") {
    refreshEditor(event.path);  // works the same for any agent
  }
}
```

**Real-time collaboration:**

Multiple users watching an agent work, using Rivet Actors for persistence:

```
Rivet Actor
  ├── Stores transcript in SQLite
  ├── Broadcasts events to all connected browsers
  └── Sandbox Agent manages the Claude Code process

Browser 1 (developer): sees live code edits
Browser 2 (reviewer): sees tool calls in real-time
Browser 3 (manager): sees progress updates
```

### 6.2 When to Use Guardian Shell

**Securing untrusted agents on a Linux server:**

You're running LLM agents that could be compromised, and you need kernel-level enforcement:

```bash
# Launch agent with full sandbox
sudo guardian-launch --name untrusted-agent \
  --memory 1G --pids 50 -- python agent.py

# Agent is now running with:
# - Landlock: can only access /tmp/** and /home/user/project/**
# - Seccomp: io_uring, memfd_create, mount, namespace escape all blocked
# - eBPF: every file open, exec, and network connection monitored
# - Cgroup: limited to 1GB RAM, 50 processes
# - PR_SET_NO_NEW_PRIVS: cannot escalate via SUID
```

**Human-in-the-loop with strong anti-manipulation:**

Agent needs to access sensitive files but requires human approval:

```bash
# Agent requests permission
guardian-ctl request-permission \
  --agent coding-agent \
  --resource /etc/nginx/nginx.conf \
  --type file \
  --justification "Need to update proxy config for new API endpoint"

# Dashboard shows:
# ┌─────────────────────────────────────────────────┐
# │  ⚠ PERMISSION REQUEST — Risk: HIGH              │
# │                                                   │
# │  Agent: coding-agent                              │
# │  Resource: /etc/nginx/nginx.conf                  │
# │  Type: File Access                                │
# │  Justification: "Need to update proxy config..."  │
# │                                                   │
# │  Risk Flags:                                      │
# │    • System configuration file                    │
# │    • Outside agent's normal working directory     │
# │                                                   │
# │  ┌─────────────────┐  Wait: 5 seconds            │
# │  │  APPROVE (5s)    │  [DENY]                     │
# │  └─────────────────┘                              │
# └─────────────────────────────────────────────────┘
```

**Compliance and audit requirements:**

Every agent action must be logged with forensic detail:

```sql
-- Query the SQLite audit trail
SELECT agent_name, resource_path, risk_level, approved, reason,
       requested_at, resolved_at, grant_duration_secs
FROM permission_audit
WHERE agent_name = 'coding-agent'
  AND requested_at > datetime('now', '-24 hours')
ORDER BY requested_at DESC;

-- Anomaly detection catches:
-- "Agent coding-agent was denied /etc/shadow 5 times, then approved.
--  Possible social engineering / persistence attack."
```

### 6.3 When to Use Both Together

**Production platform with defense-in-depth:**

```
┌──────────────────────────────────────────────────────────────┐
│  Linux Server                                                 │
│                                                               │
│  Guardian Shell (kernel enforcement)                          │
│  ├── Landlock: inode-level file access                        │
│  ├── Seccomp: blocks dangerous syscalls                       │
│  ├── eBPF: monitors all operations + enforces policy          │
│  └── Cgroups: resource limits                                 │
│                                                               │
│  Inside the cgroup:                                           │
│  ┌──────────────────────────────────────────────────────┐    │
│  │  Sandbox Agent (API layer)                            │    │
│  │  ├── Provides unified HTTP API to your platform       │    │
│  │  ├── Handles session management                       │    │
│  │  ├── Normalizes events for your frontend              │    │
│  │  │                                                    │    │
│  │  │  Inside Sandbox Agent:                             │    │
│  │  │  ┌──────────────────────────────────────────┐     │    │
│  │  │  │  Claude Code (or Codex, etc.)             │     │    │
│  │  │  │  All syscalls monitored by Guardian       │     │    │
│  │  │  │  All file access controlled by Landlock   │     │    │
│  │  │  │  All execs checked by eBPF LSM            │     │    │
│  │  │  └──────────────────────────────────────────┘     │    │
│  │  └────────────────────────────────────────────────────┘    │
│  └────────────────────────────────────────────────────────────┘
│                                                               │
│  Rivet provides: unified API, session management, agent swap  │
│  Guardian provides: kernel enforcement, audit, evasion detect │
└──────────────────────────────────────────────────────────────┘
```

---

## 7. Strengths and Weaknesses

### 7.1 Rivet Sandbox Agent

**Strengths:**
- **Agent-agnostic**: Write once, run with any coding agent
- **Lightweight**: 15MB binary, no runtime dependencies, instant startup
- **Cloud-native**: Works in E2B, Vercel, Docker, Daytona out of the box
- **Simple API**: HTTP/SSE — any language can integrate
- **Session management**: Create, stream, resume sessions easily
- **Rivet Actors integration**: Persistent state, real-time broadcasting, hibernation
- **No root required**: Runs as a normal user process
- **Cross-platform friendly**: Works anywhere that runs a Linux binary
- **Active ecosystem**: TypeScript SDK, CLI, Inspector UI, OpenAPI spec
- **Agent swapping**: Switch from Claude Code to Codex with one config change

**Weaknesses:**
- **No security enforcement**: Relies entirely on host sandbox (Docker, E2B, etc.)
- **No file-level policy**: Cannot say "allow /tmp but deny /etc/shadow"
- **No syscall filtering**: Cannot block io_uring, memfd_create, mount, etc.
- **No evasion detection**: Symlinks, TOCTOU, dynamic linker bypasses not addressed
- **No risk scoring**: Permission events have no risk classification
- **No rate limiting**: Agent can flood with permission requests
- **No anomaly detection**: Rubber-stamping patterns not tracked
- **No persistent audit trail**: Events are ephemeral (consumer must store them)
- **No kernel-level visibility**: Cannot see what syscalls the agent actually makes
- **Single point of failure**: If the Sandbox Agent process crashes, session is lost

### 7.2 Guardian Shell

**Strengths:**
- **Kernel-level enforcement**: Attacks blocked before they can succeed
- **7-layer defense-in-depth**: Landlock + seccomp + eBPF + cgroup + approval + rate limit + anomaly
- **Symlink-immune**: Landlock operates on inodes, not path strings
- **Fine-grained policy**: Per-file, per-binary, per-port rules
- **Evasion detection**: Dynamic linker, memfd, io_uring, rename attacks all covered
- **Human approval hardening**: Risk scoring, mandatory wait timers, justification analysis
- **Persistent audit trail**: SQLite with anomaly detection queries
- **Agent-agnostic at kernel level**: Monitors any Linux process regardless of implementation
- **Resource limits**: Cgroup v2 memory, PID, CPU enforcement
- **Real-time dashboard**: Built-in web UI with live event streaming

**Weaknesses:**
- **Requires root**: eBPF and cgroups need elevated privileges
- **Linux-only**: eBPF and Landlock are Linux kernel features
- **Kernel version requirements**: Landlock needs 5.13+, bpf_d_path needs 5.11+
- **Not cloud-native**: Designed for bare metal / VM, not serverless
- **No multi-agent API**: Each agent managed independently, no unified HTTP API
- **No session management**: Doesn't track agent sessions or conversations
- **No agent swapping**: Doesn't abstract away agent protocol differences
- **Complex deployment**: Requires kernel configuration (CONFIG_BPF_LSM, cgroup v2)
- **x86_64 focused**: Tracepoint offsets hardcoded for x86_64 architecture
- **No SDK**: No TypeScript/Python SDK for programmatic agent control

---

## 8. Can They Work Together?

Yes, and it makes a lot of sense for production deployments. Here's a concrete example:

### Architecture for a Coding Agent Platform

```
┌─────────────────────────────────────────────────────────────┐
│  Your Platform Backend (Node.js / Python / Go)               │
│                                                              │
│  Uses Rivet TypeScript SDK to:                               │
│    - Create sessions for users                               │
│    - Stream agent events to frontend                         │
│    - Handle agent swapping (Claude Code ↔ Codex)             │
│    - Manage session lifecycle                                │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTP / SSE
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Linux VM (your infrastructure)                              │
│                                                              │
│  Guardian Shell daemon (root, always running)                │
│  ├── Monitors all agent cgroups                              │
│  ├── Enforces file/exec/network policy per agent             │
│  ├── Sends alerts on suspicious activity                     │
│  └── Provides audit trail for compliance                     │
│                                                              │
│  Per-user agent launch:                                      │
│  guardian-launch --name user-123-agent -- \                   │
│    sandbox-agent server --token $TOKEN --port $PORT          │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Cgroup: guardian/user-123-agent-45678                  │ │
│  │  Landlock: allow /home/user-123/project/**, /tmp/**     │ │
│  │  Seccomp: io_uring, memfd, mount, namespace blocked     │ │
│  │                                                         │ │
│  │  Sandbox Agent (port $PORT)                             │ │
│  │  └── Claude Code (subprocess)                           │ │
│  │      Every syscall monitored + enforced by Guardian     │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### What Each Layer Provides

| Concern | Handled By |
|---------|-----------|
| "Which agent to use?" | Rivet (agent selection via config) |
| "How to talk to the agent?" | Rivet (unified HTTP/SSE API) |
| "How to manage sessions?" | Rivet (session create/stream/complete) |
| "Can the agent read /etc/shadow?" | Guardian (Landlock + eBPF = NO) |
| "Can the agent run curl?" | Guardian (exec policy + seccomp) |
| "Can the agent connect to port 22?" | Guardian (eBPF + Landlock TCP) |
| "Is the agent using symlinks to bypass?" | Guardian (Landlock inode detection) |
| "Should a human approve this?" | Guardian (risk scoring + approval flow) |
| "Is someone rubber-stamping approvals?" | Guardian (anomaly detection) |
| "What did the agent do last week?" | Guardian (SQLite audit trail) |
| "Show me live progress" | Rivet (normalized event stream) |

---

## 9. Summary

### One Sentence Each

- **Rivet Sandbox Agent**: "A universal remote control for coding agents."
- **Guardian Shell**: "A kernel-level security cage for any Linux process."

### Decision Matrix

| If you need... | Use |
|---------------|-----|
| One API for multiple coding agents | Rivet |
| Kernel-level file/exec/network blocking | Guardian |
| Session management and event streaming | Rivet |
| Symlink/TOCTOU/io_uring attack prevention | Guardian |
| Cloud-native deployment (E2B, Vercel) | Rivet |
| Bare metal / VM security enforcement | Guardian |
| Human approval with risk scoring | Guardian |
| Agent protocol abstraction | Rivet |
| Compliance audit trail | Guardian |
| Quick integration (no root needed) | Rivet |
| Both API convenience AND kernel security | **Both together** |

### The Fundamental Difference

Rivet asks: **"How do I control agents?"** (developer experience)

Guardian asks: **"How do I stop agents from doing dangerous things?"** (security enforcement)

They are complementary tools solving different halves of the same problem.
In a production system, you likely want both: Rivet for the developer-facing API,
Guardian for the security enforcement underneath.
