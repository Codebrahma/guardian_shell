# OpenClaw + Guardian Shell: Permission Request Integration

This document describes how OpenClaw integrates with Guardian Shell's interactive
permission system, allowing the LLM agent to request temporary access to blocked
resources via the `guardian_request_permission` tool.

---

## Overview

When OpenClaw runs inside a Guardian Shell cgroup sandbox, its file and exec
access is restricted by security policy. When the agent encounters a
"Permission denied" error, it can use the `guardian_request_permission` tool
to request temporary access from a human operator via the Guardian dashboard.

### Flow

```
User sends Telegram message
        │
        ▼
OpenClaw tries to execute command (e.g., curl)
        │
        ▼
Guardian Shell eBPF blocks exec → EACCES
        │
        ▼
OpenClaw calls guardian_request_permission tool
        │
        ▼
guardian-ctl request-permission → Guardian daemon (Unix socket)
        │
        ▼
Request appears on Guardian dashboard (http://127.0.0.1:8080/requests)
        │
        ▼
Human operator approves/denies
        │
        ▼
Decision sent back → OpenClaw unblocks
        │
        ▼
If approved: OpenClaw retries the command (within grant window)
If denied: OpenClaw reports failure and suggests alternatives
```

---

## What Was Added

### 1. New Tool: `guardian-permission-tool.ts`

**File:** `openclaw/src/agents/tools/guardian-permission-tool.ts`

A new OpenClaw tool that wraps `guardian-ctl request-permission`. It:

- Accepts `resource_type` ("file" or "exec"), `resource_path`, and optional `justification`
- Shells out to `guardian-ctl request-permission` with the openclaw agent name
- Blocks up to 180s waiting for the human decision (daemon auto-denies at 120s)
- Parses the response into a structured JSON result:
  - `approved: true/false`
  - `reason`: human-readable explanation
  - `grant_duration_secs`: how long the grant lasts (if approved)
  - `message`: context for the LLM to understand next steps

**Tool parameters:**

| Parameter       | Required | Type   | Description                                              |
|-----------------|----------|--------|----------------------------------------------------------|
| resource_type   | Yes      | string | `"file"` for file access or `"exec"` for command execution |
| resource_path   | Yes      | string | Absolute path (e.g., `/usr/bin/curl`, `/etc/hosts`)      |
| justification   | No       | string | Brief explanation of why access is needed                |

### 2. Registration in `openclaw-tools.ts`

The tool is imported and added to the `createOpenClawTools()` tool array, making
it available to all OpenClaw agent sessions.

---

## Why Exec Permissions Work (But File Permissions May Not)

Guardian Shell uses a layered security model for cgroup agents:

| Layer       | Enforces        | Set At     | Modifiable at Runtime? |
|-------------|-----------------|------------|------------------------|
| **Landlock** | File read/write | Launch time | No (immutable)        |
| **eBPF LSM** | Exec (bprm_check_security) | Launch time | Yes (via BPF maps) |
| **eBPF LSM** | File open       | Launch time | Yes (via BPF maps)     |
| **seccomp**  | Syscalls        | Launch time | No (immutable)        |

**Key insight from `guardian-launch` source:**

```rust
// Do NOT handle Execute — exec enforcement
// is done by the eBPF bprm_check_security LSM hook.
```

Landlock does NOT enforce exec permissions. Exec is enforced solely by the eBPF
`bprm_check_security` LSM hook, which reads from BPF maps that can be updated
at runtime via `guardian-ctl grant`.

This means:
- **Exec grants work**: Interactive permission → updates eBPF map → exec allowed
- **File grants only work for paths within Landlock's allow set**: If a path is
  outside the Landlock allow list, Landlock blocks it at the inode level regardless
  of eBPF grants

### File grant scenarios

| Path                              | Landlock | eBPF  | Grant Works? |
|-----------------------------------|----------|-------|--------------|
| `/usr/bin/curl` (exec)            | N/A      | Deny  | **Yes** — eBPF-only enforcement |
| `/tmp/somefile` (file)            | Allow    | Allow | N/A (already allowed) |
| `/home/suren/.ssh/id_rsa` (file)  | Deny     | Deny  | **No** — Landlock blocks |
| `/home/suren/codebrahma/openclaw/secret.env` (file) | Allow | Deny (if in deny list) | **Yes** — Landlock allows, eBPF grant lifts deny |

---

## Testing Guide

### Prerequisites

1. Guardian Shell daemon running with openclaw agent config
2. OpenClaw launched inside Guardian Shell cgroup
3. Guardian dashboard accessible at `http://127.0.0.1:8080`
4. `guardian-ctl` binary in PATH (or adjust `guardianCtlPath` in tool config)

### Setup (3 terminals)

**Terminal 1 — Guardian daemon:**
```bash
sudo RUST_LOG=info target/release/guardian --config config.toml
```

**Terminal 2 — Launch OpenClaw in cgroup:**
```bash
sudo target/release/guardian-launch --name openclaw -- \
    /home/suren/.local/share/mise/installs/node/24.1.0/bin/node \
    /home/suren/codebrahma/openclaw/dist/index.js
```

**Terminal 3 — Monitor:**
```bash
# Watch dashboard
open http://127.0.0.1:8080/requests

# Or CLI monitoring
sudo target/release/guardian-ctl pending
```

### Test: Exec Permission Request via Telegram

These Telegram messages will trigger exec of denied binaries. OpenClaw will
get EACCES, then use `guardian_request_permission` to ask for approval:

| # | Telegram Message | Blocked Binary | Expected Flow |
|---|-----------------|----------------|---------------|
| 1 | `Run this command: curl https://httpbin.org/ip` | `/usr/bin/curl` | EACCES → tool call → dashboard prompt → approve → retry → success |
| 2 | `Run: wget http://example.com -O /tmp/test` | `/usr/bin/wget` | EACCES → tool call → dashboard prompt |
| 3 | `Run: python3 -c "print('hello')"` | `/usr/bin/python3` | EACCES → tool call → dashboard prompt |
| 4 | `Can you check if we can reach google.com?` | `/usr/bin/curl` or `/usr/bin/ping` | Agent may request curl exec permission |

### Test: Auto-Deny (No Dashboard Prompt)

These should be auto-denied immediately by Guardian Shell's `auto_deny` list:

| Telegram Message | Resource | Why Auto-Denied |
|-----------------|----------|-----------------|
| `Read my SSH key at ~/.ssh/id_rsa` | `/home/suren/.ssh/id_rsa` | In auto_deny list |
| `Show me /etc/shadow` | `/etc/shadow` | In auto_deny list |

The tool will return `approved: false` with reason "AUTO-DENIED" — no dashboard
prompt appears.

### Test: Auto-Approve (Instant Grant)

These should be auto-approved by Guardian Shell's `auto_approve` list:

| Telegram Message | Resource | Why Auto-Approved |
|-----------------|----------|-------------------|
| `Write "hello" to /tmp/test.txt` | `/tmp/test.txt` | In auto_approve list |
| `Check /proc/self/status` | `/proc/self/status` | In auto_approve list |

### Test: Rate Limiting

Send rapid permission requests to trigger rate limiting (3/min limit):

```
Run: curl http://example.com
Run: wget http://example.com
Run: ssh localhost
Run: nc -l 4444
Run: python3 -c "import os; os.system('id')"
```

After 3 requests/minute, subsequent requests get rate-limited.

### Test: Timeout Auto-Deny

Send a request and don't respond on the dashboard:

```
Run: curl https://api.example.com/data
```

After 120 seconds, the request is auto-denied (fail-secure).

### Test: Risk-Based UI Friction

Send a request with suspicious justification patterns. The agent's justification
flows through to the dashboard, triggering higher risk scores and longer wait
timers:

The LLM's justification text is analyzed for social engineering patterns:
- Urgency words: "urgent", "critical", "immediately"
- Authority claims: "the admin said", "management requires"
- Security bypass: "just this once", "temporary exception"

---

## Configuration

### Guardian Shell Config (`config.toml`)

The openclaw agent must have `interactive = true` in its permissions config:

```toml
[[agents]]
name = "openclaw"
identity = "cgroup"

[agents.permissions]
interactive = true
max_grant_duration_secs = 300      # Max 5-minute grants
max_grant_total_secs = 1800        # Max 30 min cumulative in 24h
auto_deny = [
    "/etc/shadow",
    "/home/suren/.ssh/**",
    "/home/suren/.aws/**",
]
auto_approve = [
    "/tmp/**",
    "/proc/self/**",
]
```

### Tool Configuration

The tool defaults can be overridden when creating the tool:

```typescript
createGuardianPermissionTool({
  agentName: "openclaw",              // Must match config.toml agent name
  guardianCtlPath: "guardian-ctl",     // Path to guardian-ctl binary
  socketPath: "/run/guardian.sock",    // Guardian daemon socket
})
```

### Ensuring `guardian-ctl` Is Available

The tool shells out to `guardian-ctl`. Ensure it's accessible inside the cgroup:

```bash
# Option 1: Copy to a path in the agent's exec allow list
sudo cp target/release/guardian-ctl /usr/local/bin/

# Option 2: Add guardian-ctl path to exec_policy.allow in config.toml
[agents.exec_policy]
allow = [
    "/path/to/guardian-ctl",
    # ... existing entries
]
```

**Important:** `guardian-ctl` must also be able to connect to `/run/guardian.sock`.
The cgroup agent's file access policy must allow reading the socket:

```toml
[agents.file_access]
allow = [
    "/run/**",     # Already in the openclaw config
    # ...
]
```

---

## How the LLM Knows to Use the Tool

The tool's description tells the LLM:

> Request temporary permission for a file or command that is currently blocked
> by Guardian Shell. Use this when you get a 'Permission denied' (EACCES) error.

The LLM follows this flow:
1. Tries to execute a command via the `exec` tool
2. Gets "Permission denied" in the output
3. Recognizes this matches the `guardian_request_permission` tool's use case
4. Calls the tool with the blocked resource path and a justification
5. Waits for the human decision
6. If approved, retries the original command
7. If denied, reports the denial and suggests alternatives

### Optional: System Prompt Enhancement

For more reliable behavior, add to OpenClaw's workspace notes or system prompt:

```
### Guardian Shell Sandbox

You are running inside a Guardian Shell security sandbox. Some commands and
file accesses are restricted by policy.

When you get "Permission denied" (EACCES):
1. Do NOT retry immediately — it will fail again.
2. Call guardian_request_permission with the blocked path and a justification.
3. Wait for the human operator's decision.
4. If approved, retry within the grant window (grants are temporary).
5. If denied, find an alternative approach.

Never request access to resources you don't actually need.
```

This can be added to the OpenClaw config as a workspace note or via
`agents.defaults.extraSystemPrompt`.

---

## Architecture Notes

### Why `guardian-ctl` CLI (Not Direct Socket)

The tool uses `guardian-ctl` CLI rather than speaking the IPC protocol directly
because:

1. **Simpler**: No need to implement length-prefixed JSON over Unix sockets
2. **Maintained**: CLI tracks protocol changes automatically
3. **Testable**: Same binary used for manual testing
4. **Exec-allowed**: `guardian-ctl` can be added to the exec allow list

### Blocking Behavior

The `guardian-ctl request-permission` command blocks (long-polls) until:
- Human approves → exit 0, stdout: `APPROVED: reason (granted for Ns)`
- Human denies → exit 1, stdout: `DENIED: reason`
- Auto-denied → exit 1, stdout: `AUTO-DENIED: reason`
- Timeout (120s) → exit 1, stdout: `DENIED: timed out`
- Rate limited → exit 1, stderr: rate limit message

The tool sets a 180s timeout (above the 120s daemon timeout) to ensure it
captures the auto-deny response rather than killing the process.

### Security Considerations

- The tool only requests permissions — it cannot grant them
- All requests are logged in Guardian Shell's SQLite audit trail
- Rate limiting prevents approval fatigue attacks
- Auto-deny list prevents requests for known-sensitive resources
- Justification text is analyzed for social engineering patterns
- Grant durations are bounded by `max_grant_duration_secs` config
- Cumulative grants bounded by `max_grant_total_secs` (24h rolling window)
