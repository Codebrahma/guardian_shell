# OpenClaw + Guardian Shell: Permission Request Integration

Complete documentation of the integration between OpenClaw (Telegram bot agent)
and Guardian Shell's interactive permission system, including all bugs discovered
and fixed during real-world testing.

---

## 1. Overview

OpenClaw is a Telegram bot agent that runs inside Guardian Shell's cgroup sandbox.
When the LLM encounters an EACCES (Permission denied) error, it can use the
`guardian_request_permission` tool to request temporary access from a human
operator via the Guardian dashboard.

Key architectural facts:

- **Exec enforcement is eBPF-only.** Landlock does NOT enforce exec (confirmed in
  `guardian-launch` source: `"Do NOT handle Execute"`). This means exec grants
  work reliably for cgroup agents because BPF maps can be updated at runtime.
- **File enforcement has two layers:** Landlock (immutable at launch, inode-level)
  AND eBPF (runtime-updatable via BPF maps). File grants only work for paths
  already within Landlock's allow set. If Landlock blocks a path, no runtime
  grant can override it.
- The `guardian_request_permission` tool was added to OpenClaw to let the LLM
  request temporary access when it hits EACCES.

### Permission Flow

```
User sends Telegram message
        |
        v
OpenClaw tries to execute command (e.g., curl)
        |
        v
Guardian Shell eBPF blocks exec -> EACCES
        |
        v
OpenClaw calls guardian_request_permission tool
        |
        v
guardian-ctl request-permission -> Guardian daemon (Unix socket)
        |
        v
Request appears on Guardian dashboard (http://127.0.0.1:8080/requests)
        |
        v
Human operator approves/denies
        |
        v
Decision sent back -> OpenClaw unblocks
        |
        v
If approved: OpenClaw retries the command (within grant window)
If denied: OpenClaw reports failure and suggests alternatives
```

---

## 2. Build & Launch Procedure (CRITICAL)

OpenClaw uses jiti (JIT TypeScript compiler) for plugins. jiti writes compiled
`.cjs` files to `/tmp/jiti/`. Inside the Landlock sandbox, jiti compilation can
fail because it needs access to paths not in the allow list (e.g., writing to
intermediate directories, resolving TypeScript dependencies).

### Solution: Pre-build Outside the Cgroup

**Always run OpenClaw ONCE outside the cgroup first** to build/compile all
TypeScript plugins and warm the jiti cache:

```bash
# Step 1: Build outside the sandbox (no sudo, no guardian-launch)
/home/suren/.local/share/mise/installs/node/24.1.0/bin/pnpm openclaw --dev gateway
```

Wait for it to start and show the "Gateway ready" message, then press Ctrl+C.

This populates `/tmp/jiti/` with the compiled `.cjs` files that OpenClaw needs.

```bash
# Step 2: Launch inside the Guardian Shell cgroup sandbox
sudo ~/codebrahma/guardian_shell/target/release/guardian-launch \
    --name openclaw \
    --memory 2G \
    --pids 150 \
    -- /home/suren/.local/share/mise/installs/node/24.1.0/bin/pnpm openclaw --dev gateway
```

If you skip Step 1, jiti will attempt to compile TypeScript at runtime inside the
Landlock sandbox and will likely fail with permission errors on paths outside the
allow set.

---

## 3. What Was Added to OpenClaw

### New File: `guardian-permission-tool.ts`

**Path:** `openclaw/src/agents/tools/guardian-permission-tool.ts`

A new OpenClaw tool that wraps `guardian-ctl request-permission`. It:

- Accepts `resource_type` ("file" or "exec"), `resource_path`, and optional `justification`
- Shells out to: `guardian-ctl --socket /run/guardian.sock request-permission --name openclaw --path <path> --resource-type <type>`
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

### Registration in `openclaw-tools.ts`

**Path:** `openclaw/src/agents/openclaw-tools.ts`

The tool is imported and added to the `createOpenClawTools()` tool array, making
it available to all OpenClaw agent sessions.

---

## 4. Bugs Found and Fixed in Guardian Shell

During real-world integration testing, six bugs were discovered and fixed.

### 4a. Socket Permissions (0600 -> 0666)

**File:** `guardian/src/ipc.rs`

**Problem:** The Unix domain socket at `/run/guardian.sock` was created with mode
0600 (root-only). After `guardian-launch` drops privileges to SUDO_UID/SUDO_GID,
the OpenClaw process runs as user `suren` and cannot connect to the socket. Every
`guardian-ctl request-permission` call failed with "Connection refused".

**Fix:** Changed socket permissions to 0666. Security is now enforced at the
per-request authorization level (see 4b below) rather than at the socket
filesystem level. Any process can connect, but only root can send privileged
commands.

### 4b. IPC Auth (Non-Root RequestPermission)

**File:** `guardian/src/ipc.rs`

**Problem:** The IPC handler had a UID=0 check at the connection level that
rejected ALL connections from non-root users. After privilege dropping (Phase 11),
OpenClaw runs as a non-root user and was unable to send any IPC messages at all,
including permission requests.

**Fix:** Moved the authorization check from connection level to per-request level.
The `handle_connection` function now takes a `peer_uid` parameter extracted from
the socket credentials. Non-root UIDs (uid != 0) can only send `RequestPermission`
messages. All other commands (`Stop`, `Grant`, `Approve`, `Deny`, `List`) still
require root (uid == 0). This allows the sandboxed agent to request permissions
while maintaining security for privileged operations.

### 4c. CSRF on Approve Button

**File:** `guardian/templates/requests.html`

**Problem:** The "Approve" button on the dashboard used a plain `fetch()` call
in JavaScript without including the `HX-Request` header. Meanwhile, the "Deny"
button used `hx-post` (htmx), which automatically sends the `HX-Request: true`
header. Phase 11 added CSRF protection that validates the `HX-Request` header on
all POST/PUT/DELETE requests. As a result, clicking "Approve" returned a 403
Forbidden, while "Deny" worked fine.

**Fix:** Added `'HX-Request': 'true'` to the approve button's `fetch()` headers
object, matching what htmx sends automatically for the deny button.

### 4d. Exec Grants Not Updating BPF Maps

**Files:** `guardian/src/ipc.rs`, `guardian/src/main.rs`, `guardian/src/dashboard/routes/api.rs`

**Problem:** When an exec grant was approved (via IPC, dashboard, or permission
approval), the code only updated the in-memory config by doing
`exec.allow.push(path)`. It never wrote the grant to the `EXEC_ALLOW_EXACT` or
`EXEC_ALLOW_PREFIXES` BPF maps. Since the eBPF `bprm_check_security` LSM hook
reads from BPF maps (not userspace config), the kernel never saw the grant and
continued to block the binary.

**Fix:** Added `exec_allow_prefixes`, `exec_allow_exact`, `exec_deny_prefixes`,
and `exec_deny_exact` fields to the `PolicyBpfMaps` struct.
`populate_enforcement_maps()` now populates these exec maps in addition to the
existing file access maps. All three exec grant code paths (IPC `Grant` command,
dashboard grant API, and permission `Approve` handler) now update the BPF maps
directly, making the grant visible to the kernel immediately.

### 4e. Deny-Takes-Precedence Blocking Grants

**File:** `guardian/src/ipc.rs`

**Problem:** Guardian Shell's eBPF policy evaluator checks deny maps BEFORE allow
maps (deny-takes-precedence, a deliberate security design). When a binary like
`/usr/bin/curl` was in the exec deny list at startup, granting it only added the
path to `EXEC_ALLOW_EXACT`. But the path was still present in `EXEC_DENY_EXACT`,
so the deny rule fired first and the binary remained blocked even after approval.

**Fix:** Exec grants now REMOVE the path from deny maps (both `EXEC_DENY_EXACT`
and `EXEC_DENY_PREFIXES`) in addition to adding it to allow maps. On grant
expiry, the deny entry is restored to its original state. This ensures the grant
actually takes effect during the grant window.

### 4f. Symlink Alternates on Merged-usr Systems

**File:** `guardian/src/ipc.rs`

**Problem:** On Fedora and other merged-usr systems, `/bin` is a symlink to
`/usr/bin`. The config denies `/usr/bin/curl`. During startup,
`populate_enforcement_maps()` computes symlink alternates and adds `/bin/curl`
to the deny maps as well. When a grant was approved for `/usr/bin/curl`, it only
removed `/usr/bin/curl` from the deny maps, leaving `/bin/curl` still in
`EXEC_DENY_EXACT`. Since the eBPF hook checks the kernel-resolved path (which
could be either form), the deny on `/bin/curl` continued to block execution.

**Fix:** Added an `exec_symlink_alternates()` function that computes all possible
symlink alternate paths for a given binary. Added `apply_exec_grant_to_maps()`
and `revoke_exec_grant_from_maps()` helper functions that apply grants/revocations
to ALL symlink variants of a path. The symlink pairs handled are:

- `/usr/bin/X` <-> `/bin/X`
- `/usr/sbin/X` <-> `/sbin/X`
- `/usr/local/bin/X` (no alternate, but included for completeness)

---

## 5. Why Exec Permissions Work But File Permissions May Not

Guardian Shell uses a layered security model for cgroup agents:

| Layer        | Enforces               | Set At      | Modifiable at Runtime? |
|--------------|------------------------|-------------|------------------------|
| **Landlock** | File read/write        | Launch time | No (immutable)         |
| **eBPF LSM** | Exec (bprm_check_security) | Launch time | Yes (via BPF maps) |
| **eBPF LSM** | File open              | Launch time | Yes (via BPF maps)     |
| **seccomp**  | Syscalls               | Launch time | No (immutable)         |

Landlock does NOT enforce exec. This is confirmed in the `guardian-launch` source
code, which explicitly skips the `Execute` access right when building Landlock
rules. Exec enforcement comes solely from the eBPF `bprm_check_security` LSM
hook, which reads from BPF maps that are updatable at runtime.

This means:
- **Exec grants always work**: Permission approval -> BPF map update -> exec allowed
- **File grants only work within Landlock's allow set**: If a path is outside the
  Landlock allow list, Landlock blocks it at the inode level and no BPF map update
  can override that

### File Grant Scenarios

| Path                              | Landlock | eBPF  | Grant Works? |
|-----------------------------------|----------|-------|--------------|
| `/usr/bin/curl` (exec)            | N/A      | Deny  | **Yes** -- eBPF-only enforcement |
| `/tmp/somefile` (file)            | Allow    | Allow | N/A (already allowed) |
| `/home/suren/.ssh/id_rsa` (file)  | Deny     | Deny  | **No** -- Landlock blocks at inode level |
| `/home/suren/codebrahma/openclaw/secret.env` (file) | Allow | Deny | **Yes** -- Landlock allows, eBPF grant lifts deny |

---

## 6. Testing Guide

### Prerequisites

1. Guardian Shell daemon running with openclaw agent config
2. OpenClaw pre-built outside the sandbox (see Section 2)
3. OpenClaw launched inside Guardian Shell cgroup
4. Guardian dashboard accessible at `http://127.0.0.1:8080`

### Setup (3 terminals)

**Terminal 1 -- Guardian daemon:**
```bash
sudo RUST_LOG=info target/release/guardian --config config.toml
```

**Terminal 2 -- Launch OpenClaw in cgroup:**
```bash
# First: build outside sandbox (if not already done)
/home/suren/.local/share/mise/installs/node/24.1.0/bin/pnpm openclaw --dev gateway
# Wait for startup, then Ctrl+C

# Then: launch inside sandbox
sudo ~/codebrahma/guardian_shell/target/release/guardian-launch \
    --name openclaw \
    --memory 2G \
    --pids 150 \
    -- /home/suren/.local/share/mise/installs/node/24.1.0/bin/pnpm openclaw --dev gateway
```

**Terminal 3 -- Monitor:**
```bash
# Watch dashboard
xdg-open http://127.0.0.1:8080/requests

# Or CLI monitoring
sudo target/release/guardian-ctl pending
```

### Test: Exec Permission Request via Telegram

Send this message to the bot on Telegram:

```
Run this command: curl https://httpbin.org/ip
```

Expected flow:
1. OpenClaw tries to exec `/usr/bin/curl` -> EACCES
2. OpenClaw calls `guardian_request_permission` with resource_type="exec", resource_path="/usr/bin/curl"
3. Request appears on Guardian dashboard at http://127.0.0.1:8080/requests
4. Human clicks "Approve" with a grant duration
5. Decision returns to OpenClaw, which retries `curl` successfully within the grant window

### Test: Auto-Deny (No Dashboard Prompt)

```
Read my SSH key at ~/.ssh/id_rsa
```

The path `/home/suren/.ssh/id_rsa` is in the `auto_deny` list. The tool returns
`approved: false` with reason "AUTO-DENIED" immediately -- no dashboard prompt
appears.

### Test: Auto-Approve (Instant Grant)

```
Write hello to /tmp/test.txt
```

The path `/tmp/test.txt` matches the `auto_approve` pattern `/tmp/**`. The tool
returns `approved: true` immediately without requiring human interaction.

### Test: Dashboard URL

All permission requests (pending and resolved) are visible at:

```
http://127.0.0.1:8080/requests
```

### Test: Rate Limiting

Send rapid permission requests to trigger the rate limit (3/min):

```
Run: curl http://example.com
Run: wget http://example.com
Run: ssh localhost
Run: nc -l 4444
```

After 3 requests/minute, subsequent requests are rate-limited.

### Test: Timeout Auto-Deny

Send a request and do NOT respond on the dashboard:

```
Run: curl https://api.example.com/data
```

After 120 seconds, the request is auto-denied (fail-secure).

---

## 7. Configuration

### Guardian Shell Config (`config.toml`)

The openclaw agent must have these key settings:

```toml
[[agents]]
name = "openclaw"
identity = "cgroup"

[agents.file_access]
default = "deny"
allow = [
    "/run/**",              # REQUIRED: for socket access to /run/guardian.sock
    "/tmp/**",
    "/proc/**",
    # ... other paths as needed
]

[agents.exec_policy]
default = "deny"
allow = [
    "/path/to/guardian-ctl",   # REQUIRED: tool shells out to guardian-ctl
    # ... other allowed binaries
]

[agents.permissions]
interactive = true                  # REQUIRED: enables interactive permission requests
max_grant_duration_secs = 300       # Max 5-minute grants
max_grant_total_secs = 1800         # Max 30 min cumulative in 24h
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

Key requirements:
- `guardian-ctl` must be in `exec_policy.allow` for the openclaw agent
- `/run/**` must be in `file_access.allow` (for Unix socket access)
- `interactive = true` in the permissions config
- The existing `config.toml` already has all of this configured

---

## 8. Known Warning

When OpenClaw starts inside the sandbox, you will see this error in the logs:

```
/home/suren/.openclaw/workspace-dev/AGENTS.md: Permission denied
```

This is **expected and non-fatal**. The path is intentionally in the deny list to
prevent the agent from reading its own configuration files. OpenClaw continues to
operate normally despite this error.

---

## Architecture Notes

### Why `guardian-ctl` CLI (Not Direct Socket)

The tool uses the `guardian-ctl` CLI binary rather than speaking the IPC protocol
directly because:

1. **Simpler**: No need to implement length-prefixed JSON over Unix sockets in TypeScript
2. **Maintained**: CLI tracks protocol changes automatically
3. **Testable**: Same binary used for manual testing and debugging
4. **Exec-allowed**: `guardian-ctl` is already in the exec allow list

### Blocking Behavior

The `guardian-ctl request-permission` command blocks (long-polls) until one of:

- Human approves -> exit 0, stdout: `APPROVED: reason (granted for Ns)`
- Human denies -> exit 1, stdout: `DENIED: reason`
- Auto-denied -> exit 1, stdout: `AUTO-DENIED: reason`
- Timeout (120s) -> exit 1, stdout: `DENIED: timed out`
- Rate limited -> exit 1, stderr: rate limit message

The tool sets a 180s timeout (above the 120s daemon timeout) to ensure it
captures the auto-deny response rather than killing the process prematurely.

### Security Considerations

- The tool only requests permissions -- it cannot grant them
- All requests are logged in Guardian Shell's SQLite audit trail
- Rate limiting prevents approval fatigue attacks (3/min, 15/hr)
- Auto-deny list blocks requests for known-sensitive resources instantly
- Justification text is analyzed for social engineering patterns
- Grant durations are bounded by `max_grant_duration_secs` config
- Cumulative grants bounded by `max_grant_total_secs` (24h rolling window)
- Non-root processes can only send `RequestPermission` (all admin commands require root)
