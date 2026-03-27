# Security Fixes

## Overview

A comprehensive security audit identified vulnerabilities across the Guardian Shell codebase. This document describes each fix implemented, its severity, and the files changed. Fixes are organized into 6 categories: IPC hardening, authentication hardening, input validation, injection prevention, SSRF prevention, and supply chain integrity.

All changes compile with zero errors and zero warnings. All 25 existing tests pass.

---

## 1. IPC Socket Authentication (CRITICAL)

**Problem:** The Unix socket at `/run/guardian.sock` accepted connections from any local process. An unprivileged user could connect and send commands to register fake agents, grant access, approve permissions, or stop agents.

**Fix:** Added `SO_PEERCRED` peer credential verification using `tokio::net::UnixStream::peer_cred()`. Only connections from UID 0 (root) are accepted. All others are rejected with a warning log.

```rust
match stream.peer_cred() {
    Ok(cred) => {
        if cred.uid() != 0 {
            warn!("IPC connection rejected: peer UID {} is not root", cred.uid());
            continue;
        }
    }
    Err(e) => {
        warn!("IPC connection rejected: failed to get peer credentials: {}", e);
        continue;
    }
}
```

**Files changed:**
- `guardian/src/ipc.rs` — Peer credential check in `start_ipc_server()`

---

## 2. IPC Socket Permissions (MEDIUM)

**Problem:** Socket was created with mode `0o660` (rw-rw----), allowing any user in the same group to connect.

**Fix:** Changed to `0o600` (rw-------), restricting access to the socket owner (root) only.

**Files changed:**
- `guardian/src/ipc.rs` — `set_permissions()` call

---

## 3. IPC Connection Rate Limiting (MEDIUM)

**Problem:** Every connection spawned an unbounded tokio task. An attacker could open thousands of connections to exhaust memory and CPU.

**Fix:** Added `tokio::sync::Semaphore` with `MAX_IPC_CONNECTIONS = 64`. Connections exceeding the limit are rejected immediately with a warning log. The semaphore permit is released when the connection handler completes.

**Files changed:**
- `guardian/src/ipc.rs` — Semaphore in `start_ipc_server()`

---

## 4. Cgroup Path Traversal Prevention (CRITICAL)

**Problem:** The `cgroup_path` field in IPC registration requests was only validated for null bytes. A malicious launcher could send `cgroup_path = "../../tmp/evil"`, causing the daemon to read PIDs from an arbitrary file and send SIGTERM to them.

**Fix:** Added two new validation rules in `validate_request()`:
- Reject paths containing `..` (path traversal)
- Reject absolute paths starting with `/` (cgroup paths must be relative to `/sys/fs/cgroup/`)

**Files changed:**
- `guardian/src/ipc.rs` — `validate_request()` Register variant

---

## 5. PID Validation Before kill() (MEDIUM)

**Problem:** PIDs read from cgroup.procs were passed to `libc::kill()` without validation. In POSIX, negative PIDs have special semantics: `kill(-1, SIGTERM)` sends SIGTERM to ALL processes.

**Fix:** Added `pid > 0` check before calling `kill()`. Invalid PIDs are logged and skipped.

**Files changed:**
- `guardian/src/ipc.rs` — `handle_stop_agent()`

---

## 6. Grant Type Validation (MEDIUM)

**Problem:** The `grant_type` field was a free-form string compared with `if grant_type == "exec"`. Typos like `"execution"` or `"EXEC"` silently fell through to file access grant instead of being rejected.

**Fix:** Added validation in `validate_request()` that rejects any `grant_type` other than `"file"` or `"exec"`.

**Files changed:**
- `guardian/src/ipc.rs` — `validate_request()` GrantAccess variant

---

## 7. Resource Path & Justification Validation (MEDIUM)

**Problem:** Resource paths in GrantAccess and RequestPermission were validated for length only, not content. Null bytes could cause C string truncation in downstream operations. Justification text could contain control characters used to manipulate logs.

**Fix:**
- Added null byte validation for `path` in GrantAccess
- Added null byte validation for `resource_path` in RequestPermission
- Added control character validation for justification text (allows `\n` and `\t` only)

**Files changed:**
- `guardian/src/ipc.rs` — `validate_request()` GrantAccess and RequestPermission variants

---

## 8. Error Message Sanitization (LOW)

**Problem:** IPC error responses included raw BPF map error strings (e.g., `"Failed to update WATCHED_CGROUPS map: ENOSPC"`), leaking implementation details to clients.

**Fix:** Error details are now logged server-side at `error!` level, while the client receives a generic error message: `"Internal error: failed to register agent for monitoring"`.

**Files changed:**
- `guardian/src/ipc.rs` — `handle_register()` BPF map error handling

---

## 9. Constant-Time Token Comparison (HIGH)

**Problem:** Dashboard auth token comparison used `==` (standard string equality), which short-circuits on first mismatched byte. An attacker can measure response timing to deduce token characters one-by-one.

**Fix:** Implemented `constant_time_eq()` using XOR-based comparison that always processes all bytes regardless of match status:

```rust
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
```

Both the Authorization header and query parameter comparisons now use this function.

**Files changed:**
- `guardian/src/dashboard/mod.rs` — `constant_time_eq()` + all token comparison call sites

---

## 10. Dashboard Auth Rate Limiting (HIGH)

**Problem:** No rate limiting on failed authentication attempts. An attacker could brute-force the dashboard token with unlimited speed.

**Fix:** Added `AuthRateLimiter` with atomic counters:
- After **10 consecutive failures**, the dashboard locks out for **60 seconds**
- All requests during lockout receive HTTP 429 (Too Many Requests)
- Successful authentication resets the failure counter
- Uses atomics (no Mutex) for zero-contention performance

**Files changed:**
- `guardian/src/dashboard/mod.rs` — `AuthRateLimiter` struct + integration in `auth_middleware()`

---

## 11. Metrics Endpoint Authentication (MEDIUM)

**Problem:** The `/metrics` Prometheus endpoint was excluded from authentication middleware. When auth was configured, an attacker could still access `/metrics` without a token to learn event counts, alert statistics, and other operational data.

**Fix:** Removed `/metrics` from the auth bypass list. Only `/static/` paths (CSS/JS needed to render pages) are now exempt from authentication. Prometheus scrapers must include the Bearer token when `auth_token` is configured.

**Files changed:**
- `guardian/src/dashboard/mod.rs` — `auth_middleware()` path skip list

---

## 12. Email Header Injection Prevention (MEDIUM)

**Problem:** The email alert subject line included `event.path` and `event.agent_name` directly. If these contained newline characters (`\r` or `\n`), an attacker could inject additional email headers (BCC, CC) to redirect alerts.

**Fix:** Strip `\r` and `\n` from path and agent_name before including them in the subject:

```rust
let safe_path = event.path.replace(['\r', '\n'], "");
let safe_agent = event.agent_name.replace(['\r', '\n'], "");
```

**Files changed:**
- `guardian/src/alerting/email.rs` — `send_email_alert()` subject construction

---

## 13. SSRF Prevention for Webhook/Slack URLs (MEDIUM)

**Problem:** Webhook and Slack URLs were accepted from config without validation. An attacker with config access could set `url = "http://127.0.0.1:9200"` to send requests to internal services (Elasticsearch, databases, etc.).

**Fix:** Added `validate_url_not_private()` function that rejects URLs targeting:
- **Localhost aliases:** `localhost`, `ip6-localhost`, `ip6-loopback`
- **Loopback IPs:** `127.0.0.0/8`, `::1`
- **Private IPv4 ranges:** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- **Link-local:** `169.254.0.0/16`
- **Unspecified:** `0.0.0.0`, `::`
- **IPv4-mapped IPv6:** `::ffff:127.0.0.1`, `::ffff:10.x.x.x`, etc.

Called before every webhook and Slack HTTP request.

**Files changed:**
- `guardian/src/alerting/mod.rs` — `validate_url_not_private()` function
- `guardian/src/alerting/webhook.rs` — SSRF check before POST
- `guardian/src/alerting/slack.rs` — SSRF check before POST

---

## 14. CDN Subresource Integrity (SRI) Hashes (MEDIUM)

**Problem:** Dashboard loaded htmx, htmx-ext-sse, and Alpine.js from unpkg CDN without integrity verification. A CDN compromise or MITM attack could inject malicious JavaScript controlling the entire dashboard.

**Fix:** Added `integrity` and `crossorigin` attributes to all CDN script tags:

```html
<script src="https://unpkg.com/htmx.org@2.0.4"
  integrity="sha384-M06VwgoUOHG3FN0UchwWKqh9jS4ejwpoL0yjF3EVljtsxFwFETEYMkyNL5lXbJ5/"
  crossorigin="anonymous"></script>
```

Browsers will refuse to execute scripts that don't match the SHA-384 hash.

**Files changed:**
- `guardian/templates/base.html` — SRI attributes on all 3 CDN script tags

---

## Summary of Changes

| File | Fixes |
|------|-------|
| `guardian/src/ipc.rs` | SO_PEERCRED auth, socket 0o600, connection semaphore, cgroup path traversal, PID validation, grant_type validation, null byte checks, control char checks, error sanitization |
| `guardian/src/dashboard/mod.rs` | Constant-time token comparison, auth rate limiting (10 failures = 60s lockout), /metrics requires auth |
| `guardian/src/alerting/mod.rs` | `validate_url_not_private()` SSRF prevention function |
| `guardian/src/alerting/webhook.rs` | SSRF check before POST |
| `guardian/src/alerting/slack.rs` | SSRF check before POST |
| `guardian/src/alerting/email.rs` | Subject line newline sanitization |
| `guardian/templates/base.html` | SRI hashes on CDN scripts |

**Total: 7 files changed, ~180 lines added.**

---

## Verification

```
$ cargo check
    Finished `dev` profile [optimized + debuginfo] target(s) in 2.68s
    # 0 errors, 0 warnings

$ cargo test
    running 25 tests
    test result: ok. 25 passed; 0 failed; 0 ignored
```

---

## Remaining Issues (Not Addressed)

These require kernel-level changes, architectural redesigns, or are accepted trade-offs:

| Issue | Severity | Reason Deferred |
|-------|----------|----------------|
| Symlink bypass in eBPF | CRITICAL | Requires `bpf_d_path()` in LSM `file_open` hook (Linux 5.11+) |
| Network enforcement (log-only) | CRITICAL | Requires LSM `socket_connect` hook (complex BPF attachment) |
| io_uring file I/O bypass | HIGH | io_uring bypasses syscall tracepoints entirely; requires BPF LSM or seccomp |
| Rename/unlink/hardlink bypass | HIGH | Requires LSM `inode_rename`/`inode_unlink`/`inode_link` hooks |
| TOCTOU race (tracepoint→LSM) | HIGH | Architectural: tracepoint captures filename before LSM enforces |
| CSRF protection | HIGH | Requires session management (no session store exists); mitigated by localhost binding |
| BPF map overflow silent failure | MEDIUM | Map inserts silently fail when full; requires eBPF error propagation redesign |
| Fail-open on eBPF errors | MEDIUM | Intentional safety choice; fail-closed requires `FAIL_CLOSED_CGROUPS` map opt-in |
| Grant persists if daemon crashes | MEDIUM | BPF maps survive daemon restart; requires kernel-side grant expiry |
| Namespace escape monitoring | MEDIUM | Requires hooks for `unshare(CLONE_NEW*)` and `clone()` flags |
| PID recycling race | LOW | `pid_tgid` could be reused; extremely low probability in practice |
| Policy sync gap (dashboard→BPF) | LOW | Dashboard edits require SIGHUP reload to update BPF maps |
| Credentials in plaintext config | LOW | Accepted; documented that config should be root-owned and 0o600 |
| Token in query parameter | LOW | Leaks in referer/logs; accepted for dashboard embedding convenience |
