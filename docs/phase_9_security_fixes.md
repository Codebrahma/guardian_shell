# Phase 9 Implementation: Network Enforcement

## What Phase 9 Solves

Phase 7 added network monitoring via the `sys_enter_connect` tracepoint — Guardian could log outbound connections with port and IP address details, but could not actually block them. Network policy evaluation happened in userspace only, meaning a denied connection was logged as `[DENY]` but still succeeded at the kernel level. An agent with `deny_ports = [22, 3306]` would see warning logs for SSH and MySQL connections, but the connections would go through.

**Problem: Network monitoring was log-only.** The `sys_enter_connect` tracepoint fires before the kernel completes the `connect()` syscall, capturing destination port and address. But tracepoints alone cannot modify syscall behavior — they are passive observers. Blocking requires an LSM (Linux Security Module) hook that can return an error code to abort the operation.

Phase 9 upgrades network policy from log-only to kernel-enforced blocking using the same tracepoint-PENDING-LSM architecture pattern used for file access and exec enforcement.

---

## What Was Built

| File | Lines Changed | What |
|------|---------------|------|
| `guardian-ebpf/src/main.rs` | +85 | 5 new BPF maps, `evaluate_net_policy()` helper, enforcement logic in `try_guardian_net_connect()`, LSM `socket_connect` hook |
| `guardian-common/src/lib.rs` | +6 | 5 new map name constants (`MAP_NET_DENY_PORTS`, `MAP_NET_ALLOW_PORTS`, etc.) |
| `guardian/src/main.rs` | +80 | `populate_net_enforcement_maps()`, LSM load/attach with graceful fallback, PENDING_NET_DENY ownership, BLOCKED status in `process_net_event()` |
| `CLAUDE.md` | Updated | Phase 9 docs, architecture notes, updated known limitations |
| `USAGE.md` | Updated | Phase 9 section in roadmap |

---

## Architecture

### Tracepoint-PENDING-LSM Pattern for Network

Phase 9 extends the proven enforcement pattern to network connections:

```
Tracepoint                     BPF Map                    LSM Hook
─────────────────             ────────────────            ─────────────────
sys_enter_connect  ──SET──> PENDING_NET_DENY    ──CHK──> socket_connect
```

1. **Tracepoint** (`sys_enter_connect`): Fires when any process calls `connect()`. Reads the `sockaddr` structure from userspace to extract destination port and address. If the process is enforced and the port is denied by policy, inserts `pid_tgid` into `PENDING_NET_DENY`.

2. **LSM hook** (`socket_connect`): Fires later in the same syscall, after the tracepoint. Checks `PENDING_NET_DENY` for the current `pid_tgid`. If found, removes the entry and returns `-ECONNREFUSED` (-111) to block the connection.

The `-ECONNREFUSED` return code was chosen over `-EACCES` because it provides more informative error messages to the blocked application — "Connection refused" is a standard network error that applications handle gracefully, while "Permission denied" can cause confusing behavior in network libraries.

### Policy Evaluation Order

The `evaluate_net_policy()` function in eBPF evaluates rules in this order:

```
1. Check NET_DENY_PORTS   → if port found, DENY  (deny takes precedence)
2. Check NET_ALLOW_PORTS  → if port found, ALLOW
3. Check NET_CGROUP_DEFAULT_ACTION → per-cgroup default (for cgroup agents)
4. Check NET_DEFAULT_ACTION        → per-comm default (for comm agents)
5. Fallback: ALLOW (fail-open unless configured otherwise)
```

This mirrors the deny-takes-precedence model used for file access policy.

---

## New BPF Maps

| Map | Type | Key | Value | Max Entries | Purpose |
|-----|------|-----|-------|-------------|---------|
| `PENDING_NET_DENY` | `HashMap<u64, u8>` | `pid_tgid` | `1` | 4096 | Transient deny signal between tracepoint and LSM |
| `NET_DENY_PORTS` | `HashMap<u32, u8>` | port (u16 as u32) | `1` | 1024 | Ports to deny regardless of agent |
| `NET_ALLOW_PORTS` | `HashMap<u32, u8>` | port (u16 as u32) | `1` | 1024 | Ports to allow regardless of agent |
| `NET_DEFAULT_ACTION` | `HashMap<[u8; 16], u8>` | comm name | 0=deny, 1=allow | 1024 | Per-comm default action |
| `NET_CGROUP_DEFAULT_ACTION` | `HashMap<u64, u8>` | cgroup ID | 0=deny, 1=allow | 1024 | Per-cgroup default action |

Port keys use `u32` instead of `u16` because BPF map keys must be at least 4 bytes for HashMap lookups. The port value is zero-extended: `port as u32`.

---

## Configuration

Network enforcement uses the existing `network_policy` configuration from Phase 7. No config changes were needed.

```toml
[[agents]]
name = "my-agent"
identity = "cgroup"

[agents.network_policy]
default = "deny"          # "allow" or "deny" — default action for unlisted ports
allow_ports = [80, 443]   # Always allow HTTP/HTTPS
deny_ports = [22, 3306]   # Always deny SSH and MySQL
```

**How it works:**

- `deny_ports` are inserted into `NET_DENY_PORTS` map (checked first, highest priority)
- `allow_ports` are inserted into `NET_ALLOW_PORTS` map (checked second)
- `default` sets the per-comm or per-cgroup default action (checked last)
- Deny rules always take precedence over allow rules

### Example: Restrict agent to web traffic only

```toml
[agents.network_policy]
default = "deny"
allow_ports = [80, 443, 53]   # HTTP, HTTPS, DNS
```

The agent can make web requests and DNS lookups. Any other outbound connection (SSH, database, SMTP, etc.) returns `ECONNREFUSED` at the kernel level.

### Example: Block known dangerous ports

```toml
[agents.network_policy]
default = "allow"
deny_ports = [22, 23, 3306, 5432, 6379, 27017]  # SSH, Telnet, MySQL, Postgres, Redis, MongoDB
```

The agent can connect to any port except the explicitly denied ones.

---

## Key Implementation Details

### eBPF: evaluate_net_policy()

```rust
#[inline(always)]
fn evaluate_net_policy(port: u16, comm: &[u8; 16], cgroup_id: u64) -> bool {
    let port_key = port as u32;
    // Deny takes precedence
    if unsafe { NET_DENY_PORTS.get(&port_key) }.is_some() { return false; }
    // Explicit allow
    if unsafe { NET_ALLOW_PORTS.get(&port_key) }.is_some() { return true; }
    // Per-cgroup default (for cgroup-based agents)
    if let Some(&action) = unsafe { NET_CGROUP_DEFAULT_ACTION.get(&cgroup_id) } {
        return action == 1;
    }
    // Per-comm default (for comm-based agents)
    match unsafe { NET_DEFAULT_ACTION.get(comm) } {
        Some(&action) => action == 1,
        None => true, // fail-open: allow if no policy configured
    }
}
```

### eBPF: LSM socket_connect hook

```rust
#[lsm(hook = "socket_connect")]
pub fn guardian_enforce_net_connect(ctx: LsmContext) -> i32 {
    match try_enforce_net_connect(&ctx) {
        Ok(ret) => ret,
        Err(_) => fail_mode_for_cgroup(),
    }
}

fn try_enforce_net_connect(_ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    if unsafe { PENDING_NET_DENY.get(&pid_tgid) }.is_some() {
        let _ = PENDING_NET_DENY.remove(&pid_tgid);
        return Ok(-111); // -ECONNREFUSED
    }
    Ok(0)
}
```

### Userspace: Map population

`populate_net_enforcement_maps()` iterates over all configured agents, reads their `network_policy`, and populates the BPF maps:

- For comm-based agents: sets `NET_DEFAULT_ACTION` keyed by comm name
- For cgroup-based agents: `NET_CGROUP_DEFAULT_ACTION` is set dynamically during agent registration via IPC
- `deny_ports` and `allow_ports` from all agents are merged into the global port maps

### Graceful fallback

If the kernel doesn't support `CONFIG_BPF_LSM` or the `socket_connect` hook fails to load:

- **Normal mode**: Logs a warning, continues with monitor-only network policy (same as Phase 7)
- **Strict mode**: Bails with an error, refusing to run without enforcement capability

---

## BPF Stack Overflow Fix

During the Phase 9 build, the eBPF verifier rejected the `guardian_exec_monitor` program with:

```
Looks like the BPF stack limit is exceeded.
Please move large on stack variables into BPF per-cpu array map.
```

**Root cause:** The Phase 8 dynamic linker detection code allocated a `[0u8; MAX_FILENAME_LEN]` (256-byte) array on the BPF stack to read `argv[1]`. Combined with other local variables in the function, this exceeded the strict 512-byte BPF stack limit.

**Fix:** Eliminated the separate stack variable by reading `argv[1]` directly into `event.filename` (which lives in the `EXEC_BUF` per-CPU array map, not on the stack). Since the dynamic linker check was already done against the original filename, the buffer could be safely reused for the real binary path.

---

## Verification

All builds and tests pass:

| Check | Command | Result |
|-------|---------|--------|
| eBPF build | `cargo xtask build-ebpf --release` | BPF verifier accepts all programs |
| Userspace build | `cargo build --release` | Clean compilation |
| Tests | `cargo test -p guardian` | 25 tests passed |
| Warnings | `cargo check` | 0 warnings |

---

## Testing Network Enforcement

### Manual test procedure

```bash
# Terminal 1: Start daemon with network policy
sudo RUST_LOG=info target/release/guardian --config config.toml

# Terminal 2: Launch agent with cgroup isolation
sudo target/release/guardian-launch --name test-agent -- bash

# Inside the agent's bash shell:
curl http://example.com       # Port 80 — ALLOWED (if in allow_ports)
curl https://example.com      # Port 443 — ALLOWED (if in allow_ports)
ssh user@example.com          # Port 22 — BLOCKED (returns "Connection refused")
mysql -h db.example.com       # Port 3306 — BLOCKED (returns "Connection refused")
```

### What to expect in daemon logs

```
INFO  guardian: NET [test-agent] PID=12345 → 93.184.216.34:80 [ALLOW]
INFO  guardian: NET [test-agent] PID=12345 → 93.184.216.34:443 [ALLOW]
CRITICAL guardian: NET [test-agent] PID=12345 → 93.184.216.34:22 [BLOCKED]
CRITICAL guardian: NET [test-agent] PID=12345 → db.example.com:3306 [BLOCKED]
```

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| `-ECONNREFUSED` instead of `-EACCES` | Network applications handle "Connection refused" gracefully (retry logic, fallback). `-EACCES` ("Permission denied") can cause confusing errors in HTTP libraries and socket code. |
| Global deny/allow port maps | Simpler than per-agent port maps. Deny ports are universally dangerous (SSH, databases). Per-agent differentiation handled by default action maps. |
| Port as `u32` key | BPF HashMap requires minimum 4-byte keys. `u16` port zero-extended to `u32`. |
| Separate `PENDING_NET_DENY` map | Cannot share with `PENDING_DENY` (file) or `PENDING_EXEC_DENY` (exec) because multiple hooks may fire in overlapping syscall contexts. Each enforcement domain needs its own pending map. |
| `fail_mode_for_cgroup()` on error | Respects per-cgroup fail-closed configuration from Phase 8. Fail-closed agents are blocked on error; fail-open agents are allowed. |
| Cgroup default set at registration time | Cgroup ID isn't known at config load time — it's assigned when the agent registers via IPC. `NET_CGROUP_DEFAULT_ACTION` is populated dynamically. |

---

## Known Limitations

1. **Port-based only**: No IP address or CIDR range filtering in BPF maps. Would require additional maps and more complex policy evaluation.
2. **No per-agent port isolation**: Deny/allow port maps are global. If agent A denies port 22 and agent B allows it, the deny wins for all agents. Per-agent isolation would require per-cgroup port maps.
3. **UDP not enforced**: `sys_enter_connect` only fires for connection-oriented sockets. UDP `sendto()` without prior `connect()` bypasses this hook. Would require `sys_enter_sendto` tracepoint.
4. **Requires `CONFIG_BPF_LSM`**: Kernel must have `CONFIG_BPF_LSM=y` and `bpf` in the LSM list. Falls back to monitor-only without it.
5. **No DNS-based policy**: Cannot deny connections by hostname. DNS resolution happens before `connect()`, so the tracepoint only sees IP addresses.
6. **IPv6-mapped IPv4 not special-cased**: `::ffff:192.168.1.1` is treated as IPv6, not IPv4. Policy evaluation is port-based so this doesn't affect enforcement, but logging shows the IPv6 representation.
