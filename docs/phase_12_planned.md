# Phase 12: Resilience & Lifecycle (Planned)

**Date:** 2026-03-24
**Status:** Planned
**Based on:** Issues discovered during pitch document preparation and security review

---

## Summary

Phase 12 addresses daemon/agent lifecycle gaps — orphaned resources, daemon
resilience, and the interaction between dynamic grants and Landlock immutability.
These are not security vulnerabilities but operational robustness issues that
affect production deployments.

---

## 12a: Orphaned Cgroup Cleanup on Daemon Startup

**Priority:** P2 (Medium)
**Component:** `guardian/src/main.rs` (daemon startup)

**Problem:** If the daemon dies while agents are running, the
`cgroup_cleanup_task` (which runs every 5s) stops. When agents subsequently
exit, their cgroup directories remain on disk at
`/sys/fs/cgroup/guardian/<agent>-<pid>/` with 0 processes. They're harmless
(empty dirs, no resources consumed) but accumulate across restarts.

**Solution:** On daemon startup, scan `/sys/fs/cgroup/guardian/` for existing
cgroup directories. For each, check `cgroup.procs` — if empty (0 processes),
`rmdir` it. If non-empty, log a warning (a previous agent is still running
without daemon supervision).

**Implementation:**
- Add `cleanup_stale_cgroups()` function called early in `main()`, before eBPF loading
- Scan `/sys/fs/cgroup/guardian/*/cgroup.procs`
- Empty cgroups: remove directory, log at INFO
- Non-empty cgroups: log at WARN with PID list — operator must decide whether to
  re-adopt or kill these orphaned agents

---

## 12b: Orphaned Agent Detection and Re-adoption

**Priority:** P3 (Low)
**Component:** `guardian/src/ipc.rs`, `guardian/src/main.rs`

**Problem:** If the daemon restarts while cgroup agents are still running, those
agents retain their Landlock/seccomp/cgroup protections (4 of 6 layers survive)
but lose eBPF monitoring and the dashboard/audit trail. The daemon has no way to
re-discover and re-monitor these agents.

**Solution:** On startup, detect non-empty cgroups under `/sys/fs/cgroup/guardian/`
and optionally re-register them:
- Parse agent name from cgroup directory name (`<agent>-<pid>`)
- Read cgroup ID via `stat()` on the cgroup directory
- Re-populate `WATCHED_CGROUPS` BPF map
- Add to daemon state as "re-adopted" agents (flagged in dashboard)

**Caveats:**
- Re-adopted agents won't have IPC connections (no permission requests possible)
- Policy must be re-derived from config (agent name must match a config entry)
- Landlock/seccomp protections remain from original launch (not re-applied)

---

## 12c: Dynamic Grants vs Landlock — Document and Mitigate

**Priority:** P2 (Medium)
**Component:** `guardian/src/ipc.rs`, `docs/`

**Problem:** Interactive permission requests (`guardian-ctl request-permission`)
update eBPF allow maps in real-time, but Landlock rules are immutable after
`restrict_self()`. For cgroup agents (Tier 1), Landlock is the primary
enforcement layer and blocks access regardless of eBPF grants. This means
dynamic grants are effectively useless for cgroup agents requesting paths
outside their initial Landlock scope.

**Current state:**
- Dashboard/CLI grants update BPF maps successfully (no error)
- Landlock silently denies the access anyway
- User sees "grant approved" but agent still gets EACCES — confusing

**Solution (phased):**

*Phase 12c-1: Honest feedback*
- When approving a grant for a cgroup agent, check if the path falls within
  the agent's Landlock scope (compare against the `SandboxConfig` stored at
  registration time)
- If outside Landlock scope, return a warning: "Grant approved at eBPF layer,
  but Landlock will still block this path. Agent must be relaunched with
  updated policy."
- Dashboard shows this warning clearly

*Phase 12c-2: Assisted relaunch (future)*
- `guardian-ctl relaunch --name <agent> --add-path /new/path` that:
  1. Updates the agent's config with the new path
  2. Sends SIGTERM to the agent's cgroup
  3. Relaunches with `guardian-launch` (new Landlock rules include the path)
- Requires the original command to be stored at registration time

---

## 12d: Daemon Watchdog / Auto-Restart

**Priority:** P3 (Low)
**Component:** Deployment / systemd integration

**Problem:** If the daemon crashes, cgroup agents keep Landlock/seccomp/cgroup
protection but lose eBPF monitoring, audit trail, dashboard, and permission
request handling. There's no mechanism to automatically restart the daemon.

**Solution:** Provide a systemd unit file with `Restart=on-failure`:

```ini
[Unit]
Description=Guardian Shell eBPF Security Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/guardian --config /etc/guardian/config.toml
Restart=on-failure
RestartSec=3
# Combines with 12b to re-adopt orphaned agents on restart

[Install]
WantedBy=multi-user.target
```

Combined with 12b (orphaned agent re-adoption), this gives near-continuous
protection: daemon crashes → systemd restarts it in 3s → daemon re-adopts
running agents → eBPF monitoring resumes.

---

## 12e: eBPF Program Pinning (Alternative to Re-adoption)

**Priority:** P4 (Explore)
**Component:** `guardian/src/main.rs` (eBPF loading)

**Problem:** eBPF programs are tied to the daemon's file descriptors. When the
daemon exits, the kernel unloads them. This is the root cause of losing layers
5 and 6 on daemon death.

**Solution (exploratory):** Pin eBPF programs and maps to bpffs
(`/sys/fs/bpf/guardian/`). Pinned programs survive process exit — the kernel
keeps them loaded as long as the pin exists. On restart, the daemon re-opens
the pinned programs instead of loading new ones.

**Tradeoffs:**
- Pro: eBPF enforcement survives daemon restart (all 6 layers persist)
- Pro: No gap in monitoring during restart
- Con: Stale BPF maps if config changes between restarts
- Con: Must handle pin cleanup on intentional shutdown
- Con: Adds complexity to eBPF lifecycle management
- Con: Must handle version mismatch (new daemon binary, old pinned program)

**Decision:** Explore after 12a-12d. Systemd restart + re-adoption may be
sufficient for most deployments.

---

## Implementation Order

| Item | Priority | Effort | Dependency |
|------|----------|--------|------------|
| 12a: Stale cgroup cleanup | P2 | Small | None |
| 12c-1: Grant/Landlock warning | P2 | Small | None |
| 12d: Systemd unit file | P3 | Small | None |
| 12b: Agent re-adoption | P3 | Medium | 12a |
| 12c-2: Assisted relaunch | P3 | Medium | 12c-1 |
| 12e: BPF pinning | P4 | Large | Research |
