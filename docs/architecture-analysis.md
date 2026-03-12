# Guardian Shell Architecture Analysis: Limits, Trade-offs, and Future Directions

## 1. What Cannot Be Implemented in the Current Architecture (and Why)

For each item below, we explain the technical limitation clearly so that readers understand not just *what* is missing, but *why* it cannot be trivially added.

### Content Hash for Exec (Veto-style binary identity)

- **Why it's hard**: eBPF has a 512-byte stack limit, bounded loops, and a ~1M instruction limit. SHA-256 requires 64 rounds per 64-byte block. A 1MB binary = ~16,000 blocks. The eBPF verifier will reject this for large binaries.
- The alternative `bpf_ima_file_hash()` requires Linux 5.18+ and `CONFIG_IMA=y` -- not enabled by default on Ubuntu, Fedora, or most distros.
- Userspace hashing has a TOCTOU race (binary swapped between hash and exec).
- This is Veto's core innovation -- they solved the kernel-side hashing problem with significant eBPF expertise.
- **Verdict**: Not implementable without major kernel config requirements or novel eBPF techniques.

### Inode-Based File Identity

- Would make Guardian immune to ALL path tricks including symlinks.
- **Challenge 1**: Inode numbers are reused after deletion. `(dev, ino)` pairs are needed.
- **Challenge 2**: Editors (vim, `sed -i`) create new files with new inodes -- deny rules break.
- **Challenge 3**: Cross-filesystem inodes are not unique without the device number.
- **Challenge 4**: Need inotify watchers + invalidation logic in userspace.
- **Challenge 5**: LSM hook needs `bpf_d_path()` (Linux 5.11+) or direct `struct inode` field reads.
- **Verdict**: Partially feasible but semantic complexity makes it fragile.

### Full Symlink Resolution in eBPF

- Proper fix requires `bpf_d_path()` (Linux 5.11+) in the LSM hook.
- Currently the LSM hook only checks `PENDING_DENY` -- it does not read the file struct at all.
- Adding path reading to LSM means moving policy evaluation INTO the LSM context.
- The 512-byte stack makes path comparison in LSM context very difficult.
- This would require fundamental rearchitecting of the enforcement flow.
- **Verdict**: Requires rearchitecting enforcement -- no longer tracepoint-decides, LSM-enforces.

### Network Enforcement (kernel-side blocking)

- LSM `socket_connect` hook could block connections.
- But requires reading `sockaddr` from LSM context (different from tracepoint context).
- Aya-ebpf supports this but it adds eBPF verifier complexity.
- Port-based blocking in eBPF is feasible; IP-range blocking needs BPF map design.
- DNS resolution happens before connect, so domain-based rules need DNS monitoring.
- **Verdict**: Feasible but complex; deferred to future phase. Monitoring implemented now.

### io_uring Bypass Protection

- `io_uring` operations bypass syscall tracepoints entirely.
- LSM hooks still fire for `io_uring` (so `file_open` enforcement works).
- But tracepoint-based monitoring misses `io_uring` operations.
- Full fix requires seccomp BPF to block `io_uring_setup` or `io_uring_enter` syscalls.
- **Verdict**: Partially mitigated (LSM still fires); full fix needs seccomp.

---

## 2. Current Architecture Assessment

### Architecture Overview

Guardian Shell uses a **tracepoint + LSM two-phase enforcement** pattern:

1. Tracepoint captures syscall arguments (easy path reading).
2. Tracepoint evaluates policy and sets `PENDING_DENY` flag.
3. LSM hook checks `PENDING_DENY` and blocks access.

### Strengths of Current Architecture

1. **Separation of concerns**: Tracepoints handle data capture and policy evaluation; LSM handles enforcement. This avoids complex path reading in LSM context.

2. **Per-agent policy**: Cgroup-based identity enables different policies for different agents. Veto and most eBPF tools are system-wide.

3. **Rich observability stack**: Dashboard, SSE, alerting, Prometheus. Most eBPF security tools are CLI-only.

4. **Interactive approval workflow**: Permission requests with risk classification. Unique among eBPF security tools.

5. **Single binary deployment**: Templates compiled in, static files embedded. No external dependencies.

6. **Graceful degradation**: If LSM unavailable, falls back to monitor-only. If `openat2`/`open` unavailable, continues with what is available.

7. **Composable policy layers**: File access + exec + network + permissions + rate limiting all stack.

### Weaknesses of Current Architecture

1. **Path-based matching is fundamentally fragile**: Symlinks, bind mounts, hard links, procfs tricks all create alternative paths to the same file. Normalization helps but cannot be complete.

2. **Tracepoint-LSM timing dependency**: The enforcement model assumes the tracepoint fires before the LSM hook in the same syscall. This is true on x86_64 but is technically a kernel implementation detail, not a guarantee.

3. **No per-agent BPF maps**: Policy maps (`DENY_EXACT`, `ALLOW_PREFIXES`, etc.) are shared across all agents. This means deny rules from one agent affect all agents. True per-agent isolation would require per-agent map instances or encoding agent identity into map keys.

4. **String matching in kernel space**: LPM trie matching works for prefix patterns, but complex glob matching (single-level wildcards) happens in userspace only. Kernel policy is a subset of userspace policy.

5. **Raw syscall argument capture**: Tracepoints see the path the application passes to the syscall, not the canonical path the kernel resolves. This is the root cause of most bypass vectors.

6. **No atomic policy updates**: BPF maps are updated entry-by-entry. During a policy reload, there is a window where the map is partially old and partially new.

---

## 3. Alternative Architectures

### Architecture A: Full LSM Enforcement (Veto-style)

**Approach**: Move ALL policy evaluation into LSM hooks. Use `bpf_d_path()` to get canonical paths.

**Pros**:
- Canonical paths -- immune to symlinks, `/proc` tricks, all path manipulation.
- Atomic enforcement point -- decision and enforcement in the same context.
- No `PENDING` map race conditions.
- Can read `struct file`, `struct inode`, get device/inode numbers.

**Cons**:
- Requires Linux 5.11+ for `bpf_d_path()`.
- 512-byte stack limit makes path comparison very difficult in LSM context.
- Would need to restructure policy evaluation to work within eBPF constraints.
- Loses easy access to syscall arguments (no filename from `openat` args).
- More complex eBPF programs = harder to pass verifier.

**When to consider**: If symlink/path bypass attacks become the primary threat. Requires committing to Linux 5.11+ as minimum kernel version.

### Architecture B: Seccomp-BPF for Enforcement

**Approach**: Use seccomp-BPF filters to restrict syscalls available to agents.

**Pros**:
- Simple, well-supported by all Linux kernels (3.5+).
- Can block entire syscall classes (`io_uring_enter`, `ptrace`, etc.).
- Inherited by child processes (like cgroups).
- No `CONFIG_BPF_LSM` requirement.

**Cons**:
- Cannot inspect file paths (operates on syscall numbers and arguments).
- Cannot make content-aware decisions.
- Binary allow/deny at syscall level -- no per-path granularity.
- Would need to be combined with other approaches for file-level control.

**When to consider**: As a defense-in-depth layer on top of existing architecture. Block dangerous syscalls (`io_uring_enter`, `ptrace`, etc.) while keeping current file/exec enforcement.

### Architecture C: Hybrid LSM + Tracepoint + Seccomp

**Approach**: Combine all three mechanisms:

- **Seccomp**: Block dangerous syscalls (`io_uring`, `ptrace`, `personality`).
- **LSM `file_open` with `bpf_d_path()`**: Canonical path enforcement (Linux 5.11+).
- **Tracepoints**: Rich event capture for monitoring and alerting.
- **Current architecture** for kernels < 5.11.

**Pros**:
- Defense in depth -- multiple enforcement layers.
- Canonical path resolution where available.
- Backward compatibility with older kernels.
- Covers `io_uring` and other tracepoint bypasses.

**Cons**:
- Most complex implementation.
- Multiple code paths based on kernel version.
- Harder to test and reason about.
- Higher maintenance burden.

**When to consider**: This is likely the long-term target architecture. Can be incrementally adopted.

### Architecture D: Containerization / Namespace Isolation

**Approach**: Run each agent in its own Linux namespace (mount, network, PID, user) with a whitelist filesystem overlay.

**Pros**:
- Kernel-enforced isolation at the namespace level.
- Mount namespace: agent only sees allowed paths.
- Network namespace: completely isolated network stack.
- No BPF/eBPF required -- works on any Linux kernel.
- Well-understood security model (OCI containers).

**Cons**:
- Heavy-weight: each agent needs its own filesystem view.
- No fine-grained per-file policy -- it is all-or-nothing per mount.
- No interactive permission requests (cannot dynamically change mounts).
- Loses the rich monitoring and alerting capabilities.
- Not suitable for agents that need to interact with host filesystem.

**When to consider**: For high-security deployments where agents have clearly defined, static resource needs. Not suitable for interactive development agents.

---

## 4. Is Veto's Architecture Better?

### Veto's Core Design

Veto uses a single LSM hook (`bprm_check_security`) with kernel-side SHA-256 hashing. Binary identity is its content hash, not its path.

### Where Veto is Superior

1. **Immune to all path manipulation**: Hash does not change regardless of path.
2. **Pre-execution blocking**: Binary never runs a single instruction.
3. **Simple, auditable policy**: List of hashes, no complex patterns.
4. **No timing dependencies**: Single enforcement point, no `PENDING` maps.

### Where Guardian Shell is Superior

1. **File access control**: Veto cannot restrict which files a process reads/writes.
2. **Per-agent policy**: Different agents get different rules.
3. **Interactive approval**: Permission requests with risk-based UI.
4. **Rich observability**: Dashboard, alerting, Prometheus, SSE.
5. **Interpreted code**: Can block script file reads; Veto is blind to Python/Bash.
6. **Network monitoring**: Can see outbound connections; Veto cannot.
7. **Dynamic policy**: Temporary grants, hot reload; Veto is static.

### Verdict

Veto and Guardian Shell solve fundamentally different problems:

- **Veto**: "Which binaries can run?" (execution control)
- **Guardian Shell**: "What can this agent access?" (resource control)

Veto's architecture is BETTER for binary execution control. Guardian Shell's architecture is BETTER for resource access control and interactive workflows. They are complementary, not competing.

The ideal deployment uses BOTH:

- Veto blocks unauthorized binary execution.
- Guardian Shell controls file access, monitors network, provides interactive approval.

---

## 5. Recommended Architecture Evolution Plan

### Phase 1 (Current): Tracepoint + LSM Two-Phase

- File enforcement via `PENDING_DENY` pattern.
- Exec enforcement via `PENDING_EXEC_DENY` pattern.
- Network monitoring via tracepoint.
- Path normalization for common bypasses.

### Phase 2 (Near-term): Add Seccomp Layer

- Add seccomp-BPF filters to `guardian-launch`.
- Block: `io_uring_enter`, `io_uring_setup`, `ptrace`, `personality`.
- Block: `process_vm_readv`, `process_vm_writev` (cross-process memory).
- This eliminates the `io_uring` bypass and several escalation vectors.
- **Effort**: Low-medium. seccomp is well-documented and supported.

### Phase 3 (Medium-term): LSM `bpf_d_path()` Enforcement

- For kernels 5.11+: Move file policy evaluation into LSM hook using `bpf_d_path()`.
- Eliminates symlink and all path manipulation bypasses.
- Keep tracepoint for monitoring/alerting (rich event data).
- Keep current tracepoint + `PENDING` pattern as fallback for older kernels.
- **Effort**: High. Requires restructuring eBPF enforcement logic.

### Phase 4 (Long-term): Hybrid Architecture

- Combine all three: seccomp + LSM with `bpf_d_path` + tracepoint monitoring.
- Inode-based deny map for critical files (using `bpf_d_path`-resolved inodes).
- Content hashing via `bpf_ima_file_hash` for critical binary verification (where IMA available).
- Network enforcement via LSM `socket_connect`.
- Full defense-in-depth stack.

---

## 6. Summary Table

| Feature | Current Architecture | Full LSM | Seccomp + Current | Hybrid (Recommended) |
|---|---|---|---|---|
| File enforcement | Path-based | Canonical path | Path-based | Canonical path |
| Exec enforcement | Phase 7 | Yes | Yes | Yes |
| Network enforcement | Monitor only | Possible | Monitor only | Yes (LSM `socket_connect`) |
| Symlink immunity | No | Yes (`bpf_d_path`) | No | Yes |
| io_uring protection | Partial (LSM) | Partial (LSM) | Yes (seccomp blocks) | Yes |
| Binary hash verification | No | No | No | Partial (IMA) |
| Kernel version requirement | 5.2+ | 5.11+ | 5.2+ | 5.11+ (degraded 5.2+) |
| Per-agent policy | Yes | Yes | Yes | Yes |
| Interactive approval | Yes | Yes | Yes | Yes |
| Implementation complexity | Medium | High | Medium | Very High |

**Bottom line**: The current architecture is sound for its scope. The weaknesses (path-based matching, no symlink resolution) are inherent to the tracepoint approach and can only be fully fixed by adding LSM `bpf_d_path()` enforcement (Architecture C). The recommended path is incremental: add seccomp first (quick win), then `bpf_d_path` LSM (when ready to commit to 5.11+).
