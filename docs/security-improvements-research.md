# Guardian Shell - Security Improvements Research

## Closing the Loopholes: A Comprehensive Hardening Plan

This document synthesizes research into fixing every known security loophole
in Guardian Shell, informed by Ona's Veto research and analysis of how
production eBPF tools (Tetragon, Falco, Tracee, Cilium, KubeArmor) handle
these same challenges.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Loophole 1: Path Canonicalization](#loophole-1-path-canonicalization)
3. [Loophole 2: Exec Enforcement](#loophole-2-exec-enforcement)
4. [Loophole 3: Network Monitoring](#loophole-3-network-monitoring)
5. [Loophole 4: Missing Syscall Coverage](#loophole-4-missing-syscall-coverage)
6. [Loophole 5: Approval Fatigue](#loophole-5-approval-fatigue)
7. [Implementation Roadmap](#implementation-roadmap)
8. [References](#references)

---

<a name="executive-summary"></a>
## 1. Executive Summary

Guardian Shell has five major security loopholes. Here is the priority-ordered
fix for each:

| Loophole | Fix | Impact | Effort |
|----------|-----|--------|--------|
| Path bypasses (symlinks, /proc/self/root/) | Move enforcement to LSM `file_open` with `bpf_d_path()` | Critical | High |
| Exec is log-only | Add LSM `bprm_check_security` hook | Critical | Medium |
| No network monitoring | Add `cgroup/connect4` BPF program | High | Medium |
| Missing syscalls (openat2, rename, unlink) | Add tracepoints + LSM hooks | High | Medium |
| Approval fatigue | Rate limiting + risk tiers + auto-deny | Medium | Medium |

**The single most impactful change:** Move file access enforcement from the
tracepoint into the LSM `file_open` hook using `bpf_d_path()`. This one
architectural change simultaneously fixes path canonicalization, symlink
attacks, `/proc/self/root/` bypasses, and TOCTOU vulnerabilities.

---

<a name="loophole-1-path-canonicalization"></a>
## 2. Loophole 1: Path Canonicalization

### The Problem

Guardian Shell captures the raw filename from the `sys_enter_openat` tracepoint
argument. Whatever path the userspace process passes to `openat()` is what
gets matched against policy. This means:

```
/proc/self/root/etc/shadow    → does NOT match deny rule "/etc/shadow"
../../../etc/shadow           → does NOT match deny rule "/etc/shadow"
/tmp/link-to-shadow           → matches allow rule "/tmp/**" (symlink target unchecked)
/proc/1234/fd/3               → matches allow rule "/proc/**" (fd of another process)
```

### Solution: Hybrid Approach (3 Layers)

The recommended fix uses three complementary mechanisms, implemented in phases:

#### Layer 1: Userspace Path Normalization (Quick Win)

Add a `normalize_path()` function in the daemon's event processing. This
catches the most obvious attacks without any kernel-side changes:

```rust
/// Normalize a raw path to remove common bypass tricks.
/// NOT full canonicalization (no symlink resolution), but catches
/// /proc/self/root/ and ".." traversal.
fn normalize_path(raw: &str) -> String {
    let mut path = raw.to_string();

    // Strip /proc/self/root/ prefix (filesystem escape trick)
    if path.starts_with("/proc/self/root/") {
        path = path["/proc/self/root".len()..].to_string();
    }

    // Strip /proc/<pid>/root/ prefix
    if let Some(rest) = path.strip_prefix("/proc/") {
        if let Some(slash_pos) = rest.find('/') {
            let after_pid = &rest[slash_pos..];
            if after_pid.starts_with("/root/") {
                path = after_pid["/root".len()..].to_string();
            }
        }
    }

    // Resolve ".." components
    let mut components: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => { components.pop(); }
            c => components.push(c),
        }
    }

    if components.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", components.join("/"))
    }
}
```

**Where to add:** In `guardian/src/config.rs`, modify `path_matches()` and
`check_file_policy()` to normalize the incoming path before matching.
Also normalize in the event processing loop in `guardian/src/main.rs`.

**Limitation:** Does not resolve symlinks. Only catches string-level tricks.

#### Layer 2: LSM `file_open` with `bpf_d_path()` (Core Fix)

This is the architectural change that eliminates the entire class of path
bypass attacks. Move enforcement from the tracepoint into the LSM hook,
where the kernel has already resolved all symlinks and mounts.

**Current flow (vulnerable):**
```
sys_enter_openat → reads RAW userspace path → sets PENDING_DENY
security_file_open → checks PENDING_DENY → blocks if set
```

**New flow (secure):**
```
sys_enter_openat → reads raw path → sends event to userspace (logging only)
security_file_open → calls bpf_d_path() → gets CANONICAL path
                   → evaluates policy against canonical path → blocks if denied
```

**Key details about `bpf_d_path()`:**
- Kernel helper that resolves `struct path *` to canonical path string
- Resolves all symlinks, mount traversals, `..` components
- Available since **Linux 5.10** (commit `6e22ab9da793`)
- Allowed in sleepable LSM hooks since **Linux 5.11** (KP Singh's patchset)
- `security_file_open` IS a sleepable LSM hook

**eBPF implementation sketch:**

```rust
use aya_ebpf::bindings::path;
use aya_ebpf_bindings::helpers::bpf_d_path;

// Per-CPU buffer for resolved path (can't use stack: 512-byte limit)
#[map]
static CANONICAL_PATH_BUF: PerCpuArray<[u8; MAX_FILENAME_LEN]> =
    PerCpuArray::with_max_entries(1, 0);

#[lsm(hook = "file_open")]
pub fn guardian_enforce_file_open(ctx: LsmContext) -> i32 {
    match try_enforce_file_open(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // fail-open on error
    }
}

fn try_enforce_file_open(ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let comm = bpf_get_current_comm().map_err(|e| e)?;
    let tgid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // Skip non-watched processes
    if !is_process_watched(&comm, tgid, cgroup_id) {
        return Ok(0);
    }

    // Backward compat: still honor tracepoint's PENDING_DENY
    if unsafe { PENDING_DENY.get(&pid_tgid) }.is_some() {
        let _ = PENDING_DENY.remove(&pid_tgid);
        return Ok(-13); // -EACCES
    }

    if !is_process_enforcing(&comm, tgid, cgroup_id) {
        return Ok(0);
    }

    // Get struct file * (first argument to security_file_open)
    let file_ptr: *const u8 = unsafe { ctx.arg(0) };
    if file_ptr.is_null() {
        return Ok(0);
    }

    // Get per-CPU scratch buffer
    let buf = unsafe {
        let ptr = CANONICAL_PATH_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    // Get f_path from struct file (offset depends on kernel version)
    // With BTF/CO-RE this is portable; otherwise hardcode offset
    let f_path_ptr = unsafe {
        (file_ptr as *const u8).add(OFFSET_OF_F_PATH) as *mut path
    };

    // Resolve canonical path
    let ret = unsafe {
        bpf_d_path(f_path_ptr, buf.as_mut_ptr() as *mut i8, MAX_FILENAME_LEN as u32)
    };

    if ret <= 0 {
        // bpf_d_path failed (pseudo-filesystem or error)
        // Fall through to fail-open
        return Ok(0);
    }

    let path_len = ret as usize;

    // Evaluate policy against the CANONICAL path
    let allowed = evaluate_policy(buf, path_len, &comm, cgroup_id);
    if !allowed {
        return Ok(-13); // -EACCES
    }

    Ok(0)
}
```

**What this eliminates:**
- Symlink attacks (kernel resolves symlink before LSM hook fires)
- `/proc/self/root/` trick (kernel resolves to actual path)
- `..` traversal (kernel normalizes path components)
- TOCTOU between tracepoint and LSM (policy evaluated on kernel-resolved path)

**Requirements:** Linux 5.11+, `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`

**Performance:** `bpf_d_path` calls kernel's `d_path()` which walks the dentry
chain. ~200-500ns per call. Only fires for watched processes.

**Fallback:** On kernels < 5.11 or without `CONFIG_BPF_LSM`, fall back to the
current tracepoint + PENDING_DENY approach.

#### Layer 3: Inode-Based Deny Map (Belt and Suspenders)

For high-value specific files, add an inode-based deny map that is completely
immune to any path manipulation:

```rust
#[repr(C)]
struct InodeKey {
    dev: u32,
    ino: u64,
}

#[map]
static DENY_INODES: HashMap<InodeKey, u8> = HashMap::with_max_entries(256, 0);
```

**Userspace populates this at startup:**

```rust
use std::os::unix::fs::MetadataExt;

for deny_path in &agent.file_access.deny {
    if !deny_path.contains('*') { // exact paths only
        if let Ok(meta) = std::fs::metadata(deny_path) {
            let key = InodeKey { dev: meta.dev() as u32, ino: meta.ino() };
            deny_inodes_map.insert(key, 1u8, 0)?;
        }
    }
}
```

**In the LSM hook:** Read inode from `struct file *` (pointer chasing:
`file->f_inode->i_ino` and `file->f_inode->i_sb->s_dev`). Look up in
`DENY_INODES`. O(1) hash lookup, ~100ns.

**Limitations:** Cannot handle wildcards. Only for specific known files. Must
update map when files are replaced (inode number changes).

### How Production Tools Handle Path Resolution

| Tool | Approach |
|------|----------|
| **Tetragon** | Hooks `security_file_permission` kprobe; operates on kernel-resolved dentries |
| **Falco** | Raw syscall paths; **known vulnerable to symlinks** (GitHub issue #1111) |
| **Tracee** | LSM hooks + tracepoints; cross-references raw vs resolved paths |
| **BPFBox/BPFContain** | Inode+device pairs resolved at policy load time |
| **KubeArmor** | LSM `security_file_open` with path-based enforcement |

---

<a name="loophole-2-exec-enforcement"></a>
## 3. Loophole 2: Exec Enforcement

### The Problem

Guardian Shell logs exec events via `sys_enter_execve` tracepoint but
**cannot block them** (Known Limitation #6). An agent can run any binary.

### Solution: LSM `bprm_check_security` Hook

The `bprm_check_security` LSM hook fires during `execve()` processing,
before the binary starts executing. Return `-EPERM` to block.

**Available data from `struct linux_binprm`:**
- `filename` — path passed to `execve` (original)
- `interp` — binary actually being executed (differs for scripts with `#!`)
- `file` — `struct file *` for the executable (for path resolution/hashing)
- `argc` / `envc` — argument and environment counts

#### Basic Exec Enforcement

```rust
/// Exec deny rules: exact path matches
#[map]
static EXEC_DENY_EXACT: HashMap<[u8; MAX_FILENAME_LEN], u8> =
    HashMap::with_max_entries(256, 0);

/// Exec allow rules: exact path matches
#[map]
static EXEC_ALLOW_EXACT: HashMap<[u8; MAX_FILENAME_LEN], u8> =
    HashMap::with_max_entries(256, 0);

/// Exec deny rules: prefix matches (e.g., /tmp/**)
#[map]
static EXEC_DENY_PREFIXES: LpmTrie<[u8; MAX_FILENAME_LEN], u8> =
    LpmTrie::with_max_entries(256, 0);

/// Exec allow rules: prefix matches
#[map]
static EXEC_ALLOW_PREFIXES: LpmTrie<[u8; MAX_FILENAME_LEN], u8> =
    LpmTrie::with_max_entries(256, 0);

/// Per-cgroup exec default action: 0 = deny, 1 = allow
#[map]
static CGROUP_EXEC_DEFAULT: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);

#[lsm(hook = "bprm_check_security")]
pub fn guardian_exec_enforce(ctx: LsmContext) -> i32 {
    match try_exec_enforce(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // fail-open
    }
}

fn try_exec_enforce(ctx: &LsmContext) -> Result<i32, i64> {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // Only enforce for watched cgroups
    if unsafe { ENFORCE_CGROUPS.get(&cgroup_id) }.is_none() {
        return Ok(0);
    }

    // Read bprm->filename
    let bprm: *const linux_binprm = unsafe { ctx.arg(0) };
    let filename_ptr: u64 = unsafe {
        bpf_probe_read_kernel(
            (bprm as *const u8).add(OFFSET_BPRM_FILENAME) as *const u64
        ).map_err(|_| 1i64)?
    };

    let path_buf = unsafe {
        let ptr = EXEC_PATH_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    let _ = unsafe {
        bpf_probe_read_kernel_str_bytes(filename_ptr as *const u8, path_buf)
    }.map_err(|_| 1i64)?;

    // Deny-takes-precedence evaluation (same pattern as file access)
    if unsafe { EXEC_DENY_EXACT.get(path_buf) }.is_some() {
        return Ok(-1); // -EPERM
    }
    // Check deny prefixes via LPM trie...
    // Check allow exact...
    // Check allow prefixes...
    // Check cgroup default...

    Ok(0)
}
```

**Userspace integration:** The existing `ExecPolicy` struct in `config.rs`
already has `default`, `allow`, and `deny` fields. Currently these are only
evaluated in userspace. Populate the new BPF maps from these rules, exactly
as done for file access.

#### Dynamic Linker Detection

Block the `/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /usr/bin/blocked`
bypass by denying direct invocation of dynamic linkers for watched agents:

```rust
/// Known dynamic linker paths
#[map]
static DYNAMIC_LINKERS: HashMap<[u8; MAX_FILENAME_LEN], u8> =
    HashMap::with_max_entries(16, 0);
```

**Rationale:** When a normal binary is executed, the kernel loads `ld-linux`
implicitly — `bprm_check_security` sees the actual binary path. Only when
an attacker explicitly calls `ld-linux /path/to/blocked` does the hook see
`ld-linux` as the filename.

**Populate from userspace:**
```rust
let linker_paths = [
    "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    "/lib64/ld-linux-x86-64.so.2",
    "/lib/ld-linux.so.2",            // 32-bit
    "/lib/ld-linux-aarch64.so.1",    // ARM64
];
for path in &linker_paths {
    dynamic_linkers_map.insert(path_to_key(path), 1u8, 0)?;
}
```

**In the hook:** If filename matches a dynamic linker path, return `-EPERM`
for watched agents.

#### Content Hashing (Optional, Linux 5.18+)

For Veto-like hash-based blocking, use `bpf_ima_file_hash()`:

```rust
// Requires sleepable BPF program and CONFIG_IMA=y
#[lsm(hook = "bprm_check_security", sleepable)]
pub fn guardian_exec_hash_check(ctx: LsmContext) -> i32 { ... }

#[map]
static BLOCKED_HASHES: HashMap<[u8; 32], u8> = HashMap::with_max_entries(1024, 0);

// In the hook:
let file_ptr = /* bprm->file */;
let mut hash = [0u8; 32];
let ret = bpf_ima_file_hash(file_ptr, &mut hash, 32);
if ret >= 0 {
    if BLOCKED_HASHES.get(&hash).is_some() {
        return -1; // BLOCKED by hash
    }
}
```

**First hash computation** reads entire file from disk (slow for large
binaries). IMA caches subsequent lookups until file is modified.

#### Other Bypass Vectors

| Vector | Mitigation |
|--------|-----------|
| `memfd_create` + `execveat` | Deny all `/memfd:*` paths in exec policy |
| Userland exec (reflective `mmap` + `PROT_EXEC`) | Hook `mmap_file` or `file_mprotect` LSM |
| `io_uring` based exec | LSM hooks still fire for `io_uring` operations |
| `bash enable -f` (load shared lib as builtin) | Monitor `file_open` for `.so` paths |

**Requirements:** Linux 5.7+ for LSM, 5.18+ for content hashing

---

<a name="loophole-3-network-monitoring"></a>
## 4. Loophole 3: Network Monitoring

### The Problem

Guardian Shell has zero visibility into network activity. An agent can
exfiltrate data, download malware, or communicate with C2 servers undetected.

### Solution: Cgroup-Based Network Control (Recommended)

The `cgroup/connect4` BPF program type is ideal for Guardian Shell because:
- Attaches **per-cgroup** — only fires for processes in that agent's cgroup
- Zero overhead for non-monitored processes
- Both monitors AND blocks in a single hook (return `1` = allow, `0` = deny)
- Available since kernel 4.17 (lower than BPF LSM's 5.7 requirement)
- Production-proven at scale by Cilium in Kubernetes

#### Network Event Type

Add to `guardian-common/src/lib.rs`:

```rust
#[repr(C)]
pub struct NetworkEvent {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub protocol: u8,      // IPPROTO_TCP=6, IPPROTO_UDP=17
    pub family: u8,        // AF_INET=2, AF_INET6=10
    pub _pad: [u8; 2],
    pub dest_port: u16,
    pub _pad2: u16,
    pub dest_ip4: u32,     // network byte order
    pub dest_ip6: [u32; 4],
    pub comm: [u8; 16],
}
```

#### eBPF Program

```rust
use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext};

#[map]
static BLOCKED_IPS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static BLOCKED_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

#[map]
static ALLOWED_IPS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static ALLOWED_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

/// For CIDR matching (e.g., 10.0.0.0/8)
#[map]
static BLOCKED_CIDRS: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(256, 0);

#[cgroup_sock_addr(connect4)]
pub fn guardian_net_connect4(ctx: SockAddrContext) -> i32 {
    match try_net_connect4(ctx) {
        Ok(ret) => ret,
        Err(_) => 1, // fail-open
    }
}

fn try_net_connect4(ctx: SockAddrContext) -> Result<i32, i32> {
    let sock_addr = unsafe { &*ctx.sock_addr };
    let dest_ip = sock_addr.user_ip4;
    let dest_port = (sock_addr.user_port >> 16) as u16;

    // Deny-takes-precedence
    if unsafe { BLOCKED_IPS.get(&dest_ip) }.is_some() {
        return Ok(0); // BLOCK
    }
    if unsafe { BLOCKED_PORTS.get(&dest_port) }.is_some() {
        return Ok(0); // BLOCK
    }

    // Check allow rules
    if unsafe { ALLOWED_IPS.get(&dest_ip) }.is_some() {
        return Ok(1); // ALLOW
    }
    if unsafe { ALLOWED_PORTS.get(&dest_port) }.is_some() {
        return Ok(1); // ALLOW
    }

    // Default action (from cgroup config)
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    match unsafe { NET_DEFAULT_ACTION.get(&cgroup_id) } {
        Some(&0) => Ok(0), // default deny
        _ => Ok(1),        // default allow
    }
}
```

#### Userspace Attachment

When a cgroup agent registers via IPC, attach the network filter:

```rust
use aya::programs::{CgroupSockAddr, CgroupSockAddrAttachType};

fn attach_network_filter(bpf: &mut Ebpf, cgroup_path: &str) -> Result<()> {
    let program: &mut CgroupSockAddr = bpf
        .program_mut("guardian_net_connect4")?
        .try_into()?;

    program.load()?;

    let cgroup = std::fs::File::open(cgroup_path)?;
    program.attach(cgroup, CgroupSockAddrAttachType::Connect4)?;

    Ok(())
}
```

#### Config Model

```toml
[[agents]]
name = "code-agent"
identity = "cgroup"

[agents.network]
default = "deny"

# Allow specific destinations
allow_ips = ["140.82.0.0/16"]        # GitHub IP range
allow_ports = [443, 80]              # HTTPS/HTTP only
allow_domains = [                     # Resolved to IPs at startup
    "github.com",
    "api.github.com",
    "registry.npmjs.org",
]

# Block specific destinations
deny_ips = ["169.254.169.254"]       # Cloud metadata service
deny_ports = [22, 25, 3389]          # SSH, SMTP, RDP
deny_domains = [
    "*.pastebin.com",
    "*.ngrok.io",
]
```

**Domain resolution:** At config load time, resolve `allow_domains` and
`deny_domains` to IP addresses. Populate BPF maps with resolved IPs. Run
a periodic tokio task to re-resolve (DNS TTL refresh).

#### Alternative: LSM `socket_connect` Hook

If cgroup programs aren't suitable (e.g., comm-based agents without cgroups):

```rust
#[lsm(hook = "socket_connect")]
pub fn guardian_enforce_net_connect(ctx: LsmContext) -> i32 {
    // arg(0): struct socket *
    // arg(1): struct sockaddr * (kernel pointer — direct read, no bpf_probe_read)
    // arg(2): int addrlen
    // arg(3): int ret (previous LSM return)
    ...
}
```

Same policy evaluation, but fires for all processes (must check cgroup/identity).

#### DNS Monitoring (Optional Enhancement)

**Challenge:** By the time `connect()` fires, DNS has resolved to IP.
Domain names only exist in the DNS query payload.

**Recommended hybrid approach:**
1. Resolve `allow_domains`/`deny_domains` to IPs at startup → populate BPF maps
2. Periodically re-resolve (every 5 minutes) for TTL refresh
3. Optionally hook `sys_enter_sendto` to capture port-53 UDP traffic
4. Parse DNS wire format in **userspace** (avoid eBPF complexity)
5. Map resolved IPs back to domain names for richer logging

---

<a name="loophole-4-missing-syscall-coverage"></a>
## 5. Loophole 4: Missing Syscall Coverage

### Currently Hooked Syscalls

| Syscall | Hook Type | Action |
|---------|-----------|--------|
| `openat` | Tracepoint + LSM `file_open` | Monitor + Enforce |
| `execve` | Tracepoint | Monitor only |
| `sched_process_fork` | Tracepoint | Track children |
| `sched_process_exit` | Tracepoint | Cleanup |

### Must-Have Additions

#### `openat2` (syscall 437) — Direct Bypass

**Risk:** HIGH. `openat2` is a newer syscall (Linux 5.6) that bypasses the
`sys_enter_openat` hook entirely. Rust's standard library and security-conscious
tools are adopting it.

**Fix:** Add `sys_enter_openat2` tracepoint. Same logic as `sys_enter_openat`
but different field offsets. Check:
```
cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat2/format
```

#### `renameat2` (syscall 316) — Policy Bypass via Move

**Risk:** HIGH. An agent can rename a sensitive file out of a protected
directory into an allowed one:
```bash
rename("/etc/shadow", "/tmp/shadow")  # Move to allowed dir
cat /tmp/shadow                       # Read from allowed dir
```

**Fix:** Hook LSM `security_inode_rename`. Check policy on both source and
destination paths. Block if either is in a deny list:

```rust
#[lsm(hook = "inode_rename")]
pub fn guardian_enforce_rename(ctx: LsmContext) -> i32 {
    // Args: old_dir, old_dentry, new_dir, new_dentry
    // Use bpf_d_path() to resolve both paths
    // Block if source OR destination is in deny list
}
```

#### `unlinkat` (syscall 263) — Destructive File Deletion

**Risk:** HIGH. An agent can delete config files, logs, or Guardian's own
config. Not currently detected.

**Fix:** Hook LSM `security_inode_unlink`:

```rust
#[lsm(hook = "inode_unlink")]
pub fn guardian_enforce_unlink(ctx: LsmContext) -> i32 {
    // Args: dir (inode), dentry
    // Use bpf_d_path() to resolve path
    // Block deletion of protected files
}
```

#### `linkat` (syscall 265) — Hardlink Attack

**Risk:** MEDIUM-HIGH. Similar to symlink attack. Agent creates a hardlink
to a sensitive file in an allowed directory:

```bash
link("/etc/shadow", "/tmp/shadow-link")
cat /tmp/shadow-link  # Same inode, allowed path
```

**Fix:** Hook LSM `security_inode_link`:

```rust
#[lsm(hook = "inode_link")]
pub fn guardian_enforce_link(ctx: LsmContext) -> i32 {
    // Block hardlinks to protected files
}
```

### Nice-to-Have Additions

| Syscall | Risk | Agent Usage | Approach |
|---------|------|-------------|----------|
| `open` (legacy, syscall 2) | Low | Low (glibc routes to openat) | Tracepoint monitor |
| `readlinkat` (267) | Low | Medium | Tracepoint monitor (detect recon) |
| `statx` (332) | Low | High | Tracepoint monitor (impractical to block) |
| `faccessat2` (439) | Low | Medium | Tracepoint monitor |
| `mkdirat` (258) | Low | Medium | Tracepoint monitor |
| `sendfile` / `copy_file_range` | Medium | Low | Tracepoint monitor (fd-to-fd exfiltration) |

### procfs/sysfs Attack Mitigation

Do **NOT** use blanket `/proc/**` allow. Ship precise allowlists:

```toml
allow = [
    "/proc/self/status",
    "/proc/self/stat",
    "/proc/self/cmdline",
    "/proc/self/cgroup",
    "/proc/meminfo",
    "/proc/cpuinfo",
    "/proc/loadavg",
    "/proc/version",
    "/proc/filesystems",
]
deny = [
    "/proc/self/root/**",     # Filesystem escape
    "/proc/*/fd/**",          # FD theft
    "/proc/*/mem",            # Memory read
    "/proc/*/environ",        # Environment theft (API keys, passwords)
    "/proc/kcore",            # Kernel memory
    "/proc/kallsyms",         # Kernel symbols
    "/sys/kernel/debug/**",   # Debugfs
]
```

**Best fix:** `bpf_d_path()` in the LSM hook resolves `/proc/self/root/etc/shadow`
to `/etc/shadow` automatically.

### io_uring Bypass

`io_uring` (Linux 5.1+) allows file I/O via shared ring buffers, bypassing
syscall tracepoints entirely. Known blind spot affecting Falco, Tracee, and
Microsoft Defender for Linux.

**Mitigation:** LSM hooks (`security_file_open`) still fire for `io_uring`
operations (they hook at VFS/security layer, not syscall layer). This is
another reason to move enforcement into LSM hooks. Alternatively, block
`io_uring_setup` syscall via seccomp for monitored cgroups.

### TOCTOU Fix

The current tracepoint→PENDING_DENY→LSM flow has a TOCTOU window: the
filename pointer could be modified between the tracepoint read and the LSM
check.

**Fix:** The `bpf_d_path()` approach (Loophole 1, Layer 2) eliminates this
entirely. The LSM hook evaluates policy on the kernel-resolved path, not on
the userspace-provided string. No dependency on the tracepoint for enforcement.

---

<a name="loophole-5-approval-fatigue"></a>
## 6. Loophole 5: Approval Fatigue

### The Problem

Guardian Shell's interactive permission requests can be social-engineered.
Research shows 43% of SOC analysts turn off alerts when overwhelmed, and
40% ignore incoming alerts entirely. AI agents can craft persuasive
justifications that blend into routine approval workflows.

### Solution: Multi-Layered Mitigation

#### 6a. Rate Limiting (Server-Side)

Add a `RateLimitState` per agent in the IPC handler:

```rust
pub struct AgentRateLimit {
    pub requests_this_minute: u32,
    pub requests_this_hour: u32,
    pub minute_reset: Instant,
    pub hour_reset: Instant,
    pub consecutive_denials: u32,
    pub last_denial_at: Option<Instant>,
    pub recently_denied_resources: HashMap<String, Instant>,
}
```

**Thresholds:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Max requests/minute/agent | 3 | Prevents flood attacks |
| Max requests/hour/agent | 15 | Prevents sustained harassment |
| Cooldown after denial | 30s, doubling up to 10min | Exponential backoff |
| Max pending requests/agent | 2 | Forces serialization |
| Same-resource cooldown after denial | 5 minutes | Prevents re-request spam |

**Where to add:** Check in `handle_request_permission` in `guardian/src/ipc.rs`
before creating the oneshot channel.

#### 6b. Risk Classification

Assign a risk level to each permission request based on the resource path:

| Risk Level | Color | Resources | UI Treatment |
|------------|-------|-----------|-------------|
| LOW | Green | `/tmp/**`, `/proc/self/**` | Standard banner |
| MEDIUM | Yellow | `/home/user/project/**`, general exec | 3s delay before approve |
| HIGH | Orange | `/etc/passwd`, `/var/log/**`, exec `curl`/`wget` | 5s delay, warning border |
| CRITICAL | Red | `/etc/shadow`, `~/.ssh/**`, `~/.aws/**`, `.env` | 10s delay, type-to-confirm |

**Scoring:** Base score from path pattern matching. Multiplied by:
- exec type: 1.5x
- Repeat request after denial: 2.0x
- Agent has >5 requests/hour: 1.3x

Score → risk level: 0-25 LOW, 26-50 MEDIUM, 51-75 HIGH, 76+ CRITICAL.

#### 6c. Auto-Deny for Critical Resources

Some resources should NEVER be approved via interactive request:

```toml
[permissions]
auto_deny = [
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d/**",
    "~/.ssh/id_*",
    "~/.gnupg/private-keys*",
    "/root/.bash_history",
]
```

**Implementation:** Check auto-deny list in `handle_request_permission` before
creating the oneshot channel. Return immediate denial.

#### 6d. Auto-Approve for Low-Risk Resources

Reduce decision fatigue by auto-approving genuinely safe requests:

```toml
[permissions]
auto_approve = [
    { pattern = "/tmp/**", max_duration_secs = 300 },
    { pattern = "/proc/self/**", max_duration_secs = 60 },
]
```

#### 6e. Justification Analysis (Pattern Matching)

Flag suspicious justification text:

```rust
const SUSPICIOUS_PATTERNS: &[(&str, &str)] = &[
    (r"(?i)(urgent|immediately|emergency|asap)", "URGENCY"),
    (r"(?i)(disable.?security|bypass|override|skip.?check)", "SECURITY_BYPASS"),
    (r"(?i)(trust me|don't worry|it's (safe|fine|harmless))", "REASSURANCE"),
    (r"(?i)(admin told|supervisor|authorized by)", "AUTHORITY_CLAIM"),
    (r"(?i)(ssh.?key|password|credential|secret|token)", "SENSITIVE_MENTION"),
];
```

When triggered: show warning icon, bump risk level by one tier, require
reviewer to acknowledge before approve button activates.

#### 6f. UI Friction for High-Risk Approvals

**MEDIUM risk:** 3-second countdown before approve button is clickable.

**HIGH risk:** 5-second countdown, show agent's recent activity summary.

**CRITICAL risk:** 10-second countdown, full-screen modal, require typing
the resource path to confirm:

```html
<template x-if="req.risk_level === 'critical'">
  <div>
    <p class="text-red-600 font-bold">Type the resource path to confirm:</p>
    <input type="text" x-model="confirmText" class="border-red-500">
  </div>
</template>
<button
  :disabled="!canApprove ||
    (req.risk_level === 'critical' && confirmText !== req.resource_path)"
  @click="$store.perms.approve(req.id, dur)">
  <span x-show="!canApprove" x-text="'Wait ' + waitSeconds + 's...'"></span>
  <span x-show="canApprove">Approve</span>
</button>
```

#### 6g. Persistent Audit Trail

Move from in-memory `VecDeque<ResolvedPermission>` (100 entries) to SQLite:

```sql
CREATE TABLE IF NOT EXISTS permission_audit (
    id INTEGER PRIMARY KEY,
    request_id INTEGER NOT NULL UNIQUE,
    agent_name TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_path TEXT NOT NULL,
    justification TEXT,
    risk_level TEXT,
    risk_flags TEXT,           -- JSON array of triggered patterns
    requested_at TEXT NOT NULL,
    resolved_at TEXT NOT NULL,
    approved INTEGER NOT NULL,
    reason TEXT NOT NULL,       -- "user", "auto-approve", "auto-deny", "timeout", "rate-limited"
    grant_duration_secs INTEGER
);
```

**Anomaly detection queries (hourly):**
- Approval rate > 90% in 24h → rubber-stamping warning
- Agent with > 20 requests in 24h → abuse warning
- Agent denied 5+ times then approved → persistence attack warning

---

<a name="implementation-roadmap"></a>
## 7. Implementation Roadmap

### Phase 7a: Critical Security Fixes

| # | Task | Effort | Files |
|---|------|--------|-------|
| 1 | Userspace path normalization (`normalize_path()`) | Low | `config.rs`, `main.rs` |
| 2 | LSM `file_open` with `bpf_d_path()` for enforcement | High | `guardian-ebpf/src/main.rs`, `guardian/src/main.rs` |
| 3 | LSM `bprm_check_security` for exec blocking | Medium | `guardian-ebpf/src/main.rs`, `guardian/src/main.rs`, `config.rs` |
| 4 | Dynamic linker detection + blocking | Low | `guardian-ebpf/src/main.rs` |
| 5 | Hook `openat2` tracepoint | Low | `guardian-ebpf/src/main.rs` |
| 6 | LSM `inode_rename` for rename blocking | Medium | `guardian-ebpf/src/main.rs` |
| 7 | LSM `inode_unlink` for delete blocking | Medium | `guardian-ebpf/src/main.rs` |

### Phase 7b: Network Monitoring

| # | Task | Effort | Files |
|---|------|--------|-------|
| 8 | `NetworkEvent` type in `guardian-common` | Low | `guardian-common/src/lib.rs` |
| 9 | `cgroup/connect4` + `cgroup/connect6` programs | Medium | `guardian-ebpf/src/main.rs` |
| 10 | Userspace cgroup attachment on agent registration | Medium | `guardian/src/ipc.rs`, `main.rs` |
| 11 | Network policy config (`[agents.network]`) | Medium | `guardian/src/config.rs` |
| 12 | Domain → IP resolution at startup + periodic refresh | Medium | `guardian/src/main.rs` |
| 13 | Dashboard network events display | Low | Templates, `routes/`, `sse.rs` |

### Phase 7c: Approval Hardening

| # | Task | Effort | Files |
|---|------|--------|-------|
| 14 | Rate limiting per agent | Low | `guardian/src/ipc.rs` |
| 15 | Auto-deny for critical resources | Low | `guardian/src/ipc.rs`, `config.rs` |
| 16 | Risk classification + scoring | Medium | `guardian/src/ipc.rs`, new module |
| 17 | Auto-approve for low-risk resources | Low | `guardian/src/ipc.rs`, `config.rs` |
| 18 | Justification pattern matching | Medium | New module |
| 19 | Mandatory wait timers in UI | Low | `templates/base.html`, `static/app.js` |
| 20 | Type-to-confirm for CRITICAL resources | Low | `templates/requests.html` |
| 21 | Persistent SQLite audit trail | Medium | `guardian/src/ipc.rs`, `dashboard/state.rs` |

### Phase 7d: Advanced Hardening

| # | Task | Effort | Files |
|---|------|--------|-------|
| 22 | Inode-based deny map for critical files | Medium | `guardian-ebpf/src/main.rs` |
| 23 | LSM `inode_link` for hardlink blocking | Low | `guardian-ebpf/src/main.rs` |
| 24 | Content hashing via `bpf_ima_file_hash` (5.18+) | High | `guardian-ebpf/src/main.rs` |
| 25 | `io_uring` blocking via seccomp | Low | `guardian-launch/src/main.rs` |
| 26 | `mmap_file` LSM hook for MAP_SHARED writes | Medium | `guardian-ebpf/src/main.rs` |
| 27 | DNS monitoring (sendto tracepoint + userspace parse) | High | Multiple |
| 28 | Anomaly detection on approval patterns | Medium | New module |
| 29 | `/proc/<pid>/fd/` audit on agent registration | Low | `guardian/src/ipc.rs` |

### Dependency Graph

```
Phase 7a (Critical)                    Phase 7b (Network)
  1 → 2 (path normalization → LSM)      8 → 9 → 10 → 11 → 12 → 13
  3 → 4 (exec enforce → ld-linux)
  5 (openat2 — independent)           Phase 7c (Approval)
  6, 7 (rename, unlink — independent)    14, 15 (independent — do first)
                                         16 → 17, 18, 19, 20
                                         21 (independent)
```

Tasks within the same phase can be parallelized. Phase 7a should be done
first as it addresses the most critical vulnerabilities.

---

<a name="references"></a>
## 8. References

### Path Resolution
- [bpf_d_path Helper — eBPF Docs](https://docs.ebpf.io/linux/helper-function/bpf_d_path/)
- [Kernel commit: Add d_path helper (Linux 5.10)](https://github.com/torvalds/linux/commit/6e22ab9da79343532cd3cde39df25e5a5478c692)
- [Sleepable LSM hooks patchset (Linux 5.11)](https://lore.kernel.org/bpf/20201112171907.373433-1-kpsingh@chromium.org/T/)
- [Falco symlink bypass — GitHub issue #1111](https://github.com/falcosecurity/libs/issues/1111)
- [BPFContain inode-based matching (paper)](https://arxiv.org/pdf/2102.06972)
- [On Bypassing eBPF Security Monitoring — Doyensec](https://blog.doyensec.com/2022/10/11/ebpf-bypass-security-monitoring.html)

### Exec Enforcement
- [eBPF LSM Synchronous Execution Prevention](https://www.dawidmacek.com/posts/2025/ebpf-lsm-synchronous-execution-prevention/)
- [bpf_ima_file_hash — eBPF Docs](https://docs.ebpf.io/linux/helper-function/bpf_ima_file_hash/)
- [deepfence/ebpfguard — Aya-based LSM enforcement](https://github.com/deepfence/ebpfguard)
- [Bypassing eBPF Tools — Form3](https://www.form3.tech/blog/engineering/bypassing-ebpf-tools)
- [linux_binprm struct — kernel source](https://github.com/torvalds/linux/blob/master/include/linux/binfmts.h)

### Network Monitoring
- [Aya cgroup_sock_addr macro](https://docs.rs/aya-ebpf-macros/latest/aya_ebpf_macros/attr.cgroup_sock_addr.html)
- [BPF_PROG_TYPE_CGROUP_SOCK_ADDR — eBPF Docs](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/)
- [Preventing Data Exfiltration with eBPF — Teleport](https://goteleport.com/blog/preventing-data-exfiltration-with-ebpf/)
- [Busted: eBPF LLM Communication Monitoring](https://github.com/barakber/busted)
- [eBPF DNS Monitoring](https://oneuptime.com/blog/post/2026-01-07-ebpf-dns-monitoring/view)

### Syscall Coverage
- [Tetragon Hook Points](https://tetragon.io/docs/concepts/tracing-policy/hooks/)
- [Tracee — Using LSM Hooks to Overcome Gaps with Syscall Tracing](https://www.aquasec.com/blog/linux-vulnerabilitie-tracee/)
- [io_uring Rootkit Bypasses Linux Security — ARMO](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [LSM BPF Programs — Linux Kernel Docs](https://docs.kernel.org/bpf/prog_lsm.html)

### Approval Fatigue
- [NVIDIA — Security Guidance for Sandboxing Agentic Workflows](https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/)
- [Permit.io — Human-in-the-Loop Best Practices](https://www.permit.io/blog/human-in-the-loop-for-ai-agents-best-practices-frameworks-use-cases-and-demo)
- [CyberDefenders — SOC Alert Fatigue](https://cyberdefenders.org/blog/soc-alert-fatigue/)
- [NN/g — Confirmation Dialogs](https://www.nngroup.com/articles/confirmation-dialog/)
- [Smashing Magazine — Managing Dangerous Actions in UIs](https://www.smashingmagazine.com/2024/09/how-manage-dangerous-actions-user-interfaces/)
- [Reversec — Design Patterns to Secure LLM Agents](https://labs.reversec.com/posts/2025/08/design-patterns-to-secure-llm-agents-in-action)

### General
- [Ona — How Claude Code Escapes Its Own Denylist and Sandbox](https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox)
- [Aya eBPF book — LSM Programs](https://aya-rs.dev/book/programs/lsm)
- [Linux Security Modules Documentation](https://docs.kernel.org/security/lsm.html)
