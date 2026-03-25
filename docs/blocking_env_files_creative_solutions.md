# Blocking `*.env` Files — Creative Solutions for Guardian Shell

The problem: an LLM agent must be prevented from reading any file ending with
`.env` — anywhere on the filesystem, at any depth, including files that don't
exist yet.

This is harder than it sounds. Guardian Shell's current enforcement uses exact
paths and prefix patterns (`/etc/shadow`, `/home/**`). There is no **suffix
matching** — no way to say "block all files ending with `.env`." Landlock works
on inodes, not filename patterns. And `.env` files can appear anywhere, be
created at runtime, be renamed, symlinked, or hardlinked.

This document explores 15 approaches — from straightforward eBPF modifications
to creative out-of-the-box techniques — each with architecture, implementation
sketch, and trade-offs.

---

## Table of Contents

**Kernel-Level Approaches:**
1. [eBPF Suffix Matching in Tracepoint](#1-ebpf-suffix-matching-in-tracepoint)
2. [eBPF LSM file_open with bpf_d_path()](#2-ebpf-lsm-file_open-with-bpf_d_path)
3. [Deny Suffix BPF Map](#3-deny-suffix-bpf-map)

**Userspace Interception:**
4. [fanotify Permission Events](#4-fanotify-permission-events)
5. [Hybrid: fanotify Watcher + BPF Deny Map](#5-hybrid-fanotify--bpf-deny-map)

**Filesystem Tricks:**
6. [Bind-Mount Masking (/dev/null Overlay)](#6-bind-mount-masking)
7. [FUSE Passthrough with Pattern Filter](#7-fuse-passthrough-with-pattern-filter)
8. [OverlayFS Whiteout Hiding](#8-overlayfs-whiteout-hiding)
9. [Mount Namespace File Hiding](#9-mount-namespace-file-hiding)

**Content-Aware:**
10. [eBPF read() Content Redaction](#10-ebpf-read-content-redaction)
11. [Encrypted .env Files with Cgroup-Aware Key Vault](#11-encrypted-env-with-cgroup-aware-vault)

**Defense-in-Depth:**
12. [Extended Attributes (xattr) Labeling](#12-xattr-labeling)
13. [Honeypot .env Files (Canary Tokens)](#13-honeypot-env-files)
14. [Git Hook Quarantine](#14-git-hook-quarantine)
15. [Agent-Transparent Secret Vault Process](#15-agent-transparent-secret-vault)

**[Comparison Matrix](#comparison-matrix)**
**[Recommended Approach](#recommended-approach)**

---

## 1. eBPF Suffix Matching in Tracepoint

### The Idea

Guardian Shell's `sys_enter_openat` tracepoint already reads the full filename
into a 256-byte buffer. Currently, `evaluate_policy()` checks exact matches and
prefix matches. We add a **suffix check** — if the filename ends with `.env`,
deny immediately.

### How It Works

```
sys_enter_openat tracepoint fires:
  filename = "/home/user/projects/webapp/.env"
  filename_len = 40

New suffix check (before evaluate_policy):
  offset = 40 - 4 = 36
  filename[36..40] = ".env"
  → MATCH → set PENDING_DENY → LSM file_open returns -EACCES
```

### Implementation

**File: `guardian-ebpf/src/main.rs`**

New BPF map for suffix patterns:

```rust
/// Deny suffixes: key = suffix bytes (right-aligned in array), value = suffix length.
/// Example: ".env" stored as [0,0,...,'.','e','n','v'], length = 4.
#[map]
static DENY_SUFFIXES: HashMap<[u8; 16], u8> = HashMap::with_max_entries(64, 0);
```

New helper function:

```rust
/// Check if filename ends with any denied suffix.
/// Works by extracting the last N bytes and comparing against DENY_SUFFIXES map.
#[inline(always)]
fn has_denied_suffix(filename: &[u8; MAX_FILENAME_LEN], filename_len: usize) -> bool {
    // Check suffixes of length 4 through 16
    // This handles: .env (4), .env.local (10), .pem (4), .key (4), etc.
    //
    // For each possible suffix length, extract the last N bytes of the filename,
    // right-align them in a 16-byte key, and look up in DENY_SUFFIXES.
    //
    // eBPF verifier requires bounded loops — we unroll for common lengths.

    // .env = 4 bytes
    if filename_len >= 4 {
        let mut key = [0u8; 16];
        let start = filename_len - 4;
        // Bounds check for verifier
        if start < MAX_FILENAME_LEN - 3 {
            key[12] = filename[start];
            key[13] = filename[start + 1];
            key[14] = filename[start + 2];
            key[15] = filename[start + 3];
            if unsafe { DENY_SUFFIXES.get(&key) }.is_some() {
                return true;
            }
        }
    }

    // .env.local = 10 bytes, .env.prod = 9 bytes, etc.
    // Check if ".env." appears anywhere in the last 16 bytes
    // This catches .env.local, .env.production, .env.staging
    if filename_len >= 5 {
        // Scan backwards for ".env" pattern
        let scan_start = if filename_len > 16 { filename_len - 16 } else { 0 };
        let scan_end = if filename_len > 4 { filename_len - 4 } else { 0 };

        // Bounded loop for eBPF verifier (max 16 iterations)
        let mut i = scan_start;
        while i <= scan_end && i < MAX_FILENAME_LEN - 4 {
            if filename[i] == b'.'
                && filename[i + 1] == b'e'
                && filename[i + 2] == b'n'
                && filename[i + 3] == b'v'
            {
                return true;
            }
            i += 1;
            if i - scan_start >= 16 { break; } // Bound for verifier
        }
    }

    false
}
```

Integrate into the openat tracepoint:

```rust
// In try_guardian_file_open(), after reading filename, before evaluate_policy:

if is_process_enforcing(&comm, tgid, cgroup_id) && event.filename_len > 0 && !is_o_path {
    // NEW: Check denied suffixes (e.g., .env, .pem, .key)
    if has_denied_suffix(&event.filename, event.filename_len as usize) {
        pending_insert_with_overflow(&PENDING_DENY, &PENDING_DENY_OVERFLOW, &pid_tgid);
    } else if event.status_flags & EVENT_FLAG_TRUNCATED != 0 {
        pending_insert_with_overflow(&PENDING_DENY, &PENDING_DENY_OVERFLOW, &pid_tgid);
    } else {
        let allowed = evaluate_policy(/* ... */);
        if !allowed {
            pending_insert_with_overflow(&PENDING_DENY, &PENDING_DENY_OVERFLOW, &pid_tgid);
        }
    }
}
```

**Userspace: populate the DENY_SUFFIXES map from config:**

```toml
# config.toml
[agents.file_access]
default = "deny"
deny_suffixes = [".env", ".pem", ".key", ".secret"]
```

### Pros
- **In-kernel enforcement** — zero latency, no userspace round-trip
- **Works for any path** — no need to know file locations in advance
- **Catches new files** — files created during agent runtime are blocked
- **Small code change** — adds ~30 lines to the eBPF program
- **Composable** — works alongside existing exact/prefix deny rules

### Cons
- **Path-based, not inode-based** — vulnerable to the same symlink issues as existing eBPF enforcement (but Landlock covers this for cgroup agents)
- **Fixed suffix length scanning** — eBPF verifier requires bounded loops, limiting how many suffix lengths we check
- **False positives** — a file named `development` would not match, but `/path/to/.environment` would match the `.env` substring scan. Needs careful pattern design.
- **No content awareness** — a `.env` file renamed to `.txt` would not be caught

### Verdict: Best first step — simple, fast, kernel-level

---

## 2. eBPF LSM file_open with bpf_d_path()

### The Idea

Instead of checking the filename in the tracepoint (which sees the raw
user-provided path string), check it in the LSM `file_open` hook using
`bpf_d_path()`. This gives the **kernel-resolved path** — after symlink
resolution, mount traversal, and canonicalization. Immune to path manipulation.

### How It Works

```
Agent: open("/workspace/symlink_to_env")
  symlink_to_env → /home/user/.env

Tracepoint sees: "/workspace/symlink_to_env" (no ".env" match!)
LSM file_open with bpf_d_path() sees: "/home/user/.env" (MATCH → DENY)
```

### Implementation

```rust
#[lsm(hook = "file_open")]
pub fn guardian_enforce_file_open(ctx: LsmContext) -> i32 {
    // ... existing PENDING_DENY check ...

    // NEW: Suffix check on resolved path
    // bpf_d_path() requires a struct path * from the file argument
    // The file_open LSM hook receives (struct file *file)
    // file->f_path gives us the resolved path

    let file_ptr: *const u8 = unsafe { ctx.arg(0) };
    if file_ptr.is_null() { return 0; }

    // Read f_path from struct file (offset depends on kernel version)
    // Use bpf_d_path() to get the full resolved path
    let mut path_buf = [0u8; 256];
    let path_len = unsafe {
        // bpf_d_path(path, buf, buf_size) -> resolved path length
        aya_ebpf::helpers::bpf_d_path(/* path ptr */, path_buf.as_mut_ptr(), 256)
    };

    if path_len > 4 {
        let len = path_len as usize;
        // Check if resolved path ends with ".env"
        if path_buf[len-4] == b'.' && path_buf[len-3] == b'e'
            && path_buf[len-2] == b'n' && path_buf[len-1] == b'v'
        {
            return -13; // -EACCES
        }
    }

    0
}
```

### Pros
- **Symlink-immune** — `bpf_d_path()` resolves the real path
- **Kernel-enforced** — blocks in the LSM hook, no PENDING map needed
- **Canonical path** — no TOCTOU between tracepoint and LSM

### Cons
- **`bpf_d_path()` availability** — requires kernel 5.10+ and `CONFIG_BPF_LSM=y`. Works in `file_open` LSM context but may be rejected by the verifier in some kernel versions.
- **Significant complexity** — accessing `struct file` fields in eBPF requires knowing exact struct offsets (varies by kernel). Would need BTF (BPF Type Format) support.
- **Breaking change** — current LSM hook is simple (check PENDING map). Adding path resolution makes it much more complex and harder to maintain.
- **Performance** — `bpf_d_path()` does a dcache walk on every file open. More expensive than a map lookup.

### Verdict: Powerful but complex — pursue when BTF support is solid

---

## 3. Deny Suffix BPF Map

### The Idea

Instead of hardcoding suffix logic in eBPF, create a general-purpose
**suffix matching engine** using BPF maps. Store reversed suffixes in a BPF
HashMap. For each file open, reverse the last N bytes of the filename and look
up in the map.

### How It Works

```
DENY_SUFFIXES map (reversed):
  "vne." → 1    (reverse of ".env")
  "mep." → 1    (reverse of ".pem")
  "yek." → 1    (reverse of ".key")

File open: "/workspace/.env.production"
  Reverse last 4 chars: "noit"  → no match
  Reverse last 5 chars: "oitcu" → no match
  ...
  This doesn't work for variable-length suffixes efficiently.

Better approach — scan for ".env" as a SUBSTRING in the last component:

File open: "/workspace/.env.production"
  Extract last component: ".env.production"
  Check if ".env" appears in it: YES → DENY
```

### Implementation

The key insight: we don't need to match the exact suffix. We need to detect
the pattern `.env` anywhere in the **filename component** (not the directory
part). This catches `.env`, `.env.local`, `.env.production`, `secrets.env`,
and `.env.bak` — all variations.

```rust
/// Extract the filename component (after last '/') and check for pattern.
#[inline(always)]
fn filename_contains_pattern(
    path: &[u8; MAX_FILENAME_LEN],
    path_len: usize,
    pattern: &[u8],      // e.g., b".env"
    pattern_len: usize,
) -> bool {
    // Find the last '/' to get the filename component
    let mut last_slash = 0;
    let mut i = 0;
    while i < path_len && i < MAX_FILENAME_LEN {
        if path[i] == b'/' {
            last_slash = i + 1;
        }
        i += 1;
    }

    // Scan filename component for pattern
    let component_start = last_slash;
    let component_len = path_len - component_start;

    if component_len < pattern_len {
        return false;
    }

    let mut j = component_start;
    let end = component_start + component_len - pattern_len;
    while j <= end && j < MAX_FILENAME_LEN - pattern_len {
        let mut matched = true;
        let mut k = 0;
        while k < pattern_len {
            if path[j + k] != pattern[k] {
                matched = false;
                break;
            }
            k += 1;
        }
        if matched {
            return true;
        }
        j += 1;
        if j - component_start >= 64 { break; } // Verifier bound
    }

    false
}
```

### Pros
- Catches all `.env` variants: `.env`, `.env.local`, `secrets.env`, `.env.bak`
- Operates on filename component only (won't match `/home/environment/data.txt`)
- General-purpose — works for any pattern, not just `.env`

### Cons
- eBPF verifier may reject the nested loops (depends on kernel version)
- Scanning is O(n) per pattern per file open — acceptable for small patterns
- Still path-based (symlink-vulnerable for non-Landlock agents)

### Verdict: More flexible than Approach 1, moderate complexity

---

## 4. fanotify Permission Events

### The Idea

Linux `fanotify` (File Access Notification) provides **permission events** —
the kernel asks userspace "should this file be opened?" and waits for a
yes/no answer before completing the syscall. This is the mechanism used by
Linux antivirus scanners.

### How It Works

```
┌─────────────────────────────────────┐
│ Guardian Daemon                     │
│                                     │
│ fanotify_init(FAN_CLASS_CONTENT)    │
│ fanotify_mark(FAN_OPEN_PERM, "/")  │
│                                     │
│ Loop:                               │
│   event = read(fanotify_fd)         │
│   path = readlink(/proc/self/fd/N)  │
│   if path ends with ".env":         │
│     write(fanotify_fd, FAN_DENY)    │
│   else:                             │
│     write(fanotify_fd, FAN_ALLOW)   │
└──────────┬──────────────────────────┘
           │
           │  Kernel waits for response
           │  before completing open()
           ▼
┌─────────────────────────────────────┐
│ Agent process                       │
│                                     │
│ open("/workspace/.env")             │
│ → Kernel sends permission event     │
│ → Guardian daemon checks filename   │
│ → Returns FAN_DENY                  │
│ → Agent gets -EPERM                 │
└─────────────────────────────────────┘
```

### Implementation

**File: `guardian/src/fanotify.rs`** (new module)

```rust
use std::os::unix::io::RawFd;
use std::ffi::CString;

const FAN_OPEN_PERM: u64 = 0x00010000;
const FAN_CLASS_CONTENT: u32 = 0x04;
const FAN_CLOEXEC: u32 = 0x01;
const FAN_NONBLOCK: u32 = 0x02;
const FAN_UNLIMITED_MARKS: u32 = 0x20;

const FAN_ALLOW: u32 = 0x01;
const FAN_DENY: u32 = 0x02;

/// Patterns to deny (checked against the last path component)
const DENY_PATTERNS: &[&str] = &[".env", ".pem", ".key", ".secret"];

pub struct FanotifyGuard {
    fd: RawFd,
    deny_patterns: Vec<String>,
    /// Only enforce for PIDs in watched cgroups
    watched_cgroup_pids: HashSet<u32>,
}

impl FanotifyGuard {
    pub fn new(deny_patterns: Vec<String>) -> anyhow::Result<Self> {
        let fd = unsafe {
            libc::fanotify_init(
                FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK | FAN_UNLIMITED_MARKS,
                libc::O_RDONLY,
            )
        };
        if fd < 0 {
            anyhow::bail!("fanotify_init failed: {}", std::io::Error::last_os_error());
        }

        // Watch the entire filesystem for open permission events
        let root = CString::new("/").unwrap();
        let ret = unsafe {
            libc::fanotify_mark(
                fd,
                libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                FAN_OPEN_PERM as u64,
                libc::AT_FDCWD,
                root.as_ptr(),
            )
        };
        if ret < 0 {
            anyhow::bail!("fanotify_mark failed: {}", std::io::Error::last_os_error());
        }

        Ok(Self { fd, deny_patterns, watched_cgroup_pids: HashSet::new() })
    }

    /// Process permission events in a loop
    pub async fn run(&self) -> anyhow::Result<()> {
        loop {
            let event = self.read_event()?;

            // Only enforce for watched agent processes
            if !self.is_watched_pid(event.pid) {
                self.respond(event.fd, FAN_ALLOW)?;
                continue;
            }

            // Get the file path from the event fd
            let path = self.fd_to_path(event.fd)?;

            // Check filename component against deny patterns
            let filename = path.file_name().unwrap_or_default();
            let filename_str = filename.to_string_lossy();

            let should_deny = self.deny_patterns.iter().any(|pattern| {
                filename_str.contains(pattern)
            });

            if should_deny {
                log::warn!("fanotify DENY: pid={} path={}", event.pid, path.display());
                self.respond(event.fd, FAN_DENY)?;
            } else {
                self.respond(event.fd, FAN_ALLOW)?;
            }

            // Close the event fd
            unsafe { libc::close(event.fd); }
        }
    }
}
```

### Pros
- **Kernel-assisted, userspace-decided** — full Rust string matching in userspace
- **Regex support** — can use any pattern matching library (regex, glob)
- **Path-resolved** — fanotify gives the resolved path via `/proc/self/fd/`
- **No eBPF changes** — purely userspace addition
- **Content inspection possible** — the event fd can be read to inspect file content before allowing access

### Cons
- **Performance overhead** — every file open by any process goes through fanotify. Even with PID filtering, the kernel must create and deliver the event.
- **Single-threaded bottleneck** — `FAN_CLASS_CONTENT` requires ordered processing. Slow decisions block all file opens system-wide.
- **Requires CAP_SYS_ADMIN** — same as eBPF, but it's an additional subsystem
- **Race condition window** — between fanotify decision and actual open, the file could be swapped (TOCTOU). Smaller window than tracepoint-LSM pattern but not zero.
- **Complexity** — managing fanotify alongside eBPF is two separate enforcement systems

### Verdict: Powerful for rich pattern matching, but performance concerns

---

## 5. Hybrid: fanotify Watcher + BPF Deny Map

### The Idea (Creative)

Combine the best of both worlds: use fanotify as a **discovery mechanism** to
find `.env` files in real-time, then add their **inodes** to a BPF deny map
for kernel-level enforcement.

```
┌─────────────────────────────────────────────────────┐
│ DISCOVERY LAYER (fanotify — fast, low-overhead)     │
│                                                     │
│ fanotify_mark(FAN_CREATE | FAN_MOVED_TO, "/")       │
│                                                     │
│ Watches for file creation and rename events.        │
│ When a new file is created or renamed:              │
│   if filename matches *.env:                        │
│     stat(file) → get inode number                   │
│     add inode to INODE_DENY BPF HashMap             │
│                                                     │
│ Also: initial filesystem scan on daemon startup     │
│   find / -name "*.env" → add all inodes to map     │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│ ENFORCEMENT LAYER (BPF LSM — zero overhead)         │
│                                                     │
│ LSM file_open:                                      │
│   inode = file->f_inode->i_ino                      │
│   dev = file->f_inode->i_sb->s_dev                  │
│   key = (dev, inode)                                │
│   if INODE_DENY.get(&key):                          │
│     return -EACCES                                  │
│                                                     │
│ Enforcement is O(1) HashMap lookup per file open.   │
│ No string matching, no path resolution, just inode. │
└─────────────────────────────────────────────────────┘
```

### Why This Is Creative

Neither fanotify nor eBPF alone solves the problem well:
- fanotify can match patterns but has performance overhead on every file open
- eBPF is fast but can't do rich pattern matching
- Landlock works on inodes but its rules are immutable after sandbox creation

This hybrid uses fanotify's **event stream** (not permission events — much lower
overhead since it doesn't block) to discover `.env` files, then leverages eBPF's
**O(1) inode lookup** for enforcement. Discovery is asynchronous; enforcement is
synchronous and kernel-fast.

### Implementation

**New BPF map in `guardian-ebpf/src/main.rs`:**

```rust
/// Inode deny map: key = (device_id: u64, inode_number: u64), value = 1.
/// Populated by userspace when .env files are discovered.
#[map]
static INODE_DENY: HashMap<[u8; 16], u8> = HashMap::with_max_entries(4096, 0);
```

**LSM file_open enhancement:**

```rust
#[lsm(hook = "file_open")]
pub fn guardian_enforce_file_open(ctx: LsmContext) -> i32 {
    // ... existing PENDING_DENY check ...

    // NEW: Check inode deny map
    // Read inode from struct file → f_inode → i_ino
    // Read device from struct file → f_inode → i_sb → s_dev
    //
    // (Requires BTF or known struct offsets)
    let file_ptr = unsafe { ctx.arg::<*const u8>(0) };
    // ... extract inode and dev ...
    let mut key = [0u8; 16];
    key[0..8].copy_from_slice(&dev.to_ne_bytes());
    key[8..16].copy_from_slice(&inode.to_ne_bytes());

    if unsafe { INODE_DENY.get(&key) }.is_some() {
        return -13; // -EACCES
    }

    // ... existing logic ...
}
```

**Userspace fanotify watcher in `guardian/src/inode_watcher.rs`:**

```rust
/// Watches for .env file creation/rename and adds inodes to BPF deny map.
pub async fn inode_deny_watcher(
    deny_patterns: Vec<String>,
    inode_deny_map: &mut aya::maps::HashMap<MapData, [u8; 16], u8>,
) -> anyhow::Result<()> {
    // Phase 1: Initial scan — find all existing .env files
    for entry in walkdir::WalkDir::new("/workspace") {
        if let Ok(e) = entry {
            let name = e.file_name().to_string_lossy();
            if deny_patterns.iter().any(|p| name.contains(p)) {
                let meta = e.metadata()?;
                add_inode_to_deny_map(inode_deny_map, meta.dev(), meta.ino())?;
                log::info!("inode_deny: blocked {} (dev={}, ino={})",
                    e.path().display(), meta.dev(), meta.ino());
            }
        }
    }

    // Phase 2: Watch for new .env files (fanotify FAN_CREATE | FAN_MOVED_TO)
    // ... fanotify event loop, non-blocking ...
    // When new .env file detected:
    //   stat(path) → add (dev, ino) to INODE_DENY map
}
```

### Pros
- **Inode-based enforcement** — immune to symlinks, hardlinks, path manipulation
- **Zero enforcement overhead** — BPF HashMap lookup is O(1)
- **Dynamic** — new `.env` files discovered in real-time via fanotify
- **No eBPF string matching needed** — pattern matching is in userspace (unlimited flexibility)
- **Composable** — works alongside existing Landlock + eBPF enforcement
- **Catches renames** — `FAN_MOVED_TO` detects `mv secrets.txt .env`

### Cons
- **Startup scan delay** — initial walkdir scan can be slow on large filesystems
- **Race window** — between `.env` file creation and fanotify event processing, there's a brief window where the file is accessible. Mitigate with eBPF suffix matching (Approach 1) as backup.
- **Requires BTF or kernel struct offsets** — reading inode/dev from `struct file` in LSM hook needs BTF support or hardcoded offsets
- **Map cleanup needed** — deleted `.env` files leave stale inode entries (inodes can be reused). Need periodic cleanup.

### Verdict: Most architecturally sound — combines discovery + enforcement

---

## 6. Bind-Mount Masking

### The Idea (Creative)

Before launching the agent, scan the workspace for `.env` files and
**bind-mount `/dev/null` over each one**. The agent sees the file in directory
listings (it still exists), but reading it returns empty content. Writing to it
goes to `/dev/null` (discarded).

```
Before bind-mount:
  /workspace/.env contains "API_KEY=sk-ant-real-key"

After bind-mount:
  mount --bind /dev/null /workspace/.env

Agent sees:
  $ ls -la /workspace/.env
  -rw-r--r-- 1 root root 0 Mar 25 10:00 /workspace/.env
  $ cat /workspace/.env
  (empty — reads /dev/null)
```

### Implementation

**File: `guardian-launch/src/main.rs`**

```rust
/// Scan workspace and bind-mount /dev/null over all .env files
fn mask_env_files(workspace: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut masked = Vec::new();

    for entry in walkdir::WalkDir::new(workspace)
        .follow_links(false) // Don't follow symlinks
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let name = entry.file_name().to_string_lossy();
        if name.contains(".env") && entry.file_type().is_file() {
            let path = entry.path();
            // Bind-mount /dev/null over the .env file
            let ret = unsafe {
                libc::mount(
                    b"/dev/null\0".as_ptr() as *const _,
                    CString::new(path.to_str().unwrap())?.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            };
            if ret == 0 {
                log::info!("Masked: {} → /dev/null", path.display());
                masked.push(path.to_path_buf());
            }
        }
    }

    Ok(masked)
}
```

### Pros
- **Invisible to agent** — file appears to exist but is empty. Agent doesn't get an error, just empty content. Less likely to trigger retry logic.
- **No eBPF changes** — pure userspace technique
- **Fast** — bind mount is a single syscall per file
- **Works with Landlock** — bind mounts happen before Landlock is applied

### Cons
- **Static** — only catches `.env` files that exist at launch time. Files created during agent runtime are not masked.
- **Requires root** — bind mounting requires `CAP_SYS_ADMIN`
- **Mount table pollution** — each masked file is a mount point. Hundreds of `.env` files = hundreds of mounts.
- **Cleanup complexity** — must `umount` each masked file on agent exit
- **Agent can detect** — `stat()` shows different device/inode for `/dev/null`
- **seccomp interaction** — if mount syscall is blocked by seccomp, this must run before seccomp is applied

### Verdict: Simple and effective for known files, but static

---

## 7. FUSE Passthrough with Pattern Filter

### The Idea (Creative)

Mount a **FUSE filesystem** over the workspace that passes through all
operations transparently, except for files matching `*.env` — those return
`EACCES` on open or appear empty.

```
/workspace (real)           /workspace (FUSE overlay)
├── src/                    ├── src/                    ← passthrough
├── package.json            ├── package.json            ← passthrough
├── .env          ──────►   ├── .env                    ← EACCES on open
├── .env.local    ──────►   ├── .env.local              ← EACCES on open
└── config.toml             └── config.toml             ← passthrough
```

### Implementation

A small Rust FUSE daemon using the `fuser` crate:

```rust
use fuser::{Filesystem, Request, ReplyEntry, ReplyOpen, ReplyData};

struct FilteredFs {
    source_dir: PathBuf,
    deny_patterns: Vec<String>,
}

impl Filesystem for FilteredFs {
    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let path = self.inode_to_path(ino);
        let filename = path.file_name().unwrap_or_default().to_string_lossy();

        // Check if filename matches any deny pattern
        if self.deny_patterns.iter().any(|p| filename.contains(p)) {
            reply.error(libc::EACCES);
            return;
        }

        // Passthrough to real filesystem
        let fd = unsafe { libc::open(path.as_ptr(), flags) };
        reply.opened(fd as u64, 0);
    }

    fn read(&mut self, _req: &Request, ino: u64, /* ... */) {
        // Passthrough — only .env files are blocked at open()
    }

    // ... other ops passthrough ...
}
```

### Pros
- **Transparent** — agent doesn't know it's on a FUSE mount
- **Pattern-based** — full regex/glob matching in userspace
- **Dynamic** — catches new `.env` files created during runtime
- **Can redact content instead of blocking** — return file with secrets replaced by `***`
- **Can hide from directory listings** — `.env` files don't appear in `readdir`

### Cons
- **Performance overhead** — every file operation crosses kernel→userspace→kernel boundary via FUSE
- **Complexity** — implementing a full FUSE filesystem correctly is significant work
- **Single point of failure** — if the FUSE daemon crashes, the entire filesystem becomes inaccessible
- **Compatibility** — some tools behave differently on FUSE mounts (inotify, mmap, O_DIRECT)
- **Not available inside Landlock sandbox** — mounting FUSE requires privileges the agent shouldn't have. Must be set up before Landlock.

### Verdict: Maximum flexibility, but heavy engineering cost

---

## 8. OverlayFS Whiteout Hiding

### The Idea (Creative)

Use an OverlayFS mount where the upper layer contains **whiteout files** for
every `.env` file. Whiteout files are a kernel feature of OverlayFS that make
lower-layer files disappear — the file literally does not exist in the merged
view.

```
Lower (real workspace):     Upper (whiteout layer):     Merged (agent sees):
├── src/                    ├── (empty)                 ├── src/
├── .env                    ├── .env  [whiteout]        │   (NO .env!)
├── .env.local              ├── .env.local [whiteout]   │   (NO .env.local!)
└── config.toml             └── (empty)                 └── config.toml
```

Whiteout files are special character devices `(0, 0)` that tell OverlayFS to
hide the lower layer file.

### Implementation

```bash
# Before launching agent:

# 1. Create upper and work directories
mkdir -p /tmp/guardian-overlay/upper /tmp/guardian-overlay/work

# 2. Scan workspace for .env files and create whiteouts
for envfile in $(find /workspace -name "*.env" -o -name ".env*"); do
    relative="${envfile#/workspace/}"
    mkdir -p "/tmp/guardian-overlay/upper/$(dirname "$relative")"
    mknod "/tmp/guardian-overlay/upper/$relative" c 0 0  # whiteout
done

# 3. Mount overlay
mount -t overlay overlay \
    -o lowerdir=/workspace,upperdir=/tmp/guardian-overlay/upper,workdir=/tmp/guardian-overlay/work \
    /workspace-safe

# 4. Agent uses /workspace-safe instead of /workspace
# .env files are completely invisible — not in ls, not accessible, ENOENT on open
```

### Pros
- **Complete invisibility** — `.env` files don't appear in directory listings at all. `ls`, `find`, `stat` — all return as if the file doesn't exist.
- **Kernel-enforced** — OverlayFS whiteout is a kernel feature, not userspace filtering
- **No performance overhead for non-.env files** — OverlayFS passthrough is near-native
- **Agent writes go to upper layer** — agent can create new files without affecting the real workspace

### Cons
- **Static** — whiteout files must be created before mount. New `.env` files created in the lower layer during runtime are visible (OverlayFS doesn't auto-whiteout).
- **Write-through complexity** — files the agent creates go to the upper layer. Syncing back to the real workspace requires manual merging.
- **`.env` files are truly gone** — if the agent legitimately needs to reference a `.env` file (e.g., to know which environment it's in), it can't.
- **Requires root** for mount setup

### Verdict: Elegant for static workspaces, but has a runtime-creation gap

---

## 9. Mount Namespace File Hiding

### The Idea

Create a **mount namespace** for the agent where `.env` files are hidden via
individual tmpfs overmounts. Unlike OverlayFS (which requires a single overlay
mount), this uses per-file tmpfs mounts that are invisible from the parent
namespace.

```rust
// In guardian-launch, after creating cgroup but before exec:

// 1. Unshare mount namespace
unsafe { libc::unshare(libc::CLONE_NEWNS); }

// 2. Make all mounts private (prevent propagation to parent)
unsafe { libc::mount(
    std::ptr::null(), b"/\0".as_ptr() as _, std::ptr::null(),
    libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()
); }

// 3. For each .env file, mount an empty tmpfs over it
for env_path in find_env_files("/workspace") {
    let empty_dir = tempdir()?;
    unsafe { libc::mount(
        b"tmpfs\0".as_ptr() as _,
        CString::new(env_path.to_str().unwrap())?.as_ptr(),
        b"tmpfs\0".as_ptr() as _,
        libc::MS_RDONLY,
        b"size=0\0".as_ptr() as _,
    ); }
}

// 4. Agent can't see .env files — they're hidden behind empty tmpfs mounts
// The parent namespace (guardian daemon) still sees the real files
```

### Pros
- Agent process and children inherit the mount namespace — no way to escape
- Parent namespace unaffected — daemon still sees real files
- Works with Landlock — mount namespace operates at a different level

### Cons
- Same "static at launch time" limitation
- Mount namespace must be created before dropping privileges
- Many individual mounts for many `.env` files

### Verdict: Clean namespace isolation, pairs well with other approaches

---

## 10. eBPF read() Content Redaction

### The Idea (Very Creative)

Instead of blocking `.env` file access entirely, allow the agent to open and
read the file but **redact sensitive content in-flight**. An eBPF program
attached to the `read()` syscall's return path inspects the data being returned
to userspace and replaces sensitive values with placeholder text.

```
Real .env file content:           What the agent reads:
ANTHROPIC_API_KEY=sk-ant-xyz123   ANTHROPIC_API_KEY=***REDACTED***
DATABASE_URL=postgres://user:pw   DATABASE_URL=***REDACTED***
SECRET_KEY=supersecret            SECRET_KEY=***REDACTED***
DEBUG=true                        DEBUG=true
PORT=3000                         PORT=3000
```

### How It Works

```
Agent: read(fd, buf, 4096)
  │
  ▼
Kernel completes read → data in userspace buffer
  │
  ▼
eBPF tracepoint sys_exit_read:
  1. Check if PID is in watched cgroup
  2. Check if fd points to a .env file (from earlier open tracking)
  3. Read the buffer content from userspace
  4. Scan for KEY=VALUE patterns
  5. If VALUE matches sensitive patterns (long strings, starts with sk-,
     contains :// for URLs, etc.):
     → Overwrite VALUE with "***REDACTED***" using bpf_probe_write_user()
  6. Agent receives redacted content
```

### The Critical Function: `bpf_probe_write_user()`

This is a rare eBPF helper that **writes to userspace memory**. It's the only
way to modify data returning from a syscall. Available since Linux 4.8 but
requires `CAP_SYS_ADMIN` and is disabled by default on many distros
(`kernel.unprivileged_bpf_disabled=1`).

### Pros
- **Agent sees the file structure** — understands it's a .env file, sees key names, can reason about the config
- **Only secrets are hidden** — non-sensitive values (DEBUG=true, PORT=3000) pass through
- **Works for any file** — not just `.env`. Could redact passwords in any file.
- **No denial to explain** — agent doesn't get EACCES, reducing retry loops

### Cons
- **`bpf_probe_write_user()` is dangerous** — modifying userspace memory from kernel is a powerful primitive. Security-sensitive distros disable it.
- **Content parsing in eBPF is hard** — 512-byte stack limit makes parsing KEY=VALUE strings within eBPF extremely difficult. Would need per-CPU scratch buffers and bounded loops.
- **Only works on read()** — mmap'd file access doesn't go through read() syscall
- **Timing** — `sys_exit_read` fires after the data is in userspace. There's a race window where another thread could read the unredacted data.
- **Not composable** — this is orthogonal to Landlock and existing eBPF enforcement

### Verdict: Brilliant concept, extremely hard to implement correctly in eBPF. Better suited for a FUSE-based implementation (Approach 7) where content redaction is trivial.

---

## 11. Encrypted .env with Cgroup-Aware Key Vault

### The Idea (Very Creative)

Encrypt all `.env` files at rest using a key held by a vault process. The vault
process uses **cgroup ID** to authenticate callers — only processes in authorized
cgroups can decrypt. The agent's cgroup is NOT authorized, so it reads only
encrypted gibberish.

```
Encryption (at workspace setup):
  guardian-vault encrypt /workspace/.env
  → Replaces .env content with AES-256-GCM encrypted blob
  → Key stored in guardian-vault's memory (never on disk)

Authorized process (not in agent cgroup):
  guardian-vault decrypt /workspace/.env
  → Vault checks caller's cgroup ID via /proc/self/cgroup
  → Authorized → returns decrypted content

Agent process (in sandboxed cgroup):
  cat /workspace/.env
  → Reads encrypted blob: "gAAAAA...base64...=="
  → Useless without the key

  OR: guardian-vault decrypt /workspace/.env
  → Vault checks cgroup → NOT authorized → returns error
```

### Implementation

```rust
/// guardian-vault: a process that holds .env decryption keys
/// and authenticates callers by cgroup membership.

fn handle_decrypt_request(stream: UnixStream) -> Result<()> {
    // 1. Get caller's PID from Unix socket peer credentials
    let cred = stream.peer_cred()?;
    let caller_pid = cred.pid();

    // 2. Read caller's cgroup ID
    let cgroup_path = std::fs::read_to_string(
        format!("/proc/{}/cgroup", caller_pid)
    )?;
    let cgroup_id = parse_cgroup_id(&cgroup_path);

    // 3. Check if cgroup is authorized (i.e., NOT the agent's cgroup)
    if is_agent_cgroup(cgroup_id) {
        stream.write_all(b"ERROR: Unauthorized cgroup")?;
        return Ok(());
    }

    // 4. Decrypt and return
    let plaintext = decrypt_env_file(&request.path, &self.master_key)?;
    stream.write_all(&plaintext)?;
    Ok(())
}
```

### Pros
- **Defense in depth** — even if all other enforcement fails, encrypted content is useless
- **Cgroup-based auth is unspoofable** — kernel-assigned, agent can't fake it
- **Transparent to legitimate tools** — CI/CD, deployment scripts use the vault to decrypt
- **Works even if agent escapes sandbox** — without the key, encrypted files are gibberish

### Cons
- **Workflow change** — developers must use vault to access `.env` files
- **Key management** — if vault process dies, `.env` files are unrecoverable without backup
- **Complexity** — full encryption/decryption system
- **Performance** — every `.env` read requires IPC to vault
- **Agent can still see encrypted content** — and could exfiltrate it (attacker might brute-force weak encryption later)

### Verdict: Strongest protection but highest workflow friction. Best for high-security environments.

---

## 12. Extended Attributes (xattr) Labeling

### The Idea (Creative)

Label sensitive files with a custom **extended attribute**
(`user.guardian.deny=agent`). An eBPF LSM hook reads the xattr and blocks
access. This is **extension-agnostic** — works even if someone renames `.env`
to `.txt`.

```bash
# Label all .env files
find /workspace -name "*.env" -exec setfattr -n user.guardian.deny -v "agent" {} \;

# Agent tries to read:
open("/workspace/.env")
  → LSM file_open fires
  → eBPF reads xattr "user.guardian.deny" from inode
  → Value = "agent" → block with -EACCES

# Rename attack:
mv /workspace/.env /workspace/data.txt
open("/workspace/data.txt")
  → LSM file_open fires
  → eBPF reads xattr from inode
  → xattr survives rename! Still labeled → BLOCK
```

### Why This Is Clever

xattrs are **inode-level metadata** — they survive renames, copies (with
`--preserve=xattr`), and are independent of the filename. Labeling `.env` files
with xattrs turns them into permanently marked objects that can't be "unlabeled"
by the agent (the agent doesn't have permission to modify xattrs in the cgroup
sandbox).

### Implementation

eBPF helper `bpf_get_file_xattr()` (available since Linux 6.10) can read xattrs
from a file in LSM hook context:

```rust
// In LSM file_open hook:
let mut xattr_buf = [0u8; 16];
let ret = unsafe {
    bpf_get_file_xattr(file_ptr, b"user.guardian.deny\0", &mut xattr_buf, 16)
};
if ret > 0 {
    // File has the "deny" xattr → block access
    return -13; // -EACCES
}
```

### Pros
- **Survives renames** — xattr is on the inode, not the filename
- **Extension-agnostic** — label any file regardless of its name
- **Kernel-enforced** — BPF LSM reads xattr at file open time
- **No string matching** — simple xattr presence check (fast)
- **Composable with fanotify** — use fanotify to auto-label new `.env` files

### Cons
- **Requires Linux 6.10+** for `bpf_get_file_xattr()` — very new
- **Initial labeling required** — must scan and label all `.env` files at setup
- **Copy without xattr** — `cp` (without `--preserve=xattr`) creates an unlabeled copy
- **Not all filesystems support xattr** — tmpfs, some network filesystems lack support
- **Agent could remove xattr** if it has write permission to the file (mitigated by Landlock read-only)

### Verdict: Elegant inode-level solution, but requires very new kernel

---

## 13. Honeypot .env Files (Canary Tokens)

### The Idea (Very Creative — Defense Through Detection)

Instead of (or in addition to) blocking `.env` access, plant **honeypot `.env`
files** with fake credentials that trigger alerts when used. If the agent (or an
attacker controlling the agent) tries to use the fake API key, the honeypot
system fires an alert.

```
Real .env:                     Honeypot .env (decoy):
API_KEY=sk-ant-real-123         API_KEY=sk-ant-HONEY-canary-456
DB_URL=postgres://prod:pw       DB_URL=postgres://honey:canary@trap.guardian.local

When fake API key is used:
  → Anthropic API returns "invalid key"
  → Our monitoring sees: agent tried to use the honeypot key
  → ALERT: Agent attempted credential exfiltration!
  → Immediate agent termination + forensic audit

When fake DB URL is used:
  → connect(trap.guardian.local) → Guardian Shell intercepts → ALERT
```

### Implementation

```rust
// In guardian-launch, before exec:

fn plant_honeypot_env(workspace: &Path, agent_name: &str) -> anyhow::Result<()> {
    let honeypot_content = format!(
        "# Auto-generated environment\n\
         API_KEY=guardian-canary-{agent}-{rand}\n\
         SECRET_KEY=guardian-canary-{agent}-{rand2}\n\
         DATABASE_URL=postgres://canary:trap@canary.guardian.internal:5432/honeypot\n",
        agent = agent_name,
        rand = generate_random_token(),
        rand2 = generate_random_token(),
    );

    // Write honeypot .env file to workspace
    std::fs::write(workspace.join(".env"), &honeypot_content)?;

    // Register canary tokens with monitoring system
    register_canary_tokens(agent_name, &honeypot_content)?;

    Ok(())
}
```

### Combine with Approach 6 (bind-mount):

```
1. Real .env is bind-mounted to /dev/null (agent reads empty)
   OR
   Real .env is replaced with honeypot content

2. If agent reads the honeypot:
   - Non-sensitive keys (PORT, DEBUG) have real values (agent works normally)
   - Sensitive keys have canary values (trigger alerts if used)

3. Guardian Shell monitors for:
   - Network connections to canary.guardian.internal → ALERT
   - HTTP requests containing "guardian-canary-" in headers → ALERT (via L7 proxy)
```

### Pros
- **Detects intent, not just access** — reading `.env` isn't an attack; using stolen credentials IS. Honeypots detect the actual malicious behavior.
- **No false positives** — legitimate agents don't use fake API keys
- **Works even if all other defenses fail** — the ultimate safety net
- **Provides forensic evidence** — proves the agent attempted credential theft
- **Low overhead** — no runtime enforcement, just monitoring

### Cons
- **Doesn't prevent reading** — the agent does read the honeypot content
- **Requires monitoring infrastructure** — need a system to watch for canary token usage
- **Agent may not use the credentials** — if the agent's goal is to read the file (not use the credentials), the honeypot doesn't help
- **Doesn't protect against content inspection** — a smart attacker could recognize canary patterns

### Verdict: Excellent complement to blocking — the last line of defense

---

## 14. Git Hook Quarantine

### The Idea

For git-based workflows, intercept `git checkout`, `git pull`, and `git clone`
to **automatically quarantine `.env` files** before the agent sees the new
content.

```
Agent: git pull origin main
  │
  ▼
post-checkout / post-merge Git hook fires:
  │
  │ 1. Find all new/modified .env files
  │ 2. Move them to /quarantine/.env.XXXXX
  │ 3. Replace with empty file or bind-mount /dev/null
  │ 4. Log quarantine action
  │
  ▼
Agent sees updated repo without .env file contents
```

### Implementation

```bash
#!/bin/bash
# .git/hooks/post-checkout (also symlink as post-merge)

# Find all .env files in the repo
find . -name "*.env" -o -name ".env*" | while read envfile; do
    # Quarantine to a location outside the workspace
    quarantine_path="/var/guardian/quarantine/$(basename "$envfile").$(date +%s)"
    cp "$envfile" "$quarantine_path"

    # Replace with empty file
    truncate -s 0 "$envfile"

    echo "[guardian] Quarantined: $envfile → $quarantine_path"
done
```

### Pros
- **Catches .env files at the source** — before the agent reads them
- **Works with any git operation** — checkout, pull, merge, clone
- **No kernel changes** — pure git hook
- **Preserves the file** — quarantined, not deleted

### Cons
- **Git hooks only** — doesn't catch non-git file creation
- **Agent can disable hooks** — `git config core.hooksPath /dev/null` (mitigate with eBPF exec enforcement on `git`)
- **Timing gap** — during `git pull`, files exist briefly before the hook runs
- **`.gitignore` issue** — `.env` files are usually in `.gitignore`, so they don't come from git operations anyway

### Verdict: Useful for git-delivered secrets, limited scope

---

## 15. Agent-Transparent Secret Vault Process

### The Idea (Most Creative)

Replace `.env` files with a **Unix domain socket** that impersonates a file.
When the agent opens the `.env` "file," it actually connects to a vault process
that authenticates the caller (by cgroup) and returns secrets only to authorized
processes.

This is based on a technique used by systemd's credential system and Docker
secrets.

```
/workspace/.env is NOT a file — it's a Unix socket:
  srwxr-xr-x 1 root root 0 .env

Agent: open("/workspace/.env")
  → Fails (can't open() a socket with read)
  → Agent falls back to reading with cat, python, node
  → All fail because .env is a socket, not a regular file

Alternative: Use a FIFO (named pipe) instead:
  mkfifo /workspace/.env

Agent: cat /workspace/.env
  → Blocks until someone writes to the other end
  → Vault process detects reader, checks cgroup
  → If unauthorized: sends empty content and closes
  → If authorized: sends real .env content
```

### More Practical Variant: Runtime Environment Injection

Instead of replacing `.env` files, inject environment variables directly into
the agent process via `/proc/{pid}/environ` manipulation — which is impossible
after exec. Instead, use the guardian-launch IPC to deliver secrets:

```
1. guardian-launch registers with daemon
2. Daemon sends SandboxConfig (already has the policy)
3. NEW: Daemon also sends an EnvironmentSecrets message
4. guardian-launch sets env vars from the message
5. guardian-launch does NOT set env vars from .env files
6. .env files are never read — secrets come from the IPC channel
7. agent's cgroup-verified identity ensures only the right agent
   receives the right secrets
```

### Pros
- **File never contains secrets** — the `.env` file doesn't need to be blocked because it never had secrets in it
- **Cgroup-authenticated delivery** — secrets delivered through the same trusted IPC channel used for SandboxConfig
- **Works for all secret types** — API keys, database URLs, tokens
- **No pattern matching needed** — eliminates the problem entirely

### Cons
- **Requires workflow change** — secrets must be configured in Guardian Shell's config, not in `.env` files
- **Not compatible with existing .env-based workflows** — tools like `dotenv` expect to read files
- **Chicken-and-egg** — if the workspace `.env` already exists with real secrets, this doesn't help retroactively

### Verdict: Eliminates the problem rather than solving it — the most "out of the box" approach

---

## Comparison Matrix

| Approach | Blocks Existing | Blocks New Files | Survives Rename | Survives Symlink | Performance | Complexity | Kernel Req |
|----------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| **1. eBPF suffix match** | Yes | Yes | No | No | Excellent | Low | 5.2+ |
| **2. eBPF LSM bpf_d_path** | Yes | Yes | N/A (resolved) | Yes | Good | High | 5.10+ BTF |
| **3. Suffix BPF map** | Yes | Yes | No | No | Excellent | Medium | 5.2+ |
| **4. fanotify permission** | Yes | Yes | Yes (resolved) | Yes | Poor | Medium | 5.1+ |
| **5. Hybrid fanotify+BPF** | Yes | Yes (small delay) | Yes | Yes | Excellent | Medium | 5.2+ |
| **6. Bind-mount mask** | Yes | No | N/A | N/A | Excellent | Low | Any |
| **7. FUSE filter** | Yes | Yes | Yes | Yes | Poor | High | Any |
| **8. OverlayFS whiteout** | Yes | No | N/A | N/A | Good | Medium | 4.0+ |
| **9. Mount namespace** | Yes | No | N/A | N/A | Good | Medium | Any |
| **10. read() redaction** | Yes | Yes | Yes | Yes | Poor | Very High | 4.8+ |
| **11. Encrypted vault** | Yes | Yes | Yes | Yes | Good | High | Any |
| **12. xattr labeling** | Yes | Yes (with watcher) | Yes | N/A | Excellent | Medium | 6.10+ |
| **13. Honeypot canary** | Detection only | Detection only | N/A | N/A | Excellent | Low | Any |
| **14. Git hook** | Partial | Partial | No | No | Excellent | Low | Any |
| **15. Secret vault IPC** | Eliminates problem | Eliminates problem | N/A | N/A | Excellent | High | Any |

**Legend:** Performance = impact on file open operations. Complexity = implementation effort.

---

## Recommended Approach

### For Immediate Implementation: Approach 1 + 6

**eBPF suffix matching (Approach 1)** for runtime enforcement, combined with
**bind-mount masking (Approach 6)** for known files at launch time. This gives:

- Kernel-level blocking of all `*.env` files at open() time (eBPF)
- Zero-content masking of known `.env` files (bind mount)
- Small code change, no new dependencies
- Works with existing Landlock + seccomp stack

### For Robust Production: Approach 1 + 5 + 13

Add **hybrid fanotify + BPF inode deny (Approach 5)** for inode-based enforcement
that survives renames, plus **honeypot canary tokens (Approach 13)** as the
last-resort detection mechanism. This gives:

- Suffix matching for immediate blocking (eBPF, Approach 1)
- Inode-based blocking that survives renames (fanotify + BPF, Approach 5)
- Canary detection if blocking somehow fails (honeypot, Approach 13)
- Three independent defense layers with different failure modes

### For Maximum Security: Approach 1 + 5 + 12 + 13 + 15

Add **xattr labeling (Approach 12)** for kernel-level inode tagging (requires
kernel 6.10+), plus **secret vault IPC (Approach 15)** to eliminate `.env` files
entirely. This gives five layers:

```
Layer 1: Secret vault IPC → secrets never written to .env files
Layer 2: eBPF suffix matching → blocks opens of anything named .env
Layer 3: Inode deny map → blocks opens of .env inodes regardless of name
Layer 4: xattr enforcement → blocks opens of labeled sensitive files
Layer 5: Honeypot canaries → detects credential exfiltration attempts
```

### Configuration Example

```toml
# config.toml — blocking *.env files

[[agents]]
name = "coding-agent"
identity = "cgroup"

[agents.file_access]
default = "deny"
allow = ["/workspace/**", "/tmp/**"]
# NEW: suffix-based deny rules
deny_suffixes = [".env", ".pem", ".key", ".secret", ".credentials"]
# NEW: content-pattern deny (for renamed .env files)
deny_content_patterns = ["^[A-Z_]+=.+$"]  # KEY=VALUE pattern

[agents.file_access.honeypot]
enabled = true
canary_prefix = "guardian-canary"
```

---

*Last updated: 2026-03-25*
