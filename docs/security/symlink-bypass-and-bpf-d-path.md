# Symlink Bypass & bpf_d_path Implementation Plan

**Date:** 2026-03-23
**Status:** Research complete, implementation deferred
**Severity:** HIGH — allows bypassing deny rules via symlinks

---

## The Vulnerability

When a parent directory is in the **allow** list and a specific subdirectory is
in the **deny** list, an agent can bypass the deny by creating a symlink from
an allowed path to the denied directory.

### Example

Config:
```toml
allow = ["/home/user/**", "/tmp/**"]
deny  = ["/home/user/confidential/**"]
```

Attack:
```bash
ln -s /home/user/confidential/ /tmp/symlink
cat /tmp/symlink/secret.txt   # SUCCEEDS — should be denied
```

### Why It Works

1. Agent calls `openat("/tmp/symlink/secret.txt")`
2. eBPF `sys_enter_openat` tracepoint reads the raw path: `/tmp/symlink/secret.txt`
3. Deny check: does `/tmp/symlink/secret.txt` match `/home/user/confidential/**`? **NO**
4. Allow check: does `/tmp/symlink/secret.txt` match `/tmp/**`? **YES**
5. eBPF: **ALLOWED**
6. Kernel resolves symlink → opens `/home/user/confidential/secret.txt`
7. File content is exposed

The eBPF tracepoint sees the **raw syscall path string**, not the kernel-resolved
path. Symlinks, bind mounts, and `/proc/self/root/` all allow path-string
manipulation to reach denied inodes via allowed path strings.

### What Landlock Does (and Doesn't)

Landlock operates at the inode level — it resolves symlinks before checking access.
But Landlock only has **allow rules** (default-deny model). It cannot deny specific
files within an allowed directory.

So for this attack:
- Landlock: `/tmp` is allowed → symlink followed → target inode is under `/home/user`
  which is also allowed → **ALLOWED**
- eBPF: raw path `/tmp/symlink/...` doesn't match deny rule → **ALLOWED**

Neither layer catches it.

---

## Current Mitigations

### 1. Don't Allow Broad Parent Directories (Recommended)

Instead of allowing `/home/user/**` (which includes everything), allow only
specific subdirectories:

```toml
# SAFE: denied folders are not in any allow rule
allow = [
    "/home/user/projects/app1/**",
    "/home/user/projects/app2/**",
    "/home/user/.config/**",
    "/home/user/.cache/**",
]
# /home/user/confidential/ is NOT in allow list → blocked by default
```

### 2. Use read_only for Reference Directories

```toml
read_only = ["/home/user/projects/docs/**"]
```

Read-only paths can't be modified, symlinked-to, or deleted.

### 3. Deny /tmp Symlink Creation

If `/tmp/**` is in the allow list, the agent can create symlinks there.
Adding `/tmp` to read_only or removing it from allow prevents symlink creation.
But many tools need `/tmp` for temporary files.

---

## The Proper Fix: bpf_d_path() in LSM Hook

### What is bpf_d_path()?

`bpf_d_path()` is a BPF helper (number 146, introduced in Linux 5.10) that
resolves a kernel `struct path` to its canonical filesystem path string. It
follows symlinks, resolves mount points, and returns the real path.

```c
long bpf_d_path(struct path *path, char *buf, u32 sz);
```

### How It Would Fix the Bypass

Instead of relying solely on the tracepoint's raw path, the `file_open` LSM
hook would call `bpf_d_path()` to get the canonical path and evaluate deny
rules against it:

```
Current flow:
  Tracepoint: raw path "/tmp/symlink/secret.txt"
    → evaluate_policy() → allow (matches /tmp/**)
    → no PENDING_DENY
  LSM file_open: check PENDING_DENY → not found → ALLOW

Proposed flow:
  Tracepoint: raw path "/tmp/symlink/secret.txt"
    → evaluate_policy() → allow (matches /tmp/**)
    → no PENDING_DENY
  LSM file_open:
    → check PENDING_DENY → not found
    → bpf_d_path(file->f_path) → "/home/user/confidential/secret.txt"
    → check DENY rules against canonical path → MATCH → DENY (-EACCES)
```

### Implementation Requirements

#### 1. Read struct file * from LSM Hook Context

The `security_file_open(struct file *file)` LSM hook receives the file struct.
In aya-ebpf, this is accessed via `ctx.arg(0)`:

```rust
let file_ptr: *const u8 = unsafe { ctx.arg(0) };
```

#### 2. Find f_path Offset in struct file

`bpf_d_path()` takes `struct path *`, which is at `file->f_path`. The offset
of `f_path` varies across kernel versions because `struct file` layout depends
on kernel CONFIG options and struct padding.

**This is the main complexity barrier.**

#### 3. Call bpf_d_path()

```rust
extern "C" {
    fn bpf_d_path(path: *const core::ffi::c_void, buf: *mut u8, sz: u32) -> i64;
}

let ret = unsafe { bpf_d_path(f_path_ptr, buf.as_mut_ptr(), MAX_FILENAME_LEN as u32) };
```

#### 4. Evaluate Deny Rules Against Canonical Path

```rust
if ret > 0 {
    let path_len = ret as usize;
    // Check only DENY rules (allow was already checked by tracepoint)
    if is_path_denied(buf, path_len) {
        return Ok(-13); // -EACCES
    }
}
```

---

## Why BTF/CO-RE Is Complex

### The Problem: f_path Offset

The offset of `f_path` in `struct file` varies across kernels:

| Kernel Version | Approximate Offset | Why Different |
|---|---|---|
| 5.10 | ~136 bytes | Older struct layout |
| 5.15 | ~144 bytes | Added f_iocb_flags union |
| 6.1 | ~152 bytes | Mutex layout changed |
| 6.6 | ~160 bytes | Added f_wb_err field |
| 6.19 (Fedora 43) | ~160-176 bytes | Latest layout with security fields |

Hardcoding an offset works for ONE kernel but breaks on updates.

### CO-RE (Compile Once Run Everywhere)

The modern solution is **BTF/CO-RE**: the eBPF program uses field names instead
of offsets, and the BPF loader resolves them at load time from the kernel's BTF
(Binary Type Format) data.

```c
// CO-RE approach (C):
struct path *f_path = BPF_CORE_READ(file, f_path);
```

### Why It's Hard in aya-ebpf

1. **aya-ebpf 0.1 doesn't expose CO-RE macros**: No equivalent of
   `BPF_CORE_READ()`. Would need raw pointer arithmetic or a crate upgrade.

2. **No bpf_d_path binding**: aya-ebpf doesn't export `bpf_d_path` as a named
   helper. Must use raw `extern "C"` FFI declaration.

3. **BTF parsing needed at load time**: The daemon would need to parse
   `/sys/kernel/btf/vmlinux` to find the `f_path` offset, then pass it to
   the eBPF program via a BPF map. This requires either:
   - A BTF parsing library (adds dependency)
   - Calling `pahole` or `bpftool` as subprocess (requires installation)
   - Manual BTF binary parsing (complex, error-prone)

4. **Verifier complexity**: Adding `bpf_d_path()` call + buffer management +
   deny rule evaluation in the LSM hook significantly increases program
   complexity. The BPF verifier may reject paths that are too complex.

5. **Sleepable hook requirement**: `bpf_d_path()` can only be called from
   sleepable BPF programs. The `security_file_open` hook IS sleepable, but
   aya-ebpf's LSM hook declaration may need changes to mark it as sleepable.

### What Would Need to Change

1. **Upgrade aya-ebpf** to a version with CO-RE support (or add raw BTF access)
2. **Add BTF parsing** to the daemon startup (to extract f_path offset)
3. **Add BPF map** for runtime config (f_path offset, enable/disable flag)
4. **Add PerCpuArray** scratch buffer for bpf_d_path output
5. **Modify LSM hook** to call bpf_d_path and evaluate deny rules
6. **Add kernel version check** to gracefully skip on < 5.11
7. **Test across kernels**: 5.13 (Landlock min), 6.1 (LTS), 6.6 (LTS), 6.19

---

## Research Findings (2026-03-23)

### bpf_d_path Availability

| Requirement | Status |
|---|---|
| Linux 5.10+ (helper introduced) | Available on Fedora 43 (6.19) |
| Linux 5.11+ (sleepable LSM hooks) | Available on Fedora 43 (6.19) |
| CONFIG_BPF_LSM=y | Confirmed active (LSM hooks work) |
| CONFIG_DEBUG_INFO_BTF=y | Confirmed (/sys/kernel/btf/vmlinux exists, 6.8MB) |
| security_file_open is sleepable | Yes (confirmed in kernel source) |

### aya-ebpf 0.1 Capabilities

| Feature | Available |
|---|---|
| LsmContext::arg(0) for file ptr | Likely (uses BPF trampoline) |
| extern "C" fn bpf_d_path() | Yes (raw FFI) |
| PerCpuArray scratch buffers | Yes (already used) |
| CO-RE / BPF_CORE_READ | No (not in aya-ebpf 0.1) |
| BTF-based struct access | No (would need upgrade) |

### BTF Data

- `/sys/kernel/btf/vmlinux` exists: 6,827,861 bytes
- Contains `f_path` string at BTF string offset 37954
- Found `f_path` as member of multiple structs (struct file, struct path, etc.)
- Full offset determination requires proper BTF type section parsing

---

## Implementation Plan (When Ready)

### Phase 1: Hardcoded Offset (Quick, Fragile)
- Hardcode f_path offset for kernel 6.19 x86_64
- Add bpf_d_path call in LSM hook
- Works on Fedora 43, breaks on other kernels
- Good for proof-of-concept

### Phase 2: Runtime BTF Resolution (Portable)
- Parse /sys/kernel/btf/vmlinux at daemon startup
- Extract f_path offset from BTF type section
- Pass offset to eBPF via BPF ArrayMap
- Works on any kernel with BTF support

### Phase 3: CO-RE Support (Ideal)
- Upgrade aya-ebpf to version with CO-RE macros
- Use BPF_CORE_READ equivalent for field access
- No runtime BTF parsing needed — BPF loader handles it
- Most portable, least fragile

### Estimated Effort

| Phase | Effort | Risk |
|---|---|---|
| Phase 1 | 2-4 hours | High (kernel-specific) |
| Phase 2 | 1-2 days | Medium (BTF parsing) |
| Phase 3 | 2-3 days | Low (requires aya upgrade) |

---

## Interim Recommendation

Until bpf_d_path is implemented:

1. **Don't use broad parent allows** (`/home/user/**`) when you need to deny subfolders
2. **Use specific allows** for each project/directory the agent needs
3. **Document the limitation** in the dashboard help panel and policy editor
4. **Use Landlock for primary enforcement** — it's inode-based but allow-only
5. **Monitor symlink creation** in the eBPF event log — symlink attempts to
   denied paths may indicate an attack

---

## References

- [bpf_d_path kernel patch](https://lore.kernel.org/bpf/20200825182919.1118197-1-jolsa@kernel.org/)
- [BPF CO-RE reference guide](https://nakryiko.com/posts/bpf-core-reference-guide/)
- [aya-ebpf crate](https://github.com/aya-rs/aya)
- [Guardian Shell Landlock Investigation](../landlock-exec-investigation.md)
- [Guardian Shell Threat Model](../user-scenarios-and-threat-model.md)
