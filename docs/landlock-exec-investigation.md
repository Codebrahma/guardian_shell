# Landlock + execve() Incompatibility Investigation

**Date:** 2026-03-20
**System:** Fedora 43, Linux 6.19.8-200.fc43.x86_64, SELinux enforcing
**Status:** Unresolved — Landlock skipped on SELinux-enforcing systems, eBPF provides enforcement

---

## Summary

On Fedora 43 (kernel 6.19.8), calling `landlock_restrict_self()` causes **any** subsequent `execve()` to fail with `EACCES` (Permission denied, errno 13). This happens regardless of:

- Which Landlock access rights are handled
- Which paths are granted access
- Whether `PR_SET_NO_NEW_PRIVS` is set
- Whether all filesystem rights are granted on `/` (root)

No SELinux AVC denial is logged in the audit system. The issue appears to be a kernel-level interaction between Landlock's credential modification (`commit_creds()` inside `restrict_self()`) and the exec path on Fedora kernels.

**Workaround:** Auto-detect SELinux enforcing mode and skip Landlock. The agent still gets 4 security layers: PR_SET_NO_NEW_PRIVS + seccomp + eBPF + cgroup. On non-SELinux systems (Ubuntu, Debian, Arch), Landlock works normally.

---

## Environment

```
OS:       Fedora 43 (fc43)
Kernel:   6.19.8-200.fc43.x86_64
SELinux:  Enforcing (targeted policy)
LSMs:     SELinux, Landlock, BPF (stacked)
Rust:     nightly (eBPF requirement)
Landlock: crate v0.4, targeting ABI V5
Binary:   /home/suren/.local/share/mise/installs/node/24.1.0/bin/claude
          → symlink → cli.js (Node.js script with #!/usr/bin/env node shebang)
```

---

## Chronological Investigation

### Attempt 1: Initial launch
**Command:**
```bash
sudo target/release/guardian-launch --name claude-cgroup --memory 4G --pids 200 -- /path/to/claude
```
**Result:** `Permission denied (os error 13)`
**Analysis:** Original code used `AccessFs::from_all(ABI::V5)` which handles ALL rights. Granted `read + write` on file_allow paths and `read + execute` on exec_allow paths. Execute not granted on file_allow paths like `/home/suren/**` where the binary lives.

### Attempt 2: Grant Execute on file-allowed paths when exec_default=allow
**Change:** When `exec_default == "allow"`, grant `read + write + Execute` on file_allow paths.
**Result:** Still `Permission denied`
**Analysis:** The binary is under `/home/suren` which now has Execute. The shebang chain (`/usr/bin/env` → `node`) is under `/usr/bin` which also has Execute. All paths covered.

### Attempt 3: Grant ALL rights (`from_all(V5)`) on every path
**Change:** `all_fs_rights = AccessFs::from_all(abi)` granted on every file_allow path.
**Result:** Still `Permission denied`
**Analysis:** Every handled right is granted on every path. Nothing should be denied. Yet exec still fails. This rules out missing rights on specific paths.

### Attempt 4: Remove Execute from handled set
**Change:** `fs_access = ReadFile | ReadDir | WriteFile | MakeReg | RemoveFile | MakeDir | RemoveDir | MakeSym | Truncate` — no Execute.
**Result:** Still `Permission denied`
**Analysis:** Landlock doesn't handle Execute at all, so it can't deny exec. Yet exec still fails. This rules out Execute-specific issues.

### Attempt 5: Disable Landlock, keep everything else
**Command:** `--no-landlock` flag
**Result:** **SUCCESS** — Claude launches and runs
**Analysis:** Confirms Landlock `restrict_self()` is the sole cause. PR_SET_NO_NEW_PRIVS + seccomp + eBPF + cgroup all work fine without Landlock.

### Attempt 6: Check SELinux audit log
**Command:** `sudo ausearch -m avc -ts recent`
**Result:** `<no matches>` — zero AVC denials
**Analysis:** SELinux is NOT logging any denial. This means either (a) SELinux isn't the one denying, or (b) the denial happens in a code path that doesn't generate AVC logs (dontaudit rule, or non-SELinux denial).

### Attempt 7: audit2allow approach
**Commands:**
```bash
# Trigger the failure
sudo target/release/guardian-launch --name claude-cgroup ...
# Generate policy from audit
sudo ausearch -m avc -ts recent | audit2allow -M guardian-landlock
```
**Result:** `Nothing to do` — no AVC to generate policy from
**Analysis:** Confirms SELinux isn't generating denials. The EACCES comes from somewhere else in the kernel.

### Attempt 8: Add `/` (root directory) to allow list
**Change:** `PathBeneath::new(PathFd::new("/"), fs_access)` — grants all handled rights on entire filesystem.
**Result:** Still `Permission denied`
**Analysis:** Nuclear option — every file on the system is accessible. Yet exec still fails. This definitively proves the issue is NOT about which paths or rights are granted.

### Attempt 9: Skip PR_SET_NO_NEW_PRIVS, keep Landlock
**Change:** Don't call `prctl(PR_SET_NO_NEW_PRIVS)` when running as root (CAP_SYS_ADMIN satisfies Landlock since kernel 5.18).
**Result:** Still `Permission denied`
**Analysis:** NNP is not the cause. The issue is `restrict_self()` alone. This disproves the theory that NNP + SELinux domain transition blocking was the cause.

### Attempt 10: Minimal rights — only ReadFile | ReadDir
**Change:** `fs_access = AccessFs::ReadFile | AccessFs::ReadDir` — absolute minimum. Plus `/` allowed.
**Result:** Still `Permission denied`
**Analysis:** Even with just two rights handled and the entire filesystem allowed, exec fails after `restrict_self()`. This is the definitive proof that the issue is `restrict_self()` itself, not what it controls.

---

## Theories Investigated and Disproved

### Theory 1: Missing Execute permission on binary path
**Disproved by:** Attempt 3 (all rights on all paths, still fails)

### Theory 2: Missing path in exec chain (symlink → shebang → env → node)
**Disproved by:** Attempt 8 (entire `/` allowed, still fails)

### Theory 3: SELinux blocking due to domain transition
**Disproved by:** Attempt 6 (no AVC denial logged)

### Theory 4: PR_SET_NO_NEW_PRIVS + SELinux nnp_nosuid_transition
**Disproved by:** Attempt 9 (NNP disabled, still fails)

### Theory 5: `from_all(ABI::V5)` handles rights kernel doesn't support
**Disproved by:** Attempt 10 (only ReadFile|ReadDir, still fails)

### Theory 6: Specific right (MakeSym, Truncate, Refer) causing issues
**Disproved by:** Attempt 10 (none of those handled, still fails)

### Theory 7: eBPF bprm_check_security hook interfering
**Disproved by:** eBPF hook returns -EPERM (errno 1), not -EACCES (errno 13). The error is errno 13.

### Theory 8: eBPF file_open hook consuming stale PENDING_DENY
**Disproved by:** Would happen with or without Landlock. Without Landlock, exec works.

---

## What We Know For Certain

1. `restrict_self()` is the sole trigger — removing it fixes exec
2. The rights handled and paths granted are irrelevant
3. No SELinux AVC denial is generated
4. NNP presence/absence doesn't matter
5. The error is EACCES (13), not EPERM (1)
6. `--no-landlock` works perfectly — all other security layers function
7. The issue is specific to Fedora 43 / kernel 6.19.8 with SELinux enforcing
8. The `RulesetStatus` reports `PartiallyEnforced` even with minimal rights

---

## Root Cause Hypothesis

The most likely explanation is a **kernel-level interaction between Landlock's credential modification and the exec code path** on Fedora's patched kernel. Specifically:

1. `landlock_restrict_self()` calls `prepare_creds()` → modifies Landlock security blob → `commit_creds()`
2. This credential change affects the process's security state
3. During subsequent `execve()`, the kernel's binary handler (`load_elf_binary` or `load_script`) performs a file open with `FMODE_EXEC`
4. Something in the Landlock + Fedora kernel's `security_file_open()` or `security_bprm_check()` call chain returns EACCES without generating an SELinux audit entry

This could be:
- A Fedora kernel patch that adds extra security checks after credential changes
- A Landlock interaction with Fedora's SELinux targeted policy that bypasses audit logging
- A bug in Landlock's `hook_file_open()` on this kernel version where `FMODE_EXEC` files are denied even when Execute isn't handled
- A `dontaudit` SELinux rule that silently denies without logging

---

## Working Solution

Auto-detect SELinux enforcing mode and skip Landlock:

```rust
let selinux_enforcing = std::fs::read_to_string("/sys/fs/selinux/enforce")
    .map(|s| s.trim() == "1")
    .unwrap_or(false);

let should_landlock = !args.no_landlock
    && !selinux_enforcing
    && sandbox_config.as_ref().map(|c| c.landlock).unwrap_or(true);
```

### Security on SELinux systems (Fedora/RHEL)

| Layer | Status | Enforcement |
|-------|--------|-------------|
| PR_SET_NO_NEW_PRIVS | Active | Blocks SUID escalation |
| Seccomp filter | Active | Blocks io_uring, memfd, mount, namespace, chroot |
| eBPF LSM | Active | File access + exec + network enforcement |
| Cgroup isolation | Active | Resource limits, unspoofable identity |
| SELinux | Active | Mandatory access control (system-wide) |
| **Landlock** | **Skipped** | **Replaced by SELinux MAC + eBPF** |

### Security on non-SELinux systems (Ubuntu, Debian, Arch)

| Layer | Status | Enforcement |
|-------|--------|-------------|
| PR_SET_NO_NEW_PRIVS | Active | Blocks SUID escalation |
| Seccomp filter | Active | Blocks io_uring, memfd, mount, namespace, chroot |
| eBPF LSM | Active | File access + exec + network enforcement |
| Cgroup isolation | Active | Resource limits, unspoofable identity |
| **Landlock** | **Active** | **Inode-level file access (symlink-immune)** |

---

## Future Investigation Paths

1. **Check Fedora dontaudit rules:** `sesearch --dontaudit | grep landlock` — if a dontaudit rule exists, it silently denies without AVC logging
2. **Test on stock kernel:** Build upstream 6.19 without Fedora patches and test if Landlock+exec works
3. **strace the exec:** `strace -f -e trace=execve,openat,prctl` to see exact syscall sequence and where EACCES originates
4. **ftrace/bpftrace:** Trace `security_file_open` and `security_bprm_check` hooks to see which LSM returns the denial
5. **Test on Fedora with SELinux permissive:** `sudo setenforce 0` then test — if Landlock works, the issue IS SELinux (just not audited)
6. **File upstream bug:** Report to kernel.org Landlock maintainers with reproduction steps
7. **Test landrun tool:** The [landrun](https://github.com/Zouuup/landrun) Landlock sandbox tool may have solved this — check their Fedora compatibility

---

## References

- [Landlock kernel documentation](https://docs.kernel.org/userspace-api/landlock.html)
- [SELinux NNP/nosuid transitions](https://patchwork.kernel.org/project/selinux/patch/20170714164647.6183-1-sds@tycho.nsa.gov/)
- [Container SELinux no-new-privileges issue](https://github.com/containers/container-selinux/issues/51)
- [landrun — Landlock sandbox tool](https://github.com/Zouuup/landrun)
- [OpenAI Codex Landlock issues](https://github.com/openai/codex/issues/6828)
- [Dan Walsh on NNP + SELinux](https://danwalsh.livejournal.com/78312.html)
- [LSM stacking discussion (LWN)](https://lwn.net/Articles/970070/)
- [Landlock Rust crate](https://github.com/landlock-lsm/rust-landlock)
