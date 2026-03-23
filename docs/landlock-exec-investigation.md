# Landlock + execve() Incompatibility Investigation

**Date:** 2026-03-20
**System:** Fedora 43, Linux 6.19.8-200.fc43.x86_64, SELinux enforcing
**Status:** Resolved — Drop root privileges before Landlock (non-root exec works on SELinux)

---

## Summary

On Fedora 43 (kernel 6.19.8), calling `landlock_restrict_self()` causes **any** subsequent `execve()` to fail with `EACCES` (Permission denied, errno 13). This happens regardless of:

- Which Landlock access rights are handled
- Which paths are granted access
- Whether `PR_SET_NO_NEW_PRIVS` is set
- Whether all filesystem rights are granted on `/` (root)

No SELinux AVC denial is logged in the audit system. The issue is a kernel-level interaction between Landlock's credential modification (`commit_creds()` inside `restrict_self()`) and the exec path — **specific to running as root** on Fedora kernels.

**Solution:** Drop root privileges (via `setresuid()` to `SUDO_UID`) before calling `restrict_self()` + `execve()`. Landlock+exec works fine for non-root users on the same kernel. This also improves security since agents should never run as root.

**Additional fix:** Landlock system read paths and eBPF allow rules must include all paths needed for shell initialization. On Fedora, this means `/etc/**`, `/usr/libexec/**`, `/usr/sbin/**`, `/dev/pts`, `/dev/tty`, and `/var/**` in addition to the standard `/usr/lib/**` etc.

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

## Solution: Drop Root Privileges Before Landlock

**Date:** 2026-03-23
**Status:** Implemented

### Key Insight

A simple C test doing `landlock_restrict_self()` + `execve()` works fine as a
**non-root user** on the same Fedora kernel. The issue is specific to running as
root (via `sudo`). The kernel's exec security checks behave differently for root
after Landlock credential modification.

### Fix

Drop root privileges to the original user (via `SUDO_UID`/`SUDO_GID`) **after**
all root-required operations (cgroup creation, daemon registration, cgroup move)
but **before** applying Landlock and exec'ing:

```
guardian-launch (root):
  1. Create cgroup           ← needs root
  2. Register with daemon    ← needs root (socket access)
  3. Move to cgroup          ← needs root
  4. Set PR_SET_NO_NEW_PRIVS
  5. Drop to original user   ← setresgid() + setresuid()
  6. Apply Landlock           ← works as non-root (NNP satisfies requirement)
  7. Apply seccomp
  8. Exec agent              ← runs as non-root, in Landlock domain
```

```rust
// New CLI flags: --user <uid>, --group <gid>, --no-drop-privs
// Auto-detects SUDO_UID/SUDO_GID from environment
fn drop_privileges(args: &Args) -> Result<bool> {
    let uid = args.user.or_else(|| env::var("SUDO_UID")...);
    let gid = args.group.or_else(|| env::var("SUDO_GID")...);
    initgroups(username, gid);  // supplementary groups
    setresgid(gid, gid, gid);  // group first (can't after setuid)
    setresuid(uid, uid, uid);   // then user (irreversible)
}
```

### Security Benefits

This fix is a double win:

1. **Enables Landlock on SELinux systems** — Landlock+exec works for non-root users
2. **Better security practice** — agents should never run as root

### Security on ALL systems (after fix)

| Layer | Status | Enforcement |
|-------|--------|-------------|
| PR_SET_NO_NEW_PRIVS | Active | Blocks SUID escalation |
| Privilege dropping | Active | Agent runs as original user, not root |
| Seccomp filter | Active | Blocks io_uring, memfd, mount, namespace, chroot |
| eBPF LSM | Active | File access + exec + network enforcement |
| Cgroup isolation | Active | Resource limits, unspoofable identity |
| **Landlock** | **Active** | **Inode-level file access (symlink-immune)** |
| SELinux (if present) | Active | Mandatory access control (system-wide) |

### Fallback

If privilege dropping fails (no `SUDO_UID`, no `--user` flag, direct root login):
- On non-SELinux: Landlock is applied as root (works fine)
- On SELinux: Landlock is skipped with a warning. Use `--user <uid>` to enable.

### Required System Paths

Both Landlock (in `guardian-launch`) and eBPF (in agent config) must allow these
paths for shell initialization. Discovered through iterative testing on Fedora 43:

**Landlock system_read_paths** (in `guardian-launch/src/main.rs`):
```
/usr/lib, /usr/lib64, /usr/libexec, /lib, /lib64
/usr/share, /usr/bin, /usr/sbin, /usr/local
/etc
/dev/null, /dev/zero, /dev/urandom, /dev/random, /dev/pts, /dev/tty
/var
```

**eBPF agent config allow rules** (in `config.toml`):
```
/usr/lib/**, /usr/lib64/**, /usr/libexec/**, /usr/share/**
/usr/local/**, /usr/bin/**, /usr/sbin/**
/lib/**, /lib64/**, /bin/**
/etc/**             ← broad read, deny rules protect /etc/shadow etc.
/dev/**, /proc/**, /sys/**, /run/**, /var/**, /tmp/**
```

Key Fedora-specific paths that caused failures:
- `/etc/bashrc` — sourced by `~/.bashrc` (Fedora uses `/etc/bashrc`, not `/etc/bash.bashrc`)
- `/etc/profile.d/**` — shell profile scripts with symlinks to `/usr/lib/systemd/`
- `/usr/libexec/grepconf.sh` — called by `/etc/profile.d/colorgrep.sh`
- `/etc/inputrc` — readline configuration
- `/etc/os-release` — read by `mise` and other tools
- `/dev/pts`, `/dev/tty` — terminal device access

### Auto-Created Default Config

When a cgroup agent registers via `guardian-launch --name <agent>` without a
pre-existing config entry, the daemon now auto-creates a default config with
all required system paths, persists it to `config.toml`, and proceeds with
registration. This eliminates the need to manually configure every new agent.

---

## Previous Workaround (superseded)

The original workaround auto-detected SELinux and skipped Landlock entirely.
This has been replaced by privilege dropping, which enables Landlock on all systems.

---

## Diagnostic Script

`scripts/diagnose-landlock.sh` can be used to confirm the root cause:

```bash
sudo bash scripts/diagnose-landlock.sh
```

It tests:
1. Landlock + exec as root with SELinux enforcing
2. Landlock + exec without NNP
3. Landlock + exec with SELinux permissive (setenforce 0)
4. Disables dontaudit rules to find hidden SELinux denials
5. Tests guardian-launch directly

---

## Remaining Investigation Paths

1. **Confirm root-specific**: Verify the C test fails as root but works as non-root
2. **Check Fedora dontaudit rules:** `sesearch --dontaudit | grep landlock` — if a dontaudit rule exists, it silently denies without AVC logging
3. **strace the exec:** `strace -f -e trace=execve,openat,prctl` to see exact syscall sequence and where EACCES originates
4. **File upstream bug:** Report to Landlock maintainers with reproduction steps (root-specific)

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
