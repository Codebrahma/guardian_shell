# eBPF vs SELinux vs AppArmor - Technical Comparison

## Overview

This document provides a deep technical comparison of three Linux security
enforcement mechanisms: **eBPF (BPF-LSM)**, **SELinux**, and **AppArmor**.
It evaluates which approach is best suited for securing AI/LLM agents on Linux.

---

## Architecture Fundamentals

### SELinux (Security-Enhanced Linux)

- **Origin:** NSA, first released 2000, merged into Linux kernel 2.6 (2003)
- **Model:** Mandatory Access Control (MAC) using **labels/types**
- **How it works:**
  - Every file, process, port, and socket gets a **security context** (label)
  - Labels have the form: `user:role:type:level` (e.g., `system_u:system_r:httpd_t:s0`)
  - Policy rules define which **types** can access which other **types**
  - The kernel checks labels on every access and consults the policy
- **Policy language:** `m4` macro-based policy files, compiled into binary
- **Kernel integration:** Linux Security Module (LSM) framework

```
Process (httpd_t) --> opens --> File (httpd_sys_content_t)
                                  |
                          SELinux checks:
                          "Can httpd_t read httpd_sys_content_t?"
                                  |
                          Policy says: allow --> ACCESS GRANTED
```

### AppArmor (Application Armor)

- **Origin:** Immunix/Novell, merged into Linux kernel 2.6.36 (2010)
- **Model:** Mandatory Access Control (MAC) using **file paths**
- **How it works:**
  - Each program gets a **profile** that lists allowed paths and capabilities
  - Profiles reference file paths directly (e.g., `/etc/passwd r`)
  - The kernel checks the path on every access against the profile
  - Two modes: **enforce** (block violations) and **complain** (log only)
- **Policy language:** Human-readable profile files
- **Kernel integration:** Linux Security Module (LSM) framework

```
Process (/usr/sbin/nginx) --> opens --> /var/log/nginx/access.log
                                          |
                                  AppArmor checks:
                                  "Does nginx profile allow /var/log/nginx/* w?"
                                          |
                                  Profile says: allow --> ACCESS GRANTED
```

### eBPF / BPF-LSM

- **Origin:** Extended BPF (2014), BPF-LSM merged in Linux 5.7 (2020)
- **Model:** **Programmable** - custom bytecode at LSM hook points
- **How it works:**
  - Developer writes eBPF programs (in C or Rust) that attach to LSM hooks
  - The eBPF verifier ensures programs are safe (no infinite loops, no crashes)
  - Programs run in kernel space with JIT compilation for near-native speed
  - Programs can access maps (key-value stores) shared with userspace
  - Return value from the program determines allow/deny
- **Policy language:** **Code** (C, Rust, or any language targeting BPF bytecode)
- **Kernel integration:** LSM framework + BPF subsystem

```
Process (claude-code) --> opens --> /etc/shadow
                                      |
                              BPF-LSM hook fires:
                              eBPF program executes:
                                - Check PID against WATCHED_PIDS map
                                - Check path against policy rules
                                - Return -EPERM (deny) or 0 (allow)
                                      |
                              Program returns -EPERM --> ACCESS DENIED
```

---

## Detailed Comparison

### 1. Security Model

| Aspect | SELinux | AppArmor | eBPF (BPF-LSM) |
|--------|---------|----------|-----------------|
| **Access control model** | Label/type-based (Type Enforcement) | Path-based | Programmable (arbitrary logic) |
| **Granularity** | Very fine - per-type, per-class, per-permission | Moderate - per-path, per-capability | Unlimited - any data available in kernel |
| **Policy scope** | System-wide (every object labeled) | Per-application (only profiled apps) | Per-hook (attach to specific LSM hooks) |
| **Multi-Level Security** | Yes (MLS + MCS) | No | Possible (implement in code) |
| **Role-Based Access** | Yes (RBAC built-in) | No | Possible (implement in code) |

**Key insight:** SELinux and AppArmor define **what** is allowed via static
policy files. eBPF defines **how** to decide via executable code. This means
eBPF can implement any policy that SELinux or AppArmor can, plus policies
neither can express (e.g., rate limiting, time-based access, ML-based anomaly
detection).

### 2. Performance

| Metric | SELinux | AppArmor | eBPF (BPF-LSM) |
|--------|---------|----------|-----------------|
| **Typical overhead** | 10-20% (microbenchmarks) | 2-5% | < 3% |
| **Worst case** | Up to 33% | ~10% | ~5% |
| **Policy lookup** | AVC cache (hash table) | Profile tree walk | BPF map lookup (O(1) hash) |
| **Context switch cost** | Label comparison | Path comparison | BPF program execution (JIT-compiled) |

**Why eBPF is faster:**
- JIT-compiled to native machine code
- BPF maps provide O(1) lookups
- No string comparisons for path matching (can use inode numbers)
- Verifier ensures no unbounded loops
- Per-CPU data structures avoid lock contention

**Why SELinux is slower:**
- Every object access requires label lookup + policy check
- AVC cache misses trigger expensive policy recalculations
- Complex policy with thousands of rules increases lookup time
- Label-based model requires more kernel state tracking

### 3. Policy Management

#### SELinux Policy Example
```
# Allow httpd to read web content
allow httpd_t httpd_sys_content_t:file { read open getattr };
allow httpd_t httpd_sys_content_t:dir { search getattr };

# Deny httpd from accessing user home directories
neverallow httpd_t user_home_t:file *;
```

**Complexity:** Requires understanding of types, classes, permissions,
transitions, and the m4 macro language. A typical system has 3000+ types
and 100,000+ policy rules.

#### AppArmor Policy Example
```
# Nginx profile
/usr/sbin/nginx {
  /var/log/nginx/*.log w,
  /etc/nginx/** r,
  /var/www/html/** r,
  deny /etc/shadow r,
  capability net_bind_service,
}
```

**Complexity:** More readable, path-based. But limited expressiveness -
cannot express relationships between processes or implement conditional logic.

#### eBPF (Guardian Shell) Policy Example
```toml
# Guardian Shell config.toml
[[agents]]
name = "claude-code"
process_name = "claude"

[agents.file_access]
default = "deny"
allow = ["/home/user/project/**", "/tmp/**"]
deny = ["/etc/shadow", "/home/user/.ssh/**", "/home/user/.aws/**"]
```

**Complexity:** Simplest configuration for the AI agent use case. The
complexity is in the eBPF program (written once by the tool developer),
not in the policy (written by the user).

### 4. Dynamic Behavior

| Capability | SELinux | AppArmor | eBPF (BPF-LSM) |
|------------|---------|----------|-----------------|
| **Hot-reload policies** | Partial (semodule reload) | Yes (apparmor_parser -r) | Yes (replace BPF program) |
| **Per-process policies** | Via type transitions | Via profile changes | Native (check PID in BPF map) |
| **Runtime policy changes** | Slow (recompile policy module) | Moderate (reload profile) | Instant (update BPF map) |
| **New process discovery** | Via type transitions | Manual profile assignment | BPF map update from userspace |
| **Conditional logic** | Type-based booleans only | No | Arbitrary (any logic in BPF code) |
| **Context-aware decisions** | Label context only | Path context only | Full kernel context (PID, UID, cgroup, namespace, time, etc.) |

**This is where eBPF excels for AI agents:**

AI agents are dynamic - they start, stop, spawn subprocesses, and change
behavior based on prompts. Static policies defined at boot time (SELinux)
or per-binary (AppArmor) cannot adapt to this. eBPF allows:

1. **Adding/removing watched PIDs at runtime** without reloading policy
2. **Per-agent policies** - different agents get different rules
3. **Temporal policies** - "allow /etc/hosts for 5 minutes"
4. **Rate limiting** - "max 10 file opens per second"
5. **Behavioral analysis** - "alert if agent accesses > 100 files in 1 second"

### 5. Kernel Integration

| Aspect | SELinux | AppArmor | eBPF (BPF-LSM) |
|--------|---------|----------|-----------------|
| **LSM type** | Major (exclusive) | Major (exclusive) | Minor (stackable) |
| **Can coexist** | Not with AppArmor | Not with SELinux | With both SELinux AND AppArmor |
| **Kernel config** | `CONFIG_SECURITY_SELINUX` | `CONFIG_SECURITY_APPARMOR` | `CONFIG_BPF_LSM` |
| **Minimum kernel** | 2.6+ | 2.6.36+ | 5.7+ |
| **Hook coverage** | All LSM hooks | Subset of LSM hooks | All LSM hooks + tracepoints + kprobes |

**Stackability is a critical advantage:**

BPF-LSM operates as a **stackable LSM**, meaning it can run alongside
SELinux or AppArmor. This enables a layered defense:

```
Layer 1: SELinux/AppArmor    (baseline system-wide MAC)
Layer 2: BPF-LSM             (dynamic, application-specific enforcement)
Layer 3: Userspace monitoring (logging, alerting, dashboards)
```

You don't have to choose one or the other. In production, the recommended
approach is to keep SELinux/AppArmor for baseline enforcement and add
BPF-LSM for dynamic, AI-agent-specific policies.

### 6. Distribution Support

| Distribution | Default LSM | SELinux | AppArmor | BPF-LSM |
|-------------|-------------|---------|----------|---------|
| RHEL / CentOS / Rocky | SELinux | Yes (default) | Available | Kernel 5.7+ |
| Fedora | SELinux | Yes (default) | Available | Kernel 5.7+ |
| Ubuntu | AppArmor | Available | Yes (default) | Kernel 5.7+ |
| Debian | AppArmor | Available | Yes (default) | Kernel 5.7+ |
| SUSE / openSUSE | AppArmor | Available | Yes (default) | Kernel 5.7+ |
| Arch Linux | None | Available | Available | Kernel 5.7+ |
| Amazon Linux 2023 | SELinux | Yes (default) | No | Kernel 5.7+ |

**Note:** BPF-LSM requires explicit kernel configuration (`CONFIG_BPF_LSM=y`)
and adding `bpf` to the LSM order in boot params or config. Most modern
distros (2022+) ship kernels that support it, but it may not be enabled
by default.

### 7. Security Guarantees

| Property | SELinux | AppArmor | eBPF (BPF-LSM) |
|----------|---------|----------|-----------------|
| **Bypass resistance** | Very high (label-based, no TOCTOU) | Moderate (path-based, symlink issues) | High (kernel-level, verifier-checked) |
| **TOCTOU vulnerability** | No (uses inodes internally) | Yes (path resolution race) | No (can use inodes) |
| **Completeness** | Complete mediation of all kernel objects | Partial (only profiled applications) | Depends on hook coverage |
| **Formal verification** | Extensive formal analysis exists | Limited | eBPF verifier (safety, not correctness) |
| **Attack surface** | Policy misconfig | Profile gaps, symlink attacks | BPF verifier bugs, rootkit potential |

**eBPF-specific security concerns:**

eBPF itself has become an attack vector. Rootkits like **TripleCross** (2023),
**Boopkit** (2024), and **RingReaper** (2025) use eBPF for kernel-level
evasion. eBPF implants:
- Don't appear in `/proc/modules`
- Can bypass Secure Boot
- Can intercept and modify syscalls transparently

**Mitigations:**
- Restrict `CAP_BPF` to root only
- Use `kernel.unprivileged_bpf_disabled=1`
- Monitor BPF program loading with audit subsystem
- Signed BPF programs (emerging feature)

---

## Decision Framework

### Use SELinux when:
- You need **government/military compliance** (MLS, Common Criteria)
- You want **system-wide mandatory access control** across all processes
- You're on RHEL/Fedora and want the default, well-integrated solution
- You need **formal security guarantees** with extensive audit history
- You have dedicated security engineers to manage complex policies

### Use AppArmor when:
- You want **simpler policy management** with readable profiles
- You're on Ubuntu/Debian/SUSE and want the default solution
- You need to **confine specific applications** without system-wide MAC
- Your team doesn't have deep Linux security expertise
- **Quick time-to-value** is more important than maximum granularity

### Use eBPF (BPF-LSM) when:
- You need **dynamic, per-process policies** that change at runtime
- You're building security tooling for **AI agents or dynamic workloads**
- You want to **stack on top of** SELinux/AppArmor, not replace them
- **Performance is critical** (< 3% overhead vs 10-20% for SELinux)
- You need **programmable security logic** (rate limiting, temporal policies,
  behavioral analysis)
- You're running **modern kernels** (5.7+) on x86_64

### Use the combination (recommended for production):
```
SELinux or AppArmor    -->  Baseline system hardening
    +
BPF-LSM (Guardian Shell) -->  AI-agent-specific enforcement
    +
Userspace monitoring   -->  Logging, alerting, dashboards
```

---

## Why eBPF is the Right Choice for Guardian Shell

### 1. Dynamic agent identification
AI agents start/stop unpredictably. eBPF maps allow adding/removing
watched PIDs instantly without reloading any policy.

### 2. Per-agent policies
Different agents need different permissions. eBPF programs can look up
per-PID policies in BPF maps, something neither SELinux nor AppArmor
can do natively.

### 3. Low overhead
AI agents are already resource-intensive. eBPF's < 3% overhead is
significantly better than SELinux's 10-20%.

### 4. Programmable enforcement
Future phases need temporal policies, rate limiting, and behavioral
analysis. These require code, not static policy files.

### 5. Stackability
Guardian Shell can work alongside the distro's existing SELinux or
AppArmor setup. Users don't have to choose.

### 6. Monitor-first approach
eBPF tracepoints (Phase 1) allow monitoring without any enforcement,
letting users build confidence before enabling blocking (Phase 2
BPF-LSM). SELinux/AppArmor don't have a clean separation between
monitoring and enforcement modes.

### 7. Unified mechanism
eBPF can monitor file access, network connections, process execution,
and DNS queries through a single technology. SELinux/AppArmor each
need additional tools for network monitoring.

---

## Limitations of eBPF Approach

| Limitation | Impact | Mitigation |
|-----------|--------|------------|
| Requires kernel 5.7+ | Old distros not supported | Most production systems run 5.10+ by now |
| `CONFIG_BPF_LSM` not always enabled | May need kernel rebuild | Advocacy + distro defaults changing |
| eBPF verifier complexity | Program rejection for valid code | Use `--release` builds, keep programs simple |
| eBPF as attack vector | Rootkit potential | Restrict CAP_BPF, monitor BPF program loading |
| Stack size limit (512 bytes) | Complex data structures need workarounds | Per-CPU arrays as scratch buffers (already used) |
| No formal policy verification | Can't mathematically prove policy correctness | Unit tests + integration tests for policy logic |
| Requires root or CAP_BPF | Not suitable for unprivileged users | Security tools should run privileged anyway |

---

## Summary Table

| Dimension | SELinux | AppArmor | eBPF (BPF-LSM) | Winner for AI Agents |
|-----------|---------|----------|-----------------|---------------------|
| Performance | 10-20% overhead | 2-5% overhead | < 3% overhead | eBPF |
| Policy complexity | Very high | Low-moderate | Moderate (code) | AppArmor (config) / eBPF (capability) |
| Dynamic policies | Poor | Poor | Excellent | eBPF |
| Per-process control | Via type transitions | Via profiles | Native BPF maps | eBPF |
| Stackability | No | No | Yes | eBPF |
| Maturity | 25+ years | 15+ years | 5 years (BPF-LSM) | SELinux |
| Compliance | MLS/MCS, Common Criteria | Basic MAC | No formal certification | SELinux |
| Ease of use | Hard | Easy | Moderate | AppArmor |
| Kernel coverage | All LSM hooks | Subset | All hooks + tracepoints + kprobes | eBPF |
| AI agent suitability | Poor | Poor | Excellent | eBPF |

**Verdict:** For the specific use case of monitoring and restricting AI agent
file access, **eBPF is the clear technical winner**. It provides the dynamic,
programmable, low-overhead enforcement that AI agents require, while being
able to layer on top of existing SELinux/AppArmor deployments.

---

## Sources

- [AccuKnox - Runtime Security with eBPF/BPF-LSM](https://accuknox.com/blog/runtime-security-ebpf-bpf-lsm)
- [SELinux vs AppArmor Deep Dive](https://dohost.us/index.php/2025/10/05/selinux-vs-apparmor-a-comparative-deep-dive-into-linux-security-modules-lsm/)
- [TuxCare - AppArmor vs SELinux](https://tuxcare.com/blog/selinux-vs-apparmor/)
- [TechTarget - SELinux vs AppArmor](https://www.techtarget.com/searchdatacenter/tip/Compare-two-Linux-security-modules-SELinux-vs-AppArmor)
- [KubeArmor - Introduction to LSMs](https://kubearmor.io/blog/introduction-to-linux-security-modules)
- [eBPF-PATROL Paper (arXiv)](https://arxiv.org/pdf/2511.18155)
- [ACM - Comparative Analysis of Linux MAC](https://dl.acm.org/doi/pdf/10.1145/3578357.3589454)
- [Linux Rootkits Using eBPF (2025-2026)](https://cybersecuritynews.com/linux-rootkits-using-advanced-ebpf/)
- [eBPF Runtime Security Comparison (2025)](https://www.scitepress.org/Papers/2025/142727/142727.pdf)
- [Container Runtime Security Tooling (2025)](https://accuknox.com/wp-content/uploads/Container_Runtime_Security_Tooling.pdf)
- [Middleware - eBPF Observability Guide](https://middleware.io/blog/ebpf-observability/)
