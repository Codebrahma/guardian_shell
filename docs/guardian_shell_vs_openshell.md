# Guardian Shell vs NVIDIA OpenShell — Architecture & Trade-off Comparison

## Executive Summary

Both Guardian Shell and NVIDIA OpenShell solve the same problem: **restricting what AI agents can do on a Linux system**. They take fundamentally different architectural approaches:

| | Guardian Shell | NVIDIA OpenShell |
|---|---|---|
| **Approach** | Kernel-level eBPF + Landlock (process-level) | Container sandbox + Application-layer proxy |
| **Enforcement** | In-kernel tracepoints, LSM hooks, Landlock, seccomp | Landlock, seccomp, network namespace + HTTP proxy |
| **Weight** | Single binary, no containers | Docker + embedded K3s cluster |
| **Policy** | TOML with glob patterns | YAML + OPA/Rego |
| **Status** | Phase 11 (functional) | Alpha (single-player) |
| **Language** | Rust + eBPF C | Rust + Python CLI |
| **License** | — | Apache 2.0 |

---

## Architecture Overview

### Guardian Shell

```
┌─────────────────────────────────────────────────────┐
│                    Linux Kernel                      │
│  ┌──────────────┐  ┌───────────┐  ┌──────────────┐  │
│  │ eBPF         │  │ Landlock  │  │ seccomp BPF  │  │
│  │ Tracepoints  │  │ LSM       │  │ (syscall     │  │
│  │ + LSM hooks  │  │ (inode)   │  │  filter)     │  │
│  └──────┬───────┘  └─────┬─────┘  └──────┬───────┘  │
└─────────┼───────────────┼────────────────┼───────────┘
          │               │                │
┌─────────▼───────────────▼────────────────▼───────────┐
│              guardian (userspace daemon)               │
│  ┌─────────┐ ┌──────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Policy  │ │Permission│ │ Dashboard │ │Alerting │ │
│  │ Engine  │ │ System   │ │ (axum+htmx│ │(webhook,│ │
│  │         │ │(risk,rate│ │  +Alpine) │ │ slack,  │ │
│  │         │ │ ,audit)  │ │           │ │ email)  │ │
│  └─────────┘ └──────────┘ └───────────┘ └─────────┘ │
└──────────────────────┬───────────────────────────────┘
                       │ Unix socket IPC
          ┌────────────┼────────────┐
          ▼            ▼            ▼
   guardian-launch  guardian-ctl   Agent process
   (cgroup setup,   (list/stop/   (runs inside
    Landlock,        grant/        cgroup with
    seccomp,         approve)      restrictions)
    priv drop)
```

**Key insight**: Guardian Shell instruments the kernel directly. eBPF tracepoints fire on every `openat`, `execve`, `connect` syscall. LSM hooks enforce deny decisions in-kernel before the syscall completes. Landlock adds inode-level enforcement immune to symlink attacks. There is no container boundary — isolation is at the process/cgroup level.

### NVIDIA OpenShell

```
┌──────────────────────────────────────────────────────┐
│                Docker Container (K3s)                 │
│                                                      │
│  ┌──────────────────────────────────────────────┐    │
│  │          Gateway (openshell-server)           │    │
│  │  gRPC + HTTP API, mTLS, credential store,    │    │
│  │  sandbox lifecycle, SSH tunnel gateway        │    │
│  └──────────────────┬───────────────────────────┘    │
│                     │                                │
│  ┌──────────────────▼───────────────────────────┐    │
│  │           Sandbox Pod (per agent)             │    │
│  │  ┌────────────────────────────────────────┐   │    │
│  │  │         Supervisor (privileged)         │   │    │
│  │  │  Sets up: network namespace, Landlock,  │   │    │
│  │  │  seccomp, privilege drop, spawns agent  │   │    │
│  │  └──────────┬─────────────────────────────┘   │    │
│  │             │                                 │    │
│  │  ┌──────────▼──────┐  ┌───────────────────┐  │    │
│  │  │  Agent Process  │  │  HTTP CONNECT      │  │    │
│  │  │  (restricted)   │──│  Proxy + OPA/Rego  │  │    │
│  │  │  Landlock +     │  │  L4/L7 filtering   │  │    │
│  │  │  seccomp +      │  │  SSRF prevention   │  │    │
│  │  │  net namespace  │  │  Binary integrity  │  │    │
│  │  └─────────────────┘  └───────────────────┘  │    │
│  │                                               │    │
│  │  ┌─────────────────────────────────────────┐  │    │
│  │  │  Privacy Router (inference.local)       │  │    │
│  │  │  Rewrites auth headers, hides API keys  │  │    │
│  │  └─────────────────────────────────────────┘  │    │
│  └───────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────┘
```

**Key insight**: OpenShell wraps each agent in a Kubernetes pod with full network namespace isolation. All outbound traffic is forced through an HTTP CONNECT proxy that evaluates OPA/Rego policies per-connection and per-request. The proxy can perform L7 HTTP inspection (method, path, headers) — something kernel-level tools cannot do.

---

## Detailed Comparison

### 1. Isolation Model

| Aspect | Guardian Shell | OpenShell |
|--------|---------------|-----------|
| **Boundary** | cgroup + Landlock + seccomp (process-level) | Kubernetes pod + network namespace (container-level) |
| **Identity** | cgroup ID (unspoofable, kernel-assigned) | Container boundary (inherent isolation) |
| **Child processes** | Automatic via cgroup inheritance | Automatic via container boundary |
| **Resource limits** | cgroup v2 controllers (memory, PIDs, CPU) | Kubernetes resource limits + cgroup |
| **Overhead** | Near-zero (kernel hooks, no containers) | Significant (Docker + K3s + pod per agent) |
| **Startup time** | Milliseconds (fork + exec + cgroup) | Seconds (pod scheduling + container start) |

**Verdict**: Guardian Shell is lighter and faster. OpenShell provides stronger isolation boundaries (full container) at the cost of infrastructure weight.

### 2. Filesystem Enforcement

| Aspect | Guardian Shell | OpenShell |
|--------|---------------|-----------|
| **Primary mechanism** | Landlock LSM (cgroup agents) + eBPF tracepoints/LSM | Landlock LSM |
| **Policy model** | Default-deny with allow/deny glob rules | Default-deny with read_only/read_write allowlists |
| **Symlink immunity** | Yes (Landlock on inodes) | Yes (Landlock on inodes) |
| **Real-time monitoring** | Yes — every file open/exec/rename/unlink is an event | No — Landlock is silent allow/deny |
| **Audit trail** | Full event stream + SQLite audit log | No per-access audit trail |
| **Temporary grants** | Yes — time-limited grants via CLI or dashboard | No — policy is static at sandbox creation |
| **Interactive approval** | Yes — human-in-the-loop approve/deny with risk scoring | No |
| **Dynamic linker detection** | Yes — eBPF detects ld-linux executing real binary | Not at kernel level |
| **inode_rename/unlink hooks** | Yes — eBPF LSM prevents rename/hardlink attacks | Landlock only (no rename-specific hooks) |

**Verdict**: Guardian Shell has significantly richer filesystem visibility and control. The ability to monitor individual file accesses in real-time, grant temporary permissions, and require human approval for risky operations is a major differentiator. OpenShell's Landlock-only approach is simpler but offers no runtime flexibility or visibility into what the agent is actually accessing.

### 3. Network Enforcement

| Aspect | Guardian Shell | OpenShell |
|--------|---------------|-----------|
| **Mechanism** | eBPF `sys_enter_connect` + LSM `socket_connect` + Landlock TCP | Network namespace + HTTP CONNECT proxy + OPA/Rego |
| **Enforcement level** | Kernel (port-based, returns -ECONNREFUSED) | Application layer (L4 host:port + L7 HTTP method/path) |
| **L7 inspection** | No | Yes — can inspect HTTP method, path, headers |
| **Per-binary policy** | No (per-agent/cgroup only) | Yes — process identity binding via /proc |
| **Binary integrity** | No | Yes — SHA256 TOFU (first-use hash pinning) |
| **SSRF prevention** | Basic (SSRF URL validation in dashboard) | Strong (DNS resolution + private IP blocking) |
| **TLS inspection** | No | Yes — ephemeral CA per sandbox, MITM for L7 |
| **Hot-reload** | Requires daemon restart or SIGHUP | Yes — network policy updates without sandbox restart |
| **DNS monitoring** | No | No (both have this gap) |
| **UDP enforcement** | No (both have this gap) | Partial (seccomp can block socket families) |
| **Credential protection** | Not built-in | Built-in inference router hides API keys from agent |

**Verdict**: OpenShell's proxy-based network enforcement is substantially more capable. L7 HTTP inspection, per-binary policy, binary integrity checking, SSRF prevention, and credential isolation are features that kernel-level port-based enforcement cannot match. This is OpenShell's strongest advantage.

### 4. Policy System

| Aspect | Guardian Shell | OpenShell |
|--------|---------------|-----------|
| **Format** | TOML with glob patterns | YAML + OPA/Rego |
| **Expressiveness** | Medium — glob patterns, per-agent allow/deny | High — full Rego logic, L4+L7 rules, per-binary |
| **Evaluation** | In-kernel (eBPF) + userspace (permissions.rs) | Embedded OPA (regorus, pure Rust) |
| **Hot reload** | SIGHUP for agent policies | Network policies hot-reloadable, filesystem static |
| **Versioning** | No | Yes — policy versioning with LKG rollback |
| **Risk scoring** | Yes — 4-tier risk classification with UI friction | No |
| **Rate limiting** | Yes — per-agent rate limits with exponential backoff | No |
| **Justification analysis** | Yes — pattern matching for social engineering | No |

**Verdict**: Different strengths. OpenShell has more expressive network policy (Rego). Guardian Shell has richer approval-time intelligence (risk scoring, rate limiting, justification analysis). OpenShell's policy versioning with rollback is a production-readiness feature Guardian Shell lacks.

### 5. Observability & Monitoring

| Aspect | Guardian Shell | OpenShell |
|--------|---------------|-----------|
| **Event stream** | Real-time SSE stream of all syscall events | Proxy logs only |
| **Dashboard** | Built-in web UI (axum + htmx + Alpine.js) | TUI (ratatui) + CLI |
| **Alerting** | Webhook, Slack, email, JSONL, Prometheus metrics | Not built-in |
| **Permission audit** | SQLite trail with full metadata | No per-access audit |
| **Anomaly detection** | Basic (rubber-stamping, deny-then-approve patterns) | No |
| **Metrics** | Prometheus endpoint (file events, exec events, alerts) | Not built-in |

**Verdict**: Guardian Shell provides much richer observability. Real-time syscall event streams, multi-channel alerting, and anomaly detection give security teams visibility that OpenShell's architecture cannot provide (since Landlock is silent).

### 6. Human-in-the-Loop

| Aspect | Guardian Shell | OpenShell |
|--------|---------------|-----------|
| **Interactive permissions** | Yes — agent blocks until human approves/denies | No |
| **Risk-based friction** | Yes — mandatory wait timers, type-to-confirm for critical | No |
| **Temporary grants** | Yes — 1 min to 1 hour, auto-expiring | No |
| **CLI approval** | Yes — `guardian-ctl approve/deny` | No |
| **Dashboard approval** | Yes — web UI with risk badges and countdown | No |
| **Auto-deny timeout** | Yes — 120s fail-secure | N/A |
| **Auto-approve rules** | Yes — configurable for low-risk resources | N/A |

**Verdict**: Guardian Shell's interactive permission system is a unique capability. OpenShell takes an "all policy must be predefined" approach — if the agent hits a boundary, it's simply blocked with no recourse. Guardian Shell allows runtime negotiation with human oversight, which is more practical for exploratory agent workloads.

### 7. Deployment & Operations

| Aspect | Guardian Shell | OpenShell |
|--------|---------------|-----------|
| **Prerequisites** | Linux kernel with BPF support, root access | Docker 28.04+ |
| **Deployment** | Single binary (< 10 MB), `sudo ./guardian` | `docker run` (full K3s cluster inside) |
| **Resource footprint** | Minimal (eBPF runs in kernel, daemon is ~50MB RSS) | Heavy (K3s + etcd + pods + proxy per sandbox) |
| **Platform** | Linux only (x86_64, kernel 5.13+ for Landlock) | Linux, macOS (Docker Desktop), Windows (WSL2) |
| **Multi-agent** | Yes — multiple cgroup agents concurrently | Yes — multiple sandbox pods |
| **Remote access** | No (local only) | Yes — SSH tunnels + mTLS |
| **GPU passthrough** | No | Experimental |
| **Auth** | Optional Bearer token for dashboard | mTLS everywhere (auto-bootstrapped PKI) |
| **Credential management** | Not built-in | Built-in (provider system, inference router) |

**Verdict**: Guardian Shell is dramatically simpler to deploy and operate. OpenShell's Docker/K3s requirement makes it portable (macOS, Windows) but adds significant operational complexity. OpenShell's remote access and credential management are enterprise features Guardian Shell lacks.

---

## Strengths Summary

### Guardian Shell Strengths

1. **Deep kernel visibility** — eBPF tracepoints on every syscall give complete real-time visibility into agent behavior. You see every file open, every exec, every network connection.
2. **Interactive permissions** — Unique human-in-the-loop system with risk scoring, rate limiting, and justification analysis. Agents can request access at runtime.
3. **Lightweight** — Single binary, no containers, near-zero overhead. eBPF runs in kernel space.
4. **Rich observability** — SSE event stream, web dashboard, Prometheus metrics, multi-channel alerting (Slack, webhook, email).
5. **Temporary grants** — Time-limited access grants that auto-expire. Critical for exploratory agent workloads.
6. **Defense-in-depth for files** — Landlock (inode-level) + eBPF (syscall-level) + seccomp, with eBPF providing audit trail that Landlock cannot.
7. **Anomaly detection** — Automated detection of suspicious approval patterns.
8. **Fast startup** — Agent isolation in milliseconds vs seconds for container-based approaches.

### NVIDIA OpenShell Strengths

1. **Superior network enforcement** — HTTP CONNECT proxy with L7 inspection can enforce policies at the HTTP method/path level. Can inspect TLS traffic via ephemeral CA.
2. **Per-binary network policy** — Proxy identifies which binary made each connection via `/proc` inspection. SHA256 TOFU ensures binary integrity.
3. **Credential isolation** — Built-in inference router hides API keys from agents. Agent calls `inference.local`, router adds real credentials.
4. **Cross-platform** — Runs on macOS and Windows via Docker Desktop. Guardian Shell is Linux-only.
5. **OPA/Rego policy** — Full-featured policy language for complex network rules.
6. **Policy versioning** — Network policies have version tracking with last-known-good rollback.
7. **SSRF prevention** — DNS resolution + private IP blocking at the proxy level.
8. **Remote access** — SSH tunnels + mTLS enable remote sandbox management.
9. **Strong container isolation** — Full network namespace with veth pairs means the agent literally cannot reach anything except the proxy.
10. **Enterprise features** — GPU passthrough, provider management, multi-architecture support.

---

## Weaknesses Summary

### Guardian Shell Weaknesses

1. **No L7 network inspection** — Port-based only. Cannot distinguish `GET /safe` from `POST /dangerous` on the same port.
2. **No credential management** — Agents can access API keys in environment or config files.
3. **Linux-only** — Requires kernel 5.13+ with BPF support. No macOS/Windows.
4. **x86_64 hardcoded** — Tracepoint offsets and seccomp syscall numbers are x86_64-specific.
5. **No binary integrity checking** — Cannot verify that a binary hasn't been replaced.
6. **No remote access** — Local-only operation.
7. **Config reload limitations** — Alerting changes require daemon restart.
8. **No policy versioning** — No rollback mechanism for policy changes.
9. **UDP/DNS blind spots** — Same as OpenShell.

### NVIDIA OpenShell Weaknesses

1. **No real-time file monitoring** — Landlock is silent. No event stream for individual file accesses. You don't know what the agent accessed, only what it was allowed to access.
2. **No interactive permissions** — All policy must be predefined. No runtime negotiation.
3. **No temporary grants** — Filesystem policy is static at sandbox creation.
4. **Heavy infrastructure** — Docker + K3s cluster in a container. Significant resource overhead per sandbox.
5. **No alerting system** — No built-in webhook, Slack, email, or metrics integration.
6. **No anomaly detection** — No analysis of agent behavior patterns.
7. **No audit trail** — No persistent record of individual file access decisions.
8. **Alpha status** — Single-player mode only, no multi-tenant.
9. **Slow sandbox startup** — Container + pod scheduling is seconds vs milliseconds.
10. **No risk scoring** — All policy decisions are binary allow/deny with no risk intelligence.

---

## When to Use Which

| Scenario | Recommended | Why |
|----------|-------------|-----|
| **Production security monitoring** | Guardian Shell | Real-time event stream, alerting, anomaly detection |
| **Exploratory agent workloads** | Guardian Shell | Interactive permissions let agents request access as needed |
| **Strict network policy (L7)** | OpenShell | HTTP-level inspection, per-binary policy, SSRF prevention |
| **Credential-sensitive environments** | OpenShell | Built-in credential isolation, inference router |
| **Lightweight / embedded** | Guardian Shell | Single binary, no containers, minimal overhead |
| **Cross-platform (macOS/Windows)** | OpenShell | Docker-based, runs anywhere Docker runs |
| **Security audit / compliance** | Guardian Shell | Full audit trail, every syscall logged |
| **Multi-agent with GPU** | OpenShell | Kubernetes-native scaling, GPU passthrough |
| **Development / learning** | Guardian Shell | Simpler setup, richer feedback on agent behavior |
| **Enterprise / remote teams** | OpenShell | SSH tunnels, mTLS, provider management |

---

## Architectural Philosophy

**Guardian Shell** follows the **"instrument the kernel, trust no process"** philosophy. Every syscall is visible. Every file access is an event. The human operator is in the loop for risky decisions. The system is transparent — you can see exactly what the agent did, when, and whether it was allowed.

**NVIDIA OpenShell** follows the **"isolate the container, control the network"** philosophy. The agent runs in a locked-down sandbox where it physically cannot reach unauthorized resources. Network policy is the primary control plane. The system is opaque at the file level but highly capable at the network level.

Neither approach is strictly superior. They optimize for different threat models:

- **Guardian Shell** excels when the threat is **what the agent does on the local filesystem** — reading sensitive files, executing dangerous binaries, escalating privileges.
- **OpenShell** excels when the threat is **what the agent communicates over the network** — exfiltrating data, calling unauthorized APIs, attacking internal services.

An ideal production setup might combine both: Guardian Shell's eBPF monitoring inside an OpenShell sandbox, getting kernel-level visibility with container-level network isolation.

---

*Last updated: 2026-03-25*
