# Guardian Shell

### Kernel-level security for AI coding agents on Linux

---

## The Problem

AI coding agents (Claude Code, Cursor, Aider, Codex) run with **full access to your machine**. Every file, every credential, every SSH key — wide open.

**This is not hypothetical.** Agents read files to do their job. But nothing stops them from reading the wrong ones.

| What agents can access today | What they actually need |
|------------------------------|------------------------|
| `~/.ssh/id_rsa` | Your project directory |
| `~/.aws/credentials` | A few system libraries |
| `.env` with production secrets | `/tmp` for scratch files |
| `/etc/shadow` | That's about it |
| Every file on your machine | |

Three forces make this worse every month:

**1. Indirect prompt injection is real.**
A malicious `.cursorrules` file, a poisoned README in a cloned repo, or a crafted code comment can instruct agents to exfiltrate credentials. The agent follows instructions — it can't tell malicious from legitimate.

**2. Agents are getting more autonomous.**
Background agents, multi-step tool use, and agentic workflows mean less human oversight per action. The attack surface grows with every capability upgrade.

**3. There's no middle ground today.**
Your options are: trust the agent completely (risky), run it in a container/VM (heavy, breaks workflow), or don't use agents at all (miss out). None of these are good.

---

## The Solution

**Guardian Shell** is an open-source Linux security tool that enforces fine-grained file, exec, and network policies for AI agents — at the kernel level.

```
You define what the agent can access. The kernel enforces it.
Everything else is blocked.
```

It's not a monitor. It's not a log aggregator. It **blocks unauthorized access before it happens**, using the same eBPF + Landlock technology that powers Cloudflare, Netflix, and Meta's production security infrastructure.

---

## How It Works (30-second version)

```bash
# 1. Write a simple policy
[[agents]]
name = "my-coding-agent"
identity = "cgroup"

[agents.file_access]
default = "deny"
allow = ["/home/user/project/**", "/tmp/**"]
deny  = ["/etc/shadow", "~/.ssh/**", "~/.aws/**"]

# 2. Start the daemon
sudo guardian --config config.toml

# 3. Launch your agent inside a sandbox
sudo guardian-launch --name my-coding-agent -- claude-code

# Done. The agent can only touch what you allowed.
# SSH keys, AWS creds, .env files — all blocked at the kernel.
```

No containers. No VMs. No workflow changes. The agent runs normally — it just can't reach what it shouldn't.

---

## What Makes Guardian Shell Different

### vs. "Just use Docker"

| | Docker/VM | Guardian Shell |
|---|-----------|----------------|
| **Overhead** | 100-500MB+ memory, seconds to start | <3% CPU, ~0 memory overhead |
| **Workflow** | Must wrap agent in container, mount volumes, manage images | Agent runs natively, transparent |
| **Granularity** | Filesystem-level isolation | Per-file, per-directory, per-binary policies |
| **Network** | All-or-nothing | Port-level control |
| **Interactive approvals** | No | Yes — approve/deny in real-time via dashboard |
| **Audit trail** | Docker logs | SQLite audit trail with risk scoring |

### vs. SELinux / AppArmor

| | SELinux/AppArmor | Guardian Shell |
|---|-----------------|----------------|
| **Config complexity** | Hundreds of policy rules, label management | Simple TOML, 10 lines for a working policy |
| **Agent-aware** | No concept of "agent sessions" | Per-agent identity, cgroup-based isolation |
| **Dynamic grants** | Requires policy reload | Temporary grants (60s-1hr) via CLI or dashboard |
| **Human-in-the-loop** | No | Real-time permission requests with risk scoring |

### vs. Commercial AI Security (Prisma AIRS, Datadog)

| | Commercial | Guardian Shell |
|---|-----------|----------------|
| **Cost** | Enterprise pricing | Free, open-source (MIT) |
| **Data** | SaaS — your data leaves your machine | Fully local, nothing phones home |
| **Focus** | Prompt/output scanning | Actual system-level enforcement |
| **Deployment** | SaaS integration | Single binary, zero dependencies |

---

## Defense in Depth: 6 Layers of Protection

Guardian Shell doesn't rely on a single mechanism. For cgroup-based agents, it stacks **six independent security layers**:

```
                    ┌──────────────────────────────┐
 Layer 1 (newest)   │  Landlock LSM                │  Inode-level file control
                    │  Immune to symlinks/TOCTOU    │  (Linux 5.13+)
                    ├──────────────────────────────┤
 Layer 2            │  Seccomp BPF                 │  Blocks dangerous syscalls
                    │  io_uring, mount, namespaces  │  (mount, chroot, unshare...)
                    ├──────────────────────────────┤
 Layer 3            │  PR_SET_NO_NEW_PRIVS         │  Prevents SUID escalation
                    ├──────────────────────────────┤
 Layer 4            │  eBPF LSM Hooks              │  Kernel-level file/exec/net
                    │  file_open, bprm_check,       │  enforcement
                    │  socket_connect               │
                    ├──────────────────────────────┤
 Layer 5            │  eBPF Tracepoints            │  Syscall monitoring + audit
                    │  openat, execve, connect      │  trail for all access
                    ├──────────────────────────────┤
 Layer 6            │  Cgroup Isolation            │  Unspoofable identity +
                    │  Memory/PID/CPU limits        │  resource limits
                    └──────────────────────────────┘
```

If any single layer is bypassed, the others still hold. This is the same defense-in-depth philosophy used in high-security production environments.

---

## Key Capabilities

### Real-Time Dashboard
A web UI (embedded in the binary, no separate install) shows live events, agent status, and pending permission requests. Built with htmx + Alpine.js — lightweight, no JS build step.

### Interactive Permission Requests
Agents can request access to protected resources. You see the request in your browser with a **risk score**, **justification analysis**, and **mandatory wait timer** (higher risk = longer wait). Approve or deny with one click.

**Important caveat:** Dynamic grants update eBPF maps in real-time (no restart). But for hardened cgroup agents, Landlock rules are set at launch and immutable — granting access to a path outside Landlock's initial scope requires relaunching the agent with an updated config. This is a deliberate security tradeoff: Landlock's immutability is what makes it immune to runtime bypass attacks.

### Risk-Based Approval Friction
Not all requests are equal. Guardian Shell scores every request:

| Risk Level | Wait Timer | Example |
|------------|-----------|---------|
| Low | 0 seconds | Reading `/tmp/scratch.txt` |
| Medium | 3 seconds | Reading project config files |
| High | 5 seconds | Accessing `/etc/passwd` |
| Critical | 10 seconds + type-to-confirm | Accessing SSH keys, AWS creds |

This prevents "approval fatigue" — you can't reflexively click "approve" on dangerous requests.

### Network Enforcement
Port-based outbound TCP control at the kernel level. Block agents from making unauthorized network connections (data exfiltration, C2 callbacks).

### Alerting & Integration
Slack notifications, email alerts, webhook integrations, Prometheus metrics, and structured JSONL logging — all built in. Connect to your existing SIEM/monitoring stack.

### Persistent Audit Trail
Every permission decision (approve, deny, auto-approve, auto-deny, timeout) is recorded in SQLite with full metadata: timestamp, agent, resource, risk level, justification, decision, and who decided.

---

## Real-World Scenarios

### Scenario 1: Prompt Injection Defense
> A developer clones a repo containing a malicious `.cursorrules` file that instructs the agent to `cat ~/.aws/credentials` and include the contents in a code comment.

**Without Guardian Shell:** Agent reads AWS credentials. Developer may not notice the exfiltration buried in generated code.

**With Guardian Shell:** Kernel blocks the read. Agent gets `EACCES`. Dashboard shows a CRITICAL-risk blocked event. Alert fires to Slack.

### Scenario 2: Supply Chain Attack
> A compromised npm package's postinstall script tries to read SSH keys and send them to a remote server.

**Without Guardian Shell:** Keys exfiltrated. No trace in any log.

**With Guardian Shell:** File read blocked by Landlock (inode-level, can't be bypassed with symlinks). Network connection blocked by port policy. Both events logged in audit trail.

### Scenario 3: Legitimate Access Escalation
> Agent needs to read a config file outside its allowed paths to complete a task.

**Without Guardian Shell:** Agent either has access to everything (risky) or nothing outside its sandbox (broken workflow).

**With Guardian Shell (two approaches depending on security tier):**

- **Comm-based agents (Tier 2):** Agent requests permission via `guardian-ctl request-permission`. Developer sees the request in dashboard with risk score, approves for 5 minutes. The daemon hot-updates the eBPF allow maps — access works immediately, no restart needed. Automatically revoked after expiry.

- **Cgroup agents (Tier 1 — hardened):** Landlock rules are set at launch and are immutable (this is a kernel security property — not a bug). The agent must be relaunched with an updated policy to access new paths. This is the tradeoff: Landlock's immutability is exactly what makes it immune to symlinks and TOCTOU attacks. You can't dynamically poke holes in it, and that's the point.

> **Design philosophy:** For hardened agents, we chose security over convenience. If an agent frequently needs access escalation, the right fix is a broader initial policy — not punching runtime holes in the sandbox.

---

## Who Is This For

**Individual developers** who use AI coding agents daily and want guardrails without giving up speed.

**Security-conscious teams** deploying AI agents in development environments and need audit trails + enforcement.

**Organizations with compliance requirements** that need to demonstrate AI agent access control and maintain approval records.

**Anyone running untrusted agent code** — open-source agents, community plugins, or agents operating on repos with untrusted content.

---

## What It's Not

Transparency matters. Here's what Guardian Shell does **not** do:

- **Not a prompt firewall** — it doesn't inspect or filter LLM inputs/outputs. It controls what the agent can do on your system.
- **Not a container runtime** — it doesn't isolate filesystems. It enforces policy on the real filesystem.
- **Not cross-platform** — Linux only (5.13+ recommended). macOS and Windows are not supported.
- **Not a network firewall** — it controls outbound TCP by port, but doesn't inspect DNS, UDP, or packet contents.
- **Not zero-config** — you write a TOML policy (though presets are provided for common setups).
- **Not dynamically re-sandboxable** — hardened (cgroup) agents use Landlock, which is immutable after launch. Changing what the agent can access requires relaunching it. This is a security feature, not a limitation — but it means you should design policies upfront rather than granting access ad-hoc.

---

## Getting Started

```bash
# Build (requires Rust nightly + bpf-linker)
cargo xtask build-ebpf --release && cargo build --release

# Use a preset config
cp configs/recommended.toml config.toml
# Edit to match your paths and agent names

# Run
sudo target/release/guardian --config config.toml

# Launch your agent
sudo target/release/guardian-launch --name my-agent \
    --memory 4G --pids 200 -- your-agent-command

# Open dashboard
# http://127.0.0.1:8080
```

---

## Technical Foundation

| Component | Technology | Why |
|-----------|-----------|-----|
| Kernel enforcement | eBPF + Landlock LSM | <3% overhead, defense-in-depth, inode-aware |
| Language | Rust | Memory-safe systems programming for kernel-adjacent code |
| Configuration | TOML | Human-readable, simple, no YAML footguns |
| Dashboard | axum + htmx + Alpine.js | Single binary, no JS build step, ~30KB frontend |
| IPC | Unix domain socket + length-prefixed JSON | Simple, debuggable, no gRPC overhead |
| Audit | SQLite | Persistent, queryable, survives restarts |
| Metrics | Prometheus | Industry standard, plugs into existing monitoring |

---

## Open Source

Guardian Shell is fully open-source. No telemetry, no phone-home, no enterprise upsell. Your security infrastructure shouldn't depend on someone else's SaaS staying online.

Built with Rust and eBPF. Runs as a single binary. Deploys in minutes.

**The kernel is the best firewall. Guardian Shell gives you the controls.**
