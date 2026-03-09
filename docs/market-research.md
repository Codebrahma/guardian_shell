# Guardian Shell - Market Research

## Executive Summary

The AI agent security space is rapidly growing in 2025-2026 as LLM-powered agents
(Claude Code, Cursor, Gemini CLI, etc.) gain the ability to execute code, access
files, and interact with systems autonomously. Multiple products exist in this
space, but **no standalone, Rust-based, simple-config tool exists that both
monitors and enforces file access policies for AI agents on bare Linux without
requiring Kubernetes.**

---

## Market Landscape

### The Problem

- AI agents routinely hold **10x more privileges** than required
- **90% of agents are over-permissioned** - most SaaS platforms default to
  "read all files" when only a single folder is needed
- Traditional LLM firewalls act as proxies and only observe prompts/outputs,
  **missing critical interactions** an AI agent has with connected systems
- Indirect prompt injection (malicious repos, .cursorrules, CLAUDE.md files)
  can cause agents to access unauthorized files or execute harmful commands

### Market Size Indicators

- Cursor reports **1/3 of all requests** on supported platforms run with
  sandboxing active (as of Feb 2026)
- Palo Alto Networks built **Prisma AIRS** - a dedicated AI runtime security product
- Datadog has **5+ years** of eBPF security investment
- Multiple academic papers published in 2025 on AI agent security with eBPF
- NVIDIA published official guidance on sandboxing agentic workflows

---

## Competitive Analysis

### Direct Competitors

#### 1. AgentSight (eunomia-bpf) - Most Similar

- **Type:** Open-source
- **GitHub:** https://github.com/eunomia-bpf/agentsight
- **Language:** C / Python
- **Published:** PACMI'25 (ACM workshop paper)
- **What it does:**
  - Uses eBPF to monitor AI agents (Claude Code, Gemini CLI)
  - Intercepts TLS traffic to correlate LLM *intent* with system *actions*
  - Two-stage correlation: real-time engine + secondary LLM analysis
  - Zero instrumentation required (no SDK, no code changes)
  - < 3% CPU overhead
- **Limitations:**
  - **Observability only** - no enforcement/blocking capability
  - Requires a secondary LLM to analyze traces (adds cost and latency)
  - Written in C/Python (not memory-safe for kernel-adjacent code)
- **How Guardian Shell differs:**
  - Planned enforcement via BPF-LSM (Phase 2)
  - Written in Rust (memory safety)
  - Simple TOML policy config (no secondary LLM needed)
  - Standalone daemon (no complex infrastructure)

#### 2. Tetragon (Cilium / CNCF)

- **Type:** Open-source (CNCF project)
- **Website:** https://tetragon.io
- **Language:** Go
- **What it does:**
  - General-purpose eBPF runtime enforcement
  - File access, process execution, network monitoring
  - Kernel-level blocking (not just alerting)
  - Kubernetes-aware with TracingPolicy CRDs
  - Most efficient CPU usage among eBPF security tools
- **Limitations:**
  - **Kubernetes-centric** - designed for container orchestration
  - Not purpose-built for AI agents
  - Complex setup for standalone Linux use
  - Requires Go ecosystem knowledge to extend
- **How Guardian Shell differs:**
  - Purpose-built for AI agent monitoring
  - Works on bare Linux without Kubernetes
  - Simpler configuration (TOML vs TracingPolicy YAML)
  - Lighter footprint for single-machine deployments

#### 3. Prisma AIRS (Palo Alto Networks)

- **Type:** Commercial (enterprise)
- **What it does:**
  - AI-specific runtime security using eBPF
  - Deep real-time visibility into agent behavior
  - Monitors interactions with connected systems beyond prompt/output
- **Limitations:**
  - **Proprietary and expensive** (enterprise pricing)
  - Requires Palo Alto ecosystem integration
  - Not suitable for individual developers or small teams
- **How Guardian Shell differs:**
  - Open-source and free
  - Lightweight, no vendor lock-in
  - Self-hosted, privacy-preserving

#### 4. Datadog Workload Protection

- **Type:** Commercial (SaaS)
- **What it does:**
  - Uses BPF-LSM for mandatory access control
  - Unified eBPF mechanism for file, network, and process monitoring
  - 5+ years of production eBPF security experience
- **Limitations:**
  - **Commercial SaaS** - requires Datadog subscription
  - General workload security, not AI-agent specific
  - Data leaves your infrastructure
- **How Guardian Shell differs:**
  - AI-agent focused policies
  - Fully local, no data exfiltration
  - No subscription cost

### Broader eBPF Runtime Security Tools

| Tool | Maintainer | Focus | Enforcement | AI-Aware |
|------|-----------|-------|-------------|----------|
| **Falco** | Sysdig / CNCF | Syscall monitoring, alerting | Detection only | No |
| **Tracee** | Aqua Security | Deep kernel tracing | Detection only | No |
| **KubeArmor** | AccuKnox | BPF-LSM enforcement | Yes | No |
| **Cilium** | Isovalent / Cisco | Network security | Yes (network) | No |

- **Falco** is the most popular open-source runtime security tool but is
  detection-only (similar to Guardian Shell Phase 1) and not AI-aware
- **Tracee** provides deep kernel tracing but has 2-4x overhead compared
  to Tetragon
- **KubeArmor** does BPF-LSM enforcement but is Kubernetes-only
- None of these are built for AI agent use cases

### Non-eBPF AI Agent Sandboxing

| Product | Approach | Trade-off |
|---------|----------|-----------|
| **Cursor Agent Sandbox** | OS-level (macOS sandbox-exec, Linux Landlock) | IDE-specific, not general-purpose |
| **Docker** | Container isolation | Heavy, requires containerizing agents |
| **gVisor** | User-space kernel | Significant performance overhead |
| **Firecracker** | MicroVM | Complex infrastructure |
| **Landlock** | Kernel-level sandboxing | Limited to file access, no network/process |

These approaches provide isolation but lack the **programmable, dynamic
policy enforcement** that eBPF offers. They also require wrapping the agent
in a container/VM rather than monitoring it transparently.

---

## Competitive Positioning Matrix

```
                    AI-Agent Specific
                          |
         Guardian Shell   |   AgentSight
         (monitor+enforce)|   (observe only)
                          |
    Standalone ───────────┼─────────── Kubernetes
                          |
         Falco/Tracee     |   Tetragon
         (general monitor)|   (general enforce)
                          |
                    General Purpose
```

---

## Guardian Shell's Unique Value Proposition

### What exists but doesn't solve the full problem:

1. **AgentSight** monitors but cannot enforce
2. **Tetragon** enforces but requires Kubernetes and isn't AI-focused
3. **Falco/Tracee** detect but cannot block
4. **Commercial tools** (Prisma AIRS, Datadog) are expensive and enterprise-only
5. **Container sandboxes** (Docker, gVisor) require wrapping agents, adding overhead

### The gap Guardian Shell fills:

**A standalone, lightweight, Rust-based daemon that provides both monitoring
AND enforcement of file access policies for AI agents on bare Linux, with
simple TOML configuration, no Kubernetes required, and no vendor lock-in.**

| Feature | Guardian Shell | Nearest Alternative |
|---------|---------------|-------------------|
| AI-agent focused | Yes | AgentSight (observe only) |
| Enforcement capability | Phase 2 (BPF-LSM) | Tetragon (K8s required) |
| Language | Rust (memory-safe) | Go (Tetragon) or C (AgentSight) |
| Configuration | Simple TOML | YAML CRDs (Tetragon) |
| Infrastructure needed | Single Linux machine | K8s cluster (Tetragon) |
| Cost | Free / open-source | Enterprise pricing (Prisma, Datadog) |
| Privacy | Fully local | SaaS (Datadog) |

---

## Market Opportunities

### Short-term (2026)

- Growing demand as Claude Code, Cursor, Windsurf, and other AI coding tools
  become mainstream
- Security teams need simple tools to audit what AI agents are doing
- Compliance requirements emerging for AI agent activity logging

### Medium-term (2026-2027)

- Enterprise adoption of AI agents will drive demand for governance tools
- Integration with CI/CD pipelines for secure AI-assisted development
- Multi-agent orchestration creates complex security requirements

### Long-term (2027+)

- Standardization of AI agent security frameworks (OWASP, NIST)
- Regulatory requirements for AI agent audit trails
- AI agents managing infrastructure will need kernel-level enforcement

---

## Recommendations

1. **Phase 1 (current)** validates the core concept - keep it simple,
   get it working on Linux, gather feedback
2. **Phase 2 (BPF-LSM enforcement)** is the key differentiator - this is
   where Guardian Shell moves beyond what AgentSight and Falco can do
3. **Consider adding TLS interception** (like AgentSight) in a future phase
   to correlate agent intent with system actions
4. **Target individual developers and small teams first** - the gap is
   clearest in the non-enterprise, non-Kubernetes segment
5. **Publish benchmarks** comparing overhead vs Tetragon/Falco to establish
   credibility

---

## Sources

- [AgentSight GitHub](https://github.com/eunomia-bpf/agentsight)
- [AgentSight Paper (arXiv)](https://arxiv.org/html/2508.02736v1)
- [AgentSight Blog](https://eunomia.dev/blog/2025/08/26/agentsight-keeping-your-ai-agents-under-control-with-ebpf-powered-system-observability/)
- [Tetragon](https://tetragon.io/)
- [Palo Alto - AI Security with eBPF](https://www.paloaltonetworks.com/blog/network-security/beginners-guide-to-ai-security-with-ebpf/)
- [Datadog eBPF Workload Protection](https://www.datadoghq.com/blog/engineering/ebpf-workload-protection-lessons/)
- [ARMO AI Agent Sandboxing Guide](https://www.armosec.io/blog/ai-agent-sandboxing-progressive-enforcement-guide/)
- [NVIDIA Sandboxing Agentic Workflows](https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/)
- [AI Agent Security Landscape 2025](https://www.obsidiansecurity.com/blog/ai-agent-market-landscape)
- [Cursor AI Agent Sandboxing](https://www.adwaitx.com/cursor-ai-agent-sandboxing-explained/)
- [eBPF Runtime Security Comparison (2025)](https://www.scitepress.org/Papers/2025/142727/142727.pdf)
- [Falco vs Tetragon](https://medium.com/@mughal.asim/falco-vs-tetragon-a-runtime-security-showdown-for-kubernetes-a0e9fb9f30a0)
- [Open Source CWPP Overview](https://cloudwithjk.hashnode.dev/open-source-cwpp-solutions)
