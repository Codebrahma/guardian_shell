# Guardian Shell - Architecture & Technical Deep Dive

This document explains the internals of Guardian Shell: how it works at every layer, what eBPF is and why it matters, the design decisions behind the architecture, and the real bugs and issues we encountered during development — along with how we debugged and fixed them.

---

## Table of Contents

1. [The Problem](#the-problem)
2. [Why eBPF?](#why-ebpf)
   - [What is eBPF?](#what-is-ebpf)
   - [The BPF Virtual Machine](#the-bpf-virtual-machine)
   - [The BPF Verifier](#the-bpf-verifier)
   - [BPF Maps](#bpf-maps)
   - [BPF Helper Functions](#bpf-helper-functions)
   - [Why Not Userspace Sandboxing?](#why-not-userspace-sandboxing)
3. [Architecture Overview](#architecture-overview)
4. [Component Deep Dive](#component-deep-dive)
   - [guardian-common: Shared Types](#guardian-common-shared-types)
   - [guardian-ebpf: Kernel Program](#guardian-ebpf-kernel-program)
   - [guardian (userspace): Daemon](#guardian-userspace-daemon)
   - [xtask: Build System](#xtask-build-system)
5. [The Data Flow: From Syscall to Log Line](#the-data-flow-from-syscall-to-log-line)
6. [Cross-Compilation: Two Targets, One Codebase](#cross-compilation-two-targets-one-codebase)
7. [The Aya Framework](#the-aya-framework)
8. [Policy Engine Internals](#policy-engine-internals)
9. [Bugs, Issues & Debugging Stories](#bugs-issues--debugging-stories)
   - [Issue 1: Code Written on macOS, Needs Linux](#issue-1-code-written-on-macos-needs-linux)
   - [Issue 2: online_cpus() Error Type Mismatch](#issue-2-online_cpus-error-type-mismatch)
   - [Issue 3: Aya API Change — map_mut vs take_map](#issue-3-aya-api-change--map_mut-vs-take_map)
   - [Issue 4: The PID Scanning Problem](#issue-4-the-pid-scanning-problem)
   - [Issue 5: Periodic Rescan Still Not Fast Enough](#issue-5-periodic-rescan-still-not-fast-enough)
   - [Issue 6: BPF Verifier Rejection](#issue-6-bpf-verifier-rejection)
   - [Issue 7: ALLOW Events Were Invisible](#issue-7-allow-events-were-invisible)
10. [Design Decisions & Trade-offs](#design-decisions--trade-offs)
11. [Memory Layout & Safety](#memory-layout--safety)
12. [Performance Characteristics](#performance-characteristics)
13. [What We Would Do Differently](#what-we-would-do-differently)
14. [Glossary](#glossary)

---

## The Problem

LLM agents (Claude Code, AutoGPT, Aider, Cursor, etc.) run on your machine with your user's permissions. They can read and write any file you can. This means an LLM agent could:

- Read your SSH private keys (`~/.ssh/id_rsa`)
- Read your cloud credentials (`~/.aws/credentials`)
- Read environment files with API keys (`.env`)
- Modify system configuration
- Access data from other projects

There's no built-in mechanism in Linux to say "this process can access files A, B, C but not D, E, F" at a granular path level with pattern matching. Traditional Unix permissions are too coarse — if your user can read a file, every process running as your user can read it.

Guardian Shell solves this by using eBPF to intercept file access at the kernel level and evaluate it against a fine-grained policy.

---

## Why eBPF?

### What is eBPF?

eBPF (extended Berkeley Packet Filter) is a technology that lets you run sandboxed programs inside the Linux kernel without modifying kernel source code or loading kernel modules.

Think of it this way:
- **Kernel modules** are like installing a new engine in your car — powerful but risky. A bug crashes the whole kernel.
- **eBPF programs** are like a dashcam — they observe and report without affecting the engine. The kernel guarantees they can't crash the system.

eBPF was originally designed for network packet filtering (hence "Packet Filter" in the name), but it has evolved into a general-purpose kernel instrumentation framework used for:
- Network monitoring and firewalling (Cilium)
- Security monitoring (Falco, Tracee)
- Performance profiling (bpftrace)
- And now, LLM agent monitoring (Guardian Shell)

### The BPF Virtual Machine

eBPF programs run on a virtual machine inside the kernel. This VM has:

- **11 registers** (R0-R10): R0 is the return value, R1-R5 are function arguments, R6-R9 are callee-saved, R10 is the read-only frame pointer
- **512-byte stack** per function: This is tiny. Our `FileAccessEvent` struct is 292 bytes, which would consume most of the stack. This is why we use per-CPU array maps as scratch buffers.
- **A limited instruction set**: ~100 instructions, similar to a RISC processor
- **No loops** (historically): The verifier must prove termination. Bounded loops were added in Linux 5.3+.
- **No dynamic memory allocation**: No `malloc`, no heap. Everything must be statically sized or use BPF maps.

eBPF programs are compiled to BPF bytecode, which is JIT-compiled to native machine code by the kernel for near-native performance.

### The BPF Verifier

Before any eBPF program runs, the kernel's BPF verifier performs static analysis to guarantee safety:

1. **Termination**: The program must not contain infinite loops (it walks all possible execution paths)
2. **Memory safety**: All memory accesses must be within bounds. The verifier tracks the type and range of every register.
3. **No null pointer dereferences**: If a map lookup returns a pointer, you must check for NULL before dereferencing
4. **Stack bounds**: Cannot access beyond the 512-byte stack frame
5. **Helper function safety**: Can only call approved BPF helper functions with correct argument types

The verifier is conservative — it rejects programs it can't prove safe, even if they are actually safe. This is why optimized (`--release`) builds pass the verifier more reliably: the optimizer removes redundant instructions that confuse the verifier's analysis.

**Real example from our project**: When we added dual PID + comm checking to the eBPF program, the verifier rejected it. The additional branches and map lookups made the program too complex for the verifier to analyze. We simplified to comm-only matching, which passed. (See [Issue 6](#issue-6-bpf-verifier-rejection) for the full story.)

### BPF Maps

Maps are shared data structures that allow communication between eBPF programs (kernel) and userspace. They survive across eBPF program invocations and are the primary mechanism for:

- **Configuration**: Userspace writes data that the eBPF program reads
- **Event output**: eBPF program writes events that userspace reads
- **State**: Persisting data across program invocations

Guardian Shell uses three maps:

| Map | Type | Key → Value | Purpose |
|-----|------|-------------|---------|
| `WATCHED_COMMS` | `HashMap` | `[u8; 16]` → `u8` | Userspace writes process names to watch; eBPF reads to filter events |
| `EVENT_BUF` | `PerCpuArray` | index → `FileAccessEvent` | Pre-allocated scratch buffer, one per CPU core. Avoids the 512-byte stack limit. |
| `EVENTS` | `PerfEventArray` | — | Per-CPU ring buffer for sending events from kernel to userspace |

**Why PerCpuArray for EVENT_BUF?**

eBPF programs run with preemption disabled — they can't be interrupted on the same CPU. This means a per-CPU array needs no locking: each CPU core has its own copy, and only one eBPF program runs on a CPU at a time. We use this as a scratch buffer to construct the 292-byte `FileAccessEvent` without blowing the 512-byte stack limit.

**Why PerfEventArray instead of RingBuf?**

`PerfEventArray` works on Linux 5.2+. `RingBuf` is more efficient (single buffer shared across CPUs, better cache behavior) but requires Linux 5.8+. We chose broader compatibility.

### BPF Helper Functions

eBPF programs can't call arbitrary kernel functions. Instead, the kernel exposes a set of "helper functions" that are verified to be safe. Guardian Shell uses:

| Helper | What It Does |
|--------|--------------|
| `bpf_get_current_pid_tgid()` | Returns the current process's PID and TGID (thread group ID) packed into a u64 |
| `bpf_get_current_uid_gid()` | Returns the current process's UID and GID packed into a u64 |
| `bpf_get_current_comm()` | Returns the 16-byte process name (from `task_struct->comm`) |
| `bpf_probe_read_user_str_bytes()` | Safely reads a null-terminated string from userspace memory into a kernel buffer |

These helpers are the only way to interact with kernel state from an eBPF program. Direct memory access to kernel structures would be rejected by the verifier (except through BTF-based programs, which we don't use here).

### Why Not Userspace Sandboxing?

Alternatives to eBPF and why we didn't use them:

| Approach | Problem |
|----------|---------|
| **LD_PRELOAD** (intercept libc calls) | Trivially bypassed. Agent can use raw syscalls, static linking, or `dlopen` to avoid the interposed library. |
| **ptrace** (strace-like monitoring) | Huge performance overhead (context switch per syscall). Agent can detach itself with `PTRACE_DETACH`. |
| **seccomp-BPF** (syscall filtering) | Can block syscalls but can't inspect arguments deeply (e.g., can't read the filename string from userspace memory). Also per-process, not per-name. |
| **AppArmor/SELinux** | Powerful but coarse-grained. Require system-wide policy changes and root setup. Can't easily do per-agent dynamic policies from a TOML file. |
| **Containers/namespaces** | Would require running agents inside containers with mounted volumes. Heavy-weight, changes the agent's environment, and some agents don't support it. |
| **eBPF tracepoints** (our approach) | Kernel-level interception that can't be bypassed by userspace. Can read syscall arguments. Low overhead. Dynamic policy from userspace. |

eBPF is the sweet spot: kernel-level visibility with userspace-level flexibility.

---

## Architecture Overview

Guardian Shell has four crates in a Cargo workspace:

```
guardian_shell/
├── guardian-common/     # Shared types (no_std) — runs in both kernel and userspace
├── guardian-ebpf/       # eBPF kernel program — compiled to BPF bytecode
├── guardian/            # Userspace daemon — loads eBPF, processes events
└── xtask/              # Build tooling — cross-compiles eBPF program
```

The system operates in two spaces simultaneously:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                            USER SPACE                                     │
│                                                                           │
│  ┌─────────────┐    ┌─────────────────────────────────────────────────┐  │
│  │ config.toml │───>│              Guardian Daemon                     │  │
│  └─────────────┘    │                                                 │  │
│                      │  1. Parse config, validate policy               │  │
│                      │  2. Load eBPF program into kernel               │  │
│                      │  3. Populate WATCHED_COMMS map                  │  │
│                      │  4. Attach to sys_enter_openat tracepoint       │  │
│                      │  5. Read events from perf buffer (async, N CPUs)│  │
│                      │  6. Evaluate policy: allow or deny?             │  │
│                      │  7. Log decision                                │  │
│                      └──────────────────────┬──────────────────────────┘  │
│                                              │ perf buffer                │
│ ═════════════════════════════════════════════╪════════════════════════════ │
│                                              │                            │
│                           KERNEL SPACE       │                            │
│                                              │                            │
│  ┌───────────────────────────────────────────┴─────────────────────────┐ │
│  │                    eBPF Program (BPF VM)                             │ │
│  │              attached to: syscalls/sys_enter_openat                   │ │
│  │                                                                      │ │
│  │  For EVERY openat() call on the entire system:                       │ │
│  │                                                                      │ │
│  │  1. bpf_get_current_comm()  → get process name                      │ │
│  │  2. WATCHED_COMMS.get(&comm) → is this process watched?             │ │
│  │     ├─ No  → return 0 (ignore, ~50ns overhead)                      │ │
│  │     └─ Yes → continue ↓                                             │ │
│  │  3. Read PID, UID, filename, flags from syscall args                │ │
│  │  4. Write FileAccessEvent to per-CPU scratch buffer                 │ │
│  │  5. EVENTS.output() → send to userspace via perf ring buffer        │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │   WATCHED_COMMS map     EVENT_BUF (per-CPU)     EVENTS (perf ring)  │ │
│  │   ┌──────┬───┐          ┌──────────────┐        ┌───────────────┐  │ │
│  │   │"cat" │ 1 │          │CPU0: [292 B] │        │CPU0: ●●●○○○○ │  │ │
│  │   │"node"│ 1 │          │CPU1: [292 B] │        │CPU1: ●●○○○○○ │  │ │
│  │   │"py3" │ 1 │          │CPU2: [292 B] │        │CPU2: ●○○○○○○ │  │ │
│  │   └──────┴───┘          │CPU3: [292 B] │        │CPU3: ○○○○○○○ │  │ │
│  │                          └──────────────┘        └───────────────┘  │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Component Deep Dive

### guardian-common: Shared Types

**Path**: `guardian-common/src/lib.rs`
**Target**: Both `bpfel-unknown-none` (kernel) and native (userspace)
**Constraint**: `#![no_std]` — cannot use anything from Rust's standard library

This crate defines the `FileAccessEvent` struct that is the "contract" between kernel and userspace:

```rust
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileAccessEvent {
    pub pid: u32,                          // 4 bytes  — kernel thread ID
    pub tgid: u32,                         // 4 bytes  — process ID (userspace PID)
    pub uid: u32,                          // 4 bytes  — user ID
    pub flags: u32,                        // 4 bytes  — openat() flags
    pub filename_len: u32,                 // 4 bytes  — length of captured filename
    pub comm: [u8; 16],                    // 16 bytes — process name
    pub filename: [u8; 256],               // 256 bytes — file path
}                                          // Total: 292 bytes
```

**Why `#[repr(C)]`?**

This is critical. Without it, Rust's default representation (`repr(Rust)`) is free to reorder struct fields for optimal alignment. The problem: the eBPF program (compiled for `bpfel-unknown-none`) and the userspace daemon (compiled for `x86_64-unknown-linux-gnu`) might choose different field orderings. The eBPF program would write `pid` at offset 0, but userspace might read `filename_len` at offset 0. Data corruption.

`#[repr(C)]` forces C-compatible layout: fields appear in declaration order with C alignment rules. Both targets produce the same memory layout.

**Why `#[derive(Clone, Copy)]`?**

BPF maps work with raw bytes. The struct must be `Copy` so it can be bitwise-copied into and out of maps without Rust's ownership system interfering. No heap allocation, no `Drop` implementation.

**Why fixed-size arrays instead of `String`/`Vec`?**

eBPF has no heap allocator. Every data structure must have a known size at compile time. We use `[u8; 256]` for filenames (covers most practical paths) and `[u8; 16]` for comm names (matches the kernel's `TASK_COMM_LEN`).

### guardian-ebpf: Kernel Program

**Path**: `guardian-ebpf/src/main.rs`
**Target**: `bpfel-unknown-none` (BPF bytecode, little-endian)
**Constraints**: `#![no_std]`, `#![no_main]`, 512-byte stack, must pass BPF verifier

This is the eBPF program that runs inside the kernel. It's attached to the `sys_enter_openat` tracepoint, which fires every time any process on the system calls `openat()` — the syscall that opens files.

**Program flow:**

```
openat() called by any process
         │
         ▼
┌─────────────────────────────┐
│ bpf_get_current_comm()      │  Get the calling process's name
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ WATCHED_COMMS.get(&comm)    │  Is this process in our watch list?
└──────┬──────────────┬───────┘
       │              │
    Not found       Found
       │              │
       ▼              ▼
   return 0     ┌─────────────────────────────┐
   (ignore)     │ EVENT_BUF.get_ptr_mut(0)    │  Get per-CPU scratch buffer
                └──────────────┬──────────────┘
                               │
                               ▼
                ┌─────────────────────────────┐
                │ Fill event:                 │
                │   pid, tgid, uid, comm      │  From BPF helpers
                │   filename_ptr → filename   │  From tracepoint args
                │   flags                     │  From tracepoint args
                └──────────────┬──────────────┘
                               │
                               ▼
                ┌─────────────────────────────┐
                │ EVENTS.output(ctx, event, 0)│  Send to userspace
                └──────────────┬──────────────┘
                               │
                               ▼
                          return 0
```

**Reading tracepoint arguments:**

The `sys_enter_openat` tracepoint provides syscall arguments at fixed byte offsets. On x86_64:

```
Offset  Field            Size   Description
──────  ─────            ────   ───────────
0       common_type       2     Event type ID (kernel internal)
2       common_flags      1     Event flags (kernel internal)
3       common_preempt    1     Preemption count
4       common_pid        4     PID (kernel internal, not same as tgid)
8       __syscall_nr      4     Syscall number (257 for openat)
12      (padding)         4     Alignment padding
16      dfd               8     Directory file descriptor (AT_FDCWD = -100)
24      filename          8     POINTER to filename string in user memory
32      flags             8     Open flags (O_RDONLY, O_WRONLY, etc.)
40      mode              8     File creation mode (if O_CREAT)
```

We read offset 24 to get the filename pointer and offset 32 to get the flags:

```rust
let filename_ptr: u64 = unsafe { ctx.read_at(24)? };
let flags: u64 = unsafe { ctx.read_at(32)? };
```

The filename pointer points to userspace memory, so we use `bpf_probe_read_user_str_bytes()` to safely copy it into our kernel buffer. This helper validates the pointer and copies bytes until it hits a null terminator or fills the buffer.

You can verify these offsets on your system:
```bash
cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
```

### guardian (userspace): Daemon

**Path**: `guardian/src/main.rs` and `guardian/src/config.rs`
**Target**: `x86_64-unknown-linux-gnu` (native Linux binary)

The daemon orchestrates everything:

**Startup sequence:**

```
1. Parse CLI args (--config, --ebpf-program)
         │
         ▼
2. Load and validate config.toml
   ├── Parse TOML
   ├── Validate agent configs
   ├── Warn about overly permissive patterns
   └── Warn about relative paths
         │
         ▼
3. Load eBPF program into kernel
   ├── Ebpf::load_file() reads ELF binary
   ├── Kernel creates BPF maps
   └── Kernel relocates program references to maps
         │
         ▼
4. Populate WATCHED_COMMS map
   ├── For each agent in config:
   │   Convert process_name to [u8; 16]
   │   Insert into WATCHED_COMMS map
   └── Log watched process names
         │
         ▼
5. Attach eBPF program to tracepoint
   ├── program.load() → load into BPF VM
   └── program.attach("syscalls", "sys_enter_openat")
         │
         ▼
6. Set up event processing
   ├── Open perf buffer for each online CPU
   ├── Spawn one async tokio task per CPU
   └── Each task loops: read events → parse → check policy → log
         │
         ▼
7. Wait for Ctrl+C
   └── On signal: log shutdown, exit (kernel auto-cleans eBPF resources)
```

**Event processing (per CPU, async):**

Each CPU has its own perf ring buffer. We spawn one tokio task per CPU that:

1. Calls `buf.read_events(&mut buffers).await` — async wait for events
2. For each event received:
   - Parse raw bytes into `FileAccessEvent` using `read_unaligned()`
   - Extract filename and comm as strings
   - Find matching agent config by comm name
   - Call `check_file_policy()` to evaluate against allow/deny rules
   - Log `[ALLOW]` at info level or `[DENY]` at warn level

**Why `read_unaligned()`?**

The perf buffer may not guarantee that events are aligned to the struct's natural alignment boundary. Using `read_unaligned()` safely handles this by copying byte-by-byte if necessary, avoiding undefined behavior from misaligned reads.

### xtask: Build System

**Path**: `xtask/src/main.rs`

The eBPF program must be cross-compiled to the `bpfel-unknown-none` target. We use the `xtask` pattern (a Cargo convention) to automate this:

```bash
cargo xtask build-ebpf [--release]
```

This runs:
```bash
cargo +nightly build \
  --package guardian-ebpf \
  --target bpfel-unknown-none \
  -Z build-std=core \
  [--release]
```

Key flags:
- `+nightly` — BPF target requires nightly Rust
- `--target bpfel-unknown-none` — BPF little-endian, no OS
- `-Z build-std=core` — rebuild `core` library for the BPF target (it doesn't come pre-built)
- `--release` — optimization helps pass the BPF verifier

The `.cargo/config.toml` configures the BPF linker:
```toml
[target.bpfel-unknown-none]
linker = "bpf-linker"
```

---

## The Data Flow: From Syscall to Log Line

Let's trace a single event end-to-end. The user runs `cat /etc/passwd` while Guardian is monitoring the `cat` process.

```
User types: cat /etc/passwd

    ┌─ Step 1 ──────────────────────────────────────────────────────┐
    │ cat's glibc calls openat(AT_FDCWD, "/etc/passwd", O_RDONLY)  │
    │ This is a syscall — execution transitions to kernel mode       │
    └──────────────────────────────┬─────────────────────────────────┘
                                   │
    ┌─ Step 2 ──────────────────────┴────────────────────────────────┐
    │ Kernel hits sys_enter_openat tracepoint                        │
    │ All registered eBPF programs fire, including ours              │
    └──────────────────────────────┬─────────────────────────────────┘
                                   │
    ┌─ Step 3 ──────────────────────┴────────────────────────────────┐
    │ eBPF: bpf_get_current_comm() → "cat\0\0\0\0\0\0\0\0\0\0\0\0" │
    │ eBPF: WATCHED_COMMS.get("cat\0...") → Some(&1)  ← MATCH!     │
    └──────────────────────────────┬─────────────────────────────────┘
                                   │
    ┌─ Step 4 ──────────────────────┴────────────────────────────────┐
    │ eBPF: Get per-CPU scratch buffer from EVENT_BUF                │
    │ eBPF: Fill in pid=42, tgid=42, uid=1000, comm="cat"           │
    │ eBPF: Read filename ptr from tracepoint args (offset 24)      │
    │ eBPF: bpf_probe_read_user_str_bytes(ptr) → "/etc/passwd"      │
    │ eBPF: Read flags from tracepoint args (offset 32) → 0 (RDONLY)│
    └──────────────────────────────┬─────────────────────────────────┘
                                   │
    ┌─ Step 5 ──────────────────────┴────────────────────────────────┐
    │ eBPF: EVENTS.output(ctx, &event, 0)                            │
    │ Event is copied into CPU N's perf ring buffer                  │
    │ eBPF program returns 0, syscall continues normally             │
    └──────────────────────────────┬─────────────────────────────────┘
                                   │
    ┌─ Step 6 ──────────────────────┴────────────────────────────────┐
    │ Userspace: tokio task for CPU N wakes up                       │
    │ Reads raw bytes from perf buffer                               │
    │ Parses into FileAccessEvent { tgid: 42, filename: "/etc/passwd"│
    │                                comm: "cat", flags: 0, ... }    │
    └──────────────────────────────┬─────────────────────────────────┘
                                   │
    ┌─ Step 7 ──────────────────────┴────────────────────────────────┐
    │ Userspace: Find agent config where process_name == "cat"       │
    │ → Found: agent "test-cat"                                      │
    └──────────────────────────────┬─────────────────────────────────┘
                                   │
    ┌─ Step 8 ──────────────────────┴────────────────────────────────┐
    │ Userspace: check_file_policy(policy, "/etc/passwd")            │
    │   1. Check deny patterns → no match                            │
    │   2. Check allow patterns → no match                           │
    │   3. Default = "deny" → DENIED                                 │
    └──────────────────────────────┬─────────────────────────────────┘
                                   │
    ┌─ Step 9 ──────────────────────┴────────────────────────────────┐
    │ Log output:                                                     │
    │ [WARN] [DENY] agent='test-cat' pid=42 uid=1000                 │
    │        file='/etc/passwd' mode=READ                             │
    │        (monitoring mode - access was NOT actually blocked)      │
    └────────────────────────────────────────────────────────────────┘

    Meanwhile, cat successfully reads /etc/passwd (Phase 1 = monitor only)
```

Total latency added to the syscall: ~1-5 microseconds for watched processes, ~50 nanoseconds for unwatched processes.

---

## Cross-Compilation: Two Targets, One Codebase

Guardian Shell is unique because it compiles the same Rust code for two completely different targets:

| | eBPF Program | Userspace Daemon |
|--|-------------|-----------------|
| **Target** | `bpfel-unknown-none` | `x86_64-unknown-linux-gnu` |
| **Runs in** | Linux kernel BPF VM | Normal Linux userspace |
| **Standard library** | None (`#![no_std]`) | Full (`std`) |
| **Heap allocation** | Forbidden | Available |
| **Stack limit** | 512 bytes | 8 MB (default) |
| **Compiler** | `rustc` + `bpf-linker` | `rustc` + system linker |
| **Output format** | BPF ELF object | Native ELF executable |
| **Toolchain** | Nightly (required) | Nightly (inherited from workspace) |

The `guardian-common` crate is the bridge — it uses `#![no_std]` so it works in both environments. The `#[repr(C)]` attribute ensures identical memory layout across both targets.

**Build order:**
1. `cargo xtask build-ebpf --release` — compiles `guardian-common` + `guardian-ebpf` for BPF target
2. `cargo build --release` — compiles `guardian-common` + `guardian` for native target
3. At runtime, the userspace daemon loads the BPF ELF binary from disk

---

## The Aya Framework

[Aya](https://aya-rs.dev/) is a Rust eBPF framework. Unlike C-based tools (BCC, libbpf), Aya lets you write both kernel and userspace code in Rust.

**What Aya provides:**

| Component | Crate | Purpose |
|-----------|-------|---------|
| Kernel-side macros | `aya-ebpf` | `#[map]`, `#[tracepoint]`, BPF map types, helper function wrappers |
| Userspace library | `aya` | Load eBPF programs, access maps, attach to hooks |
| Build tooling | `aya-build` | Helps with cross-compilation setup |

**Key Aya types used in Guardian Shell:**

```rust
// Kernel side (guardian-ebpf)
use aya_ebpf::maps::HashMap;          // BPF hash map
use aya_ebpf::maps::PerCpuArray;      // Per-CPU array (scratch buffer)
use aya_ebpf::maps::PerfEventArray;   // Perf ring buffer
use aya_ebpf::programs::TracePointContext;  // Tracepoint argument access

// Userspace side (guardian)
use aya::Ebpf;                         // Load and manage eBPF programs
use aya::maps::HashMap;                // Access BPF hash maps from userspace
use aya::maps::AsyncPerfEventArray;    // Async perf buffer reader
use aya::programs::TracePoint;         // Tracepoint program type
```

---

## Policy Engine Internals

The policy engine in `guardian/src/config.rs` evaluates file access decisions:

```
                  ┌─────────────────┐
                  │ Incoming Event: │
                  │ file="/etc/passwd" │
                  └────────┬────────┘
                           │
              ┌────────────▼────────────┐
              │ For each deny pattern:  │
              │   path_matches(file, p)?│
              └─────┬──────────┬────────┘
                    │          │
                 Matches    No match
                    │          │
                    ▼          ▼
               DENIED   ┌─────────────────────┐
                        │ For each allow pattern: │
                        │   path_matches(file, p)?│
                        └──────┬──────────┬───────┘
                               │          │
                            Matches    No match
                               │          │
                               ▼          ▼
                           ALLOWED   ┌──────────────┐
                                     │ default ==   │
                                     │  "allow"?    │
                                     └───┬──────┬───┘
                                         │      │
                                        Yes    No
                                         │      │
                                         ▼      ▼
                                     ALLOWED  DENIED
```

**Pattern matching implementation:**

```rust
fn path_matches(path: &str, pattern: &str) -> bool {
    if pattern.ends_with("/**") {
        // Recursive wildcard: /home/user/** matches /home/user/a/b/c
        let prefix = &pattern[..pattern.len() - 3];
        path == prefix || path.starts_with(&format!("{}/", prefix))
    } else if pattern.ends_with("/*") {
        // Single-level: /tmp/* matches /tmp/file but not /tmp/sub/file
        let prefix = &pattern[..pattern.len() - 2];
        if let Some(rest) = path.strip_prefix(prefix) {
            rest.starts_with('/') && !rest[1..].contains('/')
        } else {
            false
        }
    } else {
        // Exact match
        path == pattern
    }
}
```

---

## Bugs, Issues & Debugging Stories

These are the real problems we encountered building Guardian Shell, in chronological order. Each one taught us something about eBPF, Rust, or the Linux kernel.

### Issue 1: Code Written on macOS, Needs Linux

**Problem**: The entire codebase was written on macOS, but `aya` (the eBPF userspace library) is Linux-only. Only `guardian-common` and `xtask` were verified to compile.

**Impact**: We couldn't even `cargo check` the main `guardian` crate on macOS because `aya` pulls in Linux-specific system calls.

**Resolution**: Moved to a Linux development machine (Fedora 43, kernel 6.18). Installed prerequisites:
- Nightly Rust toolchain with `rust-src`
- `bpf-linker` for eBPF linking
- Verified kernel BPF support (`CONFIG_BPF=y`, `CONFIG_FTRACE=y`)

**Lesson**: eBPF development requires Linux. There's no way around it — the BPF verifier, the tracepoints, the perf buffers are all kernel features. Develop on Linux from the start, or use a Linux VM.

### Issue 2: online_cpus() Error Type Mismatch

**Problem**: The code called `online_cpus().context("...")` but `online_cpus()` returns `Result<Vec<u32>, (&'static str, std::io::Error)>`, not a standard `Result` with a type implementing `std::error::Error`. The `anyhow::Context` trait requires the error type to implement `StdError`, which a tuple does not.

**Error message**:
```
error[E0599]: the method `context` exists for enum `Result<Vec<u32>, (&'static str, std::io::Error)>`,
but its trait bounds were not satisfied
```

**Fix**: Replaced `.context()` with `.map_err()` to manually convert the error:
```rust
// Before (doesn't compile):
let cpus = online_cpus().context("Failed to get online CPUs")?;

// After:
let cpus = online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))?;
```

**Lesson**: Not all `Result` types are compatible with `anyhow::Context`. The `Context` trait requires `E: std::error::Error`, and custom error types like tuples don't satisfy this. Always check the actual error type of the functions you're calling.

### Issue 3: Aya API Change — map_mut vs take_map

**Problem**: The code used `bpf.map_mut("EVENTS")` to get a mutable reference to the BPF map, then passed it to `AsyncPerfEventArray::try_from()`. The `AsyncPerfEventArray` was used inside `tokio::spawn()` tasks that require `'static` lifetime. But `map_mut()` returns a borrow from `bpf`, so the borrow can't outlive `bpf`.

**Error message**:
```
error[E0597]: `bpf` does not live long enough
  --> guardian/src/main.rs:248:9
     |
248  |     bpf.map_mut("EVENTS")
     |     ^^^ borrowed value does not live long enough
...
268  |     tokio::spawn(async move {
     |     - argument requires that `bpf` is borrowed for `'static`
```

**Root cause**: Aya 0.13's `map_mut()` returns `&mut Map`, which borrows from the `Ebpf` struct. But `tokio::spawn()` requires `'static` futures.

**Fix**: Used `bpf.take_map("EVENTS")` instead, which takes ownership of the map data, transferring it out of the `Ebpf` struct:
```rust
// Before (borrow — doesn't work with tokio::spawn):
let mut perf_array = AsyncPerfEventArray::try_from(
    bpf.map_mut("EVENTS").context("...")?
)?;

// After (ownership — works with tokio::spawn):
let mut perf_array = AsyncPerfEventArray::try_from(
    bpf.take_map("EVENTS").context("...")?
)?;
```

**Lesson**: When using Aya maps with async runtimes like tokio, prefer `take_map()` over `map_mut()`. The owned map can be moved into async tasks. This is a common Aya pattern that changed between versions.

### Issue 4: The PID Scanning Problem

**Problem**: Guardian Shell initially worked by scanning `/proc/` at startup to find processes matching the configured `process_name`, then inserting their PIDs into the `WATCHED_PIDS` eBPF map. The eBPF program would then only capture events from those specific PIDs.

We started Guardian, then ran `cat /tmp/testfile`. **No events appeared.**

**Root cause**: `cat` is a short-lived process. It didn't exist when Guardian started, so its PID was never added to `WATCHED_PIDS`. By the time it ran and opened files, the eBPF program checked `WATCHED_PIDS`, didn't find the PID, and ignored the event.

```
Timeline:
  t=0  Guardian starts, scans /proc/ → no "cat" processes found
  t=5  User runs: cat /tmp/testfile
       cat starts (PID 1234), opens /tmp/testfile
       eBPF: WATCHED_PIDS.get(1234) → None → ignore
       cat exits
       User sees: no output from Guardian
```

**First attempt (didn't work)**: We added a periodic PID rescan every 2 seconds using a tokio task. But `cat` runs and exits in milliseconds — the 2-second scan window will never catch it.

**Lesson**: PID-based filtering fundamentally doesn't work for short-lived processes. You need to match on a property that exists at syscall time, not at scan time.

### Issue 5: Periodic Rescan Still Not Fast Enough

**Problem**: After adding 2-second periodic PID rescanning, we tested again. Still no events for `cat`. The rescan couldn't catch processes that complete in <1ms.

**Root cause**: Even if we reduced the interval to 100ms or 10ms, we'd still miss most short-lived processes. The fundamental issue is that PID scanning is a polling approach, but we need an event-driven approach.

**Solution**: Completely replaced PID-based filtering with **comm name matching**. Instead of storing PIDs in a map, we store process names:

```rust
// Old approach (eBPF side):
static WATCHED_PIDS: HashMap<u32, u8>;  // PID → watched
if WATCHED_PIDS.get(&tgid).is_none() { return Ok(0); }

// New approach (eBPF side):
static WATCHED_COMMS: HashMap<[u8; 16], u8>;  // comm name → watched
let comm = bpf_get_current_comm()?;
if WATCHED_COMMS.get(&comm).is_none() { return Ok(0); }
```

Now the eBPF program checks the process name at syscall time. Even if `cat` runs for 1ms, during that 1ms when it calls `openat()`, the eBPF program fires and checks the comm name. Match found. Event captured.

**Lesson**: In eBPF, match on properties that are available in the kernel context at event time, not on pre-computed data from userspace. Process names (comm) are always available via `bpf_get_current_comm()`.

### Issue 6: BPF Verifier Rejection

**Problem**: After implementing comm-based matching, we tried to keep both PID and comm checking as a "belt and suspenders" approach:

```rust
let pid_watched = unsafe { WATCHED_PIDS.get(&tgid) }.is_some();
let comm = bpf_get_current_comm()?;
let comm_watched = unsafe { WATCHED_COMMS.get(&comm) }.is_some();
if !pid_watched && !comm_watched { return Ok(0); }
```

The eBPF program compiled fine but was **rejected by the kernel's BPF verifier** at load time.

**Error**: `Failed to load eBPF program into kernel (is BPF enabled?): the BPF_PROG_LOAD syscall failed. Verifier output: ...`

**Root cause**: The dual-check approach created too many code paths for the verifier to analyze. The verifier tracks the state of every register through every possible execution path. With two map lookups and boolean logic combining their results, plus the `aya-log-ebpf` logging code (which adds its own map operations and code complexity), the verifier couldn't prove safety within its instruction limit.

**Fix**: Simplified to comm-only matching and removed `aya-log-ebpf`:

```rust
// Simplified — single map lookup, no logging library
let comm = bpf_get_current_comm().map_err(|e| e)?;
if unsafe { WATCHED_COMMS.get(&comm) }.is_none() {
    return Ok(0);
}
```

We also removed the `aya-log-ebpf` dependency entirely. The logging library adds hidden BPF maps and code for forwarding log messages from kernel to userspace, significantly increasing program complexity.

**Lesson**: The BPF verifier is the biggest constraint in eBPF development. Keep programs as simple as possible:
- Fewer map lookups = fewer code paths
- Fewer branches = easier for verifier to analyze
- Remove logging libraries if they cause verification failures
- Always build with `--release` (optimizer reduces instruction count)
- Test verification on the actual target kernel, not just compilation

### Issue 7: ALLOW Events Were Invisible

**Problem**: After getting comm-based matching working, we tested with `cat`. DENY events appeared for `/etc/passwd`, but when we ran `cat /tmp/testfile` (which should be allowed per the policy), **nothing appeared in the logs**.

The user reported "testfile is logged as deny" — but actually, no log line for testfile appeared at all.

**Root cause**: The `[ALLOW]` decision was logged at `debug!()` level, while `[DENY]` was logged at `warn!()` level. We were running with `RUST_LOG=info`, which shows `warn` but hides `debug`.

```rust
// The bug:
if allowed {
    debug!("[ALLOW] ...");   // ← Hidden at info level!
} else {
    warn!("[DENY] ...");     // ← Visible at info level
}
```

**Fix**: Changed `[ALLOW]` to use `info!()`:
```rust
if allowed {
    info!("[ALLOW] ...");    // ← Now visible at info level
} else {
    warn!("[DENY] ...");
}
```

**Lesson**: Log levels matter. If a user can't see an event, it doesn't exist as far as they're concerned. For a security monitoring tool, both ALLOW and DENY decisions should be visible at the normal operating log level. Reserve `debug!()` for internal diagnostics, not for the primary output of the tool.

---

## Design Decisions & Trade-offs

### Why Tracepoints Instead of LSM Hooks?

| | Tracepoints | LSM BPF Hooks |
|--|-------------|---------------|
| **Kernel support** | All kernels with `CONFIG_FTRACE=y` | Requires `CONFIG_BPF_LSM=y` (not universal) |
| **Can block access?** | No (observe only) | Yes (return -EPERM) |
| **Performance** | Minimal overhead | Slightly more (on syscall hot path) |
| **Complexity** | Simple attachment | Need LSM program type, security hooks |

We chose tracepoints for Phase 1 because they work everywhere and are simpler. Phase 2 will add LSM hooks for enforcement.

### Why Rust + Aya Instead of C + libbpf?

| | Rust + Aya | C + libbpf |
|--|-----------|-----------|
| **Type safety** | Compile-time type checking across kernel/userspace boundary | Manual casting, easy to get struct layout wrong |
| **Memory safety** | Borrow checker, no use-after-free | Manual memory management |
| **Error handling** | `Result<T, E>` with `?` operator | Return codes, easy to miss error checks |
| **Build system** | Cargo workspace, single `cargo build` | Makefiles, separate build steps |
| **Ecosystem** | Full Rust ecosystem (serde, tokio, clap) | C libraries, manual parsing |
| **Drawbacks** | Nightly Rust required, BPF verifier sometimes confused by Rust codegen | Mature, well-documented, more examples available |

### Why PerfEventArray Instead of RingBuf?

`PerfEventArray` (per-CPU ring buffers) works on Linux 5.2+, covering more systems. `RingBuf` (single shared ring buffer) is more efficient but requires Linux 5.8+. For Phase 1, compatibility won.

### Why Process Name Instead of PID Matching?

Initially we used PID matching (scan `/proc/` for matching process names, store PIDs in a BPF map). This failed for short-lived processes like `cat` that start and exit between scans. Comm name matching checks the process name directly in the eBPF program at syscall time, catching every process regardless of lifetime.

Trade-off: comm matching is slightly less precise (two different processes with the same name are both caught), but it works universally. Future phases will use cgroup-based matching for precise identification.

---

## Memory Layout & Safety

### The FileAccessEvent Struct

```
Offset  Size   Field          Notes
──────  ────   ─────          ─────
0       4      pid            u32, kernel thread ID
4       4      tgid           u32, process ID (userspace PID)
8       4      uid            u32, user ID
12      4      flags          u32, openat() flags
16      4      filename_len   u32, valid bytes in filename
20      16     comm           [u8; 16], null-padded process name
36      256    filename       [u8; 256], null-terminated file path
──────  ────
Total:  292 bytes
```

This struct is 292 bytes. The eBPF stack limit is 512 bytes. If we put this on the stack, we'd only have 220 bytes left for local variables, function calls, etc. That's why we use a `PerCpuArray` map as a scratch buffer — the struct lives in map memory (kernel heap), not on the BPF stack.

### Safety Guarantees

| Component | Guarantee | Mechanism |
|-----------|-----------|-----------|
| eBPF program | Can't crash kernel | BPF verifier checks all programs before loading |
| eBPF program | Can't infinite loop | Verifier proves termination for all code paths |
| eBPF program | Can't access invalid memory | Verifier tracks register types and value ranges |
| Shared struct | Same layout in both targets | `#[repr(C)]` forces C-compatible field ordering |
| Userspace event parsing | No misaligned reads | `read_unaligned()` used for perf buffer events |
| Policy evaluation | Deny wins over allow | Deny patterns checked first, short-circuit return |

---

## Performance Characteristics

### eBPF Program Overhead

| Scenario | Overhead per openat() | Notes |
|----------|----------------------|-------|
| Unwatched process | ~50 ns | Hash map lookup, early return |
| Watched process | ~1-5 us | Full event capture, perf buffer write |

The eBPF program runs for every `openat()` call on the system. On a typical desktop, there are thousands of `openat()` calls per second. The 50ns overhead for unwatched processes is negligible.

### Userspace Processing

| Component | Performance | Notes |
|-----------|-------------|-------|
| Perf buffer read | Async, zero-copy | Memory-mapped ring buffer, no data copying |
| Event parsing | ~100 ns | `read_unaligned()`, no allocation |
| Policy evaluation | ~1-10 us | String matching, scales with number of patterns |
| Logging | ~10-50 us | Formatted output to stderr/file |

### Memory Usage

| Component | Memory | Notes |
|-----------|--------|-------|
| WATCHED_COMMS map | 256 entries x ~20 bytes = ~5 KB | Kernel memory |
| EVENT_BUF (per-CPU) | N_CPUs x 292 bytes | Kernel memory, one per CPU |
| EVENTS perf buffer | N_CPUs x 4 pages (16 KB) = ~64 KB | Kernel memory |
| Userspace daemon | ~5-10 MB | Tokio runtime, config, buffers |

---

## What We Would Do Differently

Looking back on the Phase 1 development, here's what we'd change:

1. **Start with comm matching from day one.** PID scanning was a dead end for short-lived processes. We spent time implementing it, adding periodic rescanning, and then replacing it entirely.

2. **Skip aya-log-ebpf.** It adds significant complexity to the eBPF program (extra maps, formatting code) and contributed to BPF verifier rejection. Userspace-side logging is sufficient for Phase 1.

3. **Develop on Linux from the start.** Writing the code on macOS and hoping it would compile on Linux was a gamble. The aya crate's API on the actual Linux version differed from what was assumed during development.

4. **Test BPF verifier early and often.** Compile the eBPF program and load it into the kernel as the first test, not the last. Verifier rejections are the most common failure mode and the hardest to debug.

5. **Make ALLOW and DENY equally visible.** Logging ALLOW at debug level was a mistake that confused users. A security tool should show all decisions clearly.

---

## What Comes Next

Phase 1 gave us a working monitor. The next two phases turn Guardian Shell into a
real enforcement tool with robust agent identification.

### Phase 2: Enforcement + Exec Monitoring

The biggest limitation of Phase 1 is that it **logs but doesn't block**. A
malicious or misconfigured agent can read `/etc/shadow` and Guardian will write
a DENY log, but the read still succeeds.

Phase 2 fixes this by:

- **Replacing the tracepoint with LSM BPF hooks** (`security_file_open`). LSM
  hooks fire *before* the kernel grants access, so returning `-EACCES` actually
  blocks the file open. This moves Guardian from "security camera" to "security
  guard."
- **Adding `sys_enter_execve` monitoring.** Phase 1 only watches file opens.
  Phase 2 will also track what commands agents execute (`curl`, `python`,
  `bash -c ...`), giving visibility into agent behavior beyond file access.
- **Process tree tracking.** When a watched agent spawns child processes, those
  children inherit the parent's policy. This closes the loophole where an agent
  could fork a subprocess to bypass monitoring.
- **Moving policy evaluation into the eBPF program.** Currently, policy rules
  are checked in userspace (after the fact). Phase 2 will encode allow/deny
  rules into BPF maps so the kernel can make enforcement decisions at syscall
  time with zero userspace latency.

> See [PHASE2_PLAN.md](PHASE2_PLAN.md) for the full implementation plan.

### Phase 3: Robust Agent Identity + Guardian Launcher

Phase 1's comm-based matching works but is fragile — any process named `cat`
gets monitored, and an agent could rename itself with `prctl(PR_SET_NAME)`.

Phase 3 fixes this by:

- **Cgroup-based agent identification.** Each agent runs in its own cgroup
  (e.g., `/sys/fs/cgroup/guardian.slice/claude-agent.scope`). The eBPF program
  checks cgroup membership, which is kernel-enforced and can't be spoofed by
  the agent.
- **Guardian Launcher (`guardian-launch`).** A CLI tool that wraps any agent
  command: `guardian-launch --agent claude -- claude-agent start`. The launcher
  creates the cgroup, places the agent process in it, registers it with the
  Guardian daemon, and applies the matching policy.
- **Dynamic agent registration.** New agents can start after the daemon is
  running. The launcher notifies the daemon via Unix socket, and the daemon
  updates BPF maps in real time — no restart needed.
- **Time-boxed permissions.** Temporary access grants like "allow `/etc/hosts`
  for 5 minutes" with automatic revocation, enabling a human-in-the-loop
  consent flow for sensitive operations.

> See [PHASE3_PLAN.md](PHASE3_PLAN.md) for the full implementation plan.

### Beyond Phase 3

Phases 4 and 5 (outlined in [CLAUDE.md](CLAUDE.md)) focus on integration and
usability: webhook alerts, Slack/email notifications, Prometheus metrics, a
web dashboard, and a visual policy editor. These build on the enforcement and
identity foundation from Phases 2 and 3.

---

## Glossary

| Term | Definition |
|------|-----------|
| **eBPF** | Extended Berkeley Packet Filter. A kernel technology for running sandboxed programs. |
| **BPF verifier** | Kernel component that statically analyzes eBPF programs to ensure safety before loading. |
| **BPF map** | Shared data structure between kernel eBPF programs and userspace. Types include HashMap, Array, PerfEventArray, RingBuf. |
| **Tracepoint** | A static instrumentation point in the kernel. `sys_enter_openat` fires on every file open. |
| **LSM hook** | Linux Security Module hook. Can enforce access control decisions (block syscalls). Used in Phase 2. |
| **comm** | Process command name, stored in `task_struct->comm` and visible at `/proc/PID/comm`. Max 15 chars + null. |
| **tgid** | Thread Group ID. What userspace calls "PID". The main thread's kernel PID. |
| **pid** | In kernel context: the thread ID. Each thread has its own PID. The main thread's PID equals its TGID. |
| **openat()** | The Linux syscall for opening files. Modern glibc converts all `open()` calls to `openat()`. |
| **PerfEventArray** | A per-CPU ring buffer BPF map type for sending events from kernel to userspace. |
| **PerCpuArray** | A BPF map where each CPU core has its own copy of the array. Used as scratch buffer. |
| **Aya** | A Rust framework for writing eBPF programs. Both kernel-side (`aya-ebpf`) and userspace (`aya`). |
| **bpf-linker** | A linker for BPF object files, required to produce the final eBPF ELF binary from Rust. |
| **`repr(C)`** | A Rust attribute that forces C-compatible struct layout (fields in declaration order). |
| **`no_std`** | A Rust attribute indicating the crate does not use the standard library. Required for eBPF and other bare-metal targets. |
| **perf buffer** | Memory-mapped ring buffer used by the kernel's perf subsystem. Events written by eBPF, read by userspace. |
| **JIT** | Just-In-Time compilation. The kernel JIT-compiles BPF bytecode to native machine code for performance. |
| **`AT_FDCWD`** | Special file descriptor value (-100) meaning "relative to current working directory". Used with `openat()`. |
