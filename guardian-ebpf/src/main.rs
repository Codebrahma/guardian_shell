// =============================================================================
// Guardian Shell - eBPF Kernel Program
// =============================================================================
//
// This program runs inside the Linux kernel as an eBPF (extended Berkeley
// Packet Filter) program. It monitors file access (openat syscall) by
// specific processes and sends events to the userspace daemon for policy
// evaluation.
//
// ┌──────────────────────────────────────────────────────────────┐
// │                    HOW THIS WORKS                            │
// │                                                              │
// │  1. Process calls open("/etc/passwd", O_RDONLY)              │
// │  2. Kernel converts to openat(AT_FDCWD, "/etc/passwd", ...) │
// │  3. Kernel hits the sys_enter_openat tracepoint              │
// │  4. Our eBPF program runs (guardian_file_open)               │
// │  5. We check: is this PID in our WATCHED_PIDS map?          │
// │     - No  → return immediately (zero overhead for unwatched) │
// │     - Yes → capture event details, send to userspace         │
// │  6. Userspace daemon receives event via perf buffer          │
// │  7. Daemon checks event against policy rules                 │
// │  8. Daemon logs ALLOW or DENY (monitoring mode)              │
// └──────────────────────────────────────────────────────────────┘
//
// SAFETY NOTES:
// - This program NEVER blocks or denies file access (Phase 1 = monitor only)
// - If any error occurs, we silently return 0 (allow the syscall to proceed)
// - The BPF verifier ensures this program cannot crash the kernel
// - We use per-CPU arrays to avoid the 512-byte stack limit

// Required attributes for eBPF programs:
// - no_std: eBPF has no standard library (no filesystem, no allocator, no threads)
// - no_main: Entry points are defined by BPF program type macros, not fn main()
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm,     // Gets the current process name (comm)
        bpf_get_current_pid_tgid, // Gets current PID and TGID (thread group ID)
        bpf_get_current_uid_gid,  // Gets current UID and GID
        bpf_probe_read_user_str_bytes, // Reads a string from user-space memory
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::TracePointContext,
};
use aya_log_ebpf::info;
use guardian_common::FileAccessEvent;

// =============================================================================
// BPF Maps
// =============================================================================
//
// Maps are the primary mechanism for communication between eBPF programs
// (kernel) and userspace. Think of them as shared data structures that both
// sides can read from and write to.
//
// We use three maps:
//   1. WATCHED_PIDS: Userspace writes PIDs here; eBPF reads to filter events
//   2. EVENT_BUF: Per-CPU scratch buffer (avoids 512-byte stack limit)
//   3. EVENTS: Perf event ring buffer for sending events to userspace

/// HashMap of process IDs to monitor.
///
/// Userspace populates this map with the PIDs of LLM agent processes.
/// The eBPF program checks this map on every openat() call to decide
/// whether to capture an event.
///
/// Key:   u32 (tgid - what userspace calls "PID")
/// Value: u8  (1 = this PID is being watched)
///
/// Max entries: 1024 simultaneous watched processes. Increase if needed,
/// but keep in mind that each entry consumes kernel memory.
///
/// Example:
///   Userspace: watched_pids.insert(1234, 1, 0)  // Watch PID 1234
///   eBPF:      watched_pids.get(&tgid) == Some(&1)  // "Is this PID watched?"
#[map]
static WATCHED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

/// Per-CPU scratch buffer for constructing events.
///
/// WHY WE NEED THIS:
/// eBPF programs have a strict 512-byte stack limit per function. Our
/// FileAccessEvent struct is ~292 bytes, which would consume most of the
/// stack and leave no room for local variables.
///
/// SOLUTION:
/// We allocate the event in a per-CPU array map instead. "Per-CPU" means
/// each CPU core gets its own copy, so there's no contention or locking
/// needed - each CPU writes to its own buffer.
///
/// This is a standard eBPF pattern for handling large data structures.
#[map]
static EVENT_BUF: PerCpuArray<FileAccessEvent> = PerCpuArray::with_max_entries(1, 0);

/// Perf event array for sending events to userspace.
///
/// When we capture a file access event, we write it to this perf buffer.
/// The userspace daemon polls this buffer asynchronously and processes
/// events as they arrive.
///
/// PerfEventArray is a per-CPU ring buffer. Events are written by the
/// CPU that's running the eBPF program and read by userspace. If the
/// buffer fills up (userspace isn't reading fast enough), events are dropped.
///
/// In future phases, we may switch to RingBuf (Linux 5.8+) which has
/// better performance characteristics for high-throughput scenarios.
#[map]
static EVENTS: PerfEventArray<FileAccessEvent> = PerfEventArray::new(0);

// =============================================================================
// Tracepoint Handler
// =============================================================================

/// Entry point for the sys_enter_openat tracepoint.
///
/// This function is called by the kernel every time ANY process on the system
/// calls the openat() syscall (which is used for all file opens on modern Linux).
///
/// The #[tracepoint] macro tells aya to:
///   1. Set up the BPF program type as BPF_PROG_TYPE_TRACEPOINT
///   2. Set the attach point to syscalls/sys_enter_openat
///   3. Generate the necessary BPF program metadata
///
/// PERFORMANCE NOTE:
/// This function runs for EVERY openat() call on the system. The first thing
/// we do is check if the PID is in our watched list - if not, we return
/// immediately. This means unwatched processes see near-zero overhead
/// (just a hash map lookup, ~50 nanoseconds).
#[tracepoint]
pub fn guardian_file_open(ctx: TracePointContext) -> u32 {
    // We wrap the actual logic in a Result-returning function.
    // If anything fails, we return 0 (don't interfere with the syscall).
    // NEVER return an error code that would block the syscall in Phase 1.
    match try_guardian_file_open(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

/// Inner implementation with proper error handling.
///
/// Returns Ok(0) on success (always 0 for tracepoints - we're just observing).
/// Returns Err on any failure (which is caught above and converted to 0).
fn try_guardian_file_open(ctx: &TracePointContext) -> Result<u32, i64> {
    // =========================================================================
    // Step 1: Get the current process identity
    // =========================================================================
    //
    // bpf_get_current_pid_tgid() returns a u64 where:
    //   - Upper 32 bits: TGID (Thread Group ID) = what userspace calls "PID"
    //   - Lower 32 bits: PID (kernel thread ID)
    //
    // For single-threaded processes: tgid == pid
    // For multi-threaded processes: tgid is the main thread's PID,
    //                               pid is the specific thread's ID
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;  // Process ID (what users expect)
    let pid = pid_tgid as u32;            // Thread ID

    // =========================================================================
    // Step 2: Check if this process is in our watch list
    // =========================================================================
    //
    // This is the critical fast-path check. For the vast majority of openat()
    // calls (from processes we don't care about), this lookup returns None
    // and we exit immediately.
    //
    // HashMap::get() is O(1) average case - it's a kernel hash table lookup.
    //
    // SAFETY: HashMap::get() in eBPF is safe because:
    //   - The map is initialized by the kernel
    //   - Concurrent access is handled by RCU (Read-Copy-Update)
    //   - The returned reference is valid for the duration of this BPF program run
    if unsafe { WATCHED_PIDS.get(&tgid) }.is_none() {
        return Ok(0); // Not watched - exit immediately
    }

    // =========================================================================
    // Step 3: Get the per-CPU event buffer
    // =========================================================================
    //
    // Instead of allocating FileAccessEvent on the stack (which would exceed
    // the 512-byte limit), we get a pointer to a pre-allocated per-CPU buffer.
    //
    // SAFETY: This is safe because:
    //   - Per-CPU arrays guarantee no concurrent access from the same CPU
    //   - eBPF programs run with preemption disabled (can't be interrupted)
    //   - The pointer is valid for the lifetime of this BPF program execution
    let event = unsafe {
        let ptr = EVENT_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    // =========================================================================
    // Step 4: Fill in process information
    // =========================================================================

    event.pid = pid;
    event.tgid = tgid;

    // Get the UID (User ID) of the calling process
    // bpf_get_current_uid_gid() returns u64: upper 32 = GID, lower 32 = UID
    event.uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;

    // Get the process command name (e.g., "python3", "node", "claude")
    // This reads from the kernel's task_struct->comm field
    event.comm = bpf_get_current_comm().map_err(|e| e)?;

    // =========================================================================
    // Step 5: Read the filename from the tracepoint arguments
    // =========================================================================
    //
    // The sys_enter_openat tracepoint provides the syscall arguments.
    // We need to read them at specific byte offsets from the tracepoint context.
    //
    // Tracepoint data layout for sys_enter_openat (x86_64):
    //   Offset  Field           Size  Description
    //   ------  -----           ----  -----------
    //   0       common_type      2    Event type (internal)
    //   2       common_flags     1    Event flags (internal)
    //   3       common_preempt   1    Preempt count (internal)
    //   4       common_pid       4    PID (internal)
    //   8       __syscall_nr     4    Syscall number (257 for openat)
    //   12      (padding)        4    Alignment padding
    //   16      dfd              8    Directory file descriptor (AT_FDCWD = -100)
    //   24      filename         8    Pointer to filename string in user memory
    //   32      flags            8    Open flags (O_RDONLY, O_WRONLY, etc.)
    //   40      mode             8    File creation mode (if O_CREAT)
    //
    // NOTE: These offsets are for x86_64 Linux. They may differ on other
    // architectures. You can verify them on your system by reading:
    //   /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
    //
    // SAFETY: read_at() performs a BPF probe read, which is safe even if the
    // offset is wrong (it returns an error instead of crashing).

    // Read the filename pointer (it's a userspace pointer, we'll dereference it below)
    let filename_ptr: u64 = unsafe { ctx.read_at(24)? };

    // Read the open flags
    let flags: u64 = unsafe { ctx.read_at(32)? };
    event.flags = flags as u32;

    // =========================================================================
    // Step 6: Read the filename string from user memory
    // =========================================================================
    //
    // The filename pointer we got in Step 5 points to user-space memory.
    // We can't just dereference it - that would be unsafe and the BPF verifier
    // would reject it. Instead, we use bpf_probe_read_user_str_bytes(), which
    // safely copies the string from user memory into our kernel buffer.
    //
    // This function:
    //   1. Validates the user pointer
    //   2. Copies bytes until null terminator or buffer full
    //   3. Returns a slice of the copied bytes (excluding null terminator)
    //
    // If the read fails (e.g., invalid pointer, page not mapped), we still
    // send the event but with filename_len = 0.
    let result = unsafe {
        bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.filename)
    };

    match result {
        Ok(name_bytes) => {
            event.filename_len = name_bytes.len() as u32;
        }
        Err(_) => {
            // Failed to read filename - send event anyway with empty filename.
            // This can happen if the pointer is invalid or the page is swapped out.
            event.filename_len = 0;
        }
    }

    // =========================================================================
    // Step 7: Send the event to userspace via the perf buffer
    // =========================================================================
    //
    // output() copies the event data into the per-CPU perf ring buffer.
    // The userspace daemon will read it asynchronously.
    //
    // The third argument (0) is flags:
    //   - 0: Use the current CPU's buffer (default, most efficient)
    //   - BPF_F_CURRENT_CPU: Same as 0
    //   - Specific CPU index: Send to a specific CPU's buffer (rarely used)
    EVENTS.output(ctx, event, 0);

    // Log the event (visible in userspace if aya-log is initialized)
    info!(ctx, "file_open: tgid={} filename_len={}", tgid, event.filename_len);

    Ok(0)
}

// =============================================================================
// Panic Handler
// =============================================================================
//
// eBPF programs must define a panic handler because they use #![no_std].
// Since eBPF programs can't actually panic (the verifier ensures this),
// this is just a formality required by the Rust compiler.
//
// We use unreachable_unchecked() because:
//   1. The BPF verifier guarantees no panics can occur
//   2. If it somehow did execute, the program would be terminated by the kernel
//   3. Using loop {} would generate unnecessary code
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
