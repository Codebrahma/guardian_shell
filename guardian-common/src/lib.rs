// =============================================================================
// Guardian Common - Shared Type Definitions
// =============================================================================
//
// This module defines data structures shared between the eBPF kernel program
// and the userspace daemon. These types are used to communicate events from
// kernel space to user space via BPF maps (specifically PerfEventArray).
//
// IMPORTANT CONSTRAINTS:
// - This crate is #![no_std] because eBPF programs cannot use the standard library
// - All types must use #[repr(C)] for deterministic memory layout
// - All types must be Copy (BPF maps work with raw bytes, not owned data)
// - No heap allocation (no Vec, String, Box, etc.)
// - Fixed-size buffers only

#![no_std]

// =============================================================================
// Constants
// =============================================================================

/// Maximum length of a captured filename.
///
/// Linux supports paths up to PATH_MAX (4096 bytes), but capturing the full path
/// in eBPF is expensive and often unnecessary. 256 bytes covers most practical
/// file paths. If you need longer paths, increase this - but be aware that:
///   - Larger events consume more perf buffer space
///   - The eBPF per-CPU array entry will be larger
///   - Values over ~4096 may cause issues with perf event output
pub const MAX_FILENAME_LEN: usize = 256;

/// Maximum length of a process command name.
///
/// This matches the Linux kernel's TASK_COMM_LEN (16 bytes including null terminator).
/// The command name is what you see in `ps` or `/proc/PID/comm`.
/// Note: This is truncated to 15 visible characters + null terminator.
///
/// Example: "claude-code" fits, but "very-long-process-name" would be truncated.
pub const MAX_COMM_LEN: usize = 16;

// =============================================================================
// Event Types
// =============================================================================

/// Represents a file access event captured by the eBPF program.
///
/// When a monitored process (LLM agent) attempts to open a file, the eBPF
/// tracepoint handler creates one of these events and sends it to userspace
/// via the perf event array.
///
/// # Memory Layout
///
/// This struct uses `#[repr(C)]` to ensure the same memory layout in both
/// the eBPF program (compiled for BPF target) and the userspace daemon
/// (compiled for x86_64/aarch64). Without `#[repr(C)]`, Rust is free to
/// reorder fields, which would cause data corruption across the boundary.
///
/// # Example (conceptual)
///
/// ```text
/// eBPF program (kernel):
///   event.pid = 1234;
///   event.filename = "/etc/passwd";
///   perf_output(event);  // Sends raw bytes
///
/// Userspace daemon:
///   let event: FileAccessEvent = read_from_perf_buffer();
///   // event.pid == 1234, event.filename == "/etc/passwd"
///   // Same layout, same interpretation
/// ```
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileAccessEvent {
    /// Thread ID (the Linux kernel PID).
    ///
    /// In Linux, what userspace calls "PID" is actually the Thread Group ID (tgid).
    /// The kernel's PID is the thread ID. For single-threaded processes, pid == tgid.
    pub pid: u32,

    /// Thread Group ID (what userspace calls "PID").
    ///
    /// This is the process ID you see in `ps`, `top`, or `/proc/`.
    /// Use this for matching against configured process names.
    pub tgid: u32,

    /// User ID of the process that triggered the event.
    ///
    /// Useful for auditing which user is running the LLM agent.
    /// Root (uid=0) processes are especially important to monitor.
    pub uid: u32,

    /// File open flags (O_RDONLY=0, O_WRONLY=1, O_RDWR=2, etc.).
    ///
    /// These flags tell us the *intent* of the file access:
    ///   - O_RDONLY (0x0000): Read-only access
    ///   - O_WRONLY (0x0001): Write-only access
    ///   - O_RDWR   (0x0002): Read-write access
    ///   - O_CREAT  (0x0040): Create file if it doesn't exist
    ///   - O_TRUNC  (0x0200): Truncate file to zero length
    ///   - O_APPEND (0x0400): Append to file
    ///
    /// In future phases, we can use these flags for finer-grained policies
    /// (e.g., allow read but deny write to certain paths).
    pub flags: u32,

    /// Length of the captured filename (number of valid bytes in `filename`).
    ///
    /// The filename buffer is fixed-size, so this tells us where the actual
    /// filename ends. Bytes beyond this length are undefined.
    pub filename_len: u32,

    /// Process command name (from /proc/PID/comm).
    ///
    /// This is the short process name, truncated to 15 characters + null.
    /// Examples: "python3", "node", "claude", "bash"
    ///
    /// Used by userspace to match events to agent configurations.
    pub comm: [u8; MAX_COMM_LEN],

    /// The filename/path being opened.
    ///
    /// This is read from userspace memory at the time of the syscall.
    /// It may be:
    ///   - An absolute path: "/etc/passwd"
    ///   - A relative path: "config.toml" (relative to process CWD)
    ///   - A special path: "/proc/self/status"
    ///
    /// Note: Relative paths are tricky for policy enforcement because we'd
    /// need to resolve them against the process's CWD. Phase 1 uses simple
    /// prefix matching; future phases may resolve full paths.
    pub filename: [u8; MAX_FILENAME_LEN],
}

// =============================================================================
// BPF Map Names (used for looking up maps by name in userspace)
// =============================================================================

/// Name of the eBPF HashMap that stores watched PIDs.
/// Key: u32 (tgid/PID), Value: u8 (1 = watched)
pub const MAP_WATCHED_PIDS: &str = "WATCHED_PIDS";

/// Name of the eBPF PerfEventArray for sending events to userspace.
pub const MAP_EVENTS: &str = "EVENTS";

/// Name of the per-CPU array used as scratch buffer in the eBPF program.
pub const MAP_EVENT_BUF: &str = "EVENT_BUF";

// =============================================================================
// Helper Implementations
// =============================================================================

impl FileAccessEvent {
    /// Returns the filename as a byte slice (without trailing garbage).
    pub fn filename_bytes(&self) -> &[u8] {
        let len = core::cmp::min(self.filename_len as usize, MAX_FILENAME_LEN);
        &self.filename[..len]
    }

    /// Returns the command name as a byte slice (without null terminator).
    pub fn comm_bytes(&self) -> &[u8] {
        // Find the null terminator position
        let len = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_COMM_LEN);
        &self.comm[..len]
    }
}
