#![no_std]

// =============================================================================
// Constants
// =============================================================================

pub const MAX_FILENAME_LEN: usize = 256;
pub const MAX_COMM_LEN: usize = 16;
pub const MAX_POLICY_RULES: usize = 64;

// =============================================================================
// Event Types
// =============================================================================

/// File access event captured by the eBPF tracepoint on sys_enter_openat.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileAccessEvent {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub flags: u32,
    pub filename_len: u32,
    pub comm: [u8; MAX_COMM_LEN],
    pub filename: [u8; MAX_FILENAME_LEN],
}

impl FileAccessEvent {
    pub fn filename_bytes(&self) -> &[u8] {
        let len = core::cmp::min(self.filename_len as usize, MAX_FILENAME_LEN);
        &self.filename[..len]
    }

    pub fn comm_bytes(&self) -> &[u8] {
        let len = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_COMM_LEN);
        &self.comm[..len]
    }
}

/// Command execution event captured by the eBPF tracepoint on sys_enter_execve.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub _pad: u32,
    pub filename_len: u32,
    pub comm: [u8; MAX_COMM_LEN],
    pub filename: [u8; MAX_FILENAME_LEN],
}

impl ExecEvent {
    pub fn filename_bytes(&self) -> &[u8] {
        let len = core::cmp::min(self.filename_len as usize, MAX_FILENAME_LEN);
        &self.filename[..len]
    }

    pub fn comm_bytes(&self) -> &[u8] {
        let len = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_COMM_LEN);
        &self.comm[..len]
    }
}

/// Policy rule stored in BPF maps for kernel-side enforcement.
///
/// match_type: 0 = exact, 1 = prefix (/**), 2 = single-level (/*)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PolicyRule {
    pub path_prefix: [u8; MAX_FILENAME_LEN],
    pub prefix_len: u32,
    pub match_type: u8,
    pub _pad: [u8; 3],
}

// =============================================================================
// Map Name Constants
// =============================================================================

pub const MAP_WATCHED_COMMS: &str = "WATCHED_COMMS";
pub const MAP_ENFORCE_COMMS: &str = "ENFORCE_COMMS";
pub const MAP_EVENTS: &str = "EVENTS";
pub const MAP_EVENT_BUF: &str = "EVENT_BUF";
pub const MAP_EXEC_EVENTS: &str = "EXEC_EVENTS";
pub const MAP_EXEC_BUF: &str = "EXEC_BUF";
pub const MAP_PENDING_DENY: &str = "PENDING_DENY";
pub const MAP_DENY_RULES: &str = "DENY_RULES";
pub const MAP_DENY_RULE_COUNT: &str = "DENY_RULE_COUNT";
pub const MAP_ALLOW_RULES: &str = "ALLOW_RULES";
pub const MAP_ALLOW_RULE_COUNT: &str = "ALLOW_RULE_COUNT";
pub const MAP_DEFAULT_ACTION: &str = "DEFAULT_ACTION";
pub const MAP_CHILD_PIDS: &str = "CHILD_PIDS";

// =============================================================================
// Aya Pod Implementations (userspace only)
// =============================================================================

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileAccessEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyRule {}
