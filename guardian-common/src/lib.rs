#![cfg_attr(not(feature = "user"), no_std)]

// =============================================================================
// Constants
// =============================================================================

pub const MAX_FILENAME_LEN: usize = 256;
pub const MAX_COMM_LEN: usize = 16;
pub const MAX_POLICY_RULES: usize = 64;

/// Default Unix socket path for daemon IPC.
pub const DEFAULT_SOCKET_PATH: &str = "/run/guardian.sock";

/// Cgroup base path under /sys/fs/cgroup.
pub const CGROUP_BASE: &str = "guardian";

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
pub const MAP_DEFAULT_ACTION: &str = "DEFAULT_ACTION";
pub const MAP_CHILD_PIDS: &str = "CHILD_PIDS";
pub const MAP_WATCHED_CGROUPS: &str = "WATCHED_CGROUPS";
pub const MAP_ENFORCE_CGROUPS: &str = "ENFORCE_CGROUPS";
pub const MAP_CGROUP_DEFAULT_ACTION: &str = "CGROUP_DEFAULT_ACTION";

// =============================================================================
// Aya Pod Implementations (userspace only)
// =============================================================================

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileAccessEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}

// =============================================================================
// IPC Protocol Types (userspace only)
// =============================================================================

#[cfg(feature = "user")]
pub mod ipc {
    use serde::{Deserialize, Serialize};

    /// Request from launcher/CLI to the Guardian daemon.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type")]
    pub enum IpcRequest {
        /// Register a new agent launched in a cgroup.
        #[serde(rename = "register")]
        Register {
            cgroup_path: String,
            cgroup_id: u64,
            agent_name: String,
        },

        /// List all running agents.
        #[serde(rename = "list")]
        ListAgents,

        /// Stop an agent by name (SIGTERM all processes in its cgroup).
        #[serde(rename = "stop")]
        StopAgent { agent_name: String },

        /// Grant temporary access to a path for an agent.
        #[serde(rename = "grant")]
        GrantAccess {
            agent_name: String,
            path: String,
            duration_secs: u64,
        },

        /// Request permission for a resource (agent asks, human approves via dashboard).
        #[serde(rename = "request_permission")]
        RequestPermission {
            agent_name: String,
            /// "file" or "exec"
            resource_type: String,
            /// Path to resource (e.g., "/usr/bin/grep" or "/etc/passwd")
            resource_path: String,
            /// Human-readable justification for why this access is needed
            justification: Option<String>,
        },
    }

    /// Response from the Guardian daemon.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type")]
    pub enum IpcResponse {
        /// Success acknowledgment.
        #[serde(rename = "ack")]
        Ack,

        /// Error response.
        #[serde(rename = "error")]
        Error { message: String },

        /// List of running agents.
        #[serde(rename = "agents")]
        AgentList { agents: Vec<AgentStatus> },

        /// Permission decision (response to RequestPermission).
        #[serde(rename = "permission_decision")]
        PermissionDecision {
            approved: bool,
            reason: String,
            /// If approved, how long the grant lasts (seconds).
            grant_duration_secs: Option<u64>,
        },
    }

    /// Status of a registered agent.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AgentStatus {
        pub name: String,
        pub cgroup_path: String,
        pub cgroup_id: u64,
        pub num_processes: u32,
        pub uptime_secs: u64,
    }

    /// Send a length-prefixed JSON message over a writer.
    pub fn send_message<W: std::io::Write>(
        writer: &mut W,
        msg: &impl Serialize,
    ) -> std::io::Result<()> {
        let json = serde_json::to_vec(msg).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        let len = (json.len() as u32).to_be_bytes();
        writer.write_all(&len)?;
        writer.write_all(&json)?;
        writer.flush()
    }

    /// Receive a length-prefixed JSON message from a reader.
    pub fn recv_message<R: std::io::Read, T: serde::de::DeserializeOwned>(
        reader: &mut R,
    ) -> std::io::Result<T> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "message too large",
            ));
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        serde_json::from_slice(&buf).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })
    }
}
