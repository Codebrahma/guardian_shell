#![cfg_attr(not(feature = "user"), no_std)]

// =============================================================================
// Constants
// =============================================================================

pub const MAX_FILENAME_LEN: usize = 256;
pub const MAX_COMM_LEN: usize = 16;
pub const MAX_POLICY_RULES: usize = 1024;

/// Flag: path was truncated at MAX_FILENAME_LEN boundary (deny by default).
pub const EVENT_FLAG_TRUNCATED: u32 = 1;

/// Default Unix socket path for daemon IPC.
pub const DEFAULT_SOCKET_PATH: &str = "/run/guardian.sock";

/// Cgroup base path under /sys/fs/cgroup.
pub const CGROUP_BASE: &str = "guardian";

/// Maximum IPC message size in bytes (1 MiB). Both sender and receiver enforce this.
#[cfg(feature = "user")]
pub const MAX_IPC_MESSAGE_LEN: usize = 1024 * 1024;

/// Maximum allowed length for agent names in IPC requests.
#[cfg(feature = "user")]
pub const MAX_AGENT_NAME_LEN: usize = 128;

/// Maximum allowed length for resource paths in IPC requests.
#[cfg(feature = "user")]
pub const MAX_RESOURCE_PATH_LEN: usize = 4096;

/// Maximum allowed length for justification text.
#[cfg(feature = "user")]
pub const MAX_JUSTIFICATION_LEN: usize = 2048;

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
    /// Bitfield: bit 0 = EVENT_FLAG_TRUNCATED (path was truncated at MAX_FILENAME_LEN).
    pub status_flags: u32,
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

/// Network connection event captured by the eBPF tracepoint on sys_enter_connect.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEvent {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub family: u8,       // AF_INET=2, AF_INET6=10
    pub _pad_proto: u8,
    pub dest_port: u16,   // destination port (host byte order)
    pub dest_addr4: u32,  // IPv4 address (network byte order), 0 for IPv6
    pub dest_addr6: [u8; 16], // IPv6 address, zeroed for IPv4
    pub comm: [u8; MAX_COMM_LEN],
}

impl NetworkEvent {
    pub fn comm_bytes(&self) -> &[u8] {
        let len = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_COMM_LEN);
        &self.comm[..len]
    }

    /// Format the destination address as a string.
    pub fn dest_addr_str(&self) -> &str {
        // This is a no_std stub; actual formatting done in userspace
        ""
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

// Exec enforcement maps (Phase 7)
pub const MAP_EXEC_DENY_EXACT: &str = "EXEC_DENY_EXACT";
pub const MAP_EXEC_DENY_PREFIXES: &str = "EXEC_DENY_PREFIXES";
pub const MAP_EXEC_ALLOW_EXACT: &str = "EXEC_ALLOW_EXACT";
pub const MAP_EXEC_ALLOW_PREFIXES: &str = "EXEC_ALLOW_PREFIXES";
pub const MAP_EXEC_DEFAULT_ACTION: &str = "EXEC_DEFAULT_ACTION";
pub const MAP_EXEC_CGROUP_DEFAULT_ACTION: &str = "EXEC_CGROUP_DEFAULT_ACTION";
pub const MAP_PENDING_EXEC_DENY: &str = "PENDING_EXEC_DENY";

// Network monitoring + enforcement maps (Phase 7 monitoring, Phase 9 enforcement)
pub const MAP_NET_EVENTS: &str = "NET_EVENTS";
pub const MAP_NET_EVENT_BUF: &str = "NET_EVENT_BUF";
pub const MAP_PENDING_NET_DENY: &str = "PENDING_NET_DENY";
pub const MAP_NET_DENY_PORTS: &str = "NET_DENY_PORTS";
pub const MAP_NET_ALLOW_PORTS: &str = "NET_ALLOW_PORTS";
pub const MAP_NET_DEFAULT_ACTION: &str = "NET_DEFAULT_ACTION";
pub const MAP_NET_CGROUP_DEFAULT_ACTION: &str = "NET_CGROUP_DEFAULT_ACTION";

// Phase 8: Inode enforcement maps (rename/unlink/hardlink)
pub const MAP_PENDING_RENAME_DENY: &str = "PENDING_RENAME_DENY";
pub const MAP_PENDING_UNLINK_DENY: &str = "PENDING_UNLINK_DENY";
pub const MAP_PENDING_LINK_DENY: &str = "PENDING_LINK_DENY";

// Phase 8: Dynamic linker detection
pub const MAP_DYNAMIC_LINKERS: &str = "DYNAMIC_LINKERS";

// Phase 8: Fail-closed mode per cgroup
pub const MAP_FAIL_CLOSED_CGROUPS: &str = "FAIL_CLOSED_CGROUPS";

// Pending map overflow protection (fail-closed on map full)
pub const MAP_PENDING_DENY_OVERFLOW: &str = "PENDING_DENY_OVERFLOW";
pub const MAP_PENDING_EXEC_DENY_OVERFLOW: &str = "PENDING_EXEC_DENY_OVERFLOW";
pub const MAP_PENDING_NET_DENY_OVERFLOW: &str = "PENDING_NET_DENY_OVERFLOW";
pub const MAP_PENDING_RENAME_DENY_OVERFLOW: &str = "PENDING_RENAME_DENY_OVERFLOW";
pub const MAP_PENDING_UNLINK_DENY_OVERFLOW: &str = "PENDING_UNLINK_DENY_OVERFLOW";
pub const MAP_PENDING_LINK_DENY_OVERFLOW: &str = "PENDING_LINK_DENY_OVERFLOW";
pub const MAP_PENDING_INSERT_FAILURES: &str = "PENDING_INSERT_FAILURES";

// =============================================================================
// Aya Pod Implementations (userspace only)
// =============================================================================

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileAccessEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NetworkEvent {}

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
            /// "file" (default) or "exec"
            #[serde(default = "default_grant_type")]
            grant_type: String,
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

        /// List pending permission requests (for CLI approval workflow).
        #[serde(rename = "list_pending")]
        ListPending,

        /// Approve a pending permission request by ID.
        #[serde(rename = "approve_permission")]
        ApprovePermission {
            request_id: u64,
            duration_secs: u64,
        },

        /// Deny a pending permission request by ID.
        #[serde(rename = "deny_permission")]
        DenyPermission {
            request_id: u64,
            reason: Option<String>,
        },
    }

    /// Sandbox configuration sent from daemon to launcher during registration.
    /// Carries the agent's policy so guardian-launch can build Landlock + seccomp rules.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SandboxConfig {
        /// Enable Landlock filesystem sandbox (inode-level, symlink-immune).
        #[serde(default = "default_true")]
        pub landlock: bool,
        /// Enable expanded seccomp filter (blocks mount, namespace, chroot, etc.).
        #[serde(default = "default_true")]
        pub seccomp_hardened: bool,
        /// Set PR_SET_NO_NEW_PRIVS to prevent SUID escalation.
        #[serde(default = "default_true")]
        pub no_new_privs: bool,
        /// File access default action: "allow" or "deny".
        pub file_default: String,
        /// Allowed file access path patterns (e.g., "/tmp/**", "/proc/self/**").
        #[serde(default)]
        pub file_allow: Vec<String>,
        /// Exec policy default action: "allow" or "deny".
        #[serde(default = "default_allow")]
        pub exec_default: String,
        /// Allowed exec path patterns (e.g., "/usr/bin/python3").
        #[serde(default)]
        pub exec_allow: Vec<String>,
        /// Allowed network ports for outbound TCP connections.
        #[serde(default)]
        pub net_allow_ports: Vec<u16>,
        /// Network default action: "allow" or "deny".
        #[serde(default = "default_allow")]
        pub net_default: String,
    }

    fn default_true() -> bool {
        true
    }

    fn default_allow() -> String {
        "allow".to_string()
    }

    /// Response from the Guardian daemon.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type")]
    pub enum IpcResponse {
        /// Success acknowledgment, optionally carrying sandbox config for launcher.
        #[serde(rename = "ack")]
        Ack {
            /// Sandbox configuration for guardian-launch (Phase 10).
            /// Present only in registration responses.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            sandbox: Option<SandboxConfig>,
        },

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

        /// List of pending permission requests.
        #[serde(rename = "pending_permissions")]
        PendingPermissions {
            requests: Vec<PendingPermissionInfo>,
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

    /// Info about a pending permission request (for CLI listing).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PendingPermissionInfo {
        pub request_id: u64,
        pub agent_name: String,
        pub resource_type: String,
        pub resource_path: String,
        pub justification: Option<String>,
        pub risk_level: String,
        pub elapsed_secs: u64,
    }

    fn default_grant_type() -> String {
        "file".to_string()
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
        if len > crate::MAX_IPC_MESSAGE_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("IPC message too large: {} bytes (max {})", len, crate::MAX_IPC_MESSAGE_LEN),
            ));
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        serde_json::from_slice(&buf).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })
    }
}
