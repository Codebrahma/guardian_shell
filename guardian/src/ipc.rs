use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::maps::{lpm_trie::Key, lpm_trie::LpmTrie, HashMap as BpfHashMap, MapData};
use guardian_common::ipc::{AgentStatus, IpcRequest, IpcResponse, PendingPermissionInfo};
use guardian_common::MAX_FILENAME_LEN;
use log::{debug, error, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, Mutex, Semaphore, oneshot};

use crate::config::Config;
use crate::permissions::{self, AgentRateLimit, RiskLevel};

// =============================================================================
// Registered Agent State
// =============================================================================

/// A cgroup-based agent registered via the launcher.
#[derive(Debug, Clone)]
pub struct RegisteredAgent {
    pub name: String,
    pub cgroup_path: String,
    pub cgroup_id: u64,
    pub registered_at: Instant,
}

/// The type of temporary grant.
#[derive(Debug, Clone, PartialEq)]
pub enum GrantType {
    /// File access grant (path added to BPF allow maps)
    FileAccess,
    /// Exec grant (command added to agent's exec policy allow list)
    Exec,
}

/// A temporary access grant with an expiry time.
#[derive(Debug, Clone)]
pub struct TemporaryGrant {
    pub agent_name: String,
    pub path: String,
    pub is_prefix: bool,
    pub grant_type: GrantType,
    pub expires_at: Instant,
}

// =============================================================================
// Permission Request Types
// =============================================================================

/// Decision sent back to an agent waiting for permission.
pub struct PermissionDecision {
    pub approved: bool,
    pub reason: String,
    pub grant_duration_secs: Option<u64>,
}

/// A pending permission request from an agent, waiting for human approval.
pub struct PendingPermission {
    pub id: u64,
    pub agent_name: String,
    pub resource_type: String,
    pub resource_path: String,
    pub justification: Option<String>,
    pub requested_at: Instant,
    pub requested_at_utc: chrono::DateTime<chrono::Utc>,
    pub timeout_secs: u64,
    pub responder: Option<oneshot::Sender<PermissionDecision>>,
    pub risk_level: RiskLevel,
    pub risk_flags: Vec<String>,
    pub justification_flags: Vec<(&'static str, &'static str)>,
}

/// A resolved (completed) permission request, kept for audit trail.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedPermission {
    pub id: u64,
    pub agent_name: String,
    pub resource_type: String,
    pub resource_path: String,
    pub justification: Option<String>,
    pub risk_level: String,
    pub risk_flags: Vec<String>,
    pub requested_at: String,
    pub resolved_at: String,
    pub approved: bool,
    pub reason: String,
    pub grant_duration_secs: Option<u64>,
}

/// SSE event for permission requests/resolutions, broadcast to dashboard.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PermissionEvent {
    pub id: u64,
    /// "request" or "resolved"
    pub kind: String,
    pub agent_name: String,
    pub resource_type: String,
    pub resource_path: String,
    pub justification: Option<String>,
    pub timeout_secs: u64,
    pub requested_at: String,
    pub approved: Option<bool>,
    pub reason: Option<String>,
    pub risk_level: Option<String>,
    pub risk_flags: Vec<String>,
    pub wait_seconds: Option<u32>,
    pub requires_type_confirm: Option<bool>,
    pub justification_warnings: Vec<String>,
}

/// Maximum number of resolved permissions to keep in memory.
const MAX_RESOLVED_HISTORY: usize = 100;

/// Shared state for BPF maps that support dynamic cgroup updates.
pub struct CgroupBpfMaps {
    pub watched_cgroups: BpfHashMap<MapData, u64, u8>,
    pub enforce_cgroups: BpfHashMap<MapData, u64, u8>,
    pub cgroup_default_action: BpfHashMap<MapData, u64, u8>,
}

/// Shared state for allow/deny BPF maps (for temporary grants).
pub struct PolicyBpfMaps {
    pub allow_prefixes: LpmTrie<MapData, [u8; MAX_FILENAME_LEN], u8>,
    pub allow_exact: BpfHashMap<MapData, [u8; MAX_FILENAME_LEN], u8>,
    pub exec_allow_prefixes: LpmTrie<MapData, [u8; MAX_FILENAME_LEN], u8>,
    pub exec_allow_exact: BpfHashMap<MapData, [u8; MAX_FILENAME_LEN], u8>,
    pub exec_deny_prefixes: LpmTrie<MapData, [u8; MAX_FILENAME_LEN], u8>,
    pub exec_deny_exact: BpfHashMap<MapData, [u8; MAX_FILENAME_LEN], u8>,
}

/// All shared IPC state.
pub struct IpcState {
    pub agents: HashMap<String, RegisteredAgent>,
    pub grants: Vec<TemporaryGrant>,
    pub cgroup_maps: CgroupBpfMaps,
    pub policy_maps: Option<PolicyBpfMaps>,
    pub config: Config,
    pub config_path: std::path::PathBuf,
    pub enforce_mode: bool,
    // Permission request state
    pub pending_permissions: Vec<PendingPermission>,
    pub resolved_permissions: VecDeque<ResolvedPermission>,
    pub next_permission_id: u64,
    pub permission_bus: Option<broadcast::Sender<PermissionEvent>>,
    // Phase 7c: Per-agent rate limiting
    pub rate_limits: HashMap<String, AgentRateLimit>,
    // Phase 7c: Optional SQLite audit trail for permissions
    pub event_db: Option<std::sync::Arc<crate::dashboard::db::EventDb>>,
    // Phase 8: Fail-closed cgroups BPF map
    pub fail_closed_map: Option<BpfHashMap<MapData, u64, u8>>,
    // Phase 8: Grant accumulation tracker
    pub grant_accumulator: permissions::GrantAccumulator,
}

pub type SharedIpcState = Arc<Mutex<IpcState>>;

// =============================================================================
// IPC Server
// =============================================================================

/// Maximum concurrent IPC connections to prevent resource exhaustion.
const MAX_IPC_CONNECTIONS: usize = 64;

/// Start the Unix socket IPC server.
pub async fn start_ipc_server(socket_path: &str, state: SharedIpcState) -> Result<()> {
    // Remove stale socket file if it exists
    let _ = std::fs::remove_file(socket_path);

    // Create parent directory if needed
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("Failed to bind IPC socket at {}", socket_path))?;

    // Allow all local users to connect to the socket. Authorization is enforced
    // per-request: only root can issue privileged commands (Stop, Grant, Approve,
    // Deny), while non-root users can only send RequestPermission (creates a
    // pending request for human review — no security impact).
    // This is required for cgroup agents with privilege dropping (Phase 11):
    // guardian-ctl runs as the dropped user and needs socket access.
    let _ = std::fs::set_permissions(
        socket_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o666),
    );

    info!("IPC server listening on {}", socket_path);

    // Limit concurrent connections to prevent resource exhaustion
    let semaphore = Arc::new(Semaphore::new(MAX_IPC_CONNECTIONS));

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                // Get peer UID for per-request authorization.
                // Non-root UIDs are allowed to connect but can only send
                // RequestPermission (safe: creates a pending request for human review).
                // Privileged operations (Stop, Grant, Approve, Deny) require root.
                let peer_uid = match stream.peer_cred() {
                    Ok(cred) => cred.uid(),
                    Err(e) => {
                        warn!("IPC connection rejected: failed to get peer credentials: {}", e);
                        continue;
                    }
                };

                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("IPC connection rejected: too many concurrent connections");
                        continue;
                    }
                };

                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, state, peer_uid).await {
                        warn!("IPC connection error: {}", e);
                    }
                    drop(permit); // Release connection slot
                });
            }
            Err(e) => {
                error!("IPC accept error: {}", e);
            }
        }
    }
}

/// IPC read timeout: prevents a client from blocking a connection slot by sending
/// the length prefix but never the body (or connecting and never sending anything).
const IPC_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Handle a single IPC connection.
async fn handle_connection(mut stream: UnixStream, state: SharedIpcState, peer_uid: u32) -> Result<()> {
    // Read length-prefixed message with a timeout to prevent hanging on
    // malicious or buggy clients that connect but never send data.
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(IPC_READ_TIMEOUT, stream.read_exact(&mut len_buf))
        .await
        .context("IPC read timed out waiting for message length")?
        .context("Failed to read IPC message length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > guardian_common::MAX_IPC_MESSAGE_LEN {
        return Err(anyhow::anyhow!(
            "IPC message too large: {} bytes (max {})", len, guardian_common::MAX_IPC_MESSAGE_LEN
        ));
    }

    let mut buf = vec![0u8; len];
    tokio::time::timeout(IPC_READ_TIMEOUT, stream.read_exact(&mut buf))
        .await
        .context("IPC read timed out waiting for message body")?
        .context("Failed to read IPC message body")?;

    let request: IpcRequest = serde_json::from_slice(&buf)
        .context("Failed to parse IPC request")?;

    debug!("IPC request: {:?}", request);

    // Authorization: non-root UIDs may only send RequestPermission.
    // This allows cgroup agents (which run with dropped privileges) to
    // request permissions via guardian-ctl, while keeping privileged
    // operations (Stop, Grant, Approve, Deny, Register) root-only.
    if peer_uid != 0 {
        let allowed = matches!(&request, IpcRequest::RequestPermission { .. });
        if !allowed {
            warn!(
                "IPC request rejected: peer UID {} is not root (only RequestPermission allowed for non-root)",
                peer_uid
            );
            let response = IpcResponse::Error {
                message: format!("Permission denied: UID {} is not authorized for this operation", peer_uid),
            };
            let resp_json = serde_json::to_vec(&response)?;
            let resp_len = (resp_json.len() as u32).to_be_bytes();
            stream.write_all(&resp_len).await?;
            stream.write_all(&resp_json).await?;
            stream.flush().await?;
            return Ok(());
        }
    }

    // Validate IPC request fields before processing
    if let Some(err) = validate_request(&request) {
        let response = IpcResponse::Error { message: err };
        let resp_json = serde_json::to_vec(&response)?;
        let resp_len = (resp_json.len() as u32).to_be_bytes();
        stream.write_all(&resp_len).await?;
        stream.write_all(&resp_json).await?;
        stream.flush().await?;
        return Ok(());
    }

    let response = process_request(request, &state).await;

    // Send response
    let resp_json = serde_json::to_vec(&response)?;
    let resp_len = (resp_json.len() as u32).to_be_bytes();
    stream.write_all(&resp_len).await?;
    stream.write_all(&resp_json).await?;
    stream.flush().await?;

    Ok(())
}

/// Validate IPC request fields. Returns Some(error_message) if invalid.
fn validate_request(request: &IpcRequest) -> Option<String> {
    match request {
        IpcRequest::Register { agent_name, cgroup_path, .. } => {
            if agent_name.is_empty() || agent_name.len() > guardian_common::MAX_AGENT_NAME_LEN {
                return Some(format!("Invalid agent_name length (must be 1-{})", guardian_common::MAX_AGENT_NAME_LEN));
            }
            if agent_name.contains('/') || agent_name.contains('\0') {
                return Some("agent_name must not contain '/' or null bytes".to_string());
            }
            if cgroup_path.contains('\0') {
                return Some("cgroup_path must not contain null bytes".to_string());
            }
            // Prevent path traversal attacks (e.g., "../../tmp/evil" → SIGTERM to arbitrary PIDs)
            if cgroup_path.contains("..") {
                return Some("cgroup_path must not contain '..' (path traversal)".to_string());
            }
            // Cgroup paths are relative to /sys/fs/cgroup/, must not be absolute
            if cgroup_path.starts_with('/') {
                return Some("cgroup_path must be relative (not start with '/')".to_string());
            }
        }
        IpcRequest::StopAgent { agent_name } => {
            if agent_name.is_empty() {
                return Some("agent_name must not be empty".to_string());
            }
        }
        IpcRequest::GrantAccess { agent_name, path, duration_secs, grant_type } => {
            if agent_name.is_empty() {
                return Some("agent_name must not be empty".to_string());
            }
            if path.is_empty() || path.len() > guardian_common::MAX_RESOURCE_PATH_LEN {
                return Some(format!("Invalid path length (must be 1-{})", guardian_common::MAX_RESOURCE_PATH_LEN));
            }
            if path.contains('\0') {
                return Some("path must not contain null bytes".to_string());
            }
            if *duration_secs == 0 || *duration_secs > 86400 {
                return Some("duration_secs must be between 1 and 86400".to_string());
            }
            // Validate grant_type to prevent silent fallthrough to file access
            if grant_type != "file" && grant_type != "exec" {
                return Some(format!("Invalid grant_type '{}' (must be 'file' or 'exec')", grant_type));
            }
        }
        IpcRequest::RequestPermission { agent_name, resource_path, justification, .. } => {
            if agent_name.is_empty() {
                return Some("agent_name must not be empty".to_string());
            }
            if resource_path.is_empty() || resource_path.len() > guardian_common::MAX_RESOURCE_PATH_LEN {
                return Some(format!("Invalid resource_path length (must be 1-{})", guardian_common::MAX_RESOURCE_PATH_LEN));
            }
            if resource_path.contains('\0') {
                return Some("resource_path must not contain null bytes".to_string());
            }
            if let Some(j) = justification {
                if j.len() > guardian_common::MAX_JUSTIFICATION_LEN {
                    return Some(format!("Justification too long (max {} chars)", guardian_common::MAX_JUSTIFICATION_LEN));
                }
                // Reject control characters in justification (except common whitespace)
                if j.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
                    return Some("Justification must not contain control characters".to_string());
                }
            }
        }
        IpcRequest::ApprovePermission { duration_secs, .. } => {
            if *duration_secs == 0 || *duration_secs > 86400 {
                return Some("duration_secs must be between 1 and 86400".to_string());
            }
        }
        // ListAgents, ListPending, DenyPermission — no validation needed
        _ => {}
    }
    None
}

/// Process an IPC request and return a response.
async fn process_request(request: IpcRequest, state: &SharedIpcState) -> IpcResponse {
    match request {
        IpcRequest::Register {
            cgroup_path,
            cgroup_id,
            agent_name,
        } => handle_register(state, agent_name, cgroup_path, cgroup_id).await,

        IpcRequest::ListAgents => handle_list_agents(state).await,

        IpcRequest::StopAgent { agent_name } => handle_stop_agent(state, &agent_name).await,

        IpcRequest::GrantAccess {
            agent_name,
            path,
            duration_secs,
            grant_type,
        } => handle_grant_access(state, &agent_name, &path, duration_secs, &grant_type).await,

        IpcRequest::RequestPermission {
            agent_name,
            resource_type,
            resource_path,
            justification,
        } => {
            handle_request_permission(
                state,
                agent_name,
                resource_type,
                resource_path,
                justification,
            )
            .await
        }

        // Phase 8: CLI permission approval
        IpcRequest::ListPending => handle_list_pending(state).await,

        IpcRequest::ApprovePermission {
            request_id,
            duration_secs,
        } => handle_approve_permission(state, request_id, duration_secs).await,

        IpcRequest::DenyPermission {
            request_id,
            reason,
        } => handle_deny_permission(state, request_id, reason).await,
    }
}

// =============================================================================
// Default Cgroup Agent Config
// =============================================================================

/// Create a default config for a new cgroup agent that registers without
/// a pre-existing config entry. Provides sensible system path defaults
/// learned from real-world testing on Fedora/RHEL and Debian/Ubuntu.
///
/// The default is deny-all with broad system read paths allowed and
/// sensitive files denied. The agent's home directory is inferred from
/// SUDO_USER or defaults to /home.
fn default_cgroup_config(name: &str) -> crate::config::AgentConfig {
    // Infer user home from environment
    let user_home = std::env::var("SUDO_USER")
        .map(|u| format!("/home/{}", u))
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| "/home".to_string());

    crate::config::AgentConfig {
        name: name.to_string(),
        identity: Some("cgroup".to_string()),
        process_name: None,
        file_access: crate::config::FileAccessPolicy {
            default: "deny".to_string(),
            allow: vec![
                // NOTE: Intentionally does NOT allow user_home/** — too permissive.
                // Users should add specific project directories to the allow list.
                // Working directories — user should customize these
                format!("{}/projects/**", user_home),
                format!("{}/.local/**", user_home),
                format!("{}/.cache/**", user_home),
                format!("{}/.config/**", user_home),
                format!("{}/.npm/**", user_home),
                format!("{}/.cargo/**", user_home),
                // Shell config (needed for bash/zsh init)
                format!("{}/.bashrc", user_home),
                format!("{}/.bash_profile", user_home),
                format!("{}/.profile", user_home),
                format!("{}/.zshrc", user_home),
                format!("{}/.inputrc", user_home),
                // Temp and runtime
                "/tmp/**".to_string(),
                "/proc/**".to_string(),
                "/sys/**".to_string(),
                "/dev/**".to_string(),
                "/run/**".to_string(),
                "/var/**".to_string(),
                // System libraries and binaries (covers both Fedora and Debian/Ubuntu)
                // Debian multiarch (/usr/lib/x86_64-linux-gnu/) is under /usr/lib/**
                "/usr/lib/**".to_string(),
                "/usr/lib64/**".to_string(),   // Fedora multilib
                "/usr/libexec/**".to_string(), // Fedora helpers (Debian uses /usr/lib/<pkg>/)
                "/usr/share/**".to_string(),
                "/usr/local/**".to_string(),
                "/usr/bin/**".to_string(),
                "/usr/sbin/**".to_string(),
                "/sbin/**".to_string(),        // Separate on older Debian
                "/lib/**".to_string(),         // Includes Debian /lib/x86_64-linux-gnu/
                "/lib64/**".to_string(),       // Fedora multilib
                "/bin/**".to_string(),
                "/snap/**".to_string(),        // Ubuntu snap packages
                // System config (deny rules protect sensitive files)
                "/etc/**".to_string(),
            ],
            deny: vec![
                "/etc/shadow".to_string(),
                "/etc/gshadow".to_string(),
                format!("{}/.ssh/**", user_home),
                format!("{}/.aws/**", user_home),
                format!("{}/.gnupg/**", user_home),
                format!("{}/.config/gcloud/**", user_home),
                format!("{}/.docker/**", user_home),
                format!("{}/.kube/**", user_home),
            ],
            read_only: vec![],
        },
        exec_policy: Some(crate::config::ExecPolicy {
            default: "allow".to_string(),
            allow: vec![
                "/usr/bin/**".to_string(),
                "/usr/sbin/**".to_string(),
                "/sbin/**".to_string(),        // Separate on older Debian
                "/usr/libexec/**".to_string(), // Fedora helpers
                "/usr/local/bin/**".to_string(),
                "/bin/**".to_string(),
                "/snap/bin/**".to_string(),    // Ubuntu snap
            ],
            deny: vec![],
        }),
        network_policy: Some(crate::config::NetworkPolicy {
            default: "allow".to_string(),
            allow_ports: vec![],
            deny_ports: vec![],
        }),
        watch_children: true,
        resources: None,
        fail_closed: None,
    }
}

// =============================================================================
// Request Handlers
// =============================================================================

async fn handle_register(
    state: &SharedIpcState,
    agent_name: String,
    cgroup_path: String,
    cgroup_id: u64,
) -> IpcResponse {
    let mut state = state.lock().await;

    // Find matching agent config, or create a default for new cgroup agents
    let agent_config = match state.config.agents.iter().find(|a| a.name == agent_name) {
        Some(cfg) => cfg.clone(),
        None => {
            // Auto-create default config for unregistered cgroup agents
            let default = default_cgroup_config(&agent_name);
            warn!(
                "Auto-created default config for '{}'. Review and customize deny rules \
                 in config.toml — default does NOT protect project-specific sensitive directories.",
                agent_name
            );
            state.config.agents.push(default.clone());

            // Persist to disk so the config survives daemon restarts
            let config_path = state.config_path.clone();
            if let Err(e) = crate::dashboard::routes::api::write_config_toml(&config_path, &state.config) {
                warn!("Failed to persist auto-created config for '{}': {} (in-memory only)", agent_name, e);
            }

            default
        }
    };

    // Insert into WATCHED_CGROUPS BPF map
    if let Err(e) = state.cgroup_maps.watched_cgroups.insert(cgroup_id, 1, 0) {
        error!("Failed to update WATCHED_CGROUPS map for '{}': {}", agent_name, e);
        return IpcResponse::Error {
            message: "Internal error: failed to register agent for monitoring".to_string(),
        };
    }

    // Insert into enforcement maps if in enforce mode
    if state.enforce_mode {
        if let Err(e) = state.cgroup_maps.enforce_cgroups.insert(cgroup_id, 1, 0) {
            warn!("Failed to update ENFORCE_CGROUPS map: {}", e);
        }

        let default_val = if agent_config.file_access.default == "deny" {
            0u8
        } else {
            1u8
        };
        if let Err(e) = state
            .cgroup_maps
            .cgroup_default_action
            .insert(cgroup_id, default_val, 0)
        {
            warn!("Failed to update CGROUP_DEFAULT_ACTION map: {}", e);
        }
    }

    // Phase 8: Set fail-closed mode for this cgroup if configured
    if agent_config.fail_closed.unwrap_or(false) {
        if let Some(ref mut fc_map) = state.fail_closed_map {
            if let Err(e) = fc_map.insert(cgroup_id, 1, 0) {
                warn!("Failed to set fail-closed for cgroup {}: {}", cgroup_id, e);
            } else {
                info!("Fail-closed mode enabled for agent '{}'", agent_name);
            }
        }
    }

    // Store registration
    let agent = RegisteredAgent {
        name: agent_name.clone(),
        cgroup_path: cgroup_path.clone(),
        cgroup_id,
        registered_at: Instant::now(),
    };
    state.agents.insert(agent_name.clone(), agent);

    // Phase 10: Build sandbox config from agent's policy for guardian-launch.
    // This allows the launcher to set up Landlock + seccomp before exec.
    let sandbox = {
        let file_allow: Vec<String> = agent_config.file_access.allow.clone();
        let file_read_only: Vec<String> = agent_config.file_access.read_only.clone();
        let exec_allow: Vec<String> = agent_config
            .exec_policy
            .as_ref()
            .map(|e| e.allow.clone())
            .unwrap_or_default();
        let (net_allow_ports, net_default) = agent_config
            .network_policy
            .as_ref()
            .map(|n| (n.allow_ports.clone(), n.default.clone()))
            .unwrap_or_else(|| (vec![], "allow".to_string()));

        let exec_default = agent_config
            .exec_policy
            .as_ref()
            .map(|e| e.default.clone())
            .unwrap_or_else(|| "allow".to_string());

        guardian_common::ipc::SandboxConfig {
            landlock: true,
            seccomp_hardened: true,
            no_new_privs: true,
            file_default: agent_config.file_access.default.clone(),
            file_allow,
            file_read_only,
            exec_default,
            exec_allow,
            net_allow_ports,
            net_default,
        }
    };

    info!(
        "Agent '{}' registered: cgroup={}, id={}",
        agent_name, cgroup_path, cgroup_id
    );

    IpcResponse::Ack { sandbox: Some(sandbox) }
}

async fn handle_list_agents(state: &SharedIpcState) -> IpcResponse {
    let state = state.lock().await;

    let agents: Vec<AgentStatus> = state
        .agents
        .values()
        .map(|agent| {
            let num_processes = count_cgroup_processes(&agent.cgroup_path);
            AgentStatus {
                name: agent.name.clone(),
                cgroup_path: agent.cgroup_path.clone(),
                cgroup_id: agent.cgroup_id,
                num_processes,
                uptime_secs: agent.registered_at.elapsed().as_secs(),
            }
        })
        .collect();

    IpcResponse::AgentList { agents }
}

async fn handle_stop_agent(state: &SharedIpcState, agent_name: &str) -> IpcResponse {
    let mut state = state.lock().await;

    let agent = match state.agents.get(agent_name) {
        Some(a) => a.clone(),
        None => {
            return IpcResponse::Error {
                message: format!("Agent '{}' not found", agent_name),
            };
        }
    };

    // Send SIGTERM to all processes in the cgroup
    let cgroup_procs_path = format!(
        "/sys/fs/cgroup/{}/cgroup.procs",
        agent.cgroup_path
    );
    match std::fs::read_to_string(&cgroup_procs_path) {
        Ok(procs) => {
            let mut killed = 0;
            for line in procs.lines() {
                if let Ok(pid) = line.trim().parse::<i32>() {
                    // Validate PID: must be positive. Negative PIDs have special
                    // POSIX semantics (e.g., -1 sends signal to ALL processes).
                    if pid <= 0 {
                        warn!("Skipping invalid PID {} in cgroup for agent '{}'", pid, agent_name);
                        continue;
                    }
                    unsafe {
                        libc::kill(pid, libc::SIGTERM);
                    }
                    killed += 1;
                }
            }
            info!(
                "Sent SIGTERM to {} process(es) in agent '{}'",
                killed, agent_name
            );
        }
        Err(e) => {
            warn!("Failed to read cgroup procs for '{}': {}", agent_name, e);
        }
    }

    // Clean up BPF maps and state
    cleanup_agent(&mut state, agent_name);

    IpcResponse::Ack { sandbox: None }
}

async fn handle_grant_access(
    state: &SharedIpcState,
    agent_name: &str,
    path: &str,
    duration_secs: u64,
    grant_type: &str,
) -> IpcResponse {
    let mut state = state.lock().await;

    // Verify agent exists (either registered or in config)
    let agent_exists = state.agents.contains_key(agent_name)
        || state.config.agents.iter().any(|a| a.name == agent_name);
    if !agent_exists {
        return IpcResponse::Error {
            message: format!("Agent '{}' not found", agent_name),
        };
    }

    let is_prefix = path.ends_with("/**");
    let expires_at = Instant::now() + Duration::from_secs(duration_secs);

    if grant_type == "exec" {
        // Exec grant: add command to agent's exec policy allow list temporarily
        if let Some(agent_cfg) = state.config.agents.iter_mut().find(|a| a.name == agent_name) {
            let exec = agent_cfg.exec_policy.get_or_insert(crate::config::ExecPolicy {
                default: "deny".to_string(),
                allow: vec![],
                deny: vec![],
            });
            if !exec.allow.contains(&path.to_string()) {
                exec.allow.push(path.to_string());
            }
        }

        // Update exec BPF maps: remove from deny + add to allow (including symlink alternates).
        if let Some(ref mut policy_maps) = state.policy_maps {
            apply_exec_grant_to_maps(policy_maps, path, is_prefix);
        }

        state.grants.push(TemporaryGrant {
            agent_name: agent_name.to_string(),
            path: path.to_string(),
            is_prefix,
            grant_type: GrantType::Exec,
            expires_at,
        });

        info!(
            "Temporary exec grant: agent='{}' command='{}' duration={}s",
            agent_name, path, duration_secs
        );
    } else {
        // File access grant: add to BPF allow maps for kernel-side enforcement
        if let Some(ref mut policy_maps) = state.policy_maps {
            if is_prefix {
                let prefix = strip_glob_to_prefix(path);
                let key = path_to_lpm_key(prefix.as_bytes());
                if let Err(e) = policy_maps.allow_prefixes.insert(&key, 1, 0) {
                    warn!("Failed to add temporary allow prefix for '{}': {}", path, e);
                }
            } else {
                let key = path_to_map_key(path.as_bytes());
                if let Err(e) = policy_maps.allow_exact.insert(key, 1, 0) {
                    warn!("Failed to add temporary allow exact for '{}': {}", path, e);
                }
            }
        }

        state.grants.push(TemporaryGrant {
            agent_name: agent_name.to_string(),
            path: path.to_string(),
            is_prefix,
            grant_type: GrantType::FileAccess,
            expires_at,
        });

        info!(
            "Temporary file grant: agent='{}' path='{}' duration={}s",
            agent_name, path, duration_secs
        );
    }

    IpcResponse::Ack { sandbox: None }
}

// =============================================================================
// Permission Request Handler
// =============================================================================

async fn handle_request_permission(
    state: &SharedIpcState,
    agent_name: String,
    resource_type: String,
    resource_path: String,
    justification: Option<String>,
) -> IpcResponse {
    let (tx, rx) = oneshot::channel::<PermissionDecision>();
    let request_id;
    let timeout_secs;

    {
        let mut s = state.lock().await;

        // Verify agent exists
        let agent_exists = s.agents.contains_key(&agent_name)
            || s.config.agents.iter().any(|a| a.name == agent_name);
        if !agent_exists {
            return IpcResponse::Error {
                message: format!("Agent '{}' not found", agent_name),
            };
        }

        // Check if dashboard/permission bus is available
        if s.permission_bus.is_none() {
            return IpcResponse::PermissionDecision {
                approved: false,
                reason: "Dashboard not enabled — no one to approve requests".to_string(),
                grant_duration_secs: None,
            };
        }

        // --- Phase 7c: Permission Hardening ---

        // Clone permissions config to avoid holding immutable borrow while mutating rate_limits.
        // This is a small struct; the alternative (restructuring IpcState) would be too invasive.
        let perm_config = s.config.permissions.clone().unwrap_or_else(|| {
            crate::config::PermissionsConfig {
                auto_deny: vec![],
                auto_approve: vec![],
                rate_limit_per_minute: 3,
                rate_limit_per_hour: 15,
                deny_cooldown_secs: 30,
                max_pending_per_agent: 2,
                timeouts: None,
                max_grant_total_secs: 3600,
            }
        });

        // Count pending before mutable borrow on rate_limits
        let pending_count = s.pending_permissions.iter()
            .filter(|p| p.agent_name == agent_name)
            .count() as u32;

        // Check max pending per agent
        if pending_count >= perm_config.max_pending_per_agent {
            return IpcResponse::PermissionDecision {
                approved: false,
                reason: format!(
                    "Too many pending requests ({}/{}). Wait for existing requests to resolve.",
                    pending_count, perm_config.max_pending_per_agent
                ),
                grant_duration_secs: None,
            };
        }

        // Check auto-deny (doesn't need rate limiter)
        if permissions::check_auto_deny(&perm_config, &resource_path) {
            let rate_limit = s.rate_limits
                .entry(agent_name.clone())
                .or_insert_with(AgentRateLimit::new);
            rate_limit.record_request();
            rate_limit.record_denial(&resource_path);
            let reason = "Auto-denied: resource is on the never-approve list".to_string();
            info!(
                "Permission auto-denied: agent='{}' path='{}' (auto-deny rule)",
                agent_name, resource_path
            );
            // Persist to audit trail
            if let Some(ref db) = s.event_db {
                let now = chrono::Utc::now().to_rfc3339();
                if let Err(e) = db.insert_permission_audit(
                    s.next_permission_id, &agent_name, &resource_type, &resource_path,
                    justification.as_deref(), "critical", &[], &now, &now, false, &reason, None,
                ) {
                    warn!("Failed to persist permission audit: {}", e);
                }
                s.next_permission_id += 1;
            }
            return IpcResponse::PermissionDecision {
                approved: false,
                reason,
                grant_duration_secs: None,
            };
        }

        // Check auto-approve (doesn't need rate limiter)
        if let Some(max_duration) = permissions::check_auto_approve(&perm_config, &resource_path) {
            let rate_limit = s.rate_limits
                .entry(agent_name.clone())
                .or_insert_with(AgentRateLimit::new);
            rate_limit.record_request();
            rate_limit.record_approval();
            let reason = "Auto-approved: low-risk resource".to_string();
            info!(
                "Permission auto-approved: agent='{}' path='{}' duration={}s",
                agent_name, resource_path, max_duration
            );
            // Persist to audit trail
            if let Some(ref db) = s.event_db {
                let now = chrono::Utc::now().to_rfc3339();
                if let Err(e) = db.insert_permission_audit(
                    s.next_permission_id, &agent_name, &resource_type, &resource_path,
                    justification.as_deref(), "low", &[], &now, &now, true, &reason, Some(max_duration),
                ) {
                    warn!("Failed to persist permission audit: {}", e);
                }
                s.next_permission_id += 1;
            }
            return IpcResponse::PermissionDecision {
                approved: true,
                reason,
                grant_duration_secs: Some(max_duration),
            };
        }

        // Get or create rate limiter for this agent
        let rate_limit = s.rate_limits
            .entry(agent_name.clone())
            .or_insert_with(AgentRateLimit::new);

        // Check rate limit
        if let Some(reason) = rate_limit.check(&perm_config, &resource_path) {
            let full_reason = format!("Rate limited: {}", reason);
            info!(
                "Permission request rate-limited: agent='{}' path='{}' reason='{}'",
                agent_name, resource_path, reason
            );
            // Persist to audit trail
            if let Some(ref db) = s.event_db {
                let now = chrono::Utc::now().to_rfc3339();
                if let Err(e) = db.insert_permission_audit(
                    s.next_permission_id, &agent_name, &resource_type, &resource_path,
                    justification.as_deref(), "medium", &[], &now, &now, false, &full_reason, None,
                ) {
                    warn!("Failed to persist permission audit: {}", e);
                }
                s.next_permission_id += 1;
            }
            return IpcResponse::PermissionDecision {
                approved: false,
                reason: full_reason,
                grant_duration_secs: None,
            };
        }

        // Classify risk
        let (mut risk_level, risk_flags) =
            permissions::classify_risk(&resource_type, &resource_path, rate_limit);

        // Analyze justification
        let (justification_flags, justification_score) = justification.as_deref()
            .map(permissions::analyze_justification)
            .unwrap_or_default();

        let justification_warnings: Vec<String> = justification_flags.iter()
            .map(|(cat, matched)| format!("{}: \"{}\"", cat, matched))
            .collect();

        // Bump risk level if suspicious justification (graduated: score >= 8 -> +2, >= 3 -> +1)
        let bumps = permissions::justification_risk_bump(&justification_flags, justification_score);
        for _ in 0..bumps {
            risk_level = match risk_level {
                RiskLevel::Low => RiskLevel::Medium,
                RiskLevel::Medium => RiskLevel::High,
                RiskLevel::High => RiskLevel::Critical,
                RiskLevel::Critical => RiskLevel::Critical,
            };
        }

        rate_limit.record_request();

        // Assign ID and store pending request
        request_id = s.next_permission_id;
        s.next_permission_id += 1;
        // Phase 8 Fix 10: Risk-based configurable timeouts
        let timeout_config = s.config.permissions.as_ref().and_then(|p| p.timeouts.as_ref());
        timeout_secs = risk_level.timeout_secs(timeout_config);

        let now_utc = chrono::Utc::now();

        s.pending_permissions.push(PendingPermission {
            id: request_id,
            agent_name: agent_name.clone(),
            resource_type: resource_type.clone(),
            resource_path: resource_path.clone(),
            justification: justification.clone(),
            requested_at: Instant::now(),
            requested_at_utc: now_utc,
            timeout_secs,
            responder: Some(tx),
            risk_level,
            risk_flags: risk_flags.clone(),
            justification_flags: justification_flags.clone(),
        });

        // Broadcast to dashboard
        if let Some(ref bus) = s.permission_bus {
            if let Err(e) = bus.send(PermissionEvent {
                id: request_id,
                kind: "request".to_string(),
                agent_name: agent_name.clone(),
                resource_type: resource_type.clone(),
                resource_path: resource_path.clone(),
                justification: justification.clone(),
                timeout_secs,
                requested_at: now_utc.to_rfc3339(),
                approved: None,
                reason: None,
                risk_level: Some(risk_level.as_str().to_string()),
                risk_flags: risk_flags.clone(),
                wait_seconds: Some(risk_level.wait_seconds()),
                requires_type_confirm: Some(risk_level.requires_type_confirm()),
                justification_warnings: justification_warnings.clone(),
            }) {
                debug!("No SSE subscribers for permission event: {}", e);
            }
        }

        info!(
            "Permission request #{}: agent='{}' type='{}' path='{}' risk={} flags={:?}",
            request_id, agent_name, resource_type, resource_path, risk_level, risk_flags
        );
    } // Lock released — agent now blocks waiting for human decision

    // Wait for approval/denial with timeout
    match tokio::time::timeout(Duration::from_secs(timeout_secs), rx).await {
        Ok(Ok(decision)) => {
            // Record approval/denial in rate limiter
            {
                let mut s = state.lock().await;
                let rate_limit = s.rate_limits
                    .entry(agent_name.clone())
                    .or_insert_with(AgentRateLimit::new);
                if decision.approved {
                    rate_limit.record_approval();
                } else {
                    rate_limit.record_denial(&resource_path);
                }
            }

            info!(
                "Permission #{} resolved: approved={} reason='{}'",
                request_id, decision.approved, decision.reason
            );
            IpcResponse::PermissionDecision {
                approved: decision.approved,
                reason: decision.reason,
                grant_duration_secs: decision.grant_duration_secs,
            }
        }
        _ => {
            // Timeout or channel closed (sender dropped)
            info!(
                "Permission #{} timed out after {}s — auto-denied",
                request_id, timeout_secs
            );

            let mut s = state.lock().await;

            // Record timeout as denial
            let rate_limit = s.rate_limits
                .entry(agent_name.clone())
                .or_insert_with(AgentRateLimit::new);
            rate_limit.record_denial(&resource_path);

            // Clean up pending and record as resolved
            if let Some(pos) = s.pending_permissions.iter().position(|p| p.id == request_id) {
                let pending = s.pending_permissions.remove(pos);
                let requested_at_str = pending.requested_at_utc.to_rfc3339();
                let resolved_at_str = chrono::Utc::now().to_rfc3339();
                let timeout_reason = "Timed out".to_string();
                // Persist to SQLite audit trail
                if let Some(ref db) = s.event_db {
                    if let Err(e) = db.insert_permission_audit(
                        pending.id, &pending.agent_name, &pending.resource_type,
                        &pending.resource_path, pending.justification.as_deref(),
                        pending.risk_level.as_str(), &pending.risk_flags,
                        &requested_at_str, &resolved_at_str, false, &timeout_reason, None,
                    ) {
                        warn!("Failed to persist permission audit: {}", e);
                    }
                }
                s.resolved_permissions.push_back(ResolvedPermission {
                    id: pending.id,
                    agent_name: pending.agent_name.clone(),
                    resource_type: pending.resource_type.clone(),
                    resource_path: pending.resource_path.clone(),
                    justification: pending.justification.clone(),
                    risk_level: pending.risk_level.as_str().to_string(),
                    risk_flags: pending.risk_flags.clone(),
                    requested_at: requested_at_str,
                    resolved_at: resolved_at_str,
                    approved: false,
                    reason: timeout_reason,
                    grant_duration_secs: None,
                });
                while s.resolved_permissions.len() > MAX_RESOLVED_HISTORY {
                    s.resolved_permissions.pop_front();
                }
            }

            // Broadcast resolution
            if let Some(ref bus) = s.permission_bus {
                if let Err(e) = bus.send(PermissionEvent {
                    id: request_id,
                    kind: "resolved".to_string(),
                    agent_name,
                    resource_type,
                    resource_path,
                    justification,
                    timeout_secs,
                    requested_at: String::new(),
                    approved: Some(false),
                    reason: Some("Timed out".to_string()),
                    risk_level: None,
                    risk_flags: vec![],
                    wait_seconds: None,
                    requires_type_confirm: None,
                    justification_warnings: vec![],
                }) {
                    debug!("No SSE subscribers for permission resolution: {}", e);
                }
            }

            IpcResponse::PermissionDecision {
                approved: false,
                reason: format!(
                    "Request timed out (no response within {} seconds)",
                    timeout_secs
                ),
                grant_duration_secs: None,
            }
        }
    }
}

/// Resolve a pending permission request (called from dashboard API).
/// Returns Ok(()) if resolved, Err(msg) if not found.
/// Generate symlink alternate paths for merged-usr systems.
/// E.g., /usr/bin/curl → /bin/curl, /usr/sbin/curl, /sbin/curl
fn exec_symlink_alternates(path: &str) -> Vec<String> {
    let mut results = Vec::new();
    let binary_name = match path.rsplit_once('/') {
        Some((_, name)) => name,
        None => return results,
    };
    let bin_dirs = ["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/local/bin/"];
    let is_bin = bin_dirs.iter().any(|d| path.starts_with(d));
    if is_bin {
        for dir in &bin_dirs {
            let candidate = format!("{}{}", dir, binary_name);
            if candidate != path && std::path::Path::new(&candidate).exists() {
                results.push(candidate);
            }
        }
    }
    results
}

/// Remove an exec path (and its symlink alternates) from deny maps,
/// and add to allow maps. Used by exec grants.
fn apply_exec_grant_to_maps(policy_maps: &mut PolicyBpfMaps, path: &str, is_prefix: bool) {
    let mut paths = vec![path.to_string()];
    if !is_prefix {
        paths.extend(exec_symlink_alternates(path));
    }
    for p in &paths {
        if is_prefix {
            let prefix = strip_glob_to_prefix(p);
            let key = path_to_lpm_key(prefix.as_bytes());
            let _ = policy_maps.exec_deny_prefixes.remove(&key);
            let _ = policy_maps.exec_allow_prefixes.insert(&key, 1, 0);
        } else {
            let key = path_to_map_key(p.as_bytes());
            let _ = policy_maps.exec_deny_exact.remove(&key);
            let _ = policy_maps.exec_allow_exact.insert(key, 1, 0);
        }
    }
}

/// Re-add an exec path (and its symlink alternates) to deny maps,
/// and remove from allow maps. Used when exec grants expire.
fn revoke_exec_grant_from_maps(policy_maps: &mut PolicyBpfMaps, path: &str, is_prefix: bool) {
    let mut paths = vec![path.to_string()];
    if !is_prefix {
        paths.extend(exec_symlink_alternates(path));
    }
    for p in &paths {
        if is_prefix {
            let prefix = strip_glob_to_prefix(p);
            let key = path_to_lpm_key(prefix.as_bytes());
            let _ = policy_maps.exec_allow_prefixes.remove(&key);
            let _ = policy_maps.exec_deny_prefixes.insert(&key, 1, 0);
        } else {
            let key = path_to_map_key(p.as_bytes());
            let _ = policy_maps.exec_allow_exact.remove(&key);
            let _ = policy_maps.exec_deny_exact.insert(key, 1, 0);
        }
    }
}

pub async fn resolve_permission(
    state: &SharedIpcState,
    permission_id: u64,
    approved: bool,
    reason: String,
    grant_duration_secs: Option<u64>,
) -> std::result::Result<(), String> {
    let mut s = state.lock().await;

    let pos = s
        .pending_permissions
        .iter()
        .position(|p| p.id == permission_id)
        .ok_or_else(|| format!("Permission request #{} not found or already resolved", permission_id))?;

    let mut pending = s.pending_permissions.remove(pos);

    // Phase 10 fix: Check grant accumulation limits BEFORE sending the decision.
    // If the limit is exceeded, override the approval to a denial.
    let (approved, reason, grant_duration_secs) = if approved {
        if let Some(duration) = grant_duration_secs {
            let max_total = s.config.permissions.as_ref()
                .map(|p| p.max_grant_total_secs)
                .unwrap_or(3600);
            let accumulated = s.grant_accumulator.record_and_check(
                &pending.agent_name,
                &pending.resource_path,
                duration,
            );
            if accumulated > max_total {
                warn!(
                    "Permission #{} grant accumulation exceeded: agent='{}' resource='{}' total={}s > limit={}s — overriding to DENY",
                    permission_id, pending.agent_name, pending.resource_path, accumulated, max_total
                );
                (false, "Grant accumulation limit exceeded".to_string(), None)
            } else {
                (approved, reason, grant_duration_secs)
            }
        } else {
            (approved, reason, grant_duration_secs)
        }
    } else {
        (approved, reason, grant_duration_secs)
    };

    // Send decision to the waiting agent via oneshot
    if let Some(responder) = pending.responder.take() {
        let _ = responder.send(PermissionDecision {
            approved,
            reason: reason.clone(),
            grant_duration_secs,
        });
    }

    // If approved, create a temporary grant
    if approved {
        if let Some(duration) = grant_duration_secs {

            let expires_at = Instant::now() + Duration::from_secs(duration);
            let is_prefix = pending.resource_path.ends_with("/**");

            if pending.resource_type == "exec" {
                // Add to agent's exec policy allow list
                if let Some(agent_cfg) = s.config.agents.iter_mut().find(|a| a.name == pending.agent_name) {
                    let exec = agent_cfg.exec_policy.get_or_insert(crate::config::ExecPolicy {
                        default: "deny".to_string(),
                        allow: vec![],
                        deny: vec![],
                    });
                    if !exec.allow.contains(&pending.resource_path) {
                        exec.allow.push(pending.resource_path.clone());
                    }
                }
                // Update exec BPF maps: remove from deny + add to allow (including symlink alternates).
                if let Some(ref mut policy_maps) = s.policy_maps {
                    apply_exec_grant_to_maps(policy_maps, &pending.resource_path, is_prefix);
                }
                s.grants.push(TemporaryGrant {
                    agent_name: pending.agent_name.clone(),
                    path: pending.resource_path.clone(),
                    is_prefix,
                    grant_type: GrantType::Exec,
                    expires_at,
                });
            } else {
                // File access — add to BPF allow maps
                if let Some(ref mut policy_maps) = s.policy_maps {
                    if is_prefix {
                        let prefix = strip_glob_to_prefix(&pending.resource_path);
                        let key = path_to_lpm_key(prefix.as_bytes());
                        if let Err(e) = policy_maps.allow_prefixes.insert(&key, 1, 0) {
                            warn!("Failed to add allow prefix for '{}': {}", pending.resource_path, e);
                        }
                    } else {
                        let key = path_to_map_key(pending.resource_path.as_bytes());
                        if let Err(e) = policy_maps.allow_exact.insert(key, 1, 0) {
                            warn!("Failed to add allow exact for '{}': {}", pending.resource_path, e);
                        }
                    }
                }
                s.grants.push(TemporaryGrant {
                    agent_name: pending.agent_name.clone(),
                    path: pending.resource_path.clone(),
                    is_prefix,
                    grant_type: GrantType::FileAccess,
                    expires_at,
                });
            }

            info!(
                "Permission #{} approved: agent='{}' {}='{}' for {}s",
                permission_id, pending.agent_name, pending.resource_type,
                pending.resource_path, duration
            );
        }
    } else {
        info!(
            "Permission #{} denied: agent='{}' {}='{}' reason='{}'",
            permission_id, pending.agent_name, pending.resource_type,
            pending.resource_path, reason
        );
    }

    // Update rate limiter
    {
        let rate_limit = s.rate_limits
            .entry(pending.agent_name.clone())
            .or_insert_with(AgentRateLimit::new);
        if approved {
            rate_limit.record_approval();
        } else {
            rate_limit.record_denial(&pending.resource_path);
        }
    }

    // Record in resolved history
    let resolved_at_str = chrono::Utc::now().to_rfc3339();
    let requested_at_str = pending.requested_at_utc.to_rfc3339();
    let resolved = ResolvedPermission {
        id: pending.id,
        agent_name: pending.agent_name.clone(),
        resource_type: pending.resource_type.clone(),
        resource_path: pending.resource_path.clone(),
        justification: pending.justification.clone(),
        risk_level: pending.risk_level.as_str().to_string(),
        risk_flags: pending.risk_flags.clone(),
        requested_at: requested_at_str.clone(),
        resolved_at: resolved_at_str.clone(),
        approved,
        reason: reason.clone(),
        grant_duration_secs,
    };
    s.resolved_permissions.push_back(resolved);
    while s.resolved_permissions.len() > MAX_RESOLVED_HISTORY {
        s.resolved_permissions.pop_front();
    }

    // Persist to SQLite audit trail
    if let Some(ref db) = s.event_db {
        if let Err(e) = db.insert_permission_audit(
            pending.id,
            &pending.agent_name,
            &pending.resource_type,
            &pending.resource_path,
            pending.justification.as_deref(),
            pending.risk_level.as_str(),
            &pending.risk_flags,
            &requested_at_str,
            &resolved_at_str,
            approved,
            &reason,
            grant_duration_secs,
        ) {
            warn!("Failed to persist permission audit: {}", e);
        }
    }

    // Broadcast resolution
    if let Some(ref bus) = s.permission_bus {
        if let Err(e) = bus.send(PermissionEvent {
            id: permission_id,
            kind: "resolved".to_string(),
            agent_name: pending.agent_name,
            resource_type: pending.resource_type,
            resource_path: pending.resource_path,
            justification: pending.justification,
            timeout_secs: pending.timeout_secs,
            requested_at: pending.requested_at_utc.to_rfc3339(),
            approved: Some(approved),
            reason: Some(reason),
            risk_level: None,
            risk_flags: vec![],
            wait_seconds: None,
            requires_type_confirm: None,
            justification_warnings: vec![],
        }) {
            debug!("No SSE subscribers for permission resolution: {}", e);
        }
    }

    Ok(())
}

// =============================================================================
// Phase 8: CLI Permission Management Handlers
// =============================================================================

async fn handle_list_pending(state: &SharedIpcState) -> IpcResponse {
    let s = state.lock().await;
    let requests: Vec<PendingPermissionInfo> = s
        .pending_permissions
        .iter()
        .map(|p| PendingPermissionInfo {
            request_id: p.id,
            agent_name: p.agent_name.clone(),
            resource_type: p.resource_type.clone(),
            resource_path: p.resource_path.clone(),
            justification: p.justification.clone(),
            risk_level: p.risk_level.as_str().to_string(),
            elapsed_secs: p.requested_at.elapsed().as_secs(),
        })
        .collect();
    IpcResponse::PendingPermissions { requests }
}

async fn handle_approve_permission(
    state: &SharedIpcState,
    request_id: u64,
    duration_secs: u64,
) -> IpcResponse {
    let reason = "Approved via CLI".to_string();
    match resolve_permission(state, request_id, true, reason, Some(duration_secs)).await {
        Ok(()) => IpcResponse::Ack { sandbox: None },
        Err(msg) => IpcResponse::Error { message: msg },
    }
}

async fn handle_deny_permission(
    state: &SharedIpcState,
    request_id: u64,
    reason: Option<String>,
) -> IpcResponse {
    let reason = reason.unwrap_or_else(|| "Denied via CLI".to_string());
    match resolve_permission(state, request_id, false, reason, None).await {
        Ok(()) => IpcResponse::Ack { sandbox: None },
        Err(msg) => IpcResponse::Error { message: msg },
    }
}

// =============================================================================
// Cgroup Lifecycle Management
// =============================================================================

/// Periodically clean up empty cgroups and expired grants.
pub async fn cgroup_cleanup_task(state: SharedIpcState) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));

    loop {
        interval.tick().await;

        let mut state = state.lock().await;

        // Find agents with empty cgroups
        let empty_agents: Vec<String> = state
            .agents
            .iter()
            .filter(|(_, agent)| {
                let procs = count_cgroup_processes(&agent.cgroup_path);
                procs == 0
            })
            .map(|(name, _)| name.clone())
            .collect();

        for name in empty_agents {
            info!("Agent '{}' cgroup is empty — cleaning up", name);
            cleanup_agent(&mut state, &name);
        }

        // Expire temporary grants
        let now = Instant::now();
        let expired: Vec<usize> = state
            .grants
            .iter()
            .enumerate()
            .filter(|(_, g)| now >= g.expires_at)
            .map(|(i, _)| i)
            .collect();

        for &idx in expired.iter().rev() {
            let grant = state.grants.remove(idx);

            match grant.grant_type {
                GrantType::FileAccess => {
                    // Remove from BPF maps
                    if let Some(ref mut policy_maps) = state.policy_maps {
                        if grant.is_prefix {
                            let prefix = strip_glob_to_prefix(&grant.path);
                            let key = path_to_lpm_key(prefix.as_bytes());
                            if let Err(e) = policy_maps.allow_prefixes.remove(&key) {
                                warn!("Failed to remove expired allow prefix for '{}': {}", grant.path, e);
                            }
                        } else {
                            let key = path_to_map_key(grant.path.as_bytes());
                            if let Err(e) = policy_maps.allow_exact.remove(&key) {
                                warn!("Failed to remove expired allow exact for '{}': {}", grant.path, e);
                            }
                        }
                    }
                    info!(
                        "Temporary grant expired: agent='{}' file path='{}'",
                        grant.agent_name, grant.path
                    );
                }
                GrantType::Exec => {
                    // Remove from agent's exec policy allow list
                    if let Some(agent_cfg) = state.config.agents.iter_mut().find(|a| a.name == grant.agent_name) {
                        if let Some(ref mut exec) = agent_cfg.exec_policy {
                            exec.allow.retain(|r| r != &grant.path);
                        }
                    }
                    info!(
                        "Temporary grant expired: agent='{}' exec command='{}'",
                        grant.agent_name, grant.path
                    );
                }
            }
        }
    }
}

/// Clean up a single agent from BPF maps, cgroup directory, and state.
fn cleanup_agent(state: &mut IpcState, agent_name: &str) {
    if let Some(agent) = state.agents.remove(agent_name) {
        // Remove from BPF maps
        let _ = state.cgroup_maps.watched_cgroups.remove(&agent.cgroup_id);
        let _ = state.cgroup_maps.enforce_cgroups.remove(&agent.cgroup_id);
        let _ = state
            .cgroup_maps
            .cgroup_default_action
            .remove(&agent.cgroup_id);

        // Remove cgroup directory
        let cgroup_dir = format!("/sys/fs/cgroup/{}", agent.cgroup_path);
        if let Err(e) = std::fs::remove_dir(&cgroup_dir) {
            debug!("Failed to remove cgroup dir '{}': {}", cgroup_dir, e);
        }

        info!(
            "Agent '{}' cleaned up (cgroup={}, uptime={}s)",
            agent_name,
            agent.cgroup_path,
            agent.registered_at.elapsed().as_secs()
        );
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Count processes in a cgroup by reading cgroup.procs.
fn count_cgroup_processes(cgroup_path: &str) -> u32 {
    let procs_path = format!("/sys/fs/cgroup/{}/cgroup.procs", cgroup_path);
    match std::fs::read_to_string(&procs_path) {
        Ok(content) => content.lines().filter(|l| !l.trim().is_empty()).count() as u32,
        Err(_) => 0,
    }
}

/// Strip glob suffix ("/**") from a path and append "/" for prefix matching.
/// Returns the path unchanged if it doesn't end with "/**".
fn strip_glob_to_prefix(path: &str) -> String {
    path.strip_suffix("/**")
        .unwrap_or(path)
        .to_string()
        + "/"
}

fn path_to_lpm_key(path: &[u8]) -> Key<[u8; MAX_FILENAME_LEN]> {
    let mut data = [0u8; MAX_FILENAME_LEN];
    let len = core::cmp::min(path.len(), MAX_FILENAME_LEN);
    data[..len].copy_from_slice(&path[..len]);
    Key::new((len as u32) * 8, data)
}

fn path_to_map_key(path: &[u8]) -> [u8; MAX_FILENAME_LEN] {
    let mut key = [0u8; MAX_FILENAME_LEN];
    let len = core::cmp::min(path.len(), MAX_FILENAME_LEN);
    key[..len].copy_from_slice(&path[..len]);
    key
}

// Public wrappers for dashboard API access
pub fn cleanup_agent_pub(state: &mut IpcState, agent_name: &str) {
    cleanup_agent(state, agent_name);
}

pub fn path_to_lpm_key_pub(path: &[u8]) -> Key<[u8; MAX_FILENAME_LEN]> {
    path_to_lpm_key(path)
}

pub fn path_to_map_key_pub(path: &[u8]) -> [u8; MAX_FILENAME_LEN] {
    path_to_map_key(path)
}
