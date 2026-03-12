use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::maps::{lpm_trie::Key, lpm_trie::LpmTrie, HashMap as BpfHashMap, MapData};
use guardian_common::ipc::{AgentStatus, IpcRequest, IpcResponse};
use guardian_common::MAX_FILENAME_LEN;
use log::{debug, error, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, Mutex, oneshot};

use crate::config::Config;

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
}

/// A resolved (completed) permission request, kept for audit trail.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedPermission {
    pub id: u64,
    pub agent_name: String,
    pub resource_type: String,
    pub resource_path: String,
    pub justification: Option<String>,
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
}

/// Default timeout for permission requests (seconds).
pub const PERMISSION_TIMEOUT_SECS: u64 = 120;
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
}

/// All shared IPC state.
pub struct IpcState {
    pub agents: HashMap<String, RegisteredAgent>,
    pub grants: Vec<TemporaryGrant>,
    pub cgroup_maps: CgroupBpfMaps,
    pub policy_maps: Option<PolicyBpfMaps>,
    pub config: Config,
    pub enforce_mode: bool,
    // Permission request state
    pub pending_permissions: Vec<PendingPermission>,
    pub resolved_permissions: VecDeque<ResolvedPermission>,
    pub next_permission_id: u64,
    pub permission_bus: Option<broadcast::Sender<PermissionEvent>>,
}

pub type SharedIpcState = Arc<Mutex<IpcState>>;

// =============================================================================
// IPC Server
// =============================================================================

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

    // Make socket accessible (guardian-launch may run as a different user initially,
    // but it must have been started with sufficient permissions)
    let _ = std::fs::set_permissions(
        socket_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o660),
    );

    info!("IPC server listening on {}", socket_path);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, state).await {
                        warn!("IPC connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("IPC accept error: {}", e);
            }
        }
    }
}

/// Handle a single IPC connection.
async fn handle_connection(mut stream: UnixStream, state: SharedIpcState) -> Result<()> {
    // Read length-prefixed message
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 1024 * 1024 {
        return Err(anyhow::anyhow!("IPC message too large: {} bytes", len));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    let request: IpcRequest = serde_json::from_slice(&buf)
        .context("Failed to parse IPC request")?;

    debug!("IPC request: {:?}", request);

    let response = process_request(request, &state).await;

    // Send response
    let resp_json = serde_json::to_vec(&response)?;
    let resp_len = (resp_json.len() as u32).to_be_bytes();
    stream.write_all(&resp_len).await?;
    stream.write_all(&resp_json).await?;
    stream.flush().await?;

    Ok(())
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

    // Find matching agent config
    let agent_config = state.config.agents.iter().find(|a| a.name == agent_name);
    if agent_config.is_none() {
        return IpcResponse::Error {
            message: format!(
                "No agent config found for '{}'. Add it to config.toml.",
                agent_name
            ),
        };
    }
    let agent_config = agent_config.unwrap().clone();

    // Insert into WATCHED_CGROUPS BPF map
    if let Err(e) = state.cgroup_maps.watched_cgroups.insert(cgroup_id, 1, 0) {
        return IpcResponse::Error {
            message: format!("Failed to update WATCHED_CGROUPS map: {}", e),
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

    // Store registration
    let agent = RegisteredAgent {
        name: agent_name.clone(),
        cgroup_path: cgroup_path.clone(),
        cgroup_id,
        registered_at: Instant::now(),
    };
    state.agents.insert(agent_name.clone(), agent);

    info!(
        "Agent '{}' registered: cgroup={}, id={}",
        agent_name, cgroup_path, cgroup_id
    );

    IpcResponse::Ack
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

    IpcResponse::Ack
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
                let prefix = format!("{}/", &path[..path.len() - 3]);
                let key = path_to_lpm_key(prefix.as_bytes());
                if let Err(e) = policy_maps.allow_prefixes.insert(&key, 1, 0) {
                    warn!("Failed to add temporary allow prefix: {}", e);
                }
            } else {
                let key = path_to_map_key(path.as_bytes());
                if let Err(e) = policy_maps.allow_exact.insert(key, 1, 0) {
                    warn!("Failed to add temporary allow exact: {}", e);
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

    IpcResponse::Ack
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

        // Assign ID and store pending request
        request_id = s.next_permission_id;
        s.next_permission_id += 1;
        timeout_secs = PERMISSION_TIMEOUT_SECS;

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
        });

        // Broadcast to dashboard
        if let Some(ref bus) = s.permission_bus {
            let _ = bus.send(PermissionEvent {
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
            });
        }

        info!(
            "Permission request #{}: agent='{}' type='{}' path='{}' justification={:?}",
            request_id, agent_name, resource_type, resource_path, justification
        );
    } // Lock released — agent now blocks waiting for human decision

    // Wait for approval/denial with timeout
    match tokio::time::timeout(Duration::from_secs(timeout_secs), rx).await {
        Ok(Ok(decision)) => {
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

            // Clean up pending and record as resolved
            if let Some(pos) = s.pending_permissions.iter().position(|p| p.id == request_id) {
                let pending = s.pending_permissions.remove(pos);
                s.resolved_permissions.push_back(ResolvedPermission {
                    id: pending.id,
                    agent_name: pending.agent_name.clone(),
                    resource_type: pending.resource_type.clone(),
                    resource_path: pending.resource_path.clone(),
                    justification: pending.justification.clone(),
                    requested_at: pending.requested_at_utc.to_rfc3339(),
                    resolved_at: chrono::Utc::now().to_rfc3339(),
                    approved: false,
                    reason: "Timed out".to_string(),
                    grant_duration_secs: None,
                });
                while s.resolved_permissions.len() > MAX_RESOLVED_HISTORY {
                    s.resolved_permissions.pop_front();
                }
            }

            // Broadcast resolution
            if let Some(ref bus) = s.permission_bus {
                let _ = bus.send(PermissionEvent {
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
                });
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
                        let prefix = format!("{}/", &pending.resource_path[..pending.resource_path.len() - 3]);
                        let key = path_to_lpm_key(prefix.as_bytes());
                        let _ = policy_maps.allow_prefixes.insert(&key, 1, 0);
                    } else {
                        let key = path_to_map_key(pending.resource_path.as_bytes());
                        let _ = policy_maps.allow_exact.insert(key, 1, 0);
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

    // Record in resolved history
    let resolved = ResolvedPermission {
        id: pending.id,
        agent_name: pending.agent_name.clone(),
        resource_type: pending.resource_type.clone(),
        resource_path: pending.resource_path.clone(),
        justification: pending.justification.clone(),
        requested_at: pending.requested_at_utc.to_rfc3339(),
        resolved_at: chrono::Utc::now().to_rfc3339(),
        approved,
        reason: reason.clone(),
        grant_duration_secs,
    };
    s.resolved_permissions.push_back(resolved);
    while s.resolved_permissions.len() > MAX_RESOLVED_HISTORY {
        s.resolved_permissions.pop_front();
    }

    // Broadcast resolution
    if let Some(ref bus) = s.permission_bus {
        let _ = bus.send(PermissionEvent {
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
        });
    }

    Ok(())
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
                            let prefix = format!("{}/", &grant.path[..grant.path.len() - 3]);
                            let key = path_to_lpm_key(prefix.as_bytes());
                            let _ = policy_maps.allow_prefixes.remove(&key);
                        } else {
                            let key = path_to_map_key(grant.path.as_bytes());
                            let _ = policy_maps.allow_exact.remove(&key);
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

/// Get the cgroup ID (inode number) for a cgroup path.
#[allow(dead_code)]
pub fn get_cgroup_id(cgroup_path: &str) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let full_path = format!("/sys/fs/cgroup/{}", cgroup_path);
    let metadata = std::fs::metadata(&full_path)
        .with_context(|| format!("Failed to stat cgroup '{}'", full_path))?;
    Ok(metadata.ino())
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
