use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::maps::{lpm_trie::Key, lpm_trie::LpmTrie, HashMap as BpfHashMap, MapData};
use guardian_common::ipc::{AgentStatus, IpcRequest, IpcResponse};
use guardian_common::MAX_FILENAME_LEN;
use log::{debug, error, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

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

/// A temporary access grant with an expiry time.
#[derive(Debug, Clone)]
pub struct TemporaryGrant {
    pub agent_name: String,
    pub path: String,
    pub is_prefix: bool,
    pub expires_at: Instant,
}

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
        } => handle_grant_access(state, &agent_name, &path, duration_secs).await,
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

    // Add to BPF allow maps for kernel-side enforcement
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

    // Store the grant for expiry tracking
    state.grants.push(TemporaryGrant {
        agent_name: agent_name.to_string(),
        path: path.to_string(),
        is_prefix,
        expires_at,
    });

    info!(
        "Temporary grant: agent='{}' path='{}' duration={}s",
        agent_name, path, duration_secs
    );

    IpcResponse::Ack
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
                "Temporary grant expired: agent='{}' path='{}'",
                grant.agent_name, grant.path
            );
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
