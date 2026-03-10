mod alerting;
mod config;
mod dashboard;
mod ipc;

use anyhow::{Context, Result};
use aya::{
    maps::{AsyncPerfEventArray, HashMap, MapData, lpm_trie::{LpmTrie, Key}},
    programs::{Lsm, TracePoint},
    util::online_cpus,
    Btf, Ebpf,
};
use bytes::BytesMut;
use clap::Parser;
use guardian_common::{ExecEvent, FileAccessEvent, MAX_FILENAME_LEN};
use log::{debug, error, info, warn};
use std::collections;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::{signal, sync::Mutex, sync::broadcast, time};

use crate::alerting::{Action, AlertEvent, AlertSender, EventType, Severity};
use crate::config::{check_exec_policy, check_file_policy, Config};
use crate::ipc::{CgroupBpfMaps, IpcState, PolicyBpfMaps, SharedIpcState};

// =============================================================================
// Command-Line Arguments
// =============================================================================

#[derive(Parser, Debug)]
#[command(name = "guardian", version, about = "Guardian Shell - Security monitor for LLM agents using eBPF")]
struct Args {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    #[arg(
        long,
        default_value = "target/bpfel-unknown-none/release/guardian-ebpf"
    )]
    ebpf_program: PathBuf,

    /// Validate configuration and exit without starting the daemon.
    #[arg(long)]
    validate_config: bool,
}

// =============================================================================
// Shared BPF Map Handle (for PID rescan)
// =============================================================================

type SharedBpfMap = Arc<std::sync::Mutex<HashMap<MapData, u32, u8>>>;

// =============================================================================
// Main Entry Point
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    // Step 1: Load Configuration
    info!("Loading configuration from: {}", args.config.display());
    let config = config::load_config(&args.config)?;

    // --validate-config: validate and exit
    if args.validate_config {
        info!("Configuration is valid.");
        if let Some(ref alerting) = config.alerting {
            info!("Alerting: configured");
            if alerting.json_log.as_ref().map(|j| j.enabled).unwrap_or(false) {
                info!("  JSON log: enabled");
            }
            if alerting.webhook.as_ref().map(|w| w.enabled).unwrap_or(false) {
                info!("  Webhook: enabled");
            }
            if alerting.slack.as_ref().map(|s| s.enabled).unwrap_or(false) {
                info!("  Slack: enabled");
            }
            if alerting.email.as_ref().map(|e| e.enabled).unwrap_or(false) {
                info!("  Email: enabled");
            }
            if alerting.prometheus.as_ref().map(|p| p.enabled).unwrap_or(false) {
                info!("  Prometheus: enabled");
            }
        } else {
            info!("Alerting: not configured");
        }
        return Ok(());
    }

    let enforce_mode = config.global.mode == "enforce";
    let rescan_interval = config.global.pid_rescan_interval;
    let socket_path = config.global.socket_path.clone();

    let comm_agents: Vec<_> = config
        .agents
        .iter()
        .filter(|a| a.effective_identity() == "comm")
        .collect();
    let cgroup_agents: Vec<_> = config
        .agents
        .iter()
        .filter(|a| a.effective_identity() == "cgroup")
        .collect();

    info!(
        "Mode: {} | {} agent(s) configured ({} comm, {} cgroup) | PID rescan: {}s",
        config.global.mode,
        config.agents.len(),
        comm_agents.len(),
        cgroup_agents.len(),
        rescan_interval
    );
    for agent in &config.agents {
        info!(
            "  Agent '{}': identity={}, default={}, allow={}, deny={}, children={}",
            agent.name,
            agent.effective_identity(),
            agent.file_access.default,
            agent.file_access.allow.len(),
            agent.file_access.deny.len(),
            agent.watch_children,
        );
        if let Some(exec) = &agent.exec_policy {
            info!(
                "    Exec policy: default={}, allow={}, deny={}",
                exec.default,
                exec.allow.len(),
                exec.deny.len()
            );
        }
        if let Some(res) = &agent.resources {
            info!(
                "    Resources: memory={}, pids={}, cpu={}",
                res.memory_max.as_deref().unwrap_or("unlimited"),
                res.pids_max
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "unlimited".to_string()),
                res.cpu_max.as_deref().unwrap_or("unlimited"),
            );
        }
    }
    if !cgroup_agents.is_empty() {
        info!(
            "IPC socket: {} (for guardian-launch registrations)",
            socket_path
        );
    }

    // Step 2: Load eBPF Program
    info!("Loading eBPF program from: {}", args.ebpf_program.display());
    let mut bpf = Ebpf::load_file(&args.ebpf_program).with_context(|| {
        format!(
            "Failed to load eBPF program from '{}'. Build with: cargo xtask build-ebpf --release",
            args.ebpf_program.display()
        )
    })?;
    info!("eBPF program loaded successfully");

    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger (non-critical): {}", e);
    }

    // Step 3: Load all eBPF programs into the kernel BEFORE taking maps.
    load_tracepoint(&mut bpf, "guardian_file_open")?;
    load_tracepoint(&mut bpf, "guardian_exec_monitor")?;
    load_tracepoint(&mut bpf, "guardian_fork_track")?;
    load_tracepoint(&mut bpf, "guardian_exit_track")?;
    if enforce_mode {
        if let Err(e) = load_lsm(&mut bpf) {
            warn!(
                "Failed to load LSM program: {}. Falling back to monitor-only mode.",
                e
            );
        }
    }
    info!("All eBPF programs loaded into kernel");

    // Step 4: Populate BPF Maps

    // 4a: Comm-based maps (Phase 1/2 compatibility)
    populate_watched_comms(&mut bpf, &config)?;
    let (watched_tgids_map, enforce_tgids_map) =
        populate_watched_tgids(&mut bpf, &config, enforce_mode)?;

    // 4b: Enforcement maps (deny/allow rules)
    let policy_maps = if enforce_mode {
        let maps = populate_enforcement_maps(&mut bpf, &config)?;
        info!("Enforcement maps populated");
        Some(maps)
    } else {
        // Still need to take the maps even if not in enforce mode, to avoid
        // issues with programs referencing them
        None
    };

    // 4c: Cgroup maps (Phase 3 — taken for dynamic updates via IPC)
    let cgroup_maps = take_cgroup_maps(&mut bpf)?;

    // Step 5: Attach eBPF Programs to hooks
    attach_tracepoint(&mut bpf, "guardian_file_open", "syscalls", "sys_enter_openat")?;
    info!("Attached: syscalls/sys_enter_openat (file monitoring)");

    attach_tracepoint(
        &mut bpf,
        "guardian_exec_monitor",
        "syscalls",
        "sys_enter_execve",
    )?;
    info!("Attached: syscalls/sys_enter_execve (exec monitoring)");

    attach_tracepoint(
        &mut bpf,
        "guardian_fork_track",
        "sched",
        "sched_process_fork",
    )?;
    info!("Attached: sched/sched_process_fork (child tracking)");

    attach_tracepoint(
        &mut bpf,
        "guardian_exit_track",
        "sched",
        "sched_process_exit",
    )?;
    info!("Attached: sched/sched_process_exit (cleanup)");

    if enforce_mode {
        match attach_lsm(&mut bpf) {
            Ok(()) => info!("Attached: LSM file_open (enforcement ACTIVE)"),
            Err(e) => {
                warn!(
                    "Failed to attach LSM program: {}. Falling back to monitor-only mode. \
                     Ensure CONFIG_BPF_LSM=y and 'bpf' is in the LSM list.",
                    e
                );
            }
        }
    }

    // Step 6: Initialize Alerting Subsystem (Phase 4)
    let (event_bus_tx, _event_bus_rx) = broadcast::channel::<AlertEvent>(1024);
    let alert_tx = if let Some(ref alerting_config) = config.alerting {
        info!("Starting alerting subsystem...");
        alerting::start(alerting_config.clone()).await
            .with_event_bus(event_bus_tx.clone())
    } else {
        AlertSender::noop().with_event_bus(event_bus_tx.clone())
    };

    // Step 7: Set Up Event Processing
    let cpus = online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))?;
    info!("Setting up event readers for {} CPUs", cpus.len());

    setup_file_event_readers(&mut bpf, &cpus, &config, alert_tx.clone())?;
    setup_exec_event_readers(&mut bpf, &cpus, &config, alert_tx.clone())?;

    // Step 8: Create shared IPC state
    let ipc_state: SharedIpcState = Arc::new(Mutex::new(IpcState {
        agents: collections::HashMap::new(),
        grants: Vec::new(),
        cgroup_maps,
        policy_maps,
        config: config.clone(),
        enforce_mode,
    }));

    // Step 8b: Start Dashboard (Phase 5) with SQLite event storage
    let dashboard_handle = if config
        .dashboard
        .as_ref()
        .map(|d| d.enabled)
        .unwrap_or(false)
    {
        let listen_addr = config
            .dashboard
            .as_ref()
            .and_then(|d| d.listen_address.clone())
            .unwrap_or_else(|| "127.0.0.1:8080".to_string());
        let db_path = config
            .dashboard
            .as_ref()
            .and_then(|d| d.db_path.clone())
            .unwrap_or_else(|| "/var/lib/guardian/events.db".to_string());

        let db = Arc::new(
            dashboard::db::EventDb::open(&db_path)
                .expect("Failed to open event database"),
        );

        // Spawn background DB writer: subscribes to broadcast and persists events
        let db_writer = db.clone();
        let mut db_rx = event_bus_tx.subscribe();
        tokio::spawn(async move {
            loop {
                match db_rx.recv().await {
                    Ok(event) => {
                        if let Err(e) = db_writer.insert_event(&event) {
                            warn!("Failed to write event to DB: {}", e);
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("DB writer lagged, missed {} events", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        // Spawn daily DB pruning task (keep 30 days of events)
        let db_pruner = db.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(86400));
            loop {
                interval.tick().await;
                match db_pruner.prune_old_events(30) {
                    Ok(n) => {
                        if n > 0 {
                            info!("Pruned {} old events from DB", n);
                        }
                    }
                    Err(e) => warn!("DB prune failed: {}", e),
                }
            }
        });

        let dash_state = Arc::new(dashboard::DashboardState {
            ipc_state: ipc_state.clone(),
            alert_sender: alert_tx.clone(),
            event_bus: event_bus_tx.clone(),
            config_path: args.config.clone(),
            db,
        });
        info!("Starting dashboard on http://{}", listen_addr);
        Some(tokio::spawn(dashboard::start(dash_state, listen_addr)))
    } else {
        None
    };

    // Step 9: Start IPC server for guardian-launch registrations
    let ipc_socket_path = socket_path.clone();
    let ipc_state_clone = ipc_state.clone();
    let ipc_handle = tokio::spawn(async move {
        if let Err(e) = ipc::start_ipc_server(&ipc_socket_path, ipc_state_clone).await {
            error!("IPC server error: {}", e);
        }
    });

    // Step 10: Start cgroup cleanup task
    let cleanup_state = ipc_state.clone();
    let cleanup_handle = tokio::spawn(ipc::cgroup_cleanup_task(cleanup_state));

    // Step 11: Periodic PID Rescanning (comm-based agents only)
    let rescan_config = config.clone();
    let rescan_watched = watched_tgids_map.clone();
    let rescan_enforce = enforce_tgids_map.clone();
    let rescan_handle = tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(rescan_interval));
        loop {
            interval.tick().await;
            for agent in &rescan_config.agents {
                if agent.effective_identity() != "comm" {
                    continue;
                }
                let process_name = agent.effective_process_name();
                match find_pids_by_name(process_name) {
                    Ok(pids) if !pids.is_empty() => {
                        debug!(
                            "PID rescan: agent '{}' has {} active process(es): {:?}",
                            agent.name,
                            pids.len(),
                            pids
                        );
                        if let Ok(mut map) = rescan_watched.lock() {
                            for pid in &pids {
                                let _ = map.insert(*pid, 1, 0);
                            }
                        }
                        if let Some(ref enforce) = rescan_enforce {
                            if let Ok(mut map) = enforce.lock() {
                                for pid in &pids {
                                    let _ = map.insert(*pid, 1, 0);
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        debug!(
                            "PID rescan: no processes found for agent '{}'",
                            agent.name
                        );
                    }
                    Err(e) => {
                        warn!("PID rescan error for '{}': {}", agent.name, e);
                    }
                }
            }
        }
    });

    // Step 12: Set up SIGHUP handler for config reload
    let reload_config_path = args.config.clone();
    let reload_ipc_state = ipc_state.clone();
    let sighup_handle = tokio::spawn(async move {
        let mut sighup =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to register SIGHUP handler: {}", e);
                    return;
                }
            };
        loop {
            sighup.recv().await;
            info!("SIGHUP received — reloading configuration...");
            match config::load_config(&reload_config_path) {
                Ok(new_config) => {
                    let mut state = reload_ipc_state.lock().await;
                    state.config = new_config.clone();
                    info!(
                        "Configuration reloaded: {} agent(s), mode={}",
                        new_config.agents.len(),
                        new_config.global.mode
                    );
                }
                Err(e) => {
                    error!("Config reload failed (keeping previous config): {}", e);
                }
            }
        }
    });

    // Step 13: Wait for Shutdown
    info!("==========================================================");
    info!(
        "Guardian Shell is running ({} mode). Monitoring {} agent(s).",
        config.global.mode,
        config.agents.len()
    );
    if config.alerting.is_some() {
        info!("Alerting subsystem: active");
    }
    if config.dashboard.as_ref().map(|d| d.enabled).unwrap_or(false) {
        info!("Dashboard: active");
    }
    if !cgroup_agents.is_empty() {
        info!(
            "Cgroup agents: use 'guardian-launch --name <agent> -- <command>' to start"
        );
    }
    info!("Send SIGHUP to reload configuration.");
    info!("Press Ctrl+C to stop.");
    info!("==========================================================");

    signal::ctrl_c()
        .await
        .context("Failed to listen for Ctrl+C signal")?;

    rescan_handle.abort();
    ipc_handle.abort();
    cleanup_handle.abort();
    sighup_handle.abort();
    if let Some(h) = dashboard_handle {
        h.abort();
    }

    // Clean up IPC socket
    let _ = std::fs::remove_file(&socket_path);

    info!("Shutting down Guardian Shell...");
    info!("eBPF programs detached. Monitoring stopped.");

    Ok(())
}

// =============================================================================
// BPF Map Population
// =============================================================================

fn populate_watched_comms(bpf: &mut Ebpf, config: &Config) -> Result<()> {
    let mut watched_comms: HashMap<MapData, [u8; 16], u8> =
        HashMap::try_from(bpf.take_map("WATCHED_COMMS").context("WATCHED_COMMS map not found")?)?;

    for agent in &config.agents {
        if agent.effective_identity() != "comm" {
            continue;
        }
        let process_name = agent.effective_process_name();
        let comm_key = comm_to_key(process_name);
        watched_comms
            .insert(comm_key, 1, 0)
            .with_context(|| format!("Failed to insert comm '{}'", process_name))?;
        info!("Watching process name '{}'", process_name);
    }

    Ok(())
}

fn populate_watched_tgids(
    bpf: &mut Ebpf,
    config: &Config,
    enforce_mode: bool,
) -> Result<(SharedBpfMap, Option<SharedBpfMap>)> {
    let mut watched_tgids: HashMap<MapData, u32, u8> =
        HashMap::try_from(bpf.take_map("WATCHED_TGIDS").context("WATCHED_TGIDS map not found")?)?;

    let mut enforce_tgids: Option<HashMap<MapData, u32, u8>> = if enforce_mode {
        Some(HashMap::try_from(
            bpf.take_map("ENFORCE_TGIDS").context("ENFORCE_TGIDS map not found")?,
        )?)
    } else {
        None
    };

    for agent in &config.agents {
        if agent.effective_identity() != "comm" {
            continue;
        }
        let process_name = agent.effective_process_name();
        let pids = find_pids_by_name(process_name).unwrap_or_default();
        for pid in &pids {
            watched_tgids.insert(*pid, 1, 0)?;
            if let Some(ref mut et) = enforce_tgids {
                let _ = et.insert(*pid, 1, 0);
            }
        }
        if !pids.is_empty() {
            info!(
                "Tracking {} PID(s) for agent '{}': {:?}",
                pids.len(),
                agent.name,
                pids
            );
        }
    }

    let watched = Arc::new(std::sync::Mutex::new(watched_tgids));
    let enforce = enforce_tgids.map(|et| Arc::new(std::sync::Mutex::new(et)));
    Ok((watched, enforce))
}

fn populate_enforcement_maps(bpf: &mut Ebpf, config: &Config) -> Result<PolicyBpfMaps> {
    let mut enforce_comms: HashMap<MapData, [u8; 16], u8> =
        HashMap::try_from(bpf.take_map("ENFORCE_COMMS").context("ENFORCE_COMMS map not found")?)?;

    let mut default_action: HashMap<MapData, [u8; 16], u8> =
        HashMap::try_from(bpf.take_map("DEFAULT_ACTION").context("DEFAULT_ACTION map not found")?)?;

    let mut deny_prefixes: LpmTrie<MapData, [u8; MAX_FILENAME_LEN], u8> =
        LpmTrie::try_from(bpf.take_map("DENY_PREFIXES").context("DENY_PREFIXES map not found")?)?;

    let mut deny_exact: HashMap<MapData, [u8; MAX_FILENAME_LEN], u8> =
        HashMap::try_from(bpf.take_map("DENY_EXACT").context("DENY_EXACT map not found")?)?;

    let mut allow_prefixes: LpmTrie<MapData, [u8; MAX_FILENAME_LEN], u8> =
        LpmTrie::try_from(bpf.take_map("ALLOW_PREFIXES").context("ALLOW_PREFIXES map not found")?)?;

    let mut allow_exact: HashMap<MapData, [u8; MAX_FILENAME_LEN], u8> =
        HashMap::try_from(bpf.take_map("ALLOW_EXACT").context("ALLOW_EXACT map not found")?)?;

    let mut deny_count = 0u32;
    let mut allow_count = 0u32;

    for agent in &config.agents {
        // Set up comm-based enforcement for comm agents
        if agent.effective_identity() == "comm" {
            let process_name = agent.effective_process_name();
            let comm_key = comm_to_key(process_name);
            enforce_comms.insert(comm_key, 1, 0)?;

            let default_val = if agent.file_access.default == "deny" {
                0u8
            } else {
                1u8
            };
            default_action.insert(comm_key, default_val, 0)?;
        }

        // Insert deny rules (shared across all agents)
        for pattern in &agent.file_access.deny {
            if pattern.ends_with("/**") {
                let prefix = format!("{}/", &pattern[..pattern.len() - 3]);
                let key = path_to_lpm_key(prefix.as_bytes());
                deny_prefixes.insert(&key, 1, 0)?;
                let exact = path_to_map_key(pattern[..pattern.len() - 3].as_bytes());
                let _ = deny_exact.insert(exact, 1, 0);
            } else {
                let key = path_to_map_key(pattern.as_bytes());
                deny_exact.insert(key, 1, 0)?;
            }
            deny_count += 1;
        }

        // Insert allow rules (shared across all agents)
        for pattern in &agent.file_access.allow {
            if pattern.ends_with("/**") {
                let prefix = format!("{}/", &pattern[..pattern.len() - 3]);
                let key = path_to_lpm_key(prefix.as_bytes());
                allow_prefixes.insert(&key, 1, 0)?;
                let exact = path_to_map_key(pattern[..pattern.len() - 3].as_bytes());
                let _ = allow_exact.insert(exact, 1, 0);
            } else {
                let key = path_to_map_key(pattern.as_bytes());
                allow_exact.insert(key, 1, 0)?;
            }
            allow_count += 1;
        }
    }

    info!(
        "Loaded {} deny rules, {} allow rules into BPF",
        deny_count, allow_count
    );

    // Return map handles for dynamic updates (temporary grants)
    Ok(PolicyBpfMaps {
        allow_prefixes,
        allow_exact,
    })
}

/// Take cgroup-related BPF maps for dynamic updates via IPC.
fn take_cgroup_maps(bpf: &mut Ebpf) -> Result<CgroupBpfMaps> {
    let watched_cgroups: HashMap<MapData, u64, u8> = HashMap::try_from(
        bpf.take_map("WATCHED_CGROUPS")
            .context("WATCHED_CGROUPS map not found")?,
    )?;

    let enforce_cgroups: HashMap<MapData, u64, u8> = HashMap::try_from(
        bpf.take_map("ENFORCE_CGROUPS")
            .context("ENFORCE_CGROUPS map not found")?,
    )?;

    let cgroup_default_action: HashMap<MapData, u64, u8> = HashMap::try_from(
        bpf.take_map("CGROUP_DEFAULT_ACTION")
            .context("CGROUP_DEFAULT_ACTION map not found")?,
    )?;

    Ok(CgroupBpfMaps {
        watched_cgroups,
        enforce_cgroups,
        cgroup_default_action,
    })
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

// =============================================================================
// Program Attachment
// =============================================================================

fn load_tracepoint(bpf: &mut Ebpf, prog_name: &str) -> Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(prog_name)
        .with_context(|| format!("Program '{}' not found", prog_name))?
        .try_into()
        .with_context(|| format!("'{}' is not a TracePoint program", prog_name))?;

    program
        .load()
        .with_context(|| format!("Failed to load '{}'", prog_name))?;

    Ok(())
}

fn attach_tracepoint(
    bpf: &mut Ebpf,
    prog_name: &str,
    category: &str,
    event: &str,
) -> Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(prog_name)
        .with_context(|| format!("Program '{}' not found", prog_name))?
        .try_into()
        .with_context(|| format!("'{}' is not a TracePoint program", prog_name))?;

    program
        .attach(category, event)
        .with_context(|| format!("Failed to attach '{}' to {}/{}", prog_name, category, event))?;

    Ok(())
}

fn load_lsm(bpf: &mut Ebpf) -> Result<()> {
    let btf = Btf::from_sys_fs().context("Failed to load BTF from /sys/kernel/btf/vmlinux")?;

    let program: &mut Lsm = bpf
        .program_mut("guardian_enforce_file_open")
        .context("LSM program 'guardian_enforce_file_open' not found")?
        .try_into()
        .context("'guardian_enforce_file_open' is not an LSM program")?;

    program
        .load("file_open", &btf)
        .context("Failed to load LSM program")?;

    Ok(())
}

fn attach_lsm(bpf: &mut Ebpf) -> Result<()> {
    let program: &mut Lsm = bpf
        .program_mut("guardian_enforce_file_open")
        .context("LSM program 'guardian_enforce_file_open' not found")?
        .try_into()
        .context("'guardian_enforce_file_open' is not an LSM program")?;

    program.attach().context("Failed to attach LSM program")?;

    Ok(())
}

// =============================================================================
// Event Processing Setup
// =============================================================================

fn setup_file_event_readers(
    bpf: &mut Ebpf,
    cpus: &[u32],
    config: &Config,
    alert_tx: AlertSender,
) -> Result<()> {
    let mut perf_array = AsyncPerfEventArray::try_from(
        bpf.take_map("EVENTS")
            .context("EVENTS map not found")?,
    )?;

    for &cpu_id in cpus {
        let mut buf = perf_array
            .open(cpu_id, None)
            .with_context(|| format!("Failed to open perf buffer for CPU {}", cpu_id))?;

        let config = config.clone();
        let enforce_mode = config.global.mode == "enforce";
        let alert_tx = alert_tx.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<FileAccessEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        error!("Error reading file events from CPU {}: {}", cpu_id, e);
                        continue;
                    }
                };

                if events.lost > 0 {
                    warn!("Lost {} file events on CPU {}", events.lost, cpu_id);
                    alert_tx.metrics.events_lost.inc_by(events.lost as u64);
                }

                for i in 0..events.read {
                    let event = unsafe {
                        (buffers[i].as_ptr() as *const FileAccessEvent).read_unaligned()
                    };
                    process_file_event(&event, &config, enforce_mode, &alert_tx);
                }
            }
        });
    }

    Ok(())
}

fn setup_exec_event_readers(
    bpf: &mut Ebpf,
    cpus: &[u32],
    config: &Config,
    alert_tx: AlertSender,
) -> Result<()> {
    let mut perf_array = AsyncPerfEventArray::try_from(
        bpf.take_map("EXEC_EVENTS")
            .context("EXEC_EVENTS map not found")?,
    )?;

    for &cpu_id in cpus {
        let mut buf = perf_array
            .open(cpu_id, None)
            .with_context(|| format!("Failed to open exec perf buffer for CPU {}", cpu_id))?;

        let config = config.clone();
        let alert_tx = alert_tx.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<ExecEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        error!("Error reading exec events from CPU {}: {}", cpu_id, e);
                        continue;
                    }
                };

                if events.lost > 0 {
                    warn!("Lost {} exec events on CPU {}", events.lost, cpu_id);
                    alert_tx.metrics.events_lost.inc_by(events.lost as u64);
                }

                for i in 0..events.read {
                    let event = unsafe {
                        (buffers[i].as_ptr() as *const ExecEvent).read_unaligned()
                    };
                    process_exec_event(&event, &config, &alert_tx);
                }
            }
        });
    }

    Ok(())
}

// =============================================================================
// Event Processing
// =============================================================================

fn find_agent_for_event<'a>(config: &'a Config, comm: &str) -> Option<&'a config::AgentConfig> {
    // Try exact comm match first (for comm-based agents)
    if let Some(agent) = config.agents.iter().find(|a| {
        a.effective_identity() == "comm" && a.effective_process_name() == comm
    }) {
        return Some(agent);
    }
    // For cgroup-based agents or worker threads, use first matching agent
    // (cgroup identification is done in kernel, userspace just needs a policy)
    config.agents.first()
}

fn process_file_event(
    event: &FileAccessEvent,
    config: &Config,
    enforce_mode: bool,
    alert_tx: &AlertSender,
) {
    let filename = std::str::from_utf8(event.filename_bytes()).unwrap_or("<invalid-utf8>");
    let comm = std::str::from_utf8(event.comm_bytes()).unwrap_or("<unknown>");
    let access_mode = decode_open_flags(event.flags);

    if filename.is_empty() {
        return;
    }

    let agent_config = find_agent_for_event(config, comm);

    match agent_config {
        Some(agent) => {
            let allowed = check_file_policy(&agent.file_access, filename);
            let mode_tag = if enforce_mode { "ENFORCE" } else { "MONITOR" };

            let (severity, action) = if allowed {
                (Severity::Info, Action::Allow)
            } else if enforce_mode {
                (Severity::Critical, Action::Blocked)
            } else {
                (Severity::Warning, Action::Deny)
            };

            // Existing log output
            if allowed {
                debug!(
                    "[ALLOW] agent='{}' pid={} comm='{}' file='{}' mode={}",
                    agent.name, event.tgid, comm, filename, access_mode
                );
            } else if enforce_mode {
                warn!(
                    "[BLOCKED|{}] agent='{}' pid={} comm='{}' file='{}' mode={}",
                    mode_tag, agent.name, event.tgid, comm, filename, access_mode
                );
            } else {
                warn!(
                    "[DENY|{}] agent='{}' pid={} comm='{}' file='{}' mode={} (not blocked)",
                    mode_tag, agent.name, event.tgid, comm, filename, access_mode
                );
            }

            // Send to alerting subsystem
            alert_tx.send(AlertEvent {
                timestamp: chrono::Utc::now(),
                severity,
                event_type: EventType::FileAccess,
                action,
                agent_name: agent.name.clone(),
                pid: event.tgid,
                comm: comm.to_string(),
                path: filename.to_string(),
                access_mode: access_mode.clone(),
                identity_method: agent.effective_identity().to_string(),
                policy_mode: mode_tag.to_lowercase(),
            });
        }
        None => {
            debug!(
                "[UNKNOWN] pid={} comm='{}' file='{}' mode={}",
                event.tgid, comm, filename, access_mode
            );
        }
    }
}

fn process_exec_event(event: &ExecEvent, config: &Config, alert_tx: &AlertSender) {
    let filename = std::str::from_utf8(event.filename_bytes()).unwrap_or("<invalid-utf8>");
    let comm = std::str::from_utf8(event.comm_bytes()).unwrap_or("<unknown>");

    let agent_config = find_agent_for_event(config, comm);

    match agent_config {
        Some(agent) => {
            let allowed = match &agent.exec_policy {
                Some(policy) => check_exec_policy(policy, filename),
                None => true,
            };

            let (severity, action) = if allowed {
                (Severity::Info, Action::Allow)
            } else {
                (Severity::Warning, Action::Deny)
            };

            if allowed {
                debug!(
                    "[EXEC|ALLOW] agent='{}' pid={} comm='{}' cmd='{}'",
                    agent.name, event.tgid, comm, filename
                );
            } else {
                warn!(
                    "[EXEC|DENY] agent='{}' pid={} comm='{}' cmd='{}'",
                    agent.name, event.tgid, comm, filename
                );
            }

            alert_tx.send(AlertEvent {
                timestamp: chrono::Utc::now(),
                severity,
                event_type: EventType::ExecAttempt,
                action,
                agent_name: agent.name.clone(),
                pid: event.tgid,
                comm: comm.to_string(),
                path: filename.to_string(),
                access_mode: String::new(),
                identity_method: agent.effective_identity().to_string(),
                policy_mode: config.global.mode.clone(),
            });
        }
        None => {
            debug!(
                "[EXEC|UNKNOWN] pid={} comm='{}' cmd='{}'",
                event.tgid, comm, filename
            );
        }
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

fn decode_open_flags(flags: u32) -> String {
    let access = match flags & 0x3 {
        0 => "READ",
        1 => "WRITE",
        2 => "RDWR",
        _ => "UNKNOWN",
    };

    let mut modifiers = Vec::new();
    if flags & 0x0040 != 0 {
        modifiers.push("CREATE");
    }
    if flags & 0x0200 != 0 {
        modifiers.push("TRUNC");
    }
    if flags & 0x0400 != 0 {
        modifiers.push("APPEND");
    }

    if modifiers.is_empty() {
        access.to_string()
    } else {
        format!("{}|{}", access, modifiers.join("|"))
    }
}

fn comm_to_key(name: &str) -> [u8; 16] {
    let mut key = [0u8; 16];
    let bytes = name.as_bytes();
    let copy_len = core::cmp::min(bytes.len(), 15);
    key[..copy_len].copy_from_slice(&bytes[..copy_len]);
    key
}

fn find_pids_by_name(name: &str) -> Result<Vec<u32>> {
    let mut pids = Vec::new();

    let proc_dir = std::fs::read_dir("/proc")
        .context("Failed to read /proc directory")?;

    for entry in proc_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let file_name = entry.file_name();
        let pid_str = match file_name.to_str() {
            Some(s) => s,
            None => continue,
        };

        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let comm_path = format!("/proc/{}/comm", pid);
        let comm = match std::fs::read_to_string(&comm_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if comm.trim() == name {
            pids.push(pid);
        }
    }

    Ok(pids)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_open_flags_read_only() {
        assert_eq!(decode_open_flags(0), "READ");
    }

    #[test]
    fn test_decode_open_flags_write_create() {
        assert_eq!(decode_open_flags(0x0041), "WRITE|CREATE");
    }

    #[test]
    fn test_decode_open_flags_rdwr_trunc() {
        assert_eq!(decode_open_flags(0x0202), "RDWR|TRUNC");
    }

    #[test]
    fn test_comm_to_key() {
        let key = comm_to_key("cat");
        assert_eq!(key[0], b'c');
        assert_eq!(key[1], b'a');
        assert_eq!(key[2], b't');
        assert_eq!(key[3], 0);
    }
}
