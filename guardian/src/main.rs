mod alerting;
mod config;
mod dashboard;
mod ipc;
mod permissions;

use anyhow::{Context, Result};
use aya::{
    maps::{AsyncPerfEventArray, HashMap, MapData, lpm_trie::{LpmTrie, Key}},
    programs::{Lsm, TracePoint},
    util::online_cpus,
    Btf, Ebpf,
};
use bytes::BytesMut;
use clap::Parser;
use guardian_common::{ExecEvent, FileAccessEvent, NetworkEvent, EVENT_FLAG_TRUNCATED, MAX_FILENAME_LEN};
use log::{debug, error, info, warn};
use std::collections;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::{signal, sync::Mutex, sync::broadcast, time};

use crate::alerting::{Action, AlertEvent, AlertSender, EventType, Severity};
use crate::config::{check_exec_policy, check_file_policy, check_network_policy, normalize_path, Config};
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

    let strict_mode = config.global.mode == "strict";
    let enforce_mode = config.global.mode == "enforce" || strict_mode;
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
            "  Agent '{}': identity={}, default={}, allow={}, deny={}, read_only={}, children={}",
            agent.name,
            agent.effective_identity(),
            agent.file_access.default,
            agent.file_access.allow.len(),
            agent.file_access.deny.len(),
            agent.file_access.read_only.len(),
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

    // Note: aya-log-ebpf was removed from the eBPF program early on to reduce
    // BPF verifier complexity (see ARCHITECTURE.md). No AYA_LOGS map exists,
    // so EbpfLogger::init() is not called.

    // Step 3: Load all eBPF programs into the kernel BEFORE taking maps.
    load_tracepoint(&mut bpf, "guardian_file_open")?;
    // openat2 tracepoint (Linux 5.6+) — may not exist on older kernels
    let has_openat2 = load_tracepoint(&mut bpf, "guardian_file_openat2").is_ok();
    // Legacy open syscall (rare on modern Linux, belt-and-suspenders)
    let has_open_legacy = load_tracepoint(&mut bpf, "guardian_file_open_legacy").is_ok();
    load_tracepoint(&mut bpf, "guardian_exec_monitor")?;
    load_tracepoint(&mut bpf, "guardian_fork_track")?;
    load_tracepoint(&mut bpf, "guardian_exit_track")?;
    // Network connection monitoring
    let has_net_connect = load_tracepoint(&mut bpf, "guardian_net_connect").is_ok();
    // Phase 8: execveat tracepoint (memfd_create + execveat bypass)
    let has_execveat = load_tracepoint(&mut bpf, "guardian_execveat_monitor").is_ok();
    // Phase 8: Inode enforcement tracepoints (rename/unlink/hardlink)
    let has_rename = load_tracepoint(&mut bpf, "guardian_rename_monitor").is_ok();
    let has_unlink = load_tracepoint(&mut bpf, "guardian_unlink_monitor").is_ok();
    let has_link = load_tracepoint(&mut bpf, "guardian_link_monitor").is_ok();

    if enforce_mode {
        if let Err(e) = load_lsm(&mut bpf, "guardian_enforce_file_open", "file_open") {
            if strict_mode {
                anyhow::bail!("Strict mode: failed to load LSM file_open: {}", e);
            }
            warn!(
                "Failed to load LSM file_open: {}. Falling back to monitor-only mode.",
                e
            );
        }
        if let Err(e) = load_lsm(&mut bpf, "guardian_enforce_exec", "bprm_check_security") {
            if strict_mode {
                anyhow::bail!("Strict mode: failed to load LSM bprm_check_security: {}", e);
            }
            warn!(
                "Failed to load LSM bprm_check_security: {}. Exec enforcement unavailable.",
                e
            );
        }
        // Phase 8: Inode LSM hooks for rename/unlink/hardlink enforcement
        if let Err(e) = load_lsm(&mut bpf, "guardian_enforce_rename", "inode_rename") {
            if strict_mode {
                anyhow::bail!("Strict mode: failed to load LSM inode_rename: {}", e);
            }
            warn!("Failed to load LSM inode_rename: {}. Rename enforcement unavailable.", e);
        }
        if let Err(e) = load_lsm(&mut bpf, "guardian_enforce_unlink", "inode_unlink") {
            if strict_mode {
                anyhow::bail!("Strict mode: failed to load LSM inode_unlink: {}", e);
            }
            warn!("Failed to load LSM inode_unlink: {}. Unlink enforcement unavailable.", e);
        }
        if let Err(e) = load_lsm(&mut bpf, "guardian_enforce_link", "inode_link") {
            if strict_mode {
                anyhow::bail!("Strict mode: failed to load LSM inode_link: {}", e);
            }
            warn!("Failed to load LSM inode_link: {}. Hardlink enforcement unavailable.", e);
        }
        // Phase 9: LSM socket_connect for network enforcement
        if let Err(e) = load_lsm(&mut bpf, "guardian_enforce_net_connect", "socket_connect") {
            if strict_mode {
                anyhow::bail!("Strict mode: failed to load LSM socket_connect: {}", e);
            }
            warn!("Failed to load LSM socket_connect: {}. Network enforcement unavailable.", e);
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

    // 4c: Exec enforcement maps (Phase 7 — kernel-side exec blocking)
    if enforce_mode {
        if let Err(e) = populate_exec_enforcement_maps(&mut bpf, &config) {
            warn!("Failed to populate exec enforcement maps: {}. Exec enforcement unavailable.", e);
        } else {
            info!("Exec enforcement maps populated");
        }
    }

    // 4c2: Phase 9 — Network enforcement maps (port-based deny/allow in kernel)
    if enforce_mode {
        if let Err(e) = populate_net_enforcement_maps(&mut bpf, &config) {
            warn!("Failed to populate network enforcement maps: {}. Network enforcement unavailable.", e);
        } else {
            info!("Network enforcement maps populated");
        }
    }

    // 4c3: Phase 8 — Dynamic linker detection map
    if let Err(e) = populate_dynamic_linkers(&mut bpf) {
        warn!("Failed to populate dynamic linkers map: {}", e);
    } else {
        info!("Dynamic linker detection map populated");
    }

    // 4c4: Phase 8 — Take inode enforcement pending maps (rename/unlink/link)
    // These just need to be taken so aya owns them.
    for map_name in ["PENDING_RENAME_DENY", "PENDING_UNLINK_DENY", "PENDING_LINK_DENY", "PENDING_NET_DENY"] {
        if let Some(map) = bpf.take_map(map_name) {
            let _: HashMap<MapData, u64, u8> = HashMap::try_from(map)
                .unwrap_or_else(|e| panic!("Failed to take {}: {}", map_name, e));
        }
    }

    // 4c4: Phase 8 — Take fail-closed cgroups map
    let fail_closed_map: Option<HashMap<MapData, u64, u8>> =
        bpf.take_map("FAIL_CLOSED_CGROUPS")
            .and_then(|m| HashMap::try_from(m).ok());

    // 4d: Cgroup maps (Phase 3 — taken for dynamic updates via IPC)
    let cgroup_maps = take_cgroup_maps(&mut bpf)?;

    // Step 5: Attach eBPF Programs to hooks
    attach_tracepoint(&mut bpf, "guardian_file_open", "syscalls", "sys_enter_openat")?;
    info!("Attached: syscalls/sys_enter_openat (file monitoring)");

    if has_openat2 {
        match attach_tracepoint(&mut bpf, "guardian_file_openat2", "syscalls", "sys_enter_openat2") {
            Ok(()) => info!("Attached: syscalls/sys_enter_openat2 (openat2 monitoring)"),
            Err(e) => warn!("openat2 tracepoint not available (kernel < 5.6?): {}", e),
        }
    }

    if has_open_legacy {
        match attach_tracepoint(&mut bpf, "guardian_file_open_legacy", "syscalls", "sys_enter_open") {
            Ok(()) => info!("Attached: syscalls/sys_enter_open (legacy open monitoring)"),
            Err(e) => warn!("Legacy open tracepoint not available: {}", e),
        }
    }

    attach_tracepoint(
        &mut bpf,
        "guardian_exec_monitor",
        "syscalls",
        "sys_enter_execve",
    )?;
    info!("Attached: syscalls/sys_enter_execve (exec monitoring + enforcement)");

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

    if has_net_connect {
        match attach_tracepoint(&mut bpf, "guardian_net_connect", "syscalls", "sys_enter_connect") {
            Ok(()) => info!("Attached: syscalls/sys_enter_connect (network monitoring)"),
            Err(e) => warn!("Network connect tracepoint not available: {}", e),
        }
    }

    // Phase 8: execveat tracepoint
    if has_execveat {
        match attach_tracepoint(&mut bpf, "guardian_execveat_monitor", "syscalls", "sys_enter_execveat") {
            Ok(()) => info!("Attached: syscalls/sys_enter_execveat (execveat/memfd monitoring)"),
            Err(e) => warn!("execveat tracepoint not available: {}", e),
        }
    }

    // Phase 8: Inode enforcement tracepoints
    if has_rename {
        match attach_tracepoint(&mut bpf, "guardian_rename_monitor", "syscalls", "sys_enter_renameat2") {
            Ok(()) => info!("Attached: syscalls/sys_enter_renameat2 (rename monitoring)"),
            Err(e) => warn!("Rename tracepoint not available: {}", e),
        }
    }
    if has_unlink {
        match attach_tracepoint(&mut bpf, "guardian_unlink_monitor", "syscalls", "sys_enter_unlinkat") {
            Ok(()) => info!("Attached: syscalls/sys_enter_unlinkat (unlink monitoring)"),
            Err(e) => warn!("Unlink tracepoint not available: {}", e),
        }
    }
    if has_link {
        match attach_tracepoint(&mut bpf, "guardian_link_monitor", "syscalls", "sys_enter_linkat") {
            Ok(()) => info!("Attached: syscalls/sys_enter_linkat (hardlink monitoring)"),
            Err(e) => warn!("Hardlink tracepoint not available: {}", e),
        }
    }

    if enforce_mode {
        match attach_lsm(&mut bpf, "guardian_enforce_file_open") {
            Ok(()) => info!("Attached: LSM file_open (file enforcement ACTIVE)"),
            Err(e) => {
                if strict_mode {
                    anyhow::bail!("Strict mode: failed to attach LSM file_open: {}", e);
                }
                warn!(
                    "Failed to attach LSM file_open: {}. File enforcement unavailable. \
                     Ensure CONFIG_BPF_LSM=y and 'bpf' is in the LSM list.",
                    e
                );
            }
        }
        match attach_lsm(&mut bpf, "guardian_enforce_exec") {
            Ok(()) => info!("Attached: LSM bprm_check_security (exec enforcement ACTIVE)"),
            Err(e) => {
                if strict_mode {
                    anyhow::bail!("Strict mode: failed to attach LSM bprm_check_security: {}", e);
                }
                warn!(
                    "Failed to attach LSM bprm_check_security: {}. Exec enforcement unavailable.",
                    e
                );
            }
        }
        // Phase 8: Inode LSM hooks
        for (prog, desc) in [
            ("guardian_enforce_rename", "inode_rename"),
            ("guardian_enforce_unlink", "inode_unlink"),
            ("guardian_enforce_link", "inode_link"),
        ] {
            match attach_lsm(&mut bpf, prog) {
                Ok(()) => info!("Attached: LSM {} ({} enforcement ACTIVE)", desc, desc),
                Err(e) => {
                    if strict_mode {
                        anyhow::bail!("Strict mode: failed to attach LSM {}: {}", desc, e);
                    }
                    warn!("Failed to attach LSM {}: {}. {} enforcement unavailable.", desc, e, desc);
                }
            }
        }
        // Phase 9: Network enforcement LSM hook
        match attach_lsm(&mut bpf, "guardian_enforce_net_connect") {
            Ok(()) => info!("Attached: LSM socket_connect (network enforcement ACTIVE)"),
            Err(e) => {
                if strict_mode {
                    anyhow::bail!("Strict mode: failed to attach LSM socket_connect: {}", e);
                }
                warn!(
                    "Failed to attach LSM socket_connect: {}. Network enforcement unavailable.",
                    e
                );
            }
        }
    }

    // Step 6: Initialize Alerting Subsystem (Phase 4)
    let (event_bus_tx, _event_bus_rx) = broadcast::channel::<AlertEvent>(8192);
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
    if has_net_connect {
        setup_net_event_readers(&mut bpf, &cpus, &config, alert_tx.clone())?;
    }

    // Step 8: Create permission bus and shared IPC state
    let (permission_bus_tx, _permission_bus_rx) = broadcast::channel::<ipc::PermissionEvent>(256);

    let ipc_state: SharedIpcState = Arc::new(Mutex::new(IpcState {
        agents: collections::HashMap::new(),
        grants: Vec::new(),
        cgroup_maps,
        policy_maps,
        config: config.clone(),
        config_path: args.config.clone(),
        enforce_mode,
        pending_permissions: Vec::new(),
        resolved_permissions: collections::VecDeque::new(),
        next_permission_id: 1,
        permission_bus: None, // Set below if dashboard is enabled
        rate_limits: collections::HashMap::new(),
        event_db: None, // Set below if dashboard is enabled
        fail_closed_map,
        grant_accumulator: permissions::GrantAccumulator::new(),
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

        let db = match dashboard::db::EventDb::open(&db_path) {
            Ok(db) => Arc::new(db),
            Err(e) => {
                error!("Failed to open event database at '{}': {} — dashboard events will not be persisted", db_path, e);
                // Create a fallback in-memory database so dashboard still functions
                Arc::new(
                    dashboard::db::EventDb::open(":memory:")
                        .expect("in-memory SQLite should always succeed"),
                )
            }
        };

        // Spawn background DB writer: subscribes to broadcast, filters by severity,
        // and batch-inserts events every 500ms for efficiency.
        let db_writer = db.clone();
        let mut db_rx = event_bus_tx.subscribe();
        let db_min_severity = config
            .dashboard
            .as_ref()
            .map(|d| d.db_min_severity.clone())
            .unwrap_or_else(|| "warning".to_string());
        let db_severity_threshold = Severity::from_str(&db_min_severity);
        info!(
            "DB writer: persisting events with severity >= {} (configure with dashboard.db_min_severity)",
            db_min_severity
        );
        tokio::spawn(async move {
            let mut batch: Vec<AlertEvent> = Vec::with_capacity(256);
            let mut flush_interval = time::interval(Duration::from_millis(500));
            let mut total_lagged: u64 = 0;
            let mut last_lag_log = std::time::Instant::now();

            loop {
                tokio::select! {
                    result = db_rx.recv() => {
                        match result {
                            Ok(event) => {
                                // Filter: only persist events at or above the configured severity
                                if event.severity >= db_severity_threshold {
                                    batch.push(event);
                                    // Flush immediately if batch is large
                                    if batch.len() >= 200 {
                                        let events = std::mem::replace(&mut batch, Vec::with_capacity(256));
                                        if let Err(e) = db_writer.batch_insert_events(&events) {
                                            warn!("Failed to batch-write {} events to DB: {}", events.len(), e);
                                        }
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                total_lagged += n;
                                // Rate-limit lag warnings to once per 30 seconds
                                if last_lag_log.elapsed() >= Duration::from_secs(30) {
                                    warn!("DB writer lagged, missed {} events total since last report", total_lagged);
                                    total_lagged = 0;
                                    last_lag_log = std::time::Instant::now();
                                }
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                    _ = flush_interval.tick() => {
                        // Periodic flush: batch-insert accumulated events
                        if !batch.is_empty() {
                            let events = std::mem::replace(&mut batch, Vec::with_capacity(256));
                            if let Err(e) = db_writer.batch_insert_events(&events) {
                                warn!("Failed to batch-write {} events to DB: {}", events.len(), e);
                            }
                        }
                    }
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

        // Enable permission bus and DB on IPC state now that dashboard is active
        {
            let mut s = ipc_state.lock().await;
            s.permission_bus = Some(permission_bus_tx.clone());
            s.event_db = Some(db.clone());
        }

        let auth_token = config
            .dashboard
            .as_ref()
            .and_then(|d| d.auth_token.clone());
        let dash_state = Arc::new(dashboard::DashboardState {
            ipc_state: ipc_state.clone(),
            alert_sender: alert_tx.clone(),
            event_bus: event_bus_tx.clone(),
            permission_bus: permission_bus_tx.clone(),
            config_path: args.config.clone(),
            db,
            auth_token,
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

    // Step 11b: Phase 8 — Spawn hourly anomaly detection + memory cleanup task
    if config.dashboard.as_ref().map(|d| d.enabled).unwrap_or(false) {
        let anomaly_state = ipc_state.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(3600));
            let detector = permissions::AnomalyDetector::new();
            loop {
                interval.tick().await;
                let mut s = anomaly_state.lock().await;
                // Anomaly detection
                if let Some(ref db) = s.event_db {
                    let findings = detector.detect_anomalies(db);
                    for finding in &findings {
                        warn!("[ANOMALY] {}", finding);
                    }
                    if !findings.is_empty() {
                        info!("Anomaly detection: {} finding(s)", findings.len());
                    }
                }
                // Phase 11: Periodic cleanup of expired grant accumulator entries
                s.grant_accumulator.cleanup_expired();
            }
        });
    }

    // Step 12: Set up SIGHUP handler for config reload (Phase 8: includes alerting reload)
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
                    // Phase 8 Fix 15: Note that alerting outputs would need
                    // AlertSender wrapped in Arc<RwLock> for full hot-reload.
                    // For now, config changes (agent policies, permissions, dashboard)
                    // are reloaded. Alerting output changes still require restart.
                    if new_config.alerting.is_some() {
                        info!("Note: alerting output changes require daemon restart");
                    }
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

    let mut readonly_prefixes: LpmTrie<MapData, [u8; MAX_FILENAME_LEN], u8> =
        LpmTrie::try_from(bpf.take_map("READONLY_PREFIXES").context("READONLY_PREFIXES map not found")?)?;

    let mut readonly_exact: HashMap<MapData, [u8; MAX_FILENAME_LEN], u8> =
        HashMap::try_from(bpf.take_map("READONLY_EXACT").context("READONLY_EXACT map not found")?)?;

    let mut deny_count = 0u32;
    let mut allow_count = 0u32;
    let mut readonly_count = 0u32;

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

        // Insert deny rules (shared across all agents).
        // Also insert symlink alternates (/usr/bin/x → /bin/x) because eBPF sees
        // the raw syscall path which may use either form on merged-usr systems.
        for pattern in &agent.file_access.deny {
            let patterns_to_insert: Vec<String> = {
                let mut v = vec![pattern.clone()];
                let base = pattern.trim_end_matches("/**");
                for alt in symlink_alternates(base) {
                    if pattern.ends_with("/**") {
                        v.push(format!("{}/**", alt.trim_end_matches('/')));
                    } else {
                        v.push(alt);
                    }
                }
                v
            };
            for p in &patterns_to_insert {
                if p.ends_with("/**") {
                    let prefix = format!("{}/", &p[..p.len() - 3]);
                    let key = path_to_lpm_key(prefix.as_bytes());
                    let _ = deny_prefixes.insert(&key, 1, 0);
                    let exact = path_to_map_key(p[..p.len() - 3].as_bytes());
                    let _ = deny_exact.insert(exact, 1, 0);
                } else {
                    let key = path_to_map_key(p.as_bytes());
                    let _ = deny_exact.insert(key, 1, 0);
                }
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

        // Insert read-only rules: allowed for reads, blocked for destructive ops
        for pattern in &agent.file_access.read_only {
            if pattern.ends_with("/**") {
                let prefix = format!("{}/", &pattern[..pattern.len() - 3]);
                let key = path_to_lpm_key(prefix.as_bytes());
                readonly_prefixes.insert(&key, 1, 0)?;
                let exact = path_to_map_key(pattern[..pattern.len() - 3].as_bytes());
                let _ = readonly_exact.insert(exact, 1, 0);
            } else {
                let key = path_to_map_key(pattern.as_bytes());
                readonly_exact.insert(key, 1, 0)?;
            }
            readonly_count += 1;
        }
    }

    info!(
        "Loaded {} deny rules, {} allow rules, {} read_only rules into BPF",
        deny_count, allow_count, readonly_count
    );

    // Return map handles for dynamic updates (temporary grants)
    Ok(PolicyBpfMaps {
        allow_prefixes,
        allow_exact,
    })
}

/// Populate exec enforcement BPF maps from config.
fn populate_exec_enforcement_maps(bpf: &mut Ebpf, config: &Config) -> Result<()> {
    let mut exec_deny_prefixes: LpmTrie<MapData, [u8; MAX_FILENAME_LEN], u8> =
        LpmTrie::try_from(bpf.take_map("EXEC_DENY_PREFIXES").context("EXEC_DENY_PREFIXES map not found")?)?;

    let mut exec_deny_exact: HashMap<MapData, [u8; MAX_FILENAME_LEN], u8> =
        HashMap::try_from(bpf.take_map("EXEC_DENY_EXACT").context("EXEC_DENY_EXACT map not found")?)?;

    let mut exec_allow_prefixes: LpmTrie<MapData, [u8; MAX_FILENAME_LEN], u8> =
        LpmTrie::try_from(bpf.take_map("EXEC_ALLOW_PREFIXES").context("EXEC_ALLOW_PREFIXES map not found")?)?;

    let mut exec_allow_exact: HashMap<MapData, [u8; MAX_FILENAME_LEN], u8> =
        HashMap::try_from(bpf.take_map("EXEC_ALLOW_EXACT").context("EXEC_ALLOW_EXACT map not found")?)?;

    let mut exec_default_action: HashMap<MapData, [u8; 16], u8> =
        HashMap::try_from(bpf.take_map("EXEC_DEFAULT_ACTION").context("EXEC_DEFAULT_ACTION map not found")?)?;

    let exec_cgroup_default: HashMap<MapData, u64, u8> =
        HashMap::try_from(bpf.take_map("EXEC_CGROUP_DEFAULT_ACTION").context("EXEC_CGROUP_DEFAULT_ACTION map not found")?)?;

    // Also take the PENDING_EXEC_DENY map so aya owns it
    let _pending_exec_deny: HashMap<MapData, u64, u8> =
        HashMap::try_from(bpf.take_map("PENDING_EXEC_DENY").context("PENDING_EXEC_DENY map not found")?)?;

    let mut deny_count = 0u32;
    let mut allow_count = 0u32;

    for agent in &config.agents {
        let exec_policy = match &agent.exec_policy {
            Some(p) => p,
            None => continue,
        };

        // Set default action for comm-based agents
        if agent.effective_identity() == "comm" {
            let comm_key = comm_to_key(agent.effective_process_name());
            let default_val = if exec_policy.default == "deny" { 0u8 } else { 1u8 };
            exec_default_action.insert(comm_key, default_val, 0)?;
        }

        // Insert exec deny rules + symlink alternates (/usr/bin/x → /bin/x, /usr/sbin/x, /sbin/x)
        for pattern in &exec_policy.deny {
            let patterns_to_insert: Vec<String> = {
                let mut v = vec![pattern.clone()];
                let base = pattern.trim_end_matches("/**");
                for alt in symlink_alternates(base) {
                    if pattern.ends_with("/**") {
                        v.push(format!("{}/**", alt.trim_end_matches('/')));
                    } else {
                        v.push(alt);
                    }
                }
                v
            };
            for p in &patterns_to_insert {
                if p.ends_with("/**") {
                    let prefix = format!("{}/", &p[..p.len() - 3]);
                    let key = path_to_lpm_key(prefix.as_bytes());
                    let _ = exec_deny_prefixes.insert(&key, 1, 0);
                    let exact = path_to_map_key(p[..p.len() - 3].as_bytes());
                    let _ = exec_deny_exact.insert(exact, 1, 0);
                } else {
                    let key = path_to_map_key(p.as_bytes());
                    let _ = exec_deny_exact.insert(key, 1, 0);
                }
            }
            deny_count += 1;
        }

        for pattern in &exec_policy.allow {
            if pattern.ends_with("/**") {
                let prefix = format!("{}/", &pattern[..pattern.len() - 3]);
                let key = path_to_lpm_key(prefix.as_bytes());
                exec_allow_prefixes.insert(&key, 1, 0)?;
                let exact = path_to_map_key(pattern[..pattern.len() - 3].as_bytes());
                let _ = exec_allow_exact.insert(exact, 1, 0);
            } else {
                let key = path_to_map_key(pattern.as_bytes());
                exec_allow_exact.insert(key, 1, 0)?;
            }
            allow_count += 1;
        }
    }

    // Phase 8 Fix 8: Always deny exec of /memfd: paths (memfd_create attack vector)
    let memfd_prefix = "/memfd:";
    let memfd_key = path_to_lpm_key(memfd_prefix.as_bytes());
    if let Err(e) = exec_deny_prefixes.insert(&memfd_key, 1, 0) {
        warn!("Failed to add /memfd: exec deny prefix: {}", e);
    } else {
        deny_count += 1;
        info!("Default exec deny: /memfd:* (memfd_create attack prevention)");
    }

    // Store cgroup exec defaults (set dynamically during registration)
    // For now, just take the map. Cgroup exec defaults will be set in IPC register handler.
    let _ = exec_cgroup_default;

    info!(
        "Loaded {} exec deny rules, {} exec allow rules into BPF",
        deny_count, allow_count
    );

    Ok(())
}

/// Phase 9: Populate network enforcement BPF maps from config.
/// Creates port-based deny/allow maps evaluated in-kernel by the sys_enter_connect tracepoint.
fn populate_net_enforcement_maps(bpf: &mut Ebpf, config: &Config) -> Result<()> {
    let mut net_deny_ports: HashMap<MapData, u32, u8> = HashMap::try_from(
        bpf.take_map("NET_DENY_PORTS")
            .context("NET_DENY_PORTS map not found")?,
    )?;

    let mut net_allow_ports: HashMap<MapData, u32, u8> = HashMap::try_from(
        bpf.take_map("NET_ALLOW_PORTS")
            .context("NET_ALLOW_PORTS map not found")?,
    )?;

    let mut net_default_action: HashMap<MapData, [u8; 16], u8> = HashMap::try_from(
        bpf.take_map("NET_DEFAULT_ACTION")
            .context("NET_DEFAULT_ACTION map not found")?,
    )?;

    // Take cgroup net default map (set dynamically during registration)
    let _net_cgroup_default: HashMap<MapData, u64, u8> = HashMap::try_from(
        bpf.take_map("NET_CGROUP_DEFAULT_ACTION")
            .context("NET_CGROUP_DEFAULT_ACTION map not found")?,
    )?;

    let mut deny_count = 0u32;
    let mut allow_count = 0u32;

    for agent in &config.agents {
        let net_policy = match &agent.network_policy {
            Some(p) => p,
            None => continue,
        };

        // Set default action for comm-based agents
        if agent.effective_identity() == "comm" {
            let comm_key = comm_to_key(agent.effective_process_name());
            let default_val = if net_policy.default == "deny" { 0u8 } else { 1u8 };
            net_default_action.insert(comm_key, default_val, 0)?;
        }

        // Insert deny ports
        for &port in &net_policy.deny_ports {
            let port_key = port as u32;
            net_deny_ports.insert(port_key, 1, 0)?;
            deny_count += 1;
        }

        // Insert allow ports
        for &port in &net_policy.allow_ports {
            let port_key = port as u32;
            net_allow_ports.insert(port_key, 1, 0)?;
            allow_count += 1;
        }
    }

    info!(
        "Loaded {} net deny ports, {} net allow ports into BPF",
        deny_count, allow_count
    );

    Ok(())
}

/// Phase 8: Populate the dynamic linker detection map.
/// Known dynamic linkers: when eBPF sees execve of one of these, it reads argv[1]
/// to find the real binary being executed.
fn populate_dynamic_linkers(bpf: &mut Ebpf) -> Result<()> {
    let mut linkers: HashMap<MapData, [u8; MAX_FILENAME_LEN], u8> = HashMap::try_from(
        bpf.take_map("DYNAMIC_LINKERS")
            .context("DYNAMIC_LINKERS map not found")?,
    )?;

    let known_linkers = [
        // Fedora/RHEL multilib
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/ld-linux.so.2",
        "/lib/ld-linux-aarch64.so.1",
        "/usr/lib64/ld-linux-x86-64.so.2",
        "/usr/lib/ld-linux.so.2",
        "/usr/lib/ld-linux-aarch64.so.1",
        // Debian/Ubuntu multiarch
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
        "/lib/i386-linux-gnu/ld-linux.so.2",
        // musl libc (Alpine, Void)
        "/lib/ld-musl-x86_64.so.1",
        "/lib/ld-musl-aarch64.so.1",
    ];

    let mut count = 0;
    for linker in &known_linkers {
        let key = path_to_map_key(linker.as_bytes());
        if linkers.insert(key, 1, 0).is_ok() {
            count += 1;
        }
    }

    info!("Populated {} dynamic linker paths for detection", count);
    Ok(())
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

/// Generate ALL symlink-equivalent paths for merged-usr systems.
/// On Fedora/Arch, /bin → /usr/bin, /sbin → /usr/sbin, /lib → /usr/lib, /lib64 → /usr/lib64.
/// Additionally, /usr/bin and /usr/sbin may overlap (some distros put binaries in both).
/// eBPF sees the raw syscall path — we must deny ALL possible paths for a binary.
/// Returns all alternate paths that exist on this system.
fn symlink_alternates(path: &str) -> Vec<String> {
    let mut results = Vec::new();

    // Extract the binary name from the path
    let binary_name = match path.rsplit_once('/') {
        Some((_, name)) => name,
        None => return results,
    };

    // All possible bin/sbin directories on merged-usr systems
    let bin_dirs = ["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/local/bin/"];
    let lib_dirs = ["/usr/lib/", "/lib/", "/usr/lib64/", "/lib64/"];

    // Check if this is a binary path (under a bin directory)
    let is_bin = bin_dirs.iter().any(|d| path.starts_with(d));
    let is_lib = lib_dirs.iter().any(|d| path.starts_with(d));

    if is_bin {
        // For binaries: check all bin/sbin directories for the same binary name
        for dir in &bin_dirs {
            let candidate = format!("{}{}", dir, binary_name);
            if candidate != path && std::path::Path::new(&candidate).exists() {
                results.push(candidate);
            }
        }
    } else if is_lib {
        // For libraries: standard /usr/lib ↔ /lib mapping
        let mappings: &[(&str, &str)] = &[
            ("/usr/lib/", "/lib/"),
            ("/usr/lib64/", "/lib64/"),
            ("/lib/", "/usr/lib/"),
            ("/lib64/", "/usr/lib64/"),
        ];
        for (from, to) in mappings {
            if let Some(rest) = path.strip_prefix(from) {
                let alt = format!("{}{}", to, rest);
                if alt != path && std::path::Path::new(to).exists() {
                    results.push(alt);
                }
            }
        }
    }

    results
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

fn load_lsm(bpf: &mut Ebpf, prog_name: &str, hook_name: &str) -> Result<()> {
    let btf = Btf::from_sys_fs().context("Failed to load BTF from /sys/kernel/btf/vmlinux")?;

    let program: &mut Lsm = bpf
        .program_mut(prog_name)
        .with_context(|| format!("LSM program '{}' not found", prog_name))?
        .try_into()
        .with_context(|| format!("'{}' is not an LSM program", prog_name))?;

    program
        .load(hook_name, &btf)
        .with_context(|| format!("Failed to load LSM program '{}' (hook: {})", prog_name, hook_name))?;

    Ok(())
}

fn attach_lsm(bpf: &mut Ebpf, prog_name: &str) -> Result<()> {
    let program: &mut Lsm = bpf
        .program_mut(prog_name)
        .with_context(|| format!("LSM program '{}' not found", prog_name))?
        .try_into()
        .with_context(|| format!("'{}' is not an LSM program", prog_name))?;

    program.attach().with_context(|| format!("Failed to attach LSM program '{}'", prog_name))?;

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

fn setup_net_event_readers(
    bpf: &mut Ebpf,
    cpus: &[u32],
    config: &Config,
    alert_tx: AlertSender,
) -> Result<()> {
    let mut perf_array = AsyncPerfEventArray::try_from(
        bpf.take_map("NET_EVENTS")
            .context("NET_EVENTS map not found")?,
    )?;

    for &cpu_id in cpus {
        let mut buf = perf_array
            .open(cpu_id, None)
            .with_context(|| format!("Failed to open net perf buffer for CPU {}", cpu_id))?;

        let config = config.clone();
        let alert_tx = alert_tx.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<NetworkEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        error!("Error reading net events from CPU {}: {}", cpu_id, e);
                        continue;
                    }
                };

                if events.lost > 0 {
                    warn!("Lost {} net events on CPU {}", events.lost, cpu_id);
                    alert_tx.metrics.events_lost.inc_by(events.lost as u64);
                }

                for i in 0..events.read {
                    let event = unsafe {
                        (buffers[i].as_ptr() as *const NetworkEvent).read_unaligned()
                    };
                    process_net_event(&event, &config, &alert_tx);
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
    // O(1) lookup via pre-built comm_cache HashMap (built in load_config, rebuilt on SIGHUP)
    if let Some(&idx) = config.comm_cache.get(comm) {
        return config.agents.get(idx);
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
    let raw_filename = std::str::from_utf8(event.filename_bytes()).unwrap_or("<invalid-utf8>");
    let comm = std::str::from_utf8(event.comm_bytes()).unwrap_or("<unknown>");
    let access_mode = decode_open_flags(event.flags);

    if raw_filename.is_empty() {
        return;
    }

    // Phase 8: Log path truncation warnings
    if event.status_flags & EVENT_FLAG_TRUNCATED != 0 {
        warn!(
            "[TRUNCATED] pid={} comm='{}' file='{}' (path exceeded {} bytes, denied by default in enforce mode)",
            event.tgid, comm, raw_filename, MAX_FILENAME_LEN
        );
    }

    // Normalize path to catch bypass attempts (/proc/self/root, .., etc.)
    let filename = normalize_path(raw_filename);
    let filename = filename.as_str();

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
    let raw_filename = std::str::from_utf8(event.filename_bytes()).unwrap_or("<invalid-utf8>");
    let comm = std::str::from_utf8(event.comm_bytes()).unwrap_or("<unknown>");
    let enforce_mode = config.global.mode == "enforce";

    let filename = normalize_path(raw_filename);
    let filename = filename.as_str();

    let agent_config = find_agent_for_event(config, comm);

    match agent_config {
        Some(agent) => {
            let allowed = match &agent.exec_policy {
                Some(policy) => check_exec_policy(policy, filename),
                None => true,
            };

            let mode_tag = if enforce_mode { "ENFORCE" } else { "MONITOR" };

            let (severity, action) = if allowed {
                (Severity::Info, Action::Allow)
            } else if enforce_mode {
                (Severity::Critical, Action::Blocked)
            } else {
                (Severity::Warning, Action::Deny)
            };

            if allowed {
                debug!(
                    "[EXEC|ALLOW] agent='{}' pid={} comm='{}' cmd='{}'",
                    agent.name, event.tgid, comm, filename
                );
            } else if enforce_mode {
                warn!(
                    "[EXEC|BLOCKED|{}] agent='{}' pid={} comm='{}' cmd='{}'",
                    mode_tag, agent.name, event.tgid, comm, filename
                );
            } else {
                warn!(
                    "[EXEC|DENY|{}] agent='{}' pid={} comm='{}' cmd='{}' (not blocked)",
                    mode_tag, agent.name, event.tgid, comm, filename
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

fn process_net_event(event: &NetworkEvent, config: &Config, alert_tx: &AlertSender) {
    let comm = std::str::from_utf8(event.comm_bytes()).unwrap_or("<unknown>");
    let enforce_mode = config.global.mode == "enforce" || config.global.mode == "strict";

    let dest_addr = if event.family == 2 {
        // AF_INET
        let octets = event.dest_addr4.to_ne_bytes();
        format!("{}.{}.{}.{}:{}", octets[0], octets[1], octets[2], octets[3], event.dest_port)
    } else {
        // AF_INET6
        format!("[{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}]:{}",
            u16::from_be_bytes([event.dest_addr6[0], event.dest_addr6[1]]),
            u16::from_be_bytes([event.dest_addr6[2], event.dest_addr6[3]]),
            u16::from_be_bytes([event.dest_addr6[4], event.dest_addr6[5]]),
            u16::from_be_bytes([event.dest_addr6[6], event.dest_addr6[7]]),
            u16::from_be_bytes([event.dest_addr6[8], event.dest_addr6[9]]),
            u16::from_be_bytes([event.dest_addr6[10], event.dest_addr6[11]]),
            u16::from_be_bytes([event.dest_addr6[12], event.dest_addr6[13]]),
            u16::from_be_bytes([event.dest_addr6[14], event.dest_addr6[15]]),
            event.dest_port)
    };

    let agent_config = find_agent_for_event(config, comm);

    match agent_config {
        Some(agent) => {
            let allowed = match &agent.network_policy {
                Some(policy) => check_network_policy(policy, event.dest_port),
                None => true,
            };

            let mode_tag = if enforce_mode { "ENFORCE" } else { "MONITOR" };

            // Phase 9: In enforce mode, denied connections are actually blocked
            // by the LSM socket_connect hook (returns -ECONNREFUSED)
            let (severity, action) = if allowed {
                (Severity::Info, Action::Allow)
            } else if enforce_mode {
                (Severity::Critical, Action::Blocked)
            } else {
                (Severity::Warning, Action::Deny)
            };

            if allowed {
                debug!(
                    "[NET|ALLOW] agent='{}' pid={} comm='{}' dest='{}'",
                    agent.name, event.tgid, comm, dest_addr
                );
            } else if enforce_mode {
                warn!(
                    "[NET|BLOCKED|{}] agent='{}' pid={} comm='{}' dest='{}'",
                    mode_tag, agent.name, event.tgid, comm, dest_addr
                );
            } else {
                warn!(
                    "[NET|DENY|{}] agent='{}' pid={} comm='{}' dest='{}' (not blocked)",
                    mode_tag, agent.name, event.tgid, comm, dest_addr
                );
            }

            alert_tx.send(AlertEvent {
                timestamp: chrono::Utc::now(),
                severity,
                event_type: EventType::NetworkConnect,
                action,
                agent_name: agent.name.clone(),
                pid: event.tgid,
                comm: comm.to_string(),
                path: dest_addr,
                access_mode: format!("port:{}", event.dest_port),
                identity_method: agent.effective_identity().to_string(),
                policy_mode: config.global.mode.clone(),
            });
        }
        None => {
            debug!(
                "[NET|UNKNOWN] pid={} comm='{}' dest='{}'",
                event.tgid, comm, dest_addr
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
