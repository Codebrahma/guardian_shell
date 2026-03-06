mod config;

use anyhow::{Context, Result};
use aya::{
    maps::{Array, AsyncPerfEventArray, HashMap, MapData},
    programs::{Lsm, TracePoint},
    util::online_cpus,
    Btf, Ebpf,
};
use bytes::BytesMut;
use clap::Parser;
use guardian_common::{ExecEvent, FileAccessEvent, PolicyRule, MAX_POLICY_RULES};
use log::{debug, error, info, warn};
use std::path::PathBuf;
use std::time::Duration;
use tokio::{signal, time};

use crate::config::{check_exec_policy, check_file_policy, pattern_to_policy_rule, Config};

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
}

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
    let enforce_mode = config.global.mode == "enforce";
    let rescan_interval = config.global.pid_rescan_interval;

    info!(
        "Mode: {} | {} agent(s) configured | PID rescan: {}s",
        config.global.mode,
        config.agents.len(),
        rescan_interval
    );
    for agent in &config.agents {
        info!(
            "  Agent '{}': process='{}', default={}, allow={}, deny={}, children={}",
            agent.name,
            agent.process_name,
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

    // Step 3: Populate BPF Maps
    populate_watched_comms(&mut bpf, &config)?;

    if enforce_mode {
        populate_enforcement_maps(&mut bpf, &config)?;
        info!("Enforcement maps populated");
    }

    // Step 4: Attach eBPF Programs

    // 4a: File access monitoring tracepoint (always attached)
    attach_tracepoint(&mut bpf, "guardian_file_open", "syscalls", "sys_enter_openat")?;
    info!("Attached: syscalls/sys_enter_openat (file monitoring)");

    // 4b: Exec monitoring tracepoint
    attach_tracepoint(
        &mut bpf,
        "guardian_exec_monitor",
        "syscalls",
        "sys_enter_execve",
    )?;
    info!("Attached: syscalls/sys_enter_execve (exec monitoring)");

    // 4c: Process fork tracking
    attach_tracepoint(
        &mut bpf,
        "guardian_fork_track",
        "sched",
        "sched_process_fork",
    )?;
    info!("Attached: sched/sched_process_fork (child tracking)");

    // 4d: Process exit cleanup
    attach_tracepoint(
        &mut bpf,
        "guardian_exit_track",
        "sched",
        "sched_process_exit",
    )?;
    info!("Attached: sched/sched_process_exit (cleanup)");

    // 4e: LSM enforcement (only in enforce mode)
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

    // Step 5: Set Up Event Processing
    let cpus = online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))?;
    info!("Setting up event readers for {} CPUs", cpus.len());

    // 5a: File access event readers
    setup_file_event_readers(&mut bpf, &cpus, &config)?;

    // 5b: Exec event readers
    setup_exec_event_readers(&mut bpf, &cpus, &config)?;

    // Step 6: Periodic PID Rescanning
    let rescan_config = config.clone();
    let rescan_handle = tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(rescan_interval));
        loop {
            interval.tick().await;
            // Log discovered processes (the BPF program uses comm-based matching,
            // so we don't need to update PID maps, but this helps with visibility)
            for agent in &rescan_config.agents {
                match find_pids_by_name(&agent.process_name) {
                    Ok(pids) if !pids.is_empty() => {
                        debug!(
                            "PID rescan: agent '{}' has {} active process(es): {:?}",
                            agent.name,
                            pids.len(),
                            pids
                        );
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

    // Step 7: Wait for Shutdown
    info!("==========================================================");
    info!(
        "Guardian Shell is running ({} mode). Monitoring {} agent(s).",
        config.global.mode,
        config.agents.len()
    );
    info!("Press Ctrl+C to stop.");
    info!("==========================================================");

    signal::ctrl_c()
        .await
        .context("Failed to listen for Ctrl+C signal")?;

    rescan_handle.abort();
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
        let comm_key = comm_to_key(&agent.process_name);
        watched_comms
            .insert(comm_key, 1, 0)
            .with_context(|| format!("Failed to insert comm '{}'", agent.process_name))?;
        info!("Watching process name '{}'", agent.process_name);
    }

    Ok(())
}

fn populate_enforcement_maps(bpf: &mut Ebpf, config: &Config) -> Result<()> {
    // Populate ENFORCE_COMMS
    let mut enforce_comms: HashMap<MapData, [u8; 16], u8> =
        HashMap::try_from(bpf.take_map("ENFORCE_COMMS").context("ENFORCE_COMMS map not found")?)?;

    // Populate DEFAULT_ACTION
    let mut default_action: HashMap<MapData, [u8; 16], u8> =
        HashMap::try_from(bpf.take_map("DEFAULT_ACTION").context("DEFAULT_ACTION map not found")?)?;

    // Collect all deny and allow rules across agents
    let mut deny_rules: Vec<PolicyRule> = Vec::new();
    let mut allow_rules: Vec<PolicyRule> = Vec::new();

    for agent in &config.agents {
        let comm_key = comm_to_key(&agent.process_name);

        enforce_comms.insert(comm_key, 1, 0)?;

        let default_val = if agent.file_access.default == "deny" {
            0u8
        } else {
            1u8
        };
        default_action.insert(comm_key, default_val, 0)?;

        for pattern in &agent.file_access.deny {
            if deny_rules.len() >= MAX_POLICY_RULES {
                warn!("Maximum deny rules ({}) reached, skipping: {}", MAX_POLICY_RULES, pattern);
                break;
            }
            deny_rules.push(pattern_to_policy_rule(pattern));
        }

        for pattern in &agent.file_access.allow {
            if allow_rules.len() >= MAX_POLICY_RULES {
                warn!(
                    "Maximum allow rules ({}) reached, skipping: {}",
                    MAX_POLICY_RULES, pattern
                );
                break;
            }
            allow_rules.push(pattern_to_policy_rule(pattern));
        }
    }

    // Populate DENY_RULES array
    let mut deny_arr: Array<MapData, PolicyRule> =
        Array::try_from(bpf.take_map("DENY_RULES").context("DENY_RULES map not found")?)?;
    for (i, rule) in deny_rules.iter().enumerate() {
        deny_arr.set(i as u32, *rule, 0)?;
    }

    let mut deny_count: Array<MapData, u32> = Array::try_from(
        bpf.take_map("DENY_RULE_COUNT")
            .context("DENY_RULE_COUNT map not found")?,
    )?;
    deny_count.set(0, deny_rules.len() as u32, 0)?;
    info!("Loaded {} deny rules into BPF", deny_rules.len());

    // Populate ALLOW_RULES array
    let mut allow_arr: Array<MapData, PolicyRule> =
        Array::try_from(bpf.take_map("ALLOW_RULES").context("ALLOW_RULES map not found")?)?;
    for (i, rule) in allow_rules.iter().enumerate() {
        allow_arr.set(i as u32, *rule, 0)?;
    }

    let mut allow_count: Array<MapData, u32> = Array::try_from(
        bpf.take_map("ALLOW_RULE_COUNT")
            .context("ALLOW_RULE_COUNT map not found")?,
    )?;
    allow_count.set(0, allow_rules.len() as u32, 0)?;
    info!("Loaded {} allow rules into BPF", allow_rules.len());

    Ok(())
}

// =============================================================================
// Program Attachment
// =============================================================================

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
        .load()
        .with_context(|| format!("Failed to load '{}'", prog_name))?;

    program
        .attach(category, event)
        .with_context(|| format!("Failed to attach '{}' to {}/{}", prog_name, category, event))?;

    Ok(())
}

fn attach_lsm(bpf: &mut Ebpf) -> Result<()> {
    let btf = Btf::from_sys_fs().context("Failed to load BTF from /sys/kernel/btf/vmlinux")?;

    let program: &mut Lsm = bpf
        .program_mut("guardian_enforce_file_open")
        .context("LSM program 'guardian_enforce_file_open' not found")?
        .try_into()
        .context("'guardian_enforce_file_open' is not an LSM program")?;

    program
        .load("file_open", &btf)
        .context("Failed to load LSM program")?;

    program.attach().context("Failed to attach LSM program")?;

    Ok(())
}

// =============================================================================
// Event Processing Setup
// =============================================================================

fn setup_file_event_readers(bpf: &mut Ebpf, cpus: &[u32], config: &Config) -> Result<()> {
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
                }

                for i in 0..events.read {
                    let event = unsafe {
                        (buffers[i].as_ptr() as *const FileAccessEvent).read_unaligned()
                    };
                    process_file_event(&event, &config, enforce_mode);
                }
            }
        });
    }

    Ok(())
}

fn setup_exec_event_readers(bpf: &mut Ebpf, cpus: &[u32], config: &Config) -> Result<()> {
    let mut perf_array = AsyncPerfEventArray::try_from(
        bpf.take_map("EXEC_EVENTS")
            .context("EXEC_EVENTS map not found")?,
    )?;

    for &cpu_id in cpus {
        let mut buf = perf_array
            .open(cpu_id, None)
            .with_context(|| format!("Failed to open exec perf buffer for CPU {}", cpu_id))?;

        let config = config.clone();

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
                }

                for i in 0..events.read {
                    let event = unsafe {
                        (buffers[i].as_ptr() as *const ExecEvent).read_unaligned()
                    };
                    process_exec_event(&event, &config);
                }
            }
        });
    }

    Ok(())
}

// =============================================================================
// Event Processing
// =============================================================================

fn process_file_event(event: &FileAccessEvent, config: &Config, enforce_mode: bool) {
    let filename = std::str::from_utf8(event.filename_bytes()).unwrap_or("<invalid-utf8>");
    let comm = std::str::from_utf8(event.comm_bytes()).unwrap_or("<unknown>");
    let access_mode = decode_open_flags(event.flags);

    let agent_config = config.agents.iter().find(|a| a.process_name == comm);

    match agent_config {
        Some(agent) => {
            let allowed = check_file_policy(&agent.file_access, filename);
            let mode_tag = if enforce_mode { "ENFORCE" } else { "MONITOR" };

            if allowed {
                info!(
                    "[ALLOW] agent='{}' pid={} file='{}' mode={}",
                    agent.name, event.tgid, filename, access_mode
                );
            } else if enforce_mode {
                warn!(
                    "[BLOCKED|{}] agent='{}' pid={} file='{}' mode={}",
                    mode_tag, agent.name, event.tgid, filename, access_mode
                );
            } else {
                warn!(
                    "[DENY|{}] agent='{}' pid={} file='{}' mode={} (not blocked)",
                    mode_tag, agent.name, event.tgid, filename, access_mode
                );
            }
        }
        None => {
            // Likely a child process of a watched agent
            debug!(
                "[CHILD] pid={} comm='{}' file='{}' mode={}",
                event.tgid, comm, filename, access_mode
            );
        }
    }
}

fn process_exec_event(event: &ExecEvent, config: &Config) {
    let filename = std::str::from_utf8(event.filename_bytes()).unwrap_or("<invalid-utf8>");
    let comm = std::str::from_utf8(event.comm_bytes()).unwrap_or("<unknown>");

    let agent_config = config.agents.iter().find(|a| a.process_name == comm);

    match agent_config {
        Some(agent) => {
            let allowed = match &agent.exec_policy {
                Some(policy) => check_exec_policy(policy, filename),
                None => true, // No exec policy = allow all
            };

            if allowed {
                info!(
                    "[EXEC|ALLOW] agent='{}' pid={} cmd='{}'",
                    agent.name, event.tgid, filename
                );
            } else {
                warn!(
                    "[EXEC|DENY] agent='{}' pid={} cmd='{}'",
                    agent.name, event.tgid, filename
                );
            }
        }
        None => {
            debug!(
                "[EXEC|CHILD] pid={} comm='{}' cmd='{}'",
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
