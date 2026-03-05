// =============================================================================
// Guardian Shell - Userspace Daemon
// =============================================================================
//
// This is the main entry point for the Guardian Shell daemon. It orchestrates:
//
//   1. Configuration loading and validation
//   2. LLM agent process discovery
//   3. eBPF program loading and attachment
//   4. Real-time event processing and policy enforcement
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │                      ARCHITECTURE OVERVIEW                         │
// │                                                                    │
// │   config.toml ──→ [Config Parser] ──→ [Policy Engine]             │
// │                                            │                       │
// │   /proc/ ──→ [PID Discovery] ──→ [WATCHED_PIDS map]              │
// │                                            │                       │
// │                                    ┌───────┴───────┐              │
// │                                    │  eBPF Loader  │              │
// │                                    └───────┬───────┘              │
// │                                            │                       │
// │                             ┌──────────────┴──────────────┐       │
// │                             │   Linux Kernel (eBPF VM)    │       │
// │                             │   tracepoint/sys_enter_openat│      │
// │                             └──────────────┬──────────────┘       │
// │                                            │ perf events          │
// │                                    ┌───────┴───────┐              │
// │                                    │ Event Handler │              │
// │                                    │ (per-CPU)     │              │
// │                                    └───────┬───────┘              │
// │                                            │                       │
// │                                    ┌───────┴───────┐              │
// │                                    │  Policy Check │              │
// │                                    │  + Logging    │              │
// │                                    └───────────────┘              │
// └─────────────────────────────────────────────────────────────────────┘
//
// SECURITY REQUIREMENTS:
//   - Must run as root (or with CAP_BPF + CAP_PERFMON capabilities)
//   - The config file should be owned by root and not world-writable
//   - The eBPF program binary should be read-only

mod config;

use anyhow::{Context, Result};
use aya::{
    maps::{AsyncPerfEventArray, HashMap, MapData},
    programs::TracePoint,
    util::online_cpus,
    Ebpf,
};
// Note: aya-log-ebpf removed from eBPF program for verifier compatibility
use bytes::BytesMut;
use clap::Parser;
use guardian_common::FileAccessEvent;
use log::{debug, error, info, warn};
use std::path::PathBuf;
use tokio::signal;

use crate::config::{check_file_policy, Config};

// =============================================================================
// Command-Line Arguments
// =============================================================================

/// Guardian Shell - Security monitor for LLM agents using eBPF
///
/// Monitors file access by configured LLM agent processes and enforces
/// security policies defined in a TOML configuration file.
///
/// Examples:
///   sudo guardian --config config.toml
///   sudo RUST_LOG=debug guardian --config config.toml
#[derive(Parser, Debug)]
#[command(name = "guardian", version, about)]
struct Args {
    /// Path to the configuration file (TOML format)
    ///
    /// See config.toml.example for a documented example configuration.
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Path to the compiled eBPF program binary
    ///
    /// This is the output of `cargo xtask build-ebpf`. Defaults to the
    /// standard location in the target directory.
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
    // Initialize logging. Use RUST_LOG env var to control log level.
    // Example: RUST_LOG=debug sudo target/debug/guardian --config config.toml
    env_logger::init();

    let args = Args::parse();

    // =========================================================================
    // Step 1: Load Configuration
    // =========================================================================
    info!("Loading configuration from: {}", args.config.display());
    let config = config::load_config(&args.config)?;
    info!(
        "Configuration loaded: {} agent(s) configured",
        config.agents.len()
    );
    for agent in &config.agents {
        info!(
            "  Agent '{}': watching process '{}', default={}, {} allow rules, {} deny rules",
            agent.name,
            agent.process_name,
            agent.file_access.default,
            agent.file_access.allow.len(),
            agent.file_access.deny.len(),
        );
    }

    // =========================================================================
    // Step 2: Load eBPF Program
    // =========================================================================
    //
    // Ebpf::load_file() does several things:
    //   1. Reads the compiled eBPF ELF binary
    //   2. Parses the ELF sections to find BPF programs and maps
    //   3. Creates the BPF maps in the kernel
    //   4. Relocates the programs to reference the correct maps
    //
    // The eBPF program is NOT yet attached to any kernel hook at this point.
    // That happens in Step 4.
    info!(
        "Loading eBPF program from: {}",
        args.ebpf_program.display()
    );
    let mut bpf = Ebpf::load_file(&args.ebpf_program).with_context(|| {
        format!(
            "Failed to load eBPF program from '{}'. \
             Make sure you've built it with: cargo xtask build-ebpf --release",
            args.ebpf_program.display()
        )
    })?;
    info!("eBPF program loaded successfully");

    // Initialize eBPF logging (forwards log messages from the eBPF program)
    // This is optional - if it fails, we just won't see eBPF-side log messages
    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        warn!(
            "Failed to initialize eBPF logger (non-critical): {}. \
             eBPF-side log messages won't be visible.",
            e
        );
    }

    // =========================================================================
    // Step 3: Register Watched Process Names
    // =========================================================================
    //
    // We populate the WATCHED_COMMS eBPF map with process names from config.
    // The eBPF program matches by comm name directly in the kernel, so even
    // short-lived processes (like `cat`) are caught during their syscall.
    let mut watched_comms: HashMap<MapData, [u8; 16], u8> =
        HashMap::try_from(bpf.take_map("WATCHED_COMMS").context(
            "Failed to find WATCHED_COMMS map in eBPF program.",
        )?)?;

    for agent in &config.agents {
        // Convert process_name to a null-padded [u8; 16] comm key
        let mut comm_key = [0u8; 16];
        let name_bytes = agent.process_name.as_bytes();
        let copy_len = core::cmp::min(name_bytes.len(), 15); // 15 chars + null
        comm_key[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        watched_comms.insert(comm_key, 1, 0).with_context(|| {
            format!("Failed to insert comm '{}' into WATCHED_COMMS map", agent.process_name)
        })?;
        info!(
            "Watching process name '{}' for agent '{}'",
            agent.process_name, agent.name
        );
    }

    // =========================================================================
    // Step 4: Attach eBPF Program to Tracepoint
    // =========================================================================
    //
    // Now we attach the eBPF program to the sys_enter_openat tracepoint.
    // After this, the eBPF program will run every time ANY process on the
    // system calls openat().
    //
    // The program flow is:
    //   program_mut("guardian_file_open")  → Get the program by its function name
    //   .load()                            → Load it into the BPF VM
    //   .attach("syscalls", "sys_enter_openat") → Attach to the tracepoint
    //
    // "syscalls" is the tracepoint category, "sys_enter_openat" is the event.
    // You can see all available tracepoints at:
    //   /sys/kernel/debug/tracing/events/
    let program: &mut TracePoint = bpf
        .program_mut("guardian_file_open")
        .context("Failed to find 'guardian_file_open' program in eBPF binary")?
        .try_into()
        .context("'guardian_file_open' is not a TracePoint program")?;

    program
        .load()
        .context("Failed to load eBPF program into kernel (is BPF enabled?)")?;

    program
        .attach("syscalls", "sys_enter_openat")
        .context(
            "Failed to attach to sys_enter_openat tracepoint. \
             Ensure CONFIG_FTRACE and CONFIG_BPF are enabled in your kernel.",
        )?;
    info!("eBPF program attached to syscalls/sys_enter_openat tracepoint");

    // =========================================================================
    // Step 5: Set Up Event Processing
    // =========================================================================
    //
    // We open the perf event array and spawn one async task per CPU to read
    // events. This is necessary because PerfEventArray has per-CPU buffers -
    // each CPU writes events to its own buffer, so we need a reader per CPU.
    //
    // The event processing flow:
    //   CPU perf buffer → read_events() → parse FileAccessEvent → check policy → log
    let mut perf_array = AsyncPerfEventArray::try_from(
        bpf.take_map("EVENTS")
            .context("Failed to find EVENTS map in eBPF program")?,
    )?;

    // Get the list of online CPUs
    let cpus = online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))?;
    info!("Setting up event readers for {} CPUs", cpus.len());

    // Spawn an async task for each CPU to process events
    for cpu_id in cpus {
        // Open the perf buffer for this CPU
        // The second argument (None) means use the default buffer size (usually 4 pages)
        let mut buf = perf_array
            .open(cpu_id, None)
            .with_context(|| format!("Failed to open perf buffer for CPU {}", cpu_id))?;

        // Clone the config so each task has its own copy
        let config = config.clone();

        // Spawn an async task to process events from this CPU
        tokio::spawn(async move {
            // Pre-allocate buffers for reading events.
            // We read up to 10 events at a time for efficiency.
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<FileAccessEvent>()))
                .collect::<Vec<_>>();

            loop {
                // Wait for events to arrive in the perf buffer.
                // This is an async operation - the task yields while waiting.
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        error!("Error reading events from CPU {}: {}", cpu_id, e);
                        continue;
                    }
                };

                // Log if any events were lost (buffer overflow)
                if events.lost > 0 {
                    warn!(
                        "Lost {} events on CPU {} (perf buffer overflow). \
                         Consider increasing buffer size or reducing event volume.",
                        events.lost, cpu_id
                    );
                }

                // Process each received event
                for i in 0..events.read {
                    // Parse the raw bytes into a FileAccessEvent struct.
                    //
                    // SAFETY: We trust the eBPF program to produce correctly
                    // formatted events (it uses the same struct definition from
                    // guardian-common). read_unaligned() is used because the
                    // perf buffer may not guarantee alignment.
                    let event = unsafe {
                        (buffers[i].as_ptr() as *const FileAccessEvent).read_unaligned()
                    };

                    process_event(&event, &config);
                }
            }
        });
    }

    // =========================================================================
    // Step 6: Wait for Shutdown Signal
    // =========================================================================
    //
    // The daemon runs until it receives Ctrl+C (SIGINT) or SIGTERM.
    // When the daemon exits, the eBPF program is automatically detached
    // from the tracepoint (the kernel cleans up BPF resources when the
    // file descriptors are closed).
    info!("==========================================================");
    info!("Guardian Shell is running. Monitoring {} agent(s).", config.agents.len());
    info!("Press Ctrl+C to stop.");
    info!("==========================================================");

    signal::ctrl_c()
        .await
        .context("Failed to listen for Ctrl+C signal")?;

    info!("Shutting down Guardian Shell...");
    info!("eBPF program detached. Monitoring stopped.");

    Ok(())
}

// =============================================================================
// Event Processing
// =============================================================================

/// Processes a single file access event from the eBPF program.
///
/// This function:
///   1. Extracts the filename and process name from the event
///   2. Finds the matching agent configuration
///   3. Checks the file access against the agent's policy
///   4. Logs the decision (ALLOW/DENY/MONITOR)
///
/// In future phases, this will also:
///   - Send alerts for policy violations
///   - Update real-time dashboard metrics
///   - Trigger automated responses (e.g., kill process on critical violations)
fn process_event(event: &FileAccessEvent, config: &Config) {
    // Extract the filename as a string
    let filename = std::str::from_utf8(event.filename_bytes()).unwrap_or("<invalid-utf8>");

    // Extract the process name as a string
    let comm = std::str::from_utf8(event.comm_bytes()).unwrap_or("<unknown>");

    // Decode open flags into a human-readable string
    let access_mode = decode_open_flags(event.flags);

    // Find the agent config that matches this process name
    let agent_config = config
        .agents
        .iter()
        .find(|a| a.process_name == comm);

    match agent_config {
        Some(agent) => {
            let allowed = check_file_policy(&agent.file_access, filename);
            if allowed {
                // File access is permitted by policy
                info!(
                    "[ALLOW] agent='{}' pid={} uid={} file='{}' mode={}",
                    agent.name, event.tgid, event.uid, filename, access_mode
                );
            } else {
                // POLICY VIOLATION: File access would be denied
                // In Phase 1, we only log. In future phases, we'll block at kernel level.
                warn!(
                    "[DENY] agent='{}' pid={} uid={} file='{}' mode={} \
                     (monitoring mode - access was NOT actually blocked)",
                    agent.name, event.tgid, event.uid, filename, access_mode
                );
            }
        }
        None => {
            // Process is watched but doesn't match any configured agent.
            // This shouldn't happen unless PID was added manually.
            debug!(
                "[MONITOR] pid={} comm='{}' uid={} file='{}' mode={}",
                event.tgid, comm, event.uid, filename, access_mode
            );
        }
    }
}

/// Decodes openat() flags into a human-readable string.
///
/// Common flags (from fcntl.h):
///   O_RDONLY    = 0x0000  (read only)
///   O_WRONLY    = 0x0001  (write only)
///   O_RDWR      = 0x0002  (read/write)
///   O_CREAT     = 0x0040  (create if not exists)
///   O_TRUNC     = 0x0200  (truncate to zero)
///   O_APPEND    = 0x0400  (append mode)
///   O_DIRECTORY = 0x10000 (must be a directory)
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

// =============================================================================
// Process Discovery
// =============================================================================

/// Finds all PIDs matching a given process name by scanning /proc/.
///
/// This reads /proc/PID/comm for each process and compares it to the
/// target name. The comm file contains the process name (first 15 chars
/// of the executable name).
///
/// # Arguments
///
/// * `name` - Process name to search for (e.g., "python3", "node", "claude")
///
/// # Returns
///
/// A vector of matching PIDs (may be empty if no processes match)
///
/// # Example
///
/// ```rust
/// let pids = find_pids_by_name("python3")?;
/// // pids might be [1234, 5678] if two Python processes are running
/// ```
///
/// # Limitations
///
/// - Only finds currently running processes (point-in-time snapshot)
/// - Doesn't track child processes spawned after the scan
/// - Process names longer than 15 characters are truncated by the kernel
///
/// # Security Note
///
/// Process names can be changed by the process itself (via prctl(PR_SET_NAME)).
/// A malicious agent could potentially evade detection by changing its comm.
/// Future phases will add cgroup-based tracking which is more robust.
fn find_pids_by_name(name: &str) -> Result<Vec<u32>> {
    let mut pids = Vec::new();

    let proc_dir = std::fs::read_dir("/proc")
        .context("Failed to read /proc directory. Are you running on Linux?")?;

    for entry in proc_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue, // Skip entries we can't read
        };

        // Only look at numeric directory names (these are PIDs)
        let file_name = entry.file_name();
        let pid_str = match file_name.to_str() {
            Some(s) => s,
            None => continue,
        };

        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue, // Not a PID directory
        };

        // Read the process command name from /proc/PID/comm
        let comm_path = format!("/proc/{}/comm", pid);
        let comm = match std::fs::read_to_string(&comm_path) {
            Ok(c) => c,
            Err(_) => continue, // Process may have exited
        };

        // /proc/PID/comm has a trailing newline
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
}
