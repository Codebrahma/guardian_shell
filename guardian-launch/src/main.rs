use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;
use guardian_common::ipc::{self, IpcRequest, IpcResponse};
use log::{debug, info};

// =============================================================================
// Command-Line Arguments
// =============================================================================

#[derive(Parser, Debug)]
#[command(
    name = "guardian-launch",
    version,
    about = "Launch an LLM agent with cgroup isolation and Guardian Shell monitoring"
)]
struct Args {
    /// Agent name (must match an agent configured in Guardian's config.toml)
    #[arg(short, long)]
    name: String,

    /// Memory limit (e.g., "4G", "512M"). Applied via cgroup memory.max.
    #[arg(long)]
    memory: Option<String>,

    /// Max number of processes. Applied via cgroup pids.max.
    #[arg(long)]
    pids: Option<u32>,

    /// CPU limit (e.g., "200000 100000" = 2 cores). Applied via cgroup cpu.max.
    #[arg(long)]
    cpu: Option<String>,

    /// Path to the Guardian daemon's Unix socket.
    #[arg(long, default_value = guardian_common::DEFAULT_SOCKET_PATH)]
    socket: String,

    /// The command to launch (everything after --)
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

// =============================================================================
// Main
// =============================================================================

fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    if args.command.is_empty() {
        bail!("No command specified. Usage: guardian-launch --name <agent> -- <command> [args...]");
    }

    info!("Guardian Launch: agent='{}' cmd={:?}", args.name, args.command);

    // Step 1: Create cgroup
    let cgroup_path = create_cgroup(&args.name)?;
    info!("Created cgroup: /sys/fs/cgroup/{}", cgroup_path);

    // Step 2: Enable cgroup controllers and set resource limits
    enable_controllers(&cgroup_path)?;
    set_resource_limits(&cgroup_path, &args)?;

    // Step 3: Get cgroup ID (inode number)
    let cgroup_id = get_cgroup_id(&cgroup_path)?;
    debug!("Cgroup ID (inode): {}", cgroup_id);

    // Step 4: Register with Guardian daemon
    match register_with_daemon(&args.socket, &cgroup_path, cgroup_id, &args.name) {
        Ok(()) => info!("Registered with Guardian daemon"),
        Err(e) => {
            // Clean up cgroup on registration failure
            cleanup_cgroup(&cgroup_path);
            bail!("Failed to register with Guardian daemon: {}. Is the daemon running?", e);
        }
    }

    // Step 5: Move self into cgroup
    move_to_cgroup(&cgroup_path)?;
    info!("Moved to cgroup");

    // Step 5b: Apply seccomp filter (blocks io_uring + memfd_create)
    if let Err(e) = apply_seccomp_filter() {
        log::warn!("Failed to apply seccomp filter (non-fatal): {}", e);
    } else {
        info!("Seccomp filter applied: io_uring and memfd_create blocked");
    }

    // Step 6: exec the agent command (replaces this process)
    info!("Launching: {:?}", args.command);
    let err = Command::new(&args.command[0])
        .args(&args.command[1..])
        .exec();

    // exec() only returns on error
    // Clean up on failure
    cleanup_cgroup(&cgroup_path);
    Err(anyhow::anyhow!(
        "Failed to exec {:?}: {}",
        args.command,
        err
    ))
}

// =============================================================================
// Cgroup Management
// =============================================================================

/// Create a cgroup directory for the agent.
/// Returns the relative cgroup path (e.g., "guardian/aider-12345").
fn create_cgroup(agent_name: &str) -> Result<String> {
    let pid = std::process::id();
    let cgroup_name = format!("{}-{}", agent_name, pid);
    let cgroup_path = format!("{}/{}", guardian_common::CGROUP_BASE, cgroup_name);
    let full_path = format!("/sys/fs/cgroup/{}", cgroup_path);

    // Create the guardian base directory if needed
    let base_path = format!("/sys/fs/cgroup/{}", guardian_common::CGROUP_BASE);
    if !Path::new(&base_path).exists() {
        std::fs::create_dir_all(&base_path)
            .with_context(|| format!("Failed to create cgroup base '{}'. Are you root?", base_path))?;
    }

    // Create the agent-specific cgroup
    std::fs::create_dir_all(&full_path)
        .with_context(|| format!("Failed to create cgroup '{}'", full_path))?;

    Ok(cgroup_path)
}

/// Enable cgroup controllers in the parent so child cgroups can use them.
fn enable_controllers(_cgroup_path: &str) -> Result<()> {
    // Enable controllers in the guardian base cgroup
    let base_path = format!(
        "/sys/fs/cgroup/{}/cgroup.subtree_control",
        guardian_common::CGROUP_BASE
    );

    // Try to enable each controller individually — some may not be available
    for controller in &["+memory", "+pids", "+cpu"] {
        if let Err(e) = std::fs::write(&base_path, controller) {
            debug!(
                "Could not enable controller {} in {}: {} (may already be enabled or unavailable)",
                controller, base_path, e
            );
        }
    }

    // Also need to enable in parent of the guardian base (root cgroup or user slice)
    // This is best-effort — systemd may have already set this up
    let root_subtree = "/sys/fs/cgroup/cgroup.subtree_control";
    for controller in &["+memory", "+pids", "+cpu"] {
        let _ = std::fs::write(root_subtree, controller);
    }

    Ok(())
}

/// Set resource limits on the cgroup.
fn set_resource_limits(cgroup_path: &str, args: &Args) -> Result<()> {
    let full_path = format!("/sys/fs/cgroup/{}", cgroup_path);

    if let Some(ref memory) = args.memory {
        let mem_path = format!("{}/memory.max", full_path);
        match std::fs::write(&mem_path, memory) {
            Ok(()) => info!("Resource limit: memory.max = {}", memory),
            Err(e) => log::warn!("Failed to set memory.max: {} (controller may not be enabled)", e),
        }
    }

    if let Some(pids) = args.pids {
        let pids_path = format!("{}/pids.max", full_path);
        match std::fs::write(&pids_path, pids.to_string()) {
            Ok(()) => info!("Resource limit: pids.max = {}", pids),
            Err(e) => log::warn!("Failed to set pids.max: {} (controller may not be enabled)", e),
        }
    }

    if let Some(ref cpu) = args.cpu {
        let cpu_path = format!("{}/cpu.max", full_path);
        match std::fs::write(&cpu_path, cpu) {
            Ok(()) => info!("Resource limit: cpu.max = {}", cpu),
            Err(e) => log::warn!("Failed to set cpu.max: {} (controller may not be enabled)", e),
        }
    }

    Ok(())
}

/// Get the cgroup ID (inode number of the cgroup directory).
/// This matches what bpf_get_current_cgroup_id() returns in the kernel.
fn get_cgroup_id(cgroup_path: &str) -> Result<u64> {
    let full_path = format!("/sys/fs/cgroup/{}", cgroup_path);
    let metadata = std::fs::metadata(&full_path)
        .with_context(|| format!("Failed to stat cgroup '{}'", full_path))?;
    Ok(metadata.ino())
}

/// Move the current process into the cgroup.
fn move_to_cgroup(cgroup_path: &str) -> Result<()> {
    let procs_path = format!("/sys/fs/cgroup/{}/cgroup.procs", cgroup_path);
    let pid = std::process::id();
    std::fs::write(&procs_path, pid.to_string())
        .with_context(|| format!("Failed to move PID {} into cgroup '{}'", pid, cgroup_path))?;
    Ok(())
}

/// Clean up cgroup directory on failure.
fn cleanup_cgroup(cgroup_path: &str) {
    let full_path = format!("/sys/fs/cgroup/{}", cgroup_path);
    let _ = std::fs::remove_dir(&full_path);
}

// =============================================================================
// IPC with Guardian Daemon
// =============================================================================

/// Register this agent with the Guardian daemon via Unix socket.
fn register_with_daemon(
    socket_path: &str,
    cgroup_path: &str,
    cgroup_id: u64,
    agent_name: &str,
) -> Result<()> {
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("Failed to connect to Guardian daemon at '{}'", socket_path))?;

    // Set timeout for the registration handshake
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

    // Send registration request
    let request = IpcRequest::Register {
        cgroup_path: cgroup_path.to_string(),
        cgroup_id,
        agent_name: agent_name.to_string(),
    };
    ipc::send_message(&mut stream, &request)?;

    // Read response
    let response: IpcResponse = ipc::recv_message(&mut stream)?;

    match response {
        IpcResponse::Ack => Ok(()),
        IpcResponse::Error { message } => {
            bail!("Daemon rejected registration: {}", message);
        }
        _ => {
            bail!("Unexpected response from daemon");
        }
    }
}

// =============================================================================
// Seccomp Filter (Phase 8 — blocks io_uring + memfd_create bypass vectors)
// =============================================================================

/// Apply a seccomp BPF filter that blocks dangerous syscalls with EPERM.
/// Blocked syscalls:
///   - io_uring_setup (425), io_uring_enter (426), io_uring_register (427)
///     io_uring bypasses eBPF file monitoring entirely.
///   - memfd_create (319)
///     memfd_create + execveat(AT_EMPTY_PATH) bypasses exec monitoring.
fn apply_seccomp_filter() -> Result<()> {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp,
        SeccompCondition, SeccompFilter, SeccompRule,
    };
    use std::collections::BTreeMap;
    use std::convert::TryInto;

    // Syscall numbers for x86_64
    const SYS_MEMFD_CREATE: i64 = 319;
    const SYS_IO_URING_SETUP: i64 = 425;
    const SYS_IO_URING_ENTER: i64 = 426;
    const SYS_IO_URING_REGISTER: i64 = 427;

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Create a condition that always matches: arg0 & 0 == 0 (always true)
    let always_match = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(0),
        0,
    ).context("Failed to create seccomp condition")?;

    // Block each syscall unconditionally
    for syscall_nr in [SYS_MEMFD_CREATE, SYS_IO_URING_SETUP, SYS_IO_URING_ENTER, SYS_IO_URING_REGISTER] {
        rules.insert(
            syscall_nr,
            vec![SeccompRule::new(vec![always_match.clone()]).unwrap()],
        );
    }

    let filter = SeccompFilter::new(
        rules,
        // Default action: allow everything else
        SeccompAction::Allow,
        // Action for matched rules: return EPERM
        SeccompAction::Errno(libc::EPERM as u32),
        std::env::consts::ARCH.try_into().context("Unsupported architecture for seccomp")?,
    ).context("Failed to create seccomp filter")?;

    let bpf_prog: BpfProgram = filter.try_into()
        .map_err(|e| anyhow::anyhow!("Failed to compile seccomp filter: {:?}", e))?;

    seccompiler::apply_filter(&bpf_prog)
        .map_err(|e| anyhow::anyhow!("Failed to apply seccomp filter: {:?}", e))?;

    Ok(())
}

// =============================================================================
// CLI Subcommands (list, stop, grant)
// =============================================================================

// These are standalone utilities that communicate with the daemon.
// They can be invoked as:
//   guardian-launch list
//   guardian-launch stop --name <agent>
//   guardian-launch grant --name <agent> --path <path> --duration <secs>
//
// For simplicity, they're part of the same binary with subcommands handled
// via environment or separate invocation. The main binary defaults to launching
// when a command is provided after --.
