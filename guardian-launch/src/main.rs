use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;
use guardian_common::ipc::{self, IpcRequest, IpcResponse, SandboxConfig};
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

    /// Disable Landlock sandbox (not recommended).
    #[arg(long)]
    no_landlock: bool,

    /// Disable expanded seccomp hardening (not recommended).
    #[arg(long)]
    no_seccomp_hardened: bool,

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

    // Step 4: Register with Guardian daemon (receives sandbox config)
    let sandbox_config = match register_with_daemon(&args.socket, &cgroup_path, cgroup_id, &args.name) {
        Ok(cfg) => {
            info!("Registered with Guardian daemon");
            cfg
        }
        Err(e) => {
            cleanup_cgroup(&cgroup_path);
            bail!("Failed to register with Guardian daemon: {}. Is the daemon running?", e);
        }
    };

    // Step 5: Move self into cgroup
    move_to_cgroup(&cgroup_path)?;
    info!("Moved to cgroup");

    // Step 6: PR_SET_NO_NEW_PRIVS (prevents SUID escalation, required by Landlock)
    let should_no_new_privs = sandbox_config
        .as_ref()
        .map(|c| c.no_new_privs)
        .unwrap_or(true);
    if should_no_new_privs {
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret == 0 {
            info!("PR_SET_NO_NEW_PRIVS set: SUID escalation blocked");
        } else {
            log::warn!("Failed to set PR_SET_NO_NEW_PRIVS (non-fatal)");
        }
    }

    // Step 7: Apply Landlock sandbox (inode-level, symlink-immune enforcement)
    // Landlock restrict_self() is fundamentally incompatible with execve() on
    // Fedora/RHEL kernels (tested on 6.19.8-200.fc43). Any Landlock domain —
    // even ReadFile|ReadDir on "/" — causes exec EACCES. No SELinux AVC denial
    // is logged, suggesting a kernel-level interaction between Landlock's
    // credential modification and the exec path. See docs/landlock-exec-investigation.md.
    // On these systems, eBPF provides equivalent file access enforcement.
    let selinux_enforcing = std::fs::read_to_string("/sys/fs/selinux/enforce")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);
    let should_landlock = !args.no_landlock
        && !selinux_enforcing
        && sandbox_config.as_ref().map(|c| c.landlock).unwrap_or(true);
    if selinux_enforcing && !args.no_landlock {
        info!("Landlock skipped: incompatible with exec on SELinux-enforcing kernels. \
               Security: PR_SET_NO_NEW_PRIVS + seccomp + eBPF + cgroup active.");
    }
    if should_landlock {
        if let Some(ref cfg) = sandbox_config {
            match apply_landlock_sandbox(cfg) {
                Ok(()) => info!("Landlock sandbox applied: inode-level enforcement active"),
                Err(e) => log::warn!("Failed to apply Landlock sandbox (non-fatal): {}", e),
            }
        }
    } else {
        info!("Landlock sandbox disabled");
    }

    // Step 8: Apply seccomp filter (blocks io_uring + memfd_create + expanded hardening)
    let should_seccomp_hardened = !args.no_seccomp_hardened
        && sandbox_config
            .as_ref()
            .map(|c| c.seccomp_hardened)
            .unwrap_or(true);
    if let Err(e) = apply_seccomp_filter(should_seccomp_hardened) {
        log::warn!("Failed to apply seccomp filter (non-fatal): {}", e);
    } else if should_seccomp_hardened {
        info!("Seccomp filter applied: io_uring, memfd, mount, namespace, chroot blocked");
    } else {
        info!("Seccomp filter applied: io_uring and memfd_create blocked");
    }

    // Step 9: exec the agent command (replaces this process)
    info!("Launching: {:?}", args.command);
    let err = Command::new(&args.command[0])
        .args(&args.command[1..])
        .exec();

    // exec() only returns on error
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
    let base_path = format!(
        "/sys/fs/cgroup/{}/cgroup.subtree_control",
        guardian_common::CGROUP_BASE
    );

    for controller in &["+memory", "+pids", "+cpu"] {
        if let Err(e) = std::fs::write(&base_path, controller) {
            debug!(
                "Could not enable controller {} in {}: {} (may already be enabled or unavailable)",
                controller, base_path, e
            );
        }
    }

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
/// Returns the sandbox config if the daemon provides one.
fn register_with_daemon(
    socket_path: &str,
    cgroup_path: &str,
    cgroup_id: u64,
    agent_name: &str,
) -> Result<Option<SandboxConfig>> {
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("Failed to connect to Guardian daemon at '{}'", socket_path))?;

    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

    let request = IpcRequest::Register {
        cgroup_path: cgroup_path.to_string(),
        cgroup_id,
        agent_name: agent_name.to_string(),
    };
    ipc::send_message(&mut stream, &request)?;

    let response: IpcResponse = ipc::recv_message(&mut stream)?;

    match response {
        IpcResponse::Ack { sandbox } => Ok(sandbox),
        IpcResponse::Error { message } => {
            bail!("Daemon rejected registration: {}", message);
        }
        _ => {
            bail!("Unexpected response from daemon");
        }
    }
}

// =============================================================================
// Phase 10: Landlock Sandbox (inode-level, symlink-immune file access control)
// =============================================================================

/// Apply a Landlock ruleset based on the agent's policy.
///
/// Landlock operates at the inode level — the kernel resolves symlinks, mounts,
/// and all path indirection BEFORE Landlock checks access. This makes it immune
/// to the symlink bypass that defeats eBPF tracepoint-based path checking.
///
/// Rules are default-deny: only explicitly allowed paths are accessible.
fn apply_landlock_sandbox(config: &SandboxConfig) -> Result<()> {
    use landlock::{
        AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset,
        RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
    };

    // Require default-deny for Landlock (it's inherently default-deny)
    if config.file_default != "deny" {
        log::warn!(
            "Landlock sandbox skipped: file_access.default='{}' (Landlock requires 'deny')",
            config.file_default
        );
        return Ok(());
    }

    // Detect best available ABI
    let _abi = ABI::V5; // Target ABI — crate auto-downgrades via CompatLevel

    // Handle file read/write rights. Do NOT handle Execute — exec enforcement
    // is done by the eBPF bprm_check_security LSM hook. Landlock's role is
    // inode-level file access control (symlink-immune, TOCTOU-immune).
    let fs_access = AccessFs::ReadFile | AccessFs::ReadDir
        | AccessFs::WriteFile | AccessFs::MakeReg | AccessFs::RemoveFile
        | AccessFs::MakeDir | AccessFs::RemoveDir
        | AccessFs::MakeSym | AccessFs::Truncate;

    // Build ruleset — handle both filesystem and network if available
    let has_net = config.net_default == "deny" && !config.net_allow_ports.is_empty();

    let ruleset_base = if has_net {
        Ruleset::default()
            .handle_access(fs_access)?
            .handle_access(AccessNet::ConnectTcp)?
    } else {
        Ruleset::default().handle_access(fs_access)?
    };

    let mut ruleset = ruleset_base.create()?;

    // Common system paths that most processes need for basic operation.
    // These get read + execute (for dynamic linking) but not write.
    let system_read_paths = [
        "/usr/lib", "/usr/lib64", "/lib", "/lib64",
        "/usr/share", "/etc/ld.so.cache", "/etc/ld.so.conf",
        "/etc/ld.so.conf.d", "/etc/localtime", "/etc/resolv.conf",
        "/etc/nsswitch.conf", "/etc/hosts", "/etc/passwd", "/etc/group",
        "/dev/null", "/dev/zero", "/dev/urandom", "/dev/random",
    ];

    let read_rights = AccessFs::ReadFile | AccessFs::ReadDir;

    // Add system read paths (needed for dynamic linking and basic operation)
    for path in &system_read_paths {
        if Path::new(path).exists() {
            if let Ok(fd) = PathFd::new(path) {
                ruleset = ruleset.add_rule(PathBeneath::new(fd, read_rights))?;
            }
        }
    }

    // /proc/self is needed for many runtime operations
    if Path::new("/proc/self").exists() {
        if let Ok(fd) = PathFd::new("/proc/self") {
            ruleset = ruleset.add_rule(PathBeneath::new(fd, read_rights))?;
        }
    }
    if Path::new("/proc/self/fd").exists() {
        if let Ok(fd) = PathFd::new("/proc/self/fd") {
            ruleset = ruleset.add_rule(PathBeneath::new(fd, read_rights))?;
        }
    }

    // Add allowed paths from agent config with full handled rights
    for pattern in &config.file_allow {
        let base_path = strip_glob(pattern);
        if !Path::new(&base_path).exists() {
            debug!("Landlock: skipping non-existent path '{}'", base_path);
            continue;
        }
        if let Ok(fd) = PathFd::new(&base_path) {
            ruleset = ruleset.add_rule(PathBeneath::new(fd, fs_access))?;
        }
    }

    // Add exec-allowed paths
    for pattern in &config.exec_allow {
        let base_path = strip_glob(pattern);
        // For specific binaries, allow the parent directory with execute
        let dir = if Path::new(&base_path).is_dir() {
            base_path.clone()
        } else {
            Path::new(&base_path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or(base_path.clone())
        };
        if Path::new(&dir).exists() {
            if let Ok(fd) = PathFd::new(&dir) {
                ruleset = ruleset.add_rule(PathBeneath::new(fd, read_rights))?;
            }
        }
    }

    // Add network port rules (Landlock ABI v4+, kernel 6.7+)
    if has_net {
        for &port in &config.net_allow_ports {
            ruleset = ruleset.add_rule(NetPort::new(port, AccessNet::ConnectTcp))?;
        }
    }

    // Enforce the ruleset — this is irreversible
    let status = ruleset.restrict_self()?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            info!("Landlock: fully enforced (all requested rights controlled)");
        }
        RulesetStatus::PartiallyEnforced => {
            info!("Landlock: partially enforced (some rights not available on this kernel)");
        }
        RulesetStatus::NotEnforced => {
            log::warn!("Landlock: not enforced (kernel may not support Landlock)");
        }
    }

    Ok(())
}

/// Strip glob suffixes from path patterns to get the base directory.
/// E.g., "/tmp/**" → "/tmp", "/usr/bin/*" → "/usr/bin", "/etc/shadow" → "/etc/shadow"
fn strip_glob(pattern: &str) -> String {
    let s = pattern.trim_end_matches("/**").trim_end_matches("/*");
    s.to_string()
}

// =============================================================================
// Seccomp Filter (Phase 8 base + Phase 10 hardened expansion)
// =============================================================================

/// Apply a seccomp BPF filter that blocks dangerous syscalls with EPERM.
///
/// Base filter (always applied):
///   - io_uring_setup (425), io_uring_enter (426), io_uring_register (427)
///   - memfd_create (319)
///
/// Hardened filter (Phase 10, when seccomp_hardened=true):
///   - mount (165), umount2 (166) — mount manipulation
///   - open_tree (428), move_mount (429), fsopen (430), fsconfig (431),
///     fsmount (432), fspick (433), mount_setattr (442) — new mount API
///   - pivot_root (155), chroot (161) — root escape
///   - setns (308), unshare (272) — namespace escape
fn apply_seccomp_filter(hardened: bool) -> Result<()> {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp,
        SeccompCondition, SeccompFilter, SeccompRule,
    };
    use std::collections::BTreeMap;
    use std::convert::TryInto;

    // Base syscalls (always blocked)
    let mut blocked: Vec<i64> = vec![
        319, // memfd_create
        425, // io_uring_setup
        426, // io_uring_enter
        427, // io_uring_register
    ];

    // Hardened syscalls (Phase 10)
    if hardened {
        blocked.extend_from_slice(&[
            155, // pivot_root
            161, // chroot
            165, // mount
            166, // umount2
            272, // unshare
            308, // setns
            428, // open_tree
            429, // move_mount
            430, // fsopen
            431, // fsconfig
            432, // fsmount
            433, // fspick
            442, // mount_setattr
        ]);
    }

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    let always_match = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(0),
        0,
    ).context("Failed to create seccomp condition")?;

    for syscall_nr in blocked {
        let rule = SeccompRule::new(vec![always_match.clone()])
            .map_err(|e| anyhow::anyhow!("Failed to create seccomp rule for syscall {}: {:?}", syscall_nr, e))?;
        rules.insert(syscall_nr, vec![rule]);
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        std::env::consts::ARCH.try_into().context("Unsupported architecture for seccomp")?,
    ).context("Failed to create seccomp filter")?;

    let bpf_prog: BpfProgram = filter.try_into()
        .map_err(|e| anyhow::anyhow!("Failed to compile seccomp filter: {:?}", e))?;

    seccompiler::apply_filter(&bpf_prog)
        .map_err(|e| anyhow::anyhow!("Failed to apply seccomp filter: {:?}", e))?;

    Ok(())
}
