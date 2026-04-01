use std::os::unix::net::UnixStream;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use guardian_common::ipc::{self, IpcRequest, IpcResponse};

// =============================================================================
// CLI
// =============================================================================

#[derive(Parser)]
#[command(
    name = "guardian-ctl",
    version,
    about = "Manage Guardian Shell agents"
)]
struct Cli {
    /// Path to the Guardian daemon's Unix socket
    #[arg(long, default_value = guardian_common::DEFAULT_SOCKET_PATH)]
    socket: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all running agents
    List,

    /// Stop an agent by name
    Stop {
        /// Agent name to stop
        #[arg(short, long)]
        name: String,
    },

    /// Grant temporary access to an agent (file or exec)
    Grant {
        /// Agent name
        #[arg(short, long)]
        name: String,

        /// Path pattern to grant access to (e.g., "/home/user/.aws/**" or "/usr/bin/curl")
        #[arg(short, long)]
        path: String,

        /// Duration in seconds
        #[arg(short, long)]
        duration: u64,

        /// Grant type: "file" for file access, "exec" for command execution
        #[arg(short = 't', long, default_value = "file")]
        grant_type: String,
    },

    /// List pending permission requests
    Pending,

    /// Approve a pending permission request
    Approve {
        /// Permission request ID
        #[arg(short, long)]
        id: u64,

        /// Grant duration in seconds
        #[arg(short, long, default_value = "300")]
        duration: u64,
    },

    /// Deny a pending permission request
    Deny {
        /// Permission request ID
        #[arg(short, long)]
        id: u64,

        /// Reason for denial
        #[arg(short, long)]
        reason: Option<String>,
    },

    /// Request permission for a resource (waits for human approval via dashboard)
    RequestPermission {
        /// Agent name
        #[arg(short, long)]
        name: String,

        /// Resource type: "file" or "exec"
        #[arg(short = 't', long, default_value = "exec")]
        resource_type: String,

        /// Resource path (e.g., "/usr/bin/grep" or "/etc/passwd")
        #[arg(short, long)]
        path: String,

        /// Human-readable justification for the request
        #[arg(short, long)]
        justification: Option<String>,
    },
}

// =============================================================================
// Main
// =============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    let is_permission_request = matches!(&cli.command, Commands::RequestPermission { .. });

    let request = match &cli.command {
        Commands::List => IpcRequest::ListAgents,
        Commands::Stop { name } => IpcRequest::StopAgent {
            agent_name: name.clone(),
        },
        Commands::Grant {
            name,
            path,
            duration,
            grant_type,
        } => IpcRequest::GrantAccess {
            agent_name: name.clone(),
            path: path.clone(),
            duration_secs: *duration,
            grant_type: grant_type.clone(),
        },
        Commands::Pending => IpcRequest::ListPending,
        Commands::Approve { id, duration } => IpcRequest::ApprovePermission {
            request_id: *id,
            duration_secs: *duration,
        },
        Commands::Deny { id, reason } => IpcRequest::DenyPermission {
            request_id: *id,
            reason: reason.clone(),
        },
        Commands::RequestPermission {
            name,
            resource_type,
            path,
            justification,
        } => IpcRequest::RequestPermission {
            agent_name: name.clone(),
            resource_type: resource_type.clone(),
            resource_path: path.clone(),
            justification: justification.clone(),
        },
    };

    let response = send_request(&cli.socket, &request, is_permission_request)?;

    match response {
        IpcResponse::Ack { .. } => {
            match &cli.command {
                Commands::Stop { name } => println!("Agent '{}' stopped.", name),
                Commands::Grant { name, path, duration, grant_type } => {
                    println!(
                        "Granted '{}' {} access to '{}' for {} seconds.",
                        name, grant_type, path, duration
                    );
                }
                _ => println!("OK"),
            }
        }
        IpcResponse::Error { message } => {
            bail!("Error: {}", message);
        }
        IpcResponse::AgentList { agents } => {
            if agents.is_empty() {
                println!("No agents currently registered.");
            } else {
                println!(
                    "{:<20} {:<8} {:<40} {:<8} {:<10}",
                    "NAME", "PROCS", "CGROUP", "ID", "UPTIME"
                );
                println!("{}", "-".repeat(86));
                for agent in &agents {
                    let uptime = format_duration(agent.uptime_secs);
                    println!(
                        "{:<20} {:<8} {:<40} {:<8} {:<10}",
                        agent.name,
                        agent.num_processes,
                        agent.cgroup_path,
                        agent.cgroup_id,
                        uptime,
                    );
                }
            }
        }
        IpcResponse::PendingPermissions { requests } => {
            if requests.is_empty() {
                println!("No pending permission requests.");
            } else {
                println!(
                    "{:<6} {:<18} {:<8} {:<40} {:<10} {:<8}",
                    "ID", "AGENT", "TYPE", "RESOURCE", "RISK", "AGE"
                );
                println!("{}", "-".repeat(90));
                for req in &requests {
                    println!(
                        "{:<6} {:<18} {:<8} {:<40} {:<10} {:<8}",
                        req.request_id,
                        req.agent_name,
                        req.resource_type,
                        if req.resource_path.len() > 38 {
                            format!("{}...", &req.resource_path[..35])
                        } else {
                            req.resource_path.clone()
                        },
                        req.risk_level,
                        format!("{}s", req.elapsed_secs),
                    );
                    if let Some(ref j) = req.justification {
                        println!("       Justification: {}", j);
                    }
                }
            }
        }
        IpcResponse::PermissionDecision {
            approved,
            reason,
            grant_duration_secs,
            warning,
        } => {
            if approved {
                let dur = grant_duration_secs.unwrap_or(0);
                println!("APPROVED: {} (granted for {}s)", reason, dur);
            } else {
                println!("DENIED: {}", reason);
            }
            if let Some(w) = warning {
                eprintln!("WARNING: {}", w);
            }
            if !approved {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

// =============================================================================
// IPC Client
// =============================================================================

fn send_request(
    socket_path: &str,
    request: &IpcRequest,
    long_wait: bool,
) -> Result<IpcResponse> {
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!(
            "Failed to connect to Guardian daemon at '{}'. Is it running?",
            socket_path
        ))?;

    // Permission requests may wait up to 180s (daemon timeout is 120s)
    let read_timeout = if long_wait { 180 } else { 10 };
    stream.set_read_timeout(Some(std::time::Duration::from_secs(read_timeout)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

    if long_wait {
        eprintln!("Waiting for human approval via dashboard (up to 120s)...");
    }

    ipc::send_message(&mut stream, request)?;
    let response: IpcResponse = ipc::recv_message(&mut stream)?;

    Ok(response)
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}
