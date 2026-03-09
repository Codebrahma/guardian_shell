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

    /// Grant temporary file access to an agent
    Grant {
        /// Agent name
        #[arg(short, long)]
        name: String,

        /// Path pattern to grant access to (e.g., "/home/user/.aws/**")
        #[arg(short, long)]
        path: String,

        /// Duration in seconds
        #[arg(short, long)]
        duration: u64,
    },
}

// =============================================================================
// Main
// =============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    let request = match &cli.command {
        Commands::List => IpcRequest::ListAgents,
        Commands::Stop { name } => IpcRequest::StopAgent {
            agent_name: name.clone(),
        },
        Commands::Grant {
            name,
            path,
            duration,
        } => IpcRequest::GrantAccess {
            agent_name: name.clone(),
            path: path.clone(),
            duration_secs: *duration,
        },
    };

    let response = send_request(&cli.socket, &request)?;

    match response {
        IpcResponse::Ack => {
            match &cli.command {
                Commands::Stop { name } => println!("Agent '{}' stopped.", name),
                Commands::Grant { name, path, duration } => {
                    println!(
                        "Granted '{}' access to '{}' for {} seconds.",
                        name, path, duration
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
    }

    Ok(())
}

// =============================================================================
// IPC Client
// =============================================================================

fn send_request(socket_path: &str, request: &IpcRequest) -> Result<IpcResponse> {
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!(
            "Failed to connect to Guardian daemon at '{}'. Is it running?",
            socket_path
        ))?;

    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

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
