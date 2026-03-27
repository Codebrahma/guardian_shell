use super::AlertEvent;
use anyhow::{Context, Result};
use crate::config::JsonLogConfig;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;

// =============================================================================
// Structured JSON Log Entry (SIEM-compatible format)
// =============================================================================

/// JSON log entry following common SIEM field conventions.
/// Each line in the log file is one complete JSON object (JSONL format).
#[derive(serde::Serialize)]
struct JsonLogEntry<'a> {
    timestamp: String,
    severity: &'a str,
    event_type: &'a str,
    action: &'a str,
    agent: AgentInfo<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<FileInfo<'a>>,
    policy: PolicyInfo<'a>,
    host: HostInfo<'a>,
}

#[derive(serde::Serialize)]
struct AgentInfo<'a> {
    name: &'a str,
    identity: &'a str,
    pid: u32,
    comm: &'a str,
}

#[derive(serde::Serialize)]
struct FileInfo<'a> {
    path: &'a str,
    flags: &'a str,
}

#[derive(serde::Serialize)]
struct PolicyInfo<'a> {
    mode: &'a str,
}

#[derive(serde::Serialize)]
struct HostInfo<'a> {
    hostname: &'a str,
}

// =============================================================================
// JSON Logger with Size-Based Rotation
// =============================================================================

pub struct JsonLogger {
    file: Option<File>,
    path: Option<String>,
    bytes_written: u64,
    max_size_bytes: u64,
    max_files: u32,
}

impl JsonLogger {
    pub async fn new(config: &JsonLogConfig) -> Result<Self> {
        let max_size_bytes = config.max_size_mb.unwrap_or(100) as u64 * 1024 * 1024;
        let max_files = config.max_files.unwrap_or(5);

        match &config.path {
            Some(path) => {
                // Ensure parent directory exists
                if let Some(parent) = std::path::Path::new(path).parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .with_context(|| format!("Failed to create log directory: {}", parent.display()))?;
                }

                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .await
                    .with_context(|| format!("Failed to open JSON log file: {}", path))?;

                let metadata = file.metadata().await?;
                let bytes_written = metadata.len();

                Ok(JsonLogger {
                    file: Some(file),
                    path: Some(path.clone()),
                    bytes_written,
                    max_size_bytes,
                    max_files,
                })
            }
            None => {
                // stdout mode - no file, no rotation
                Ok(JsonLogger {
                    file: None,
                    path: None,
                    bytes_written: 0,
                    max_size_bytes,
                    max_files,
                })
            }
        }
    }

    pub async fn write_event(&mut self, event: &AlertEvent, hostname: &str) -> Result<()> {
        let entry = JsonLogEntry {
            timestamp: event.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            severity: &event.severity.to_string(),
            event_type: &event.event_type.to_string(),
            action: &event.action.to_string(),
            agent: AgentInfo {
                name: &event.agent_name,
                identity: &event.identity_method,
                pid: event.pid,
                comm: &event.comm,
            },
            file: if !event.path.is_empty() {
                Some(FileInfo {
                    path: &event.path,
                    flags: &event.access_mode,
                })
            } else {
                None
            },
            policy: PolicyInfo {
                mode: &event.policy_mode,
            },
            host: HostInfo { hostname },
        };

        let mut json = serde_json::to_vec(&entry)?;
        json.push(b'\n');

        match &mut self.file {
            Some(file) => {
                file.write_all(&json).await?;
                // Skip per-event flush — OS write-back and log rotation handle durability.
                // This avoids an extra syscall per event under high throughput.
                self.bytes_written += json.len() as u64;

                // Check if rotation needed
                if self.bytes_written >= self.max_size_bytes {
                    self.rotate().await?;
                }
            }
            None => {
                // Write to stdout
                let mut stdout = tokio::io::stdout();
                stdout.write_all(&json).await?;
            }
        }

        Ok(())
    }

    async fn rotate(&mut self) -> Result<()> {
        let path = match &self.path {
            Some(p) => p.clone(),
            None => return Ok(()),
        };

        // Close current file
        self.file = None;

        // Rotate existing files: .4 -> .5, .3 -> .4, ... .1 -> .2, current -> .1
        // Delete the oldest if it exceeds max_files
        for i in (1..self.max_files).rev() {
            let from = format!("{}.{}", path, i);
            let to = format!("{}.{}", path, i + 1);
            let _ = tokio::fs::rename(&from, &to).await;
        }

        // Rename current to .1
        let _ = tokio::fs::rename(&path, format!("{}.1", path)).await;

        // Open new file
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("Failed to open new log file after rotation: {}", path))?;

        self.file = Some(file);
        self.bytes_written = 0;

        // Delete files beyond max_files
        let overflow = format!("{}.{}", path, self.max_files + 1);
        let _ = tokio::fs::remove_file(&overflow).await;

        log::info!("JSON log rotated: {}", path);
        Ok(())
    }
}
