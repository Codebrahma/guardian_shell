use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

// =============================================================================
// Configuration Data Structures
// =============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub global: GlobalConfig,
    pub agents: Vec<AgentConfig>,
    /// Phase 4: Alerting & integration configuration.
    /// Optional — when absent, no alerting outputs are active.
    #[serde(default)]
    pub alerting: Option<AlertingConfig>,
    /// Phase 5: Web dashboard configuration.
    #[serde(default)]
    pub dashboard: Option<DashboardConfig>,
    /// Phase 7c: Permission request hardening.
    #[serde(default)]
    pub permissions: Option<PermissionsConfig>,
    /// Cached mapping from comm name → agent index for O(1) lookup in event processing.
    /// Built after config load and rebuilt on SIGHUP reload. Skipped during deserialization.
    #[serde(skip)]
    pub comm_cache: HashMap<String, usize>,
}

impl Config {
    /// Build the comm_cache HashMap from the agents list.
    /// Maps each comm-based agent's effective_process_name to its index in the agents vec.
    pub fn build_comm_cache(&mut self) {
        self.comm_cache.clear();
        for (i, agent) in self.agents.iter().enumerate() {
            if agent.effective_identity() == "comm" {
                self.comm_cache.insert(agent.effective_process_name().to_string(), i);
            }
        }
    }
}

// =============================================================================
// Alerting Configuration (Phase 4)
// =============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct AlertingConfig {
    /// Minimum severity for any alert output: "info", "warning", "critical".
    /// Default: "warning"
    pub min_severity: Option<String>,
    /// Suppress duplicate alerts (same agent + event + path + action) within
    /// this window. Default: 300 seconds.
    pub dedup_window_seconds: Option<u64>,
    /// Maximum alerts dispatched per minute across all outputs.
    /// Default: 100
    pub rate_limit_per_minute: Option<u32>,

    pub json_log: Option<JsonLogConfig>,
    pub webhook: Option<WebhookConfig>,
    pub slack: Option<SlackConfig>,
    pub email: Option<EmailConfig>,
    pub prometheus: Option<PrometheusConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JsonLogConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// File path for JSONL output. If omitted, logs to stdout.
    pub path: Option<String>,
    /// Max file size in MB before rotation. Default: 100
    pub max_size_mb: Option<u32>,
    /// Max rotated files to keep. Default: 5
    pub max_files: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebhookConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Webhook endpoint URL (HTTP POST with JSON body).
    pub url: Option<String>,
    /// Optional Authorization header value (e.g. "Bearer token123").
    pub auth_header: Option<String>,
    /// Optional custom headers as key-value pairs.
    pub headers: Option<HashMap<String, String>>,
    /// Minimum severity for this output. Default: "warning"
    pub min_severity: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SlackConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Slack incoming webhook URL.
    pub webhook_url: Option<String>,
    /// Optional channel override (only works with Slack apps, not incoming webhooks).
    pub channel: Option<String>,
    /// Minimum severity for this output. Default: "critical"
    pub min_severity: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailConfig {
    #[serde(default)]
    pub enabled: bool,
    /// SMTP server hostname.
    pub smtp_host: Option<String>,
    /// SMTP server port. Default: 587 (STARTTLS)
    pub smtp_port: Option<u16>,
    /// SMTP username for authentication.
    pub username: Option<String>,
    /// SMTP password for authentication.
    pub password: Option<String>,
    /// Sender email address.
    pub from: Option<String>,
    /// Recipient email addresses.
    pub to: Option<Vec<String>>,
    /// Minimum severity for this output. Default: "critical"
    pub min_severity: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PrometheusConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Address to bind the metrics HTTP server. Default: "127.0.0.1:9090"
    pub listen_address: Option<String>,
    /// URL path for the metrics endpoint. Default: "/metrics"
    pub endpoint: Option<String>,
}

// =============================================================================
// Dashboard Configuration (Phase 5)
// =============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct DashboardConfig {
    #[serde(default)]
    pub enabled: bool,
    /// HTTP listen address for the dashboard. Default: "127.0.0.1:8080"
    pub listen_address: Option<String>,
    /// Path to SQLite database for event storage. Default: "/var/lib/guardian/events.db"
    pub db_path: Option<String>,
    /// Phase 8: Optional authentication token for dashboard access.
    /// When set, all dashboard requests must include this token.
    pub auth_token: Option<String>,
}

// =============================================================================
// Permissions Hardening Configuration (Phase 7c)
// =============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct PermissionsConfig {
    /// Paths that are NEVER approvable via interactive request.
    #[serde(default)]
    pub auto_deny: Vec<String>,
    /// Low-risk paths that are auto-approved without human intervention.
    #[serde(default)]
    pub auto_approve: Vec<AutoApproveRule>,
    /// Max permission requests per agent per minute. Default: 3.
    #[serde(default = "default_rate_per_minute")]
    pub rate_limit_per_minute: u32,
    /// Max permission requests per agent per hour. Default: 15.
    #[serde(default = "default_rate_per_hour")]
    pub rate_limit_per_hour: u32,
    /// Cooldown after denial in seconds (doubles each time, up to max). Default: 30.
    #[serde(default = "default_deny_cooldown")]
    pub deny_cooldown_secs: u64,
    /// Max pending requests per agent. Default: 2.
    #[serde(default = "default_max_pending")]
    pub max_pending_per_agent: u32,
    /// Phase 8: Risk-based configurable timeouts for permission requests (in seconds).
    pub timeouts: Option<RiskTimeoutConfig>,
    /// Phase 8: Maximum total grant seconds allowed per agent. Default: 3600 (1 hour).
    #[serde(default = "default_max_grant_total_secs")]
    pub max_grant_total_secs: u64,
}

/// Phase 8: Risk-based configurable timeouts for permission requests.
/// Each field specifies the timeout in seconds for the corresponding risk level.
#[derive(Debug, Clone, Deserialize)]
pub struct RiskTimeoutConfig {
    #[serde(default = "default_timeout_low")]
    pub low: u64,
    #[serde(default = "default_timeout_medium")]
    pub medium: u64,
    #[serde(default = "default_timeout_high")]
    pub high: u64,
    #[serde(default = "default_timeout_critical")]
    pub critical: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AutoApproveRule {
    pub pattern: String,
    #[serde(default = "default_auto_approve_duration")]
    pub max_duration_secs: u64,
}

fn default_rate_per_minute() -> u32 { 3 }
fn default_rate_per_hour() -> u32 { 15 }
fn default_deny_cooldown() -> u64 { 30 }
fn default_max_pending() -> u32 { 2 }
fn default_auto_approve_duration() -> u64 { 300 }
fn default_max_grant_total_secs() -> u64 { 3600 }
fn default_timeout_low() -> u64 { 60 }
fn default_timeout_medium() -> u64 { 120 }
fn default_timeout_high() -> u64 { 180 }
fn default_timeout_critical() -> u64 { 300 }

#[derive(Debug, Clone, Deserialize)]
pub struct GlobalConfig {
    pub log_level: String,
    /// Operating mode: "monitor" (log only) or "enforce" (block denied access).
    /// Default: "monitor"
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Interval in seconds for rescanning /proc to discover new agent processes.
    /// Default: 5
    #[serde(default = "default_rescan_interval")]
    pub pid_rescan_interval: u64,
    /// Unix socket path for IPC with guardian-launch and CLI tools.
    /// Default: "/run/guardian.sock"
    #[serde(default = "default_socket_path")]
    pub socket_path: String,
}

fn default_mode() -> String {
    "monitor".to_string()
}

fn default_rescan_interval() -> u64 {
    5
}

fn default_socket_path() -> String {
    guardian_common::DEFAULT_SOCKET_PATH.to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    pub name: String,
    /// Identity method: "comm" (Phase 1/2) or "cgroup" (Phase 3).
    /// Default: "comm" when process_name is set, "cgroup" otherwise.
    #[serde(default)]
    pub identity: Option<String>,
    /// Process name for comm-based identification (Phase 1/2).
    /// Required when identity = "comm", ignored when identity = "cgroup".
    #[serde(default)]
    pub process_name: Option<String>,
    pub file_access: FileAccessPolicy,
    /// Exec policy: controls which commands the agent can execute.
    /// Optional - if not set, all exec is allowed (monitor-only).
    pub exec_policy: Option<ExecPolicy>,
    /// Network policy: controls outbound connections.
    /// Optional - if not set, all connections are allowed (monitor-only).
    pub network_policy: Option<NetworkPolicy>,
    /// Whether to track child processes of this agent. Default: true
    #[serde(default = "default_true")]
    pub watch_children: bool,
    /// Resource limits applied via cgroup controllers (Phase 3).
    /// Only effective for cgroup-based agents.
    pub resources: Option<ResourceLimits>,
    /// Phase 8: Fail-closed mode. When true, the agent is blocked if the daemon
    /// is unreachable or encounters an internal error. Default: None (not set).
    pub fail_closed: Option<bool>,
}

impl AgentConfig {
    /// Returns the effective identity method for this agent.
    pub fn effective_identity(&self) -> &str {
        if let Some(ref id) = self.identity {
            id.as_str()
        } else if self.process_name.is_some() {
            "comm"
        } else {
            "cgroup"
        }
    }

    /// Returns the process name, defaulting to the agent name if not set.
    pub fn effective_process_name(&self) -> &str {
        self.process_name.as_deref().unwrap_or(&self.name)
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileAccessPolicy {
    pub default: String,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

/// Policy for command execution (execve monitoring).
#[derive(Debug, Clone, Deserialize)]
pub struct ExecPolicy {
    /// Default action for exec: "allow" or "deny"
    pub default: String,
    /// List of allowed command path patterns
    pub allow: Vec<String>,
    /// List of denied command path patterns
    pub deny: Vec<String>,
}

/// Policy for outbound network connections.
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkPolicy {
    /// Default action for connections: "allow" or "deny"
    pub default: String,
    /// Allowed destination ports
    #[serde(default)]
    pub allow_ports: Vec<u16>,
    /// Denied destination ports
    #[serde(default)]
    pub deny_ports: Vec<u16>,
}

/// Resource limits applied via cgroup v2 controllers.
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceLimits {
    /// Memory limit (e.g., "4G", "512M"). Written to memory.max.
    pub memory_max: Option<String>,
    /// Max number of processes. Written to pids.max.
    pub pids_max: Option<u32>,
    /// CPU limit (e.g., "200000 100000" = 2 cores). Written to cpu.max.
    pub cpu_max: Option<String>,
}

// =============================================================================
// Configuration Loading
// =============================================================================

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;

    let mut config: Config = toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

    validate_config(&config)?;

    // Build the comm name → agent index cache for O(1) event lookups
    config.build_comm_cache();

    Ok(config)
}

fn validate_config(config: &Config) -> Result<()> {
    if config.agents.is_empty() {
        log::warn!("No agents configured - Guardian Shell won't monitor anything");
    }

    // Validate mode
    match config.global.mode.as_str() {
        "monitor" | "enforce" | "strict" => {}
        other => {
            anyhow::bail!(
                "Invalid global mode '{}'. Must be 'monitor', 'enforce', or 'strict'",
                other
            );
        }
    }

    for agent in &config.agents {
        // Validate identity method
        match agent.effective_identity() {
            "comm" => {
                // Comm-based agents need a process_name (or use agent name)
            }
            "cgroup" => {
                // Cgroup-based agents are registered dynamically via launcher
            }
            other => {
                anyhow::bail!(
                    "Agent '{}': invalid identity method '{}'. Must be 'comm' or 'cgroup'",
                    agent.name,
                    other
                );
            }
        }

        match agent.file_access.default.as_str() {
            "allow" | "deny" => {}
            other => {
                anyhow::bail!(
                    "Agent '{}': invalid default action '{}'. Must be 'allow' or 'deny'",
                    agent.name,
                    other
                );
            }
        }

        if agent.file_access.default == "allow" {
            log::warn!(
                "Agent '{}': default action is 'allow'. Consider using 'deny' for better security.",
                agent.name
            );
        }

        for pattern in &agent.file_access.allow {
            if pattern == "/**" || pattern == "/*" {
                log::warn!(
                    "Agent '{}': allow pattern '{}' is extremely broad.",
                    agent.name,
                    pattern
                );
            }
        }

        for pattern in agent
            .file_access
            .allow
            .iter()
            .chain(agent.file_access.deny.iter())
        {
            if !pattern.starts_with('/') {
                log::warn!(
                    "Agent '{}': pattern '{}' is not an absolute path.",
                    agent.name,
                    pattern
                );
            }
        }

        // Validate exec policy if present
        if let Some(exec) = &agent.exec_policy {
            match exec.default.as_str() {
                "allow" | "deny" => {}
                other => {
                    anyhow::bail!(
                        "Agent '{}': invalid exec default action '{}'. Must be 'allow' or 'deny'",
                        agent.name,
                        other
                    );
                }
            }
        }
    }

    // Validate alerting config
    if let Some(ref alerting) = config.alerting {
        validate_alerting_config(alerting)?;
    }

    Ok(())
}

fn validate_alerting_config(config: &AlertingConfig) -> Result<()> {
    // Validate severity values
    if let Some(ref sev) = config.min_severity {
        match sev.as_str() {
            "info" | "warning" | "critical" => {}
            other => anyhow::bail!("Invalid alerting min_severity '{}'. Must be 'info', 'warning', or 'critical'", other),
        }
    }

    // Validate webhook config
    if let Some(ref wh) = config.webhook {
        if wh.enabled {
            if wh.url.as_ref().map(|u| u.is_empty()).unwrap_or(true) {
                anyhow::bail!("Webhook is enabled but 'url' is not set");
            }
            if let Some(ref url) = wh.url {
                if !url.starts_with("http://") && !url.starts_with("https://") {
                    log::warn!("Webhook URL does not start with http:// or https://: {}", url);
                }
            }
        }
        if let Some(ref sev) = wh.min_severity {
            match sev.as_str() {
                "info" | "warning" | "critical" => {}
                other => anyhow::bail!("Invalid webhook min_severity '{}'", other),
            }
        }
    }

    // Validate Slack config
    if let Some(ref slack) = config.slack {
        if slack.enabled {
            if slack.webhook_url.as_ref().map(|u| u.is_empty()).unwrap_or(true) {
                anyhow::bail!("Slack is enabled but 'webhook_url' is not set");
            }
            if let Some(ref url) = slack.webhook_url {
                if !url.starts_with("https://hooks.slack.com/") && !url.starts_with("https://") {
                    log::warn!("Slack webhook URL doesn't look like a Slack webhook: {}", url);
                }
            }
        }
    }

    // Validate email config
    if let Some(ref email) = config.email {
        if email.enabled {
            if email.smtp_host.as_ref().map(|h| h.is_empty()).unwrap_or(true) {
                anyhow::bail!("Email is enabled but 'smtp_host' is not set");
            }
            if email.from.as_ref().map(|f| f.is_empty()).unwrap_or(true) {
                anyhow::bail!("Email is enabled but 'from' address is not set");
            }
            if email.to.as_ref().map(|t| t.is_empty()).unwrap_or(true) {
                anyhow::bail!("Email is enabled but 'to' addresses list is empty");
            }
        }
    }

    // Validate Prometheus config
    if let Some(ref prom) = config.prometheus {
        if prom.enabled {
            if let Some(ref addr) = prom.listen_address {
                // Basic validation: should contain a colon (host:port)
                if !addr.contains(':') {
                    log::warn!("Prometheus listen_address '{}' doesn't contain a port (expected host:port)", addr);
                }
            }
        }
    }

    Ok(())
}

// =============================================================================
// Path Normalization (Phase 7a — closes symlink, traversal, /proc/self/root bypasses)
// =============================================================================

/// Normalize a raw path to remove common bypass tricks.
/// Catches /proc/self/root/, /proc/<pid>/root/, and ".." traversal.
/// Does NOT resolve symlinks (that requires kernel-side bpf_d_path).
pub fn normalize_path(raw: &str) -> String {
    // Phase 1: Strip /proc/self/root/ or /proc/<pid>/root/ prefixes.
    // Work on &str slices to avoid intermediate String allocations.
    let stripped = if let Some(rest) = raw.strip_prefix("/proc/self/root/") {
        rest
    } else if raw == "/proc/self/root" {
        return "/".to_string();
    } else if raw.starts_with("/proc/") {
        let after_proc = &raw[6..];
        if let Some(slash_pos) = after_proc.find('/') {
            let pid_part = &after_proc[..slash_pos];
            if pid_part.bytes().all(|b| b.is_ascii_digit()) {
                let after_pid = &after_proc[slash_pos..];
                if let Some(rest) = after_pid.strip_prefix("/root/") {
                    rest
                } else if after_pid == "/root" {
                    return "/".to_string();
                } else {
                    raw
                }
            } else {
                raw
            }
        } else {
            raw
        }
    } else {
        raw
    };

    // Phase 2: Resolve ".." and "." components into a single String.
    // Pre-allocate with capacity to avoid repeated reallocations.
    let mut result = String::with_capacity(stripped.len() + 1);
    // First pass: collect valid components into a small stack-friendly Vec
    let mut components: Vec<&str> = Vec::with_capacity(16);
    for component in stripped.split('/') {
        match component {
            "" | "." => {}
            ".." => { components.pop(); }
            c => components.push(c),
        }
    }

    if components.is_empty() {
        return "/".to_string();
    }

    for comp in &components {
        result.push('/');
        result.push_str(comp);
    }
    result
}

// =============================================================================
// Path Pattern Matching
// =============================================================================

pub fn check_file_policy(policy: &FileAccessPolicy, path: &str) -> bool {
    let normalized = normalize_path(path);
    let path = normalized.as_str();

    for pattern in &policy.deny {
        if path_matches(path, pattern) {
            return false;
        }
    }

    for pattern in &policy.allow {
        if path_matches(path, pattern) {
            return true;
        }
    }

    policy.default == "allow"
}

pub fn check_exec_policy(policy: &ExecPolicy, path: &str) -> bool {
    let normalized = normalize_path(path);
    let path = normalized.as_str();

    for pattern in &policy.deny {
        if path_matches(path, pattern) {
            return false;
        }
    }

    for pattern in &policy.allow {
        if path_matches(path, pattern) {
            return true;
        }
    }

    policy.default == "allow"
}

/// Check whether a network connection (by port) is allowed by a network policy.
/// Deny takes precedence over allow.
pub fn check_network_policy(policy: &NetworkPolicy, port: u16) -> bool {
    if policy.deny_ports.contains(&port) {
        return false;
    }
    if policy.allow_ports.contains(&port) {
        return true;
    }
    policy.default == "allow"
}

pub fn path_matches(path: &str, pattern: &str) -> bool {
    if pattern.ends_with("/**") {
        let prefix = &pattern[..pattern.len() - 3];
        path == prefix || path.starts_with(&format!("{}/", prefix))
    } else if pattern.ends_with("/*") {
        let prefix = &pattern[..pattern.len() - 2];
        if let Some(rest) = path.strip_prefix(prefix) {
            rest.starts_with('/') && !rest[1..].contains('/')
        } else {
            false
        }
    } else {
        path == pattern
    }
}

// =============================================================================
// Policy Rule Conversion (for BPF maps)
// =============================================================================

/// Convert a path pattern string into a PolicyRule for kernel-side enforcement.
#[allow(dead_code)]
pub fn pattern_to_policy_rule(pattern: &str) -> guardian_common::PolicyRule {
    let mut rule = guardian_common::PolicyRule {
        path_prefix: [0u8; guardian_common::MAX_FILENAME_LEN],
        prefix_len: 0,
        match_type: 0,
        _pad: [0; 3],
    };

    let (prefix, match_type) = if pattern.ends_with("/**") {
        (&pattern[..pattern.len() - 3], 1u8)
    } else if pattern.ends_with("/*") {
        (&pattern[..pattern.len() - 2], 2u8)
    } else {
        (pattern, 0u8)
    };

    let bytes = prefix.as_bytes();
    let copy_len = core::cmp::min(bytes.len(), guardian_common::MAX_FILENAME_LEN);
    rule.path_prefix[..copy_len].copy_from_slice(&bytes[..copy_len]);
    rule.prefix_len = copy_len as u32;
    rule.match_type = match_type;

    rule
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(path_matches("/etc/passwd", "/etc/passwd"));
        assert!(!path_matches("/etc/shadow", "/etc/passwd"));
        assert!(!path_matches("/etc/passwd/extra", "/etc/passwd"));
    }

    #[test]
    fn test_recursive_wildcard() {
        assert!(path_matches("/home/user/file.txt", "/home/user/**"));
        assert!(path_matches("/home/user/sub/dir/file.txt", "/home/user/**"));
        assert!(path_matches("/home/user/a/b/c", "/home/user/**"));
        assert!(!path_matches("/home/other/file.txt", "/home/user/**"));
        assert!(!path_matches("/home/username/file.txt", "/home/user/**"));
    }

    #[test]
    fn test_single_level_wildcard() {
        assert!(path_matches("/tmp/file.txt", "/tmp/*"));
        assert!(path_matches("/tmp/another", "/tmp/*"));
        assert!(!path_matches("/tmp/sub/file.txt", "/tmp/*"));
        assert!(!path_matches("/tmp", "/tmp/*"));
    }

    #[test]
    fn test_policy_deny_takes_precedence() {
        let policy = FileAccessPolicy {
            default: "allow".to_string(),
            allow: vec!["/home/user/**".to_string()],
            deny: vec!["/home/user/.ssh/**".to_string()],
        };

        assert!(check_file_policy(&policy, "/home/user/code/main.rs"));
        assert!(!check_file_policy(&policy, "/home/user/.ssh/id_rsa"));
    }

    #[test]
    fn test_policy_default_deny() {
        let policy = FileAccessPolicy {
            default: "deny".to_string(),
            allow: vec!["/tmp/**".to_string()],
            deny: vec![],
        };

        assert!(check_file_policy(&policy, "/tmp/file.txt"));
        assert!(!check_file_policy(&policy, "/etc/passwd"));
    }

    #[test]
    fn test_policy_default_allow() {
        let policy = FileAccessPolicy {
            default: "allow".to_string(),
            allow: vec![],
            deny: vec!["/etc/shadow".to_string()],
        };

        assert!(check_file_policy(&policy, "/tmp/file.txt"));
        assert!(!check_file_policy(&policy, "/etc/shadow"));
    }

    #[test]
    fn test_exec_policy() {
        let policy = ExecPolicy {
            default: "deny".to_string(),
            allow: vec!["/usr/bin/**".to_string()],
            deny: vec!["/usr/bin/rm".to_string()],
        };

        assert!(check_exec_policy(&policy, "/usr/bin/ls"));
        assert!(!check_exec_policy(&policy, "/usr/bin/rm"));
        assert!(!check_exec_policy(&policy, "/usr/sbin/reboot"));
    }

    #[test]
    fn test_pattern_to_policy_rule() {
        let rule = pattern_to_policy_rule("/home/user/.ssh/**");
        assert_eq!(rule.match_type, 1);
        assert_eq!(rule.prefix_len, 15);
        assert_eq!(&rule.path_prefix[..15], b"/home/user/.ssh");

        let rule = pattern_to_policy_rule("/etc/shadow");
        assert_eq!(rule.match_type, 0);
        assert_eq!(rule.prefix_len, 11);
    }

    #[test]
    fn test_normalize_path_dotdot() {
        assert_eq!(normalize_path("/tmp/../etc/shadow"), "/etc/shadow");
        assert_eq!(normalize_path("/home/user/../../etc/passwd"), "/etc/passwd");
        assert_eq!(normalize_path("/tmp/./file"), "/tmp/file");
    }

    #[test]
    fn test_normalize_path_proc_self_root() {
        assert_eq!(normalize_path("/proc/self/root/etc/shadow"), "/etc/shadow");
        assert_eq!(normalize_path("/proc/self/root/home/user/.ssh/id_rsa"), "/home/user/.ssh/id_rsa");
    }

    #[test]
    fn test_normalize_path_proc_pid_root() {
        assert_eq!(normalize_path("/proc/1234/root/etc/shadow"), "/etc/shadow");
        assert_eq!(normalize_path("/proc/1/root/etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn test_normalize_path_already_clean() {
        assert_eq!(normalize_path("/etc/shadow"), "/etc/shadow");
        assert_eq!(normalize_path("/tmp/file.txt"), "/tmp/file.txt");
    }

    #[test]
    fn test_policy_blocks_normalized_bypass() {
        let policy = FileAccessPolicy {
            default: "allow".to_string(),
            allow: vec!["/tmp/**".to_string()],
            deny: vec!["/etc/shadow".to_string()],
        };
        // These should all be denied after normalization
        assert!(!check_file_policy(&policy, "/proc/self/root/etc/shadow"));
        assert!(!check_file_policy(&policy, "/tmp/../etc/shadow"));
        assert!(!check_file_policy(&policy, "/proc/1234/root/etc/shadow"));
    }

    #[test]
    fn test_effective_identity_comm() {
        let agent = AgentConfig {
            name: "test".to_string(),
            identity: None,
            process_name: Some("myproc".to_string()),
            file_access: FileAccessPolicy {
                default: "deny".to_string(),
                allow: vec![],
                deny: vec![],
            },
            exec_policy: None,
            network_policy: None,
            watch_children: true,
            resources: None,
            fail_closed: None,
        };
        assert_eq!(agent.effective_identity(), "comm");
        assert_eq!(agent.effective_process_name(), "myproc");
    }

    #[test]
    fn test_effective_identity_cgroup() {
        let agent = AgentConfig {
            name: "test".to_string(),
            identity: Some("cgroup".to_string()),
            process_name: None,
            file_access: FileAccessPolicy {
                default: "deny".to_string(),
                allow: vec![],
                deny: vec![],
            },
            exec_policy: None,
            network_policy: None,
            watch_children: true,
            resources: None,
            fail_closed: None,
        };
        assert_eq!(agent.effective_identity(), "cgroup");
        assert_eq!(agent.effective_process_name(), "test");
    }
}
