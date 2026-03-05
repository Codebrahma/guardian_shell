// =============================================================================
// Guardian Shell - Configuration Module
// =============================================================================
//
// This module handles loading and parsing the TOML configuration file that
// defines security policies for monitored LLM agents.
//
// The configuration follows a hierarchical structure:
//
//   Global Settings
//   └── Agents (one or more)
//       ├── Identity (process_name)
//       └── File Access Policy
//           ├── Default action (allow/deny)
//           ├── Allow patterns
//           └── Deny patterns
//
// SECURITY DESIGN PRINCIPLES:
//
//   1. Deny by default: If no rule matches, access should be denied.
//      This follows the principle of least privilege - agents only get
//      the access they explicitly need.
//
//   2. Deny takes precedence: If a path matches both an allow and deny
//      pattern, it is DENIED. This prevents accidental over-permissioning.
//
//   3. Pattern specificity: More specific patterns should be used for
//      sensitive paths (e.g., deny "/home/user/.ssh/**" even if
//      "/home/user/**" is allowed).

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

// =============================================================================
// Configuration Data Structures
// =============================================================================

/// Root configuration structure.
///
/// # Example Configuration (config.toml)
///
/// ```toml
/// [global]
/// log_level = "info"
///
/// [[agents]]
/// name = "claude-code"
/// process_name = "claude"
///
/// [agents.file_access]
/// default = "deny"
/// allow = ["/home/user/projects/**", "/tmp/**"]
/// deny = ["/home/user/.ssh/**"]
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Global settings that apply to the entire Guardian daemon
    pub global: GlobalConfig,

    /// List of agent configurations, each defining an LLM agent to monitor
    /// and its associated security policy
    pub agents: Vec<AgentConfig>,
}

/// Global daemon settings.
#[derive(Debug, Clone, Deserialize)]
pub struct GlobalConfig {
    /// Log level for the daemon: "trace", "debug", "info", "warn", "error"
    ///
    /// - "trace": Everything, including raw event data (very verbose)
    /// - "debug": Detailed operational info (eBPF loading, PID discovery)
    /// - "info":  Normal operation (allow/deny decisions, startup/shutdown)
    /// - "warn":  Policy violations and potential issues
    /// - "error": Failures that prevent monitoring
    pub log_level: String,
}

/// Configuration for a single LLM agent.
///
/// Each agent represents a process (or set of processes with the same name)
/// that Guardian Shell monitors and restricts.
///
/// # Future Extensions
///
/// In later phases, this will be extended with:
///   - `cgroup`: Match by cgroup path (better for containerized agents)
///   - `exec_policy`: Control which commands the agent can execute
///   - `network_policy`: Control network access
///   - `time_window`: Only allow access during specific time periods
///   - `alert_channels`: Where to send alerts (Slack, email, webhook)
#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    /// Human-readable name for this agent (used in logs and alerts)
    ///
    /// Example: "claude-code", "auto-gpt", "aider"
    pub name: String,

    /// Process name to match against /proc/PID/comm.
    ///
    /// The Linux kernel truncates process names to 15 characters.
    /// You can check a process's comm with: `cat /proc/<PID>/comm`
    ///
    /// Example: "node" for a Node.js-based agent, "python3" for Python-based
    ///
    /// IMPORTANT: This must match EXACTLY. If the agent runs as "python3.11",
    /// you must use "python3.11" (which gets truncated to "python3.11" - 11 chars, fits).
    pub process_name: String,

    /// File access policy for this agent
    pub file_access: FileAccessPolicy,
}

/// Defines which files/directories an agent is allowed to access.
///
/// # Path Matching Rules
///
/// Patterns support simple glob-style matching:
///
///   - Exact path: "/etc/passwd" matches only that specific file
///   - Directory wildcard: "/home/user/**" matches everything under /home/user/
///     including all subdirectories recursively
///   - Single-level wildcard: "/tmp/*" matches files directly in /tmp/
///     but NOT files in subdirectories like /tmp/subdir/file
///
/// # Evaluation Order
///
///   1. Check DENY patterns first - if ANY deny pattern matches → DENIED
///   2. Check ALLOW patterns - if ANY allow pattern matches → ALLOWED
///   3. Apply default action
///
/// This means deny patterns ALWAYS win over allow patterns. This is a
/// security best practice: it's better to accidentally deny something
/// (user notices and adds an allow rule) than to accidentally allow
/// access to sensitive files.
///
/// # Example
///
/// ```toml
/// [agents.file_access]
/// default = "deny"
/// allow = [
///     "/home/user/projects/**",   # Allow access to project files
///     "/usr/lib/**",              # Allow reading system libraries
///     "/tmp/guardian-*",          # Allow specific temp files
/// ]
/// deny = [
///     "/home/user/projects/.env", # But deny .env files even in projects!
///     "/home/user/.ssh/**",       # Never allow SSH key access
/// ]
/// ```
///
/// With this config:
///   - /home/user/projects/main.rs     → ALLOWED (matches allow pattern)
///   - /home/user/projects/.env        → DENIED  (matches deny, deny wins)
///   - /home/user/.ssh/id_rsa          → DENIED  (matches deny)
///   - /etc/passwd                     → DENIED  (no match, default=deny)
#[derive(Debug, Clone, Deserialize)]
pub struct FileAccessPolicy {
    /// Default action when no pattern matches: "allow" or "deny"
    ///
    /// SECURITY RECOMMENDATION: Always use "deny" as the default.
    /// This implements the principle of least privilege - agents only
    /// get access to explicitly allowed paths.
    pub default: String,

    /// List of path patterns that are ALLOWED.
    ///
    /// Supports glob patterns:
    ///   - "/path/to/dir/**" : recursive wildcard (all files under dir)
    ///   - "/path/to/dir/*"  : single-level wildcard (files directly in dir)
    ///   - "/path/to/file"   : exact match
    pub allow: Vec<String>,

    /// List of path patterns that are DENIED.
    ///
    /// These take precedence over allow patterns. Even if a path matches
    /// an allow rule, a matching deny rule will block access.
    pub deny: Vec<String>,
}

// =============================================================================
// Configuration Loading
// =============================================================================

/// Loads and parses the configuration file from the given path.
///
/// # Arguments
///
/// * `path` - Path to the TOML configuration file
///
/// # Returns
///
/// The parsed configuration, or an error with context about what went wrong.
///
/// # Errors
///
/// - File not found: Check the path and ensure the file exists
/// - Parse error: Check the TOML syntax and field names
/// - Missing required fields: Ensure all required fields are present
///
/// # Example
///
/// ```rust
/// let config = load_config("config.toml")?;
/// println!("Monitoring {} agents", config.agents.len());
/// for agent in &config.agents {
///     println!("  - {} (process: {})", agent.name, agent.process_name);
/// }
/// ```
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;

    let config: Config = toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

    validate_config(&config)?;

    Ok(config)
}

/// Validates the configuration for common mistakes and security issues.
///
/// This function checks for:
///   - Empty agent list (probably a config mistake)
///   - Invalid default actions (must be "allow" or "deny")
///   - Overly permissive patterns (e.g., "/**" allows everything)
///   - Missing deny patterns for sensitive system files
fn validate_config(config: &Config) -> Result<()> {
    if config.agents.is_empty() {
        log::warn!("No agents configured - Guardian Shell won't monitor anything");
    }

    for agent in &config.agents {
        // Validate the default action
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

        // Security warning: default "allow" is risky
        if agent.file_access.default == "allow" {
            log::warn!(
                "Agent '{}': default action is 'allow'. This is permissive - \
                 consider using 'deny' with explicit allow patterns for better security.",
                agent.name
            );
        }

        // Security warning: overly broad allow patterns
        for pattern in &agent.file_access.allow {
            if pattern == "/**" || pattern == "/*" {
                log::warn!(
                    "Agent '{}': allow pattern '{}' is extremely broad and \
                     effectively allows access to everything. Consider being more specific.",
                    agent.name,
                    pattern
                );
            }
        }

        // Validate patterns are absolute paths
        for pattern in agent
            .file_access
            .allow
            .iter()
            .chain(agent.file_access.deny.iter())
        {
            if !pattern.starts_with('/') {
                log::warn!(
                    "Agent '{}': pattern '{}' is not an absolute path. \
                     Relative path matching may not work as expected since the \
                     eBPF program captures the path as provided by the syscall \
                     (which may be relative to the process CWD).",
                    agent.name,
                    pattern
                );
            }
        }
    }

    Ok(())
}

// =============================================================================
// Path Pattern Matching
// =============================================================================

/// Checks if a file access is allowed by the given policy.
///
/// # Evaluation Order
///
/// 1. If path matches ANY deny pattern → DENIED (deny always wins)
/// 2. If path matches ANY allow pattern → ALLOWED
/// 3. Apply default action from policy
///
/// # Arguments
///
/// * `policy` - The file access policy to evaluate against
/// * `path` - The file path being accessed (from the eBPF event)
///
/// # Returns
///
/// `true` if access is allowed, `false` if denied
///
/// # Examples
///
/// ```rust
/// let policy = FileAccessPolicy {
///     default: "deny".to_string(),
///     allow: vec!["/home/user/**".to_string()],
///     deny: vec!["/home/user/.ssh/**".to_string()],
/// };
///
/// assert!(check_file_policy(&policy, "/home/user/code/main.rs"));   // allowed
/// assert!(!check_file_policy(&policy, "/home/user/.ssh/id_rsa"));   // denied
/// assert!(!check_file_policy(&policy, "/etc/passwd"));              // default deny
/// ```
pub fn check_file_policy(policy: &FileAccessPolicy, path: &str) -> bool {
    // Step 1: Check deny list first (deny takes precedence over everything)
    for pattern in &policy.deny {
        if path_matches(path, pattern) {
            return false;
        }
    }

    // Step 2: Check allow list
    for pattern in &policy.allow {
        if path_matches(path, pattern) {
            return true;
        }
    }

    // Step 3: Apply default action
    policy.default == "allow"
}

/// Matches a file path against a glob-like pattern.
///
/// Supported patterns:
///
///   - `/path/to/dir/**` : Recursive wildcard
///     Matches everything under /path/to/dir/, including subdirectories.
///     Example: "/home/user/**" matches "/home/user/a/b/c/file.txt"
///
///   - `/path/to/dir/*` : Single-level wildcard
///     Matches files directly in /path/to/dir/, but NOT subdirectories.
///     Example: "/tmp/*" matches "/tmp/file.txt" but NOT "/tmp/sub/file.txt"
///
///   - `/path/to/file` : Exact match
///     Matches only the exact path.
///     Example: "/etc/passwd" matches only "/etc/passwd"
///
/// # Arguments
///
/// * `path` - The actual file path to check
/// * `pattern` - The glob pattern to match against
///
/// # Returns
///
/// `true` if the path matches the pattern
fn path_matches(path: &str, pattern: &str) -> bool {
    if pattern.ends_with("/**") {
        // Recursive wildcard: match everything under this directory
        // Remove the trailing "/**" to get the directory prefix
        let prefix = &pattern[..pattern.len() - 3];
        // The path must start with the prefix and either:
        //   - Equal the prefix exactly (the directory itself)
        //   - Have a '/' after the prefix (a file/dir under it)
        path == prefix || path.starts_with(&format!("{}/", prefix))
    } else if pattern.ends_with("/*") {
        // Single-level wildcard: match files directly in this directory
        let prefix = &pattern[..pattern.len() - 2];
        if let Some(rest) = path.strip_prefix(prefix) {
            // Must start with '/' and not contain another '/' after that
            rest.starts_with('/') && !rest[1..].contains('/')
        } else {
            false
        }
    } else {
        // Exact match
        path == pattern
    }
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
}
