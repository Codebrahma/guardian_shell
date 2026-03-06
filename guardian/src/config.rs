use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

// =============================================================================
// Configuration Data Structures
// =============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub global: GlobalConfig,
    pub agents: Vec<AgentConfig>,
}

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
}

fn default_mode() -> String {
    "monitor".to_string()
}

fn default_rescan_interval() -> u64 {
    5
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    pub name: String,
    pub process_name: String,
    pub file_access: FileAccessPolicy,
    /// Exec policy: controls which commands the agent can execute.
    /// Optional - if not set, all exec is allowed (monitor-only).
    pub exec_policy: Option<ExecPolicy>,
    /// Whether to track child processes of this agent. Default: true
    #[serde(default = "default_true")]
    pub watch_children: bool,
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

// =============================================================================
// Configuration Loading
// =============================================================================

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;

    let config: Config = toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

    validate_config(&config)?;

    Ok(config)
}

fn validate_config(config: &Config) -> Result<()> {
    if config.agents.is_empty() {
        log::warn!("No agents configured - Guardian Shell won't monitor anything");
    }

    // Validate mode
    match config.global.mode.as_str() {
        "monitor" | "enforce" => {}
        other => {
            anyhow::bail!(
                "Invalid global mode '{}'. Must be 'monitor' or 'enforce'",
                other
            );
        }
    }

    for agent in &config.agents {
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

    Ok(())
}

// =============================================================================
// Path Pattern Matching
// =============================================================================

pub fn check_file_policy(policy: &FileAccessPolicy, path: &str) -> bool {
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

fn path_matches(path: &str, pattern: &str) -> bool {
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
}
