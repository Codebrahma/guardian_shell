//! Permission request hardening: rate limiting, risk classification,
//! auto-deny/auto-approve, and justification analysis.
//!
//! Phase 7c implementation based on security-improvements-research.md.

use std::collections::HashMap;
use std::time::Instant;

use crate::config::{normalize_path, path_matches, PermissionsConfig};

// =============================================================================
// Rate Limiter
// =============================================================================

/// Per-agent rate limiting state.
#[derive(Debug, Clone)]
pub struct AgentRateLimit {
    pub requests_this_minute: u32,
    pub requests_this_hour: u32,
    pub minute_reset: Instant,
    pub hour_reset: Instant,
    pub consecutive_denials: u32,
    pub last_denial_at: Option<Instant>,
    /// Resources denied recently: resource_path -> denial time.
    pub recently_denied_resources: HashMap<String, Instant>,
}

impl AgentRateLimit {
    pub fn new() -> Self {
        Self {
            requests_this_minute: 0,
            requests_this_hour: 0,
            minute_reset: Instant::now(),
            hour_reset: Instant::now(),
            consecutive_denials: 0,
            last_denial_at: None,
            recently_denied_resources: HashMap::new(),
        }
    }

    /// Check if the agent is rate-limited. Returns Some(reason) if blocked.
    pub fn check(&mut self, config: &PermissionsConfig, resource_path: &str) -> Option<String> {
        let now = Instant::now();

        // Reset minute counter
        if now.duration_since(self.minute_reset).as_secs() >= 60 {
            self.requests_this_minute = 0;
            self.minute_reset = now;
        }

        // Reset hour counter
        if now.duration_since(self.hour_reset).as_secs() >= 3600 {
            self.requests_this_hour = 0;
            self.hour_reset = now;
        }

        // Check per-minute limit
        if self.requests_this_minute >= config.rate_limit_per_minute {
            return Some(format!(
                "Rate limited: {} requests/minute exceeded (max {})",
                self.requests_this_minute, config.rate_limit_per_minute
            ));
        }

        // Check per-hour limit
        if self.requests_this_hour >= config.rate_limit_per_hour {
            return Some(format!(
                "Rate limited: {} requests/hour exceeded (max {})",
                self.requests_this_hour, config.rate_limit_per_hour
            ));
        }

        // Exponential backoff after denials
        if self.consecutive_denials > 0 {
            if let Some(last_denial) = self.last_denial_at {
                let cooldown = std::cmp::min(
                    config.deny_cooldown_secs * (1 << (self.consecutive_denials - 1).min(8)),
                    600, // Max 10 minutes
                );
                let elapsed = now.duration_since(last_denial).as_secs();
                if elapsed < cooldown {
                    return Some(format!(
                        "Cooldown active: {} denials, wait {}s ({}s remaining)",
                        self.consecutive_denials,
                        cooldown,
                        cooldown - elapsed
                    ));
                }
            }
        }

        // Same-resource cooldown after denial (5 minutes)
        if let Some(denied_at) = self.recently_denied_resources.get(resource_path) {
            let elapsed = now.duration_since(*denied_at).as_secs();
            if elapsed < 300 {
                return Some(format!(
                    "Same resource '{}' was denied {}s ago (cooldown: 300s)",
                    resource_path, elapsed
                ));
            }
        }

        // Clean up old denied resources (older than 5 minutes)
        self.recently_denied_resources
            .retain(|_, t| now.duration_since(*t).as_secs() < 300);

        None
    }

    /// Record that a request was made.
    pub fn record_request(&mut self) {
        self.requests_this_minute += 1;
        self.requests_this_hour += 1;
    }

    /// Record that a request was denied.
    pub fn record_denial(&mut self, resource_path: &str) {
        self.consecutive_denials += 1;
        self.last_denial_at = Some(Instant::now());
        self.recently_denied_resources
            .insert(resource_path.to_string(), Instant::now());
    }

    /// Record that a request was approved (resets consecutive denials).
    pub fn record_approval(&mut self) {
        self.consecutive_denials = 0;
    }
}

// =============================================================================
// Risk Classification
// =============================================================================

/// Risk level for a permission request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }

    /// Mandatory wait time in seconds before approve button activates.
    pub fn wait_seconds(&self) -> u32 {
        match self {
            RiskLevel::Low => 0,
            RiskLevel::Medium => 3,
            RiskLevel::High => 5,
            RiskLevel::Critical => 10,
        }
    }

    /// Whether type-to-confirm is required.
    pub fn requires_type_confirm(&self) -> bool {
        matches!(self, RiskLevel::Critical)
    }

    /// Permission request timeout based on risk level.
    pub fn timeout_secs(&self, config: Option<&crate::config::RiskTimeoutConfig>) -> u64 {
        match config {
            Some(c) => match self {
                RiskLevel::Low => c.low,
                RiskLevel::Medium => c.medium,
                RiskLevel::High => c.high,
                RiskLevel::Critical => c.critical,
            },
            None => match self {
                RiskLevel::Low => 60,
                RiskLevel::Medium => 120,
                RiskLevel::High => 180,
                RiskLevel::Critical => 300,
            },
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Tracks cumulative grant durations per agent per resource within a 24-hour window.
#[derive(Debug, Clone)]
pub struct GrantAccumulator {
    /// Map of (agent_name, resource_path) -> Vec<(grant_time, duration_secs)>
    grants: HashMap<(String, String), Vec<(Instant, u64)>>,
}

impl GrantAccumulator {
    pub fn new() -> Self {
        Self { grants: HashMap::new() }
    }

    /// Record a grant and return the total accumulated seconds in the past 24 hours.
    pub fn record_and_check(&mut self, agent_name: &str, resource_path: &str, duration_secs: u64) -> u64 {
        let key = (agent_name.to_string(), resource_path.to_string());
        let entries = self.grants.entry(key).or_default();
        let now = Instant::now();
        // Prune entries older than 24 hours
        entries.retain(|(t, _)| now.duration_since(*t).as_secs() < 86400);
        entries.push((now, duration_secs));
        entries.iter().map(|(_, d)| *d).sum()
    }

    /// Get total accumulated grant seconds for an agent+resource in the past 24h.
    pub fn total_secs(&mut self, agent_name: &str, resource_path: &str) -> u64 {
        let key = (agent_name.to_string(), resource_path.to_string());
        let now = Instant::now();
        if let Some(entries) = self.grants.get_mut(&key) {
            entries.retain(|(t, _)| now.duration_since(*t).as_secs() < 86400);
            entries.iter().map(|(_, d)| *d).sum()
        } else {
            0
        }
    }
}

/// Critical resource patterns — HIGH/CRITICAL risk.
const CRITICAL_PATTERNS: &[&str] = &[
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d/**",
    "/root/**",
    "/root/.bash_history",
];

const HIGH_PATTERNS: &[&str] = &[
    "/etc/passwd",
    "/var/log/**",
];

/// Exec commands considered high-risk.
const HIGH_RISK_EXECS: &[&str] = &[
    "/usr/bin/curl",
    "/usr/bin/wget",
    "/usr/bin/nc",
    "/usr/bin/ncat",
    "/usr/bin/ssh",
    "/usr/bin/scp",
    "/usr/bin/rsync",
    "/usr/bin/rm",
    "/usr/bin/dd",
    "/usr/sbin/mkfs",
    "/usr/bin/shred",
];

const LOW_PATTERNS: &[&str] = &[
    "/tmp/**",
    "/proc/self/status",
    "/proc/self/stat",
    "/proc/self/cmdline",
    "/proc/meminfo",
    "/proc/cpuinfo",
    "/proc/loadavg",
    "/proc/version",
];

/// Classify the risk level of a permission request.
pub fn classify_risk(
    resource_type: &str,
    resource_path: &str,
    agent_rate: &AgentRateLimit,
) -> (RiskLevel, Vec<String>) {
    let normalized = normalize_path(resource_path);
    let path = normalized.as_str();
    let mut score: u32 = 25; // Base: MEDIUM
    let mut flags: Vec<String> = Vec::new();

    // Check critical patterns
    for pattern in CRITICAL_PATTERNS {
        if path_matches(path, pattern) {
            score = 90;
            flags.push(format!("critical_path:{}", pattern));
            break;
        }
    }

    // Check high-risk patterns
    if score < 51 {
        for pattern in HIGH_PATTERNS {
            if path_matches(path, pattern) {
                score = 60;
                flags.push(format!("sensitive_path:{}", pattern));
                break;
            }
        }
    }

    // Check low-risk patterns
    if score <= 25 {
        for pattern in LOW_PATTERNS {
            if path_matches(path, pattern) {
                score = 10;
                flags.push("low_risk_path".to_string());
                break;
            }
        }
    }

    // Exec type: 1.5x multiplier
    if resource_type == "exec" {
        score = (score as f64 * 1.5) as u32;
        flags.push("exec_type".to_string());

        // Known risky executables
        for exec in HIGH_RISK_EXECS {
            if path == *exec {
                score = score.max(60);
                flags.push(format!("risky_exec:{}", exec));
                break;
            }
        }
    }

    // Repeat request after denial: 2.0x
    if agent_rate.consecutive_denials > 0 {
        score = (score as f64 * 2.0).min(100.0) as u32;
        flags.push(format!("post_denial:{}", agent_rate.consecutive_denials));
    }

    // High request rate: 1.3x
    if agent_rate.requests_this_hour > 5 {
        score = (score as f64 * 1.3).min(100.0) as u32;
        flags.push(format!("high_rate:{}/hr", agent_rate.requests_this_hour));
    }

    let level = match score {
        0..=25 => RiskLevel::Low,
        26..=50 => RiskLevel::Medium,
        51..=75 => RiskLevel::High,
        _ => RiskLevel::Critical,
    };

    (level, flags)
}

// =============================================================================
// Auto-Deny / Auto-Approve
// =============================================================================

/// Check if a resource should be auto-denied (never approvable).
pub fn check_auto_deny(config: &PermissionsConfig, resource_path: &str) -> bool {
    let normalized = normalize_path(resource_path);
    for pattern in &config.auto_deny {
        if path_matches(&normalized, pattern) {
            return true;
        }
    }
    false
}

/// Check if a resource should be auto-approved.
/// Returns Some(max_duration_secs) if auto-approvable, None otherwise.
pub fn check_auto_approve(config: &PermissionsConfig, resource_path: &str) -> Option<u64> {
    let normalized = normalize_path(resource_path);
    for rule in &config.auto_approve {
        if path_matches(&normalized, &rule.pattern) {
            return Some(rule.max_duration_secs);
        }
    }
    None
}

// =============================================================================
// Justification Analysis
// =============================================================================

/// Suspicious patterns in justification text: (pattern, category, weight).
const SUSPICIOUS_PATTERNS: &[(&str, &str, u32)] = &[
    ("urgent", "URGENCY", 3),
    ("immediately", "URGENCY", 3),
    ("emergency", "URGENCY", 4),
    ("asap", "URGENCY", 2),
    ("disable security", "SECURITY_BYPASS", 5),
    ("bypass", "SECURITY_BYPASS", 4),
    ("override", "SECURITY_BYPASS", 3),
    ("skip check", "SECURITY_BYPASS", 4),
    ("trust me", "REASSURANCE", 3),
    ("don't worry", "REASSURANCE", 2),
    ("it's safe", "REASSURANCE", 3),
    ("it's fine", "REASSURANCE", 2),
    ("it's harmless", "REASSURANCE", 3),
    ("admin told", "AUTHORITY_CLAIM", 4),
    ("supervisor", "AUTHORITY_CLAIM", 3),
    ("authorized by", "AUTHORITY_CLAIM", 4),
    ("ssh key", "SENSITIVE_MENTION", 2),
    ("password", "SENSITIVE_MENTION", 2),
    ("credential", "SENSITIVE_MENTION", 2),
    ("secret", "SENSITIVE_MENTION", 2),
    ("token", "SENSITIVE_MENTION", 1),
    ("api key", "SENSITIVE_MENTION", 2),
];

/// Analyze justification text for suspicious patterns.
/// Returns list of (pattern_type, matched_text) tuples and a total suspicion score.
pub fn analyze_justification(justification: &str) -> (Vec<(String, String)>, u32) {
    let lower = justification.to_lowercase();
    let mut findings = Vec::new();
    let mut total_score: u32 = 0;

    for &(pattern, category, weight) in SUSPICIOUS_PATTERNS {
        if lower.contains(pattern) {
            findings.push((category.to_string(), pattern.to_string()));
            total_score += weight;
        }
    }

    (findings, total_score)
}

/// Returns the number of risk tier bumps based on justification score.
/// Score >= 8 -> +2 tiers, score >= 3 -> +1 tier, else 0.
pub fn justification_risk_bump(findings: &[(String, String)], score: u32) -> u32 {
    if findings.is_empty() {
        return 0;
    }
    if score >= 8 {
        2
    } else if score >= 3 {
        1
    } else {
        0
    }
}

// =============================================================================
// Anomaly Detection
// =============================================================================

/// Anomaly detection for approval patterns.
/// Queries SQLite for rubber-stamping, persistence, and flood patterns.
pub struct AnomalyDetector;

impl AnomalyDetector {
    pub fn new() -> Self { Self }

    /// Run anomaly detection checks. Returns a list of findings.
    pub fn detect_anomalies(&self, db: &crate::dashboard::db::EventDb) -> Vec<String> {
        let mut findings = Vec::new();

        // Check for rubber-stamping (>90% approval rate in last 24h)
        match db.approval_rate_24h() {
            Ok((total, approved)) if total >= 10 => {
                let rate = approved as f64 / total as f64;
                if rate > 0.9 {
                    findings.push(format!(
                        "Rubber-stamping detected: {:.0}% approval rate ({}/{} requests in 24h)",
                        rate * 100.0, approved, total
                    ));
                }
            }
            _ => {}
        }

        // Check for high-volume agents
        match db.high_volume_agents_24h(20) {
            Ok(agents) => {
                for (name, count) in agents {
                    findings.push(format!(
                        "High-volume agent '{}': {} permission requests in 24h",
                        name, count
                    ));
                }
            }
            _ => {}
        }

        // Check for deny-then-approve patterns (persistence attacks)
        match db.agents_with_deny_then_approve() {
            Ok(agents) => {
                for name in agents {
                    findings.push(format!(
                        "Persistence pattern: agent '{}' had denied requests later approved for same resource",
                        name
                    ));
                }
            }
            _ => {}
        }

        findings
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> PermissionsConfig {
        PermissionsConfig {
            auto_deny: vec![
                "/etc/shadow".to_string(),
                "/home/user/.ssh/**".to_string(),
            ],
            auto_approve: vec![crate::config::AutoApproveRule {
                pattern: "/tmp/**".to_string(),
                max_duration_secs: 300,
            }],
            rate_limit_per_minute: 3,
            rate_limit_per_hour: 15,
            deny_cooldown_secs: 30,
            max_pending_per_agent: 2,
            timeouts: None,
            max_grant_total_secs: 3600,
        }
    }

    #[test]
    fn test_auto_deny() {
        let config = test_config();
        assert!(check_auto_deny(&config, "/etc/shadow"));
        assert!(check_auto_deny(&config, "/home/user/.ssh/id_rsa"));
        assert!(!check_auto_deny(&config, "/tmp/file.txt"));
    }

    #[test]
    fn test_auto_deny_with_bypass_attempts() {
        let config = test_config();
        // These should be caught by normalize_path + auto_deny
        assert!(check_auto_deny(&config, "/proc/self/root/etc/shadow"));
        assert!(check_auto_deny(&config, "/tmp/../etc/shadow"));
    }

    #[test]
    fn test_auto_approve() {
        let config = test_config();
        assert_eq!(check_auto_approve(&config, "/tmp/file.txt"), Some(300));
        assert_eq!(check_auto_approve(&config, "/etc/passwd"), None);
    }

    #[test]
    fn test_risk_classification() {
        let rate = AgentRateLimit::new();
        let (level, _) = classify_risk("file", "/etc/shadow", &rate);
        assert_eq!(level, RiskLevel::Critical);

        let (level, _) = classify_risk("file", "/tmp/file.txt", &rate);
        assert_eq!(level, RiskLevel::Low);

        let (level, _) = classify_risk("exec", "/usr/bin/curl", &rate);
        assert!(level >= RiskLevel::High);
    }

    #[test]
    fn test_justification_analysis() {
        let (findings, score) = analyze_justification("This is urgent, trust me it's safe");
        assert!(findings.iter().any(|(cat, _)| cat == "URGENCY"));
        assert!(findings.iter().any(|(cat, _)| cat == "REASSURANCE"));
        assert!(score >= 3);

        let (findings, score) = analyze_justification("Need to read config for deployment");
        assert!(findings.is_empty());
        assert_eq!(score, 0);
    }

    #[test]
    fn test_rate_limiter() {
        let config = test_config();
        let mut rate = AgentRateLimit::new();

        // First 3 requests should be fine
        assert!(rate.check(&config, "/tmp/a").is_none());
        rate.record_request();
        assert!(rate.check(&config, "/tmp/b").is_none());
        rate.record_request();
        assert!(rate.check(&config, "/tmp/c").is_none());
        rate.record_request();

        // 4th request should be rate-limited
        assert!(rate.check(&config, "/tmp/d").is_some());
    }
}
