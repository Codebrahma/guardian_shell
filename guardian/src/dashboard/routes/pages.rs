use askama::Template;
use axum::extract::State;
use axum::response::Html;
use prometheus::core::Collector;
use std::sync::Arc;

use crate::dashboard::DashboardState;

// =============================================================================
// Template Structs
// =============================================================================

#[derive(Template)]
#[template(path = "index.html")]
#[allow(dead_code)]
struct IndexTemplate {
    mode: String,
    agent_count: usize,
    active_cgroup_agents: usize,
    file_events: u64,
    blocked_events: u64,
}

#[derive(Template)]
#[template(path = "agents.html")]
#[allow(dead_code)]
struct AgentsTemplate {
    config_agents: Vec<AgentInfo>,
    cgroup_agents: Vec<CgroupAgentInfo>,
    user_home: String,
}

#[allow(dead_code)]
struct AgentInfo {
    name: String,
    identity: String,
    default_action: String,
    allow_count: usize,
    deny_count: usize,
    has_exec_policy: bool,
    /// Whether a cgroup agent is actively running (registered via guardian-launch).
    is_running: bool,
    /// "Tier 1" for cgroup (hardened), "Tier 2" for comm (limited).
    security_tier: String,
}

#[allow(dead_code)]
struct CgroupAgentInfo {
    name: String,
    cgroup_path: String,
    cgroup_id: u64,
    num_processes: u32,
    uptime_secs: u64,
}

#[derive(Template)]
#[template(path = "policy.html")]
#[allow(dead_code)]
struct PolicyTemplate {
    agents: Vec<PolicyAgentInfo>,
}

#[allow(dead_code)]
struct PolicyAgentInfo {
    name: String,
    identity: String,
    default_action: String,
    allow_rules: Vec<String>,
    deny_rules: Vec<String>,
    read_only_rules: Vec<String>,
    exec_default: Option<String>,
    exec_allow: Vec<String>,
    exec_deny: Vec<String>,
    net_default: Option<String>,
    net_allow_ports: Vec<u16>,
    net_deny_ports: Vec<u16>,
}

#[derive(Template)]
#[template(path = "alerts.html")]
#[allow(dead_code)]
struct AlertsTemplate {
    min_severity: String,
    dedup_window: u64,
    rate_limit: u32,
    json_enabled: bool,
    json_path: String,
    webhook_enabled: bool,
    webhook_url: String,
    slack_enabled: bool,
    slack_url: String,
    email_enabled: bool,
    email_host: String,
    prometheus_enabled: bool,
    prometheus_addr: String,
}

#[derive(Template)]
#[template(path = "events.html")]
struct EventsTemplate;

#[derive(Template)]
#[template(path = "requests.html")]
#[allow(dead_code)]
struct RequestsTemplate {
    pending: Vec<PendingRequestInfo>,
    resolved: Vec<ResolvedRequestInfo>,
}

#[allow(dead_code)]
struct PendingRequestInfo {
    id: u64,
    agent_name: String,
    resource_type: String,
    resource_path: String,
    justification: String,
    timeout_secs: u64,
    elapsed_secs: u64,
    requested_at: String,
    risk_level: String,
    risk_flags: Vec<String>,
    wait_seconds: u32,
    requires_type_confirm: bool,
    justification_warnings: Vec<String>,
}

#[allow(dead_code)]
struct ResolvedRequestInfo {
    id: u64,
    agent_name: String,
    resource_type: String,
    resource_path: String,
    justification: String,
    requested_at: String,
    resolved_at: String,
    approved: bool,
    reason: String,
    grant_duration_secs: u64,
    risk_level: String,
}

// =============================================================================
// Page Handlers
// =============================================================================

pub async fn index(
    State(state): State<Arc<DashboardState>>,
) -> Html<String> {
    let ipc = state.ipc_state.lock().await;
    let metrics = &state.alert_sender.metrics;

    // Gather metric totals
    let file_events = metrics.file_events.collect().iter().fold(0u64, |acc, mf| {
        acc + mf.get_metric().iter().fold(0u64, |a, m| a + m.get_counter().get_value() as u64)
    });
    let blocked_events = {
        let mut count = 0u64;
        for mf in metrics.file_events.collect().iter() {
            for m in mf.get_metric() {
                for lp in m.get_label() {
                    if lp.get_name() == "action" && lp.get_value() == "blocked" {
                        count += m.get_counter().get_value() as u64;
                    }
                }
            }
        }
        count
    };

    let tmpl = IndexTemplate {
        mode: ipc.config.global.mode.clone(),
        agent_count: ipc.config.agents.len(),
        active_cgroup_agents: ipc.agents.len(),
        file_events,
        blocked_events,
    };

    Html(tmpl.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn agents(
    State(state): State<Arc<DashboardState>>,
) -> Html<String> {
    let ipc = state.ipc_state.lock().await;

    let config_agents: Vec<AgentInfo> = ipc
        .config
        .agents
        .iter()
        .map(|a| {
            let ident = a.effective_identity();
            let is_cgroup = ident == "cgroup";
            AgentInfo {
                name: a.name.clone(),
                identity: ident.to_string(),
                default_action: a.file_access.default.clone(),
                allow_count: a.file_access.allow.len(),
                deny_count: a.file_access.deny.len(),
                has_exec_policy: a.exec_policy.is_some(),
                is_running: if is_cgroup { ipc.agents.contains_key(&a.name) } else { false },
                security_tier: if is_cgroup { "Tier 1".to_string() } else { "Tier 2".to_string() },
            }
        })
        .collect();

    let cgroup_agents: Vec<CgroupAgentInfo> = ipc
        .agents
        .values()
        .map(|a| {
            let procs_path = format!("/sys/fs/cgroup/{}/cgroup.procs", a.cgroup_path);
            let num_processes = std::fs::read_to_string(&procs_path)
                .map(|c| c.lines().filter(|l| !l.trim().is_empty()).count() as u32)
                .unwrap_or(0);
            CgroupAgentInfo {
                name: a.name.clone(),
                cgroup_path: a.cgroup_path.clone(),
                cgroup_id: a.cgroup_id,
                num_processes,
                uptime_secs: a.registered_at.elapsed().as_secs(),
            }
        })
        .collect();

    let user_home = std::env::var("HOME")
        .or_else(|_| std::env::var("SUDO_USER").map(|u| format!("/home/{}", u)))
        .unwrap_or_else(|_| "/home".to_string());

    let tmpl = AgentsTemplate {
        config_agents,
        cgroup_agents,
        user_home,
    };

    Html(tmpl.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn policy(
    State(state): State<Arc<DashboardState>>,
) -> Html<String> {
    let ipc = state.ipc_state.lock().await;

    let agents: Vec<PolicyAgentInfo> = ipc
        .config
        .agents
        .iter()
        .map(|a| PolicyAgentInfo {
            name: a.name.clone(),
            identity: a.effective_identity().to_string(),
            default_action: a.file_access.default.clone(),
            allow_rules: a.file_access.allow.clone(),
            deny_rules: a.file_access.deny.clone(),
            read_only_rules: a.file_access.read_only.clone(),
            exec_default: a.exec_policy.as_ref().map(|e| e.default.clone()),
            exec_allow: a.exec_policy.as_ref().map(|e| e.allow.clone()).unwrap_or_default(),
            exec_deny: a.exec_policy.as_ref().map(|e| e.deny.clone()).unwrap_or_default(),
            net_default: a.network_policy.as_ref().map(|n| n.default.clone()),
            net_allow_ports: a.network_policy.as_ref().map(|n| n.allow_ports.clone()).unwrap_or_default(),
            net_deny_ports: a.network_policy.as_ref().map(|n| n.deny_ports.clone()).unwrap_or_default(),
        })
        .collect();

    let tmpl = PolicyTemplate { agents };

    Html(tmpl.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn alerts(
    State(state): State<Arc<DashboardState>>,
) -> Html<String> {
    let ipc = state.ipc_state.lock().await;
    let alerting = ipc.config.alerting.as_ref();

    let tmpl = AlertsTemplate {
        min_severity: alerting.and_then(|a| a.min_severity.clone()).unwrap_or_else(|| "warning".to_string()),
        dedup_window: alerting.and_then(|a| a.dedup_window_seconds).unwrap_or(300),
        rate_limit: alerting.and_then(|a| a.rate_limit_per_minute).unwrap_or(100),
        json_enabled: alerting.and_then(|a| a.json_log.as_ref().map(|j| j.enabled)).unwrap_or(false),
        json_path: alerting.and_then(|a| a.json_log.as_ref().and_then(|j| j.path.clone())).unwrap_or_default(),
        webhook_enabled: alerting.and_then(|a| a.webhook.as_ref().map(|w| w.enabled)).unwrap_or(false),
        webhook_url: alerting.and_then(|a| a.webhook.as_ref().and_then(|w| w.url.clone())).unwrap_or_default(),
        slack_enabled: alerting.and_then(|a| a.slack.as_ref().map(|s| s.enabled)).unwrap_or(false),
        slack_url: alerting.and_then(|a| a.slack.as_ref().and_then(|s| s.webhook_url.clone())).unwrap_or_default(),
        email_enabled: alerting.and_then(|a| a.email.as_ref().map(|e| e.enabled)).unwrap_or(false),
        email_host: alerting.and_then(|a| a.email.as_ref().and_then(|e| e.smtp_host.clone())).unwrap_or_default(),
        prometheus_enabled: alerting.and_then(|a| a.prometheus.as_ref().map(|p| p.enabled)).unwrap_or(false),
        prometheus_addr: alerting.and_then(|a| a.prometheus.as_ref().and_then(|p| p.listen_address.clone())).unwrap_or_default(),
    };

    Html(tmpl.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn events() -> Html<String> {
    let tmpl = EventsTemplate;
    Html(tmpl.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn requests(
    State(state): State<Arc<DashboardState>>,
) -> Html<String> {
    let s = state.ipc_state.lock().await;

    let pending: Vec<PendingRequestInfo> = s
        .pending_permissions
        .iter()
        .map(|p| {
            let justification_warnings: Vec<String> = p.justification_flags.iter()
                .map(|(cat, matched)| format!("{}: \"{}\"", cat, matched))
                .collect();
            PendingRequestInfo {
                id: p.id,
                agent_name: p.agent_name.clone(),
                resource_type: p.resource_type.clone(),
                resource_path: p.resource_path.clone(),
                justification: p.justification.clone().unwrap_or_default(),
                timeout_secs: p.timeout_secs,
                elapsed_secs: p.requested_at.elapsed().as_secs(),
                requested_at: p.requested_at_utc.format("%H:%M:%S").to_string(),
                risk_level: p.risk_level.as_str().to_string(),
                risk_flags: p.risk_flags.clone(),
                wait_seconds: p.risk_level.wait_seconds(),
                requires_type_confirm: p.risk_level.requires_type_confirm(),
                justification_warnings,
            }
        })
        .collect();

    let resolved: Vec<ResolvedRequestInfo> = s
        .resolved_permissions
        .iter()
        .rev()
        .map(|r| ResolvedRequestInfo {
            id: r.id,
            agent_name: r.agent_name.clone(),
            resource_type: r.resource_type.clone(),
            resource_path: r.resource_path.clone(),
            justification: r.justification.clone().unwrap_or_default(),
            requested_at: r.requested_at.clone(),
            resolved_at: r.resolved_at.clone(),
            approved: r.approved,
            reason: r.reason.clone(),
            grant_duration_secs: r.grant_duration_secs.unwrap_or(0),
            risk_level: r.risk_level.clone(),
        })
        .collect();

    let tmpl = RequestsTemplate { pending, resolved };
    Html(tmpl.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}
