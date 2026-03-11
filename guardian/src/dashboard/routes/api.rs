use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse};
use axum::Form;
use log::{error, info};
use prometheus::core::Collector;
use prometheus::{Encoder, TextEncoder};
use serde::Deserialize;
use std::sync::Arc;

use crate::config;
use crate::dashboard::DashboardState;
use crate::dashboard::db::EventFilter;

// =============================================================================
// Status Summary (htmx polling target)
// =============================================================================

pub async fn status_summary(
    State(state): State<Arc<DashboardState>>,
) -> Html<String> {
    let ipc = state.ipc_state.lock().await;
    let metrics = &state.alert_sender.metrics;

    let file_events: u64 = metrics
        .file_events
        .collect()
        .iter()
        .flat_map(|mf| mf.get_metric())
        .map(|m| m.get_counter().get_value() as u64)
        .sum();

    let blocked_events: u64 = metrics
        .file_events
        .collect()
        .iter()
        .flat_map(|mf| mf.get_metric())
        .filter(|m| {
            m.get_label()
                .iter()
                .any(|lp| lp.get_name() == "action" && lp.get_value() == "blocked")
        })
        .map(|m| m.get_counter().get_value() as u64)
        .sum();

    let mode_badge = if ipc.config.global.mode == "enforce" {
        "badge-mode-enforce"
    } else {
        "badge-mode-monitor"
    };

    Html(format!(
        r#"<div class="grid-4">
  <div class="stat-card">
    <div class="stat-label">Mode</div>
    <div style="margin-top: 8px;"><span class="badge {}">{}</span></div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Configured Agents</div>
    <div class="stat-value">{}</div>
    <div class="stat-sub">{} active cgroup</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">File Events</div>
    <div class="stat-value">{}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Blocked</div>
    <div class="stat-value" style="color: var(--danger);">{}</div>
  </div>
</div>"#,
        mode_badge,
        ipc.config.global.mode,
        ipc.config.agents.len(),
        ipc.agents.len(),
        file_events,
        blocked_events,
    ))
}

// =============================================================================
// Agent Management
// =============================================================================

pub async fn stop_agent(
    State(state): State<Arc<DashboardState>>,
    Path(name): Path<String>,
) -> Html<String> {
    let mut ipc = state.ipc_state.lock().await;

    let agent = match ipc.agents.get(&name) {
        Some(a) => a.clone(),
        None => {
            return Html(format!(
                r#"<div class="toast-error">Agent '{}' not found</div>"#,
                name
            ));
        }
    };

    // Send SIGTERM to all processes in the cgroup
    let cgroup_procs_path = format!("/sys/fs/cgroup/{}/cgroup.procs", agent.cgroup_path);
    let killed = match std::fs::read_to_string(&cgroup_procs_path) {
        Ok(procs) => {
            let mut count = 0;
            for line in procs.lines() {
                if let Ok(pid) = line.trim().parse::<i32>() {
                    unsafe { libc::kill(pid, libc::SIGTERM); }
                    count += 1;
                }
            }
            count
        }
        Err(_) => 0,
    };

    // Clean up BPF maps and state
    crate::ipc::cleanup_agent_pub(&mut ipc, &name);

    info!("Dashboard: stopped agent '{}' ({} processes killed)", name, killed);

    Html(format!(
        r#"<tr>
  <td colspan="6" style="text-align: center; padding: 16px; color: var(--text-muted);">Agent '{}' stopped ({} processes terminated)</td>
</tr>"#,
        name, killed
    ))
}

#[derive(Deserialize)]
pub struct GrantForm {
    pub grant_type: String,
    pub path: String,
    pub duration: u64,
}

pub async fn grant_access(
    State(state): State<Arc<DashboardState>>,
    Path(name): Path<String>,
    Form(form): Form<GrantForm>,
) -> Html<String> {
    let mut ipc = state.ipc_state.lock().await;

    // Verify agent exists
    let exists = ipc.agents.contains_key(&name)
        || ipc.config.agents.iter().any(|a| a.name == name);
    if !exists {
        return Html(format!(
            r#"<div class="toast-error">Agent '{}' not found</div>"#,
            name
        ));
    }

    let is_prefix = form.path.ends_with("/**");
    let expires_at = std::time::Instant::now() + std::time::Duration::from_secs(form.duration);

    if form.grant_type == "exec" {
        // Exec grant: add command to agent's exec policy allow list temporarily
        if let Some(agent_cfg) = ipc.config.agents.iter_mut().find(|a| a.name == name) {
            let exec = agent_cfg.exec_policy.get_or_insert(crate::config::ExecPolicy {
                default: "deny".to_string(),
                allow: vec![],
                deny: vec![],
            });
            if !exec.allow.contains(&form.path) {
                exec.allow.push(form.path.clone());
            }
        }

        ipc.grants.push(crate::ipc::TemporaryGrant {
            agent_name: name.clone(),
            path: form.path.clone(),
            is_prefix,
            grant_type: crate::ipc::GrantType::Exec,
            expires_at,
        });

        info!(
            "Dashboard: granted '{}' exec access to '{}' for {}s",
            name, form.path, form.duration
        );

        Html(format!(
            r#"<div class="toast-success">Granted '{}' exec access to '{}' for {}s</div>"#,
            name, form.path, form.duration
        ))
    } else {
        // File access grant: add to BPF allow maps
        if let Some(ref mut policy_maps) = ipc.policy_maps {
            if is_prefix {
                let prefix = format!("{}/", &form.path[..form.path.len() - 3]);
                let key = crate::ipc::path_to_lpm_key_pub(prefix.as_bytes());
                let _ = policy_maps.allow_prefixes.insert(&key, 1, 0);
            } else {
                let key = crate::ipc::path_to_map_key_pub(form.path.as_bytes());
                let _ = policy_maps.allow_exact.insert(key, 1, 0);
            }
        }

        ipc.grants.push(crate::ipc::TemporaryGrant {
            agent_name: name.clone(),
            path: form.path.clone(),
            is_prefix,
            grant_type: crate::ipc::GrantType::FileAccess,
            expires_at,
        });

        info!(
            "Dashboard: granted '{}' file access to '{}' for {}s",
            name, form.path, form.duration
        );

        Html(format!(
            r#"<div class="toast-success">Granted '{}' file access to '{}' for {}s</div>"#,
            name, form.path, form.duration
        ))
    }
}

// =============================================================================
// Policy Update
// =============================================================================

#[derive(Deserialize)]
pub struct PolicyUpdate {
    pub default_action: String,
    pub allow_rules: String,
    pub deny_rules: String,
    pub exec_default: Option<String>,
    pub exec_allow: Option<String>,
    pub exec_deny: Option<String>,
}

pub async fn update_policy(
    State(state): State<Arc<DashboardState>>,
    Path(agent_name): Path<String>,
    Form(form): Form<PolicyUpdate>,
) -> Html<String> {
    let mut ipc = state.ipc_state.lock().await;

    let agent = match ipc.config.agents.iter_mut().find(|a| a.name == agent_name) {
        Some(a) => a,
        None => {
            return Html(format!(
                r#"<div class="toast-error">Agent '{}' not found</div>"#,
                agent_name
            ));
        }
    };

    // Update file access policy
    agent.file_access.default = form.default_action;
    agent.file_access.allow = form
        .allow_rules
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    agent.file_access.deny = form
        .deny_rules
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    // Update exec policy if provided
    if let Some(exec_default) = form.exec_default {
        let exec = agent.exec_policy.get_or_insert(config::ExecPolicy {
            default: "allow".to_string(),
            allow: vec![],
            deny: vec![],
        });
        exec.default = exec_default;
        exec.allow = form
            .exec_allow
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        exec.deny = form
            .exec_deny
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
    }

    info!("Dashboard: updated policy for agent '{}'", agent_name);

    // Write config to disk
    let config_path = state.config_path.clone();
    let config = ipc.config.clone();
    drop(ipc);

    if let Err(e) = write_config_toml(&config_path, &config) {
        return Html(format!(
            r#"<div class="toast-error">Policy updated in memory but failed to write config: {}</div>"#,
            e
        ));
    }

    Html(format!(
        r#"<div class="toast-success">Policy for '{}' saved. Config written to disk. Send SIGHUP or use reload to apply to BPF maps.</div>"#,
        agent_name
    ))
}

// =============================================================================
// Alert Configuration
// =============================================================================

#[derive(Deserialize)]
pub struct AlertsUpdate {
    pub min_severity: String,
    pub dedup_window_seconds: u64,
    pub rate_limit_per_minute: u32,
    pub json_enabled: Option<String>,
    pub json_path: Option<String>,
    pub webhook_enabled: Option<String>,
    pub webhook_url: Option<String>,
    pub slack_enabled: Option<String>,
    pub slack_url: Option<String>,
    pub email_enabled: Option<String>,
    pub email_host: Option<String>,
    pub prometheus_enabled: Option<String>,
    pub prometheus_addr: Option<String>,
}

pub async fn update_alerts(
    State(state): State<Arc<DashboardState>>,
    Form(form): Form<AlertsUpdate>,
) -> Html<String> {
    let mut ipc = state.ipc_state.lock().await;

    let alerting = ipc.config.alerting.get_or_insert(config::AlertingConfig {
        min_severity: None,
        dedup_window_seconds: None,
        rate_limit_per_minute: None,
        json_log: None,
        webhook: None,
        slack: None,
        email: None,
        prometheus: None,
    });

    alerting.min_severity = Some(form.min_severity);
    alerting.dedup_window_seconds = Some(form.dedup_window_seconds);
    alerting.rate_limit_per_minute = Some(form.rate_limit_per_minute);

    // JSON log
    if form.json_enabled.is_some() {
        let jl = alerting.json_log.get_or_insert(config::JsonLogConfig {
            enabled: false,
            path: None,
            max_size_mb: None,
            max_files: None,
        });
        jl.enabled = true;
        jl.path = form.json_path.filter(|p| !p.is_empty());
    } else if let Some(ref mut jl) = alerting.json_log {
        jl.enabled = false;
    }

    // Webhook
    if form.webhook_enabled.is_some() {
        let wh = alerting.webhook.get_or_insert(config::WebhookConfig {
            enabled: false,
            url: None,
            auth_header: None,
            headers: None,
            min_severity: None,
        });
        wh.enabled = true;
        wh.url = form.webhook_url.filter(|u| !u.is_empty());
    } else if let Some(ref mut wh) = alerting.webhook {
        wh.enabled = false;
    }

    // Slack
    if form.slack_enabled.is_some() {
        let sl = alerting.slack.get_or_insert(config::SlackConfig {
            enabled: false,
            webhook_url: None,
            channel: None,
            min_severity: None,
        });
        sl.enabled = true;
        sl.webhook_url = form.slack_url.filter(|u| !u.is_empty());
    } else if let Some(ref mut sl) = alerting.slack {
        sl.enabled = false;
    }

    // Email
    if form.email_enabled.is_some() {
        let em = alerting.email.get_or_insert(config::EmailConfig {
            enabled: false,
            smtp_host: None,
            smtp_port: None,
            username: None,
            password: None,
            from: None,
            to: None,
            min_severity: None,
        });
        em.enabled = true;
        em.smtp_host = form.email_host.filter(|h| !h.is_empty());
    } else if let Some(ref mut em) = alerting.email {
        em.enabled = false;
    }

    // Prometheus
    if form.prometheus_enabled.is_some() {
        let pm = alerting.prometheus.get_or_insert(config::PrometheusConfig {
            enabled: false,
            listen_address: None,
            endpoint: None,
        });
        pm.enabled = true;
        pm.listen_address = form.prometheus_addr.filter(|a| !a.is_empty());
    } else if let Some(ref mut pm) = alerting.prometheus {
        pm.enabled = false;
    }

    info!("Dashboard: updated alerting configuration");

    let config_path = state.config_path.clone();
    let config = ipc.config.clone();
    drop(ipc);

    if let Err(e) = write_config_toml(&config_path, &config) {
        return Html(format!(
            r#"<div class="toast-error">Alert config updated in memory but failed to write: {}</div>"#,
            e
        ));
    }

    Html(r#"<div class="toast-success">Alerting configuration saved. Note: changes to alerting outputs take effect on next daemon restart.</div>"#.to_string())
}

// =============================================================================
// Permission Request Management
// =============================================================================

#[derive(Deserialize)]
pub struct ApproveForm {
    pub duration: Option<u64>,
}

pub async fn approve_permission(
    State(state): State<Arc<DashboardState>>,
    Path(id): Path<u64>,
    Form(form): Form<ApproveForm>,
) -> Html<String> {
    let duration = form.duration.unwrap_or(600);

    match crate::ipc::resolve_permission(
        &state.ipc_state,
        id,
        true,
        "Approved by user".to_string(),
        Some(duration),
    )
    .await
    {
        Ok(()) => Html(format!(
            r#"<div class="toast-success">Permission #{} approved ({}s grant)</div>"#,
            id, duration
        )),
        Err(msg) => Html(format!(
            r#"<div class="toast-error">{}</div>"#,
            msg
        )),
    }
}

pub async fn deny_permission(
    State(state): State<Arc<DashboardState>>,
    Path(id): Path<u64>,
) -> Html<String> {
    match crate::ipc::resolve_permission(
        &state.ipc_state,
        id,
        false,
        "Denied by user".to_string(),
        None,
    )
    .await
    {
        Ok(()) => Html(format!(
            r#"<div class="toast-success">Permission #{} denied</div>"#,
            id
        )),
        Err(msg) => Html(format!(
            r#"<div class="toast-error">{}</div>"#,
            msg
        )),
    }
}

/// JSON endpoint: list pending permission requests.
pub async fn list_pending_permissions(
    State(state): State<Arc<DashboardState>>,
) -> impl IntoResponse {
    let s = state.ipc_state.lock().await;
    let pending: Vec<serde_json::Value> = s
        .pending_permissions
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "agent_name": p.agent_name,
                "resource_type": p.resource_type,
                "resource_path": p.resource_path,
                "justification": p.justification,
                "timeout_secs": p.timeout_secs,
                "requested_at": p.requested_at_utc.to_rfc3339(),
                "elapsed_secs": p.requested_at.elapsed().as_secs(),
            })
        })
        .collect();
    axum::Json(pending)
}

/// JSON endpoint: list resolved permission requests (audit trail).
pub async fn list_resolved_permissions(
    State(state): State<Arc<DashboardState>>,
) -> impl IntoResponse {
    let s = state.ipc_state.lock().await;
    let resolved: Vec<_> = s.resolved_permissions.iter().rev().cloned().collect();
    axum::Json(resolved)
}

// =============================================================================
// Config Reload
// =============================================================================

pub async fn reload_config(
    State(state): State<Arc<DashboardState>>,
) -> Html<String> {
    match config::load_config(&state.config_path) {
        Ok(new_config) => {
            let mut ipc = state.ipc_state.lock().await;
            ipc.config = new_config.clone();
            info!(
                "Dashboard: config reloaded — {} agent(s), mode={}",
                new_config.agents.len(),
                new_config.global.mode
            );
            Html(format!(
                r#"<div class="toast-success">Config reloaded: {} agent(s), mode={}</div>"#,
                new_config.agents.len(),
                new_config.global.mode
            ))
        }
        Err(e) => {
            error!("Dashboard: config reload failed: {}", e);
            Html(format!(
                r#"<div class="toast-error">Reload failed: {}</div>"#,
                e
            ))
        }
    }
}

// =============================================================================
// Prometheus Metrics Endpoint
// =============================================================================

pub async fn prometheus_metrics(
    State(state): State<Arc<DashboardState>>,
) -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = state.alert_sender.metrics.registry.gather();
    let mut body = Vec::new();
    encoder.encode(&metric_families, &mut body).unwrap();

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

// =============================================================================
// Historical Events Query (from SQLite)
// =============================================================================

pub async fn query_events(
    State(state): State<Arc<DashboardState>>,
    Query(filter): Query<EventFilter>,
) -> impl IntoResponse {
    let count = state.db.count_events(&filter).unwrap_or(0);
    match state.db.query_events(&filter) {
        Ok(events) => axum::Json(serde_json::json!({
            "events": events,
            "total": count,
            "limit": filter.limit.unwrap_or(100),
            "offset": filter.offset.unwrap_or(0),
        }))
        .into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response(),
    }
}

// =============================================================================
// Config Serialization (write back to TOML)
// =============================================================================

fn write_config_toml(
    path: &std::path::Path,
    config: &config::Config,
) -> Result<(), String> {
    // Build TOML manually to preserve readable structure
    let mut out = String::new();

    // Global
    out.push_str("[global]\n");
    out.push_str(&format!("log_level = \"{}\"\n", config.global.log_level));
    out.push_str(&format!("mode = \"{}\"\n", config.global.mode));
    out.push_str(&format!(
        "pid_rescan_interval = {}\n",
        config.global.pid_rescan_interval
    ));
    out.push_str(&format!(
        "socket_path = \"{}\"\n",
        config.global.socket_path
    ));
    out.push_str("\n");

    // Dashboard
    if let Some(ref dash) = config.dashboard {
        out.push_str("[dashboard]\n");
        out.push_str(&format!("enabled = {}\n", dash.enabled));
        if let Some(ref addr) = dash.listen_address {
            out.push_str(&format!("listen_address = \"{}\"\n", addr));
        }
        if let Some(ref db) = dash.db_path {
            out.push_str(&format!("db_path = \"{}\"\n", db));
        }
        out.push_str("\n");
    }

    // Alerting
    if let Some(ref alerting) = config.alerting {
        out.push_str("[alerting]\n");
        if let Some(ref sev) = alerting.min_severity {
            out.push_str(&format!("min_severity = \"{}\"\n", sev));
        }
        if let Some(dedup) = alerting.dedup_window_seconds {
            out.push_str(&format!("dedup_window_seconds = {}\n", dedup));
        }
        if let Some(rate) = alerting.rate_limit_per_minute {
            out.push_str(&format!("rate_limit_per_minute = {}\n", rate));
        }
        out.push_str("\n");

        if let Some(ref jl) = alerting.json_log {
            out.push_str("[alerting.json_log]\n");
            out.push_str(&format!("enabled = {}\n", jl.enabled));
            if let Some(ref p) = jl.path {
                out.push_str(&format!("path = \"{}\"\n", p));
            }
            if let Some(ms) = jl.max_size_mb {
                out.push_str(&format!("max_size_mb = {}\n", ms));
            }
            if let Some(mf) = jl.max_files {
                out.push_str(&format!("max_files = {}\n", mf));
            }
            out.push_str("\n");
        }

        if let Some(ref wh) = alerting.webhook {
            out.push_str("[alerting.webhook]\n");
            out.push_str(&format!("enabled = {}\n", wh.enabled));
            if let Some(ref url) = wh.url {
                out.push_str(&format!("url = \"{}\"\n", url));
            }
            if let Some(ref auth) = wh.auth_header {
                out.push_str(&format!("auth_header = \"{}\"\n", auth));
            }
            if let Some(ref sev) = wh.min_severity {
                out.push_str(&format!("min_severity = \"{}\"\n", sev));
            }
            out.push_str("\n");
        }

        if let Some(ref sl) = alerting.slack {
            out.push_str("[alerting.slack]\n");
            out.push_str(&format!("enabled = {}\n", sl.enabled));
            if let Some(ref url) = sl.webhook_url {
                out.push_str(&format!("webhook_url = \"{}\"\n", url));
            }
            if let Some(ref ch) = sl.channel {
                out.push_str(&format!("channel = \"{}\"\n", ch));
            }
            if let Some(ref sev) = sl.min_severity {
                out.push_str(&format!("min_severity = \"{}\"\n", sev));
            }
            out.push_str("\n");
        }

        if let Some(ref em) = alerting.email {
            out.push_str("[alerting.email]\n");
            out.push_str(&format!("enabled = {}\n", em.enabled));
            if let Some(ref h) = em.smtp_host {
                out.push_str(&format!("smtp_host = \"{}\"\n", h));
            }
            if let Some(p) = em.smtp_port {
                out.push_str(&format!("smtp_port = {}\n", p));
            }
            if let Some(ref u) = em.username {
                out.push_str(&format!("username = \"{}\"\n", u));
            }
            if let Some(ref f) = em.from {
                out.push_str(&format!("from = \"{}\"\n", f));
            }
            if let Some(ref to) = em.to {
                let to_str: Vec<String> = to.iter().map(|t| format!("\"{}\"", t)).collect();
                out.push_str(&format!("to = [{}]\n", to_str.join(", ")));
            }
            if let Some(ref sev) = em.min_severity {
                out.push_str(&format!("min_severity = \"{}\"\n", sev));
            }
            out.push_str("\n");
        }

        if let Some(ref pm) = alerting.prometheus {
            out.push_str("[alerting.prometheus]\n");
            out.push_str(&format!("enabled = {}\n", pm.enabled));
            if let Some(ref addr) = pm.listen_address {
                out.push_str(&format!("listen_address = \"{}\"\n", addr));
            }
            if let Some(ref ep) = pm.endpoint {
                out.push_str(&format!("endpoint = \"{}\"\n", ep));
            }
            out.push_str("\n");
        }
    }

    // Agents
    for agent in &config.agents {
        out.push_str("[[agents]]\n");
        out.push_str(&format!("name = \"{}\"\n", agent.name));
        if let Some(ref id) = agent.identity {
            out.push_str(&format!("identity = \"{}\"\n", id));
        }
        if let Some(ref pn) = agent.process_name {
            out.push_str(&format!("process_name = \"{}\"\n", pn));
        }
        out.push_str(&format!("watch_children = {}\n", agent.watch_children));
        out.push_str("\n");

        out.push_str("[agents.file_access]\n");
        out.push_str(&format!("default = \"{}\"\n", agent.file_access.default));
        out.push_str("allow = [\n");
        for rule in &agent.file_access.allow {
            out.push_str(&format!("    \"{}\",\n", rule));
        }
        out.push_str("]\n");
        out.push_str("deny = [\n");
        for rule in &agent.file_access.deny {
            out.push_str(&format!("    \"{}\",\n", rule));
        }
        out.push_str("]\n\n");

        if let Some(ref exec) = agent.exec_policy {
            out.push_str("[agents.exec_policy]\n");
            out.push_str(&format!("default = \"{}\"\n", exec.default));
            out.push_str("allow = [\n");
            for rule in &exec.allow {
                out.push_str(&format!("    \"{}\",\n", rule));
            }
            out.push_str("]\n");
            out.push_str("deny = [\n");
            for rule in &exec.deny {
                out.push_str(&format!("    \"{}\",\n", rule));
            }
            out.push_str("]\n\n");
        }

        if let Some(ref res) = agent.resources {
            out.push_str("[agents.resources]\n");
            if let Some(ref mem) = res.memory_max {
                out.push_str(&format!("memory_max = \"{}\"\n", mem));
            }
            if let Some(pids) = res.pids_max {
                out.push_str(&format!("pids_max = {}\n", pids));
            }
            if let Some(ref cpu) = res.cpu_max {
                out.push_str(&format!("cpu_max = \"{}\"\n", cpu));
            }
            out.push_str("\n");
        }
    }

    std::fs::write(path, &out).map_err(|e| format!("Failed to write config: {}", e))
}
