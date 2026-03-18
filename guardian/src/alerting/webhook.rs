use super::AlertEvent;
use crate::config::WebhookConfig;
use anyhow::{Context, Result};

/// JSON payload sent to webhook endpoints. Follows a common security event
/// schema designed for easy ingestion by SIEM tools, log aggregators, etc.
#[derive(serde::Serialize)]
struct WebhookPayload<'a> {
    version: &'static str,
    source: &'static str,
    timestamp: String,
    hostname: &'a str,
    severity: &'a str,
    event_type: &'a str,
    action: &'a str,
    agent_name: &'a str,
    pid: u32,
    comm: &'a str,
    path: &'a str,
    access_mode: &'a str,
    identity_method: &'a str,
    policy_mode: &'a str,
}

/// Send an alert to a generic webhook endpoint via HTTP POST.
pub async fn send_webhook(
    client: &reqwest::Client,
    config: &WebhookConfig,
    event: &AlertEvent,
    hostname: &str,
) -> Result<()> {
    let url = config
        .url
        .as_deref()
        .context("Webhook URL not configured")?;

    // Prevent SSRF: reject URLs targeting private/internal network addresses
    if let Err(reason) = super::validate_url_not_private(url) {
        anyhow::bail!("Webhook URL rejected (SSRF prevention): {}", reason);
    }

    let payload = WebhookPayload {
        version: "1.0",
        source: "guardian-shell",
        timestamp: event
            .timestamp
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        hostname,
        severity: &event.severity.to_string(),
        event_type: &event.event_type.to_string(),
        action: &event.action.to_string(),
        agent_name: &event.agent_name,
        pid: event.pid,
        comm: &event.comm,
        path: &event.path,
        access_mode: &event.access_mode,
        identity_method: &event.identity_method,
        policy_mode: &event.policy_mode,
    };

    let mut request = client.post(url).json(&payload);

    // Add optional auth header
    if let Some(ref auth) = config.auth_header {
        if !auth.is_empty() {
            request = request.header("Authorization", auth.as_str());
        }
    }

    // Add optional custom headers
    if let Some(ref headers) = config.headers {
        for (key, value) in headers {
            request = request.header(key.as_str(), value.as_str());
        }
    }

    let response = request.send().await.context("Webhook request failed")?;

    if !response.status().is_success() {
        anyhow::bail!(
            "Webhook returned HTTP {}: {}",
            response.status(),
            response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string())
        );
    }

    Ok(())
}
