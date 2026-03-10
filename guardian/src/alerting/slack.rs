use super::{AlertEvent, Severity};
use crate::config::SlackConfig;
use anyhow::{Context, Result};

/// Send a richly-formatted alert to a Slack channel via incoming webhook.
/// Uses Slack Block Kit for structured, readable messages.
pub async fn send_slack_alert(
    client: &reqwest::Client,
    config: &SlackConfig,
    event: &AlertEvent,
    hostname: &str,
) -> Result<()> {
    let url = config
        .webhook_url
        .as_deref()
        .context("Slack webhook URL not configured")?;

    let severity_emoji = match event.severity {
        Severity::Critical => ":rotating_light:",
        Severity::Warning => ":warning:",
        Severity::Info => ":information_source:",
    };

    let color = match event.severity {
        Severity::Critical => "#dc3545",
        Severity::Warning => "#ffc107",
        Severity::Info => "#17a2b8",
    };

    // Build the message payload using Slack attachments for colored sidebar
    let payload = serde_json::json!({
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": format!(
                            "{} Guardian Shell — {} ({})",
                            severity_emoji,
                            event.action.to_string().to_uppercase(),
                            event.severity
                        )
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": format!("*Agent:*\n{}", event.agent_name)
                        },
                        {
                            "type": "mrkdwn",
                            "text": format!("*Event:*\n{}", event.event_type)
                        },
                        {
                            "type": "mrkdwn",
                            "text": format!("*Path:*\n`{}`", event.path)
                        },
                        {
                            "type": "mrkdwn",
                            "text": format!("*PID:*\n{} (`{}`)", event.pid, event.comm)
                        }
                    ]
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": format!(
                                "Host: {} | Mode: {} | Identity: {} | {}",
                                hostname,
                                event.policy_mode,
                                event.identity_method,
                                event.timestamp.to_rfc3339_opts(
                                    chrono::SecondsFormat::Secs, true
                                )
                            )
                        }
                    ]
                }
            ]
        }]
    });

    let mut request = client.post(url).json(&payload);

    if let Some(ref channel) = config.channel {
        // For Slack apps (not incoming webhooks), you can override channel.
        // Incoming webhooks ignore this field.
        request = request.header("X-Slack-Channel", channel.as_str());
    }

    let response = request.send().await.context("Slack webhook request failed")?;

    if !response.status().is_success() {
        anyhow::bail!(
            "Slack webhook returned HTTP {}: {}",
            response.status(),
            response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string())
        );
    }

    Ok(())
}
