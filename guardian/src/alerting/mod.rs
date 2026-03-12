pub mod email;
pub mod json_log;
pub mod metrics;
pub mod slack;
pub mod webhook;

use crate::config::AlertingConfig;
use log::{error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc};

// =============================================================================
// Alert Event Types
// =============================================================================

/// Severity levels for alert events, ordered by increasing severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s {
            "critical" => Severity::Critical,
            "warning" => Severity::Warning,
            _ => Severity::Info,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// Types of events that can trigger alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum EventType {
    FileAccess,
    ExecAttempt,
    NetworkConnect,
    AgentRegistered,
    AgentStopped,
    EventsLost,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::FileAccess => write!(f, "file_access"),
            EventType::ExecAttempt => write!(f, "exec_attempt"),
            EventType::NetworkConnect => write!(f, "network_connect"),
            EventType::AgentRegistered => write!(f, "agent_registered"),
            EventType::AgentStopped => write!(f, "agent_stopped"),
            EventType::EventsLost => write!(f, "events_lost"),
        }
    }
}

/// Policy action taken on an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
    Blocked,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Allow => write!(f, "allow"),
            Action::Deny => write!(f, "deny"),
            Action::Blocked => write!(f, "blocked"),
        }
    }
}

/// A structured alert event produced by the event processing pipeline.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AlertEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub severity: Severity,
    pub event_type: EventType,
    pub action: Action,
    pub agent_name: String,
    pub pid: u32,
    pub comm: String,
    pub path: String,
    pub access_mode: String,
    pub identity_method: String,
    pub policy_mode: String,
}

impl AlertEvent {
    /// Compute a dedup key based on (agent, event_type, path, action).
    fn dedup_key(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.agent_name.hash(&mut hasher);
        self.event_type.hash(&mut hasher);
        self.path.hash(&mut hasher);
        self.action.hash(&mut hasher);
        hasher.finish()
    }
}

// =============================================================================
// Alert Sender (passed to event processors)
// =============================================================================

/// Clonable handle for sending alert events to the AlertManager.
/// Also holds a reference to Prometheus metrics for synchronous updates
/// and an optional broadcast channel for the dashboard SSE stream.
#[derive(Clone)]
pub struct AlertSender {
    tx: mpsc::Sender<AlertEvent>,
    pub metrics: Arc<metrics::AlertMetrics>,
    event_bus: Option<broadcast::Sender<AlertEvent>>,
}

impl AlertSender {
    /// Send an alert event. Updates metrics synchronously, then queues
    /// the event for async processing by the AlertManager.
    /// Also broadcasts to the dashboard SSE stream if connected.
    pub fn send(&self, event: AlertEvent) {
        self.metrics.record_event(&event);

        // Broadcast to dashboard SSE subscribers (ignore if no receivers)
        if let Some(ref bus) = self.event_bus {
            let _ = bus.send(event.clone());
        }

        // Non-blocking send: if the channel is full, drop the event
        // (the metric was already recorded)
        if self.tx.try_send(event).is_err() {
            self.metrics.alerts_dropped.inc();
        }
    }

    /// Attach a broadcast sender for the dashboard event bus.
    pub fn with_event_bus(mut self, bus: broadcast::Sender<AlertEvent>) -> Self {
        self.event_bus = Some(bus);
        self
    }

    /// Get a reference to the event bus sender (for dashboard state).
    #[allow(dead_code)]
    pub fn event_bus(&self) -> Option<&broadcast::Sender<AlertEvent>> {
        self.event_bus.as_ref()
    }

    /// Create a no-op sender that only tracks metrics (no alerting outputs).
    pub fn noop() -> Self {
        let (tx, _rx) = mpsc::channel(1);
        AlertSender {
            tx,
            metrics: Arc::new(metrics::AlertMetrics::new()),
            event_bus: None,
        }
    }
}

// =============================================================================
// Alert Manager
// =============================================================================

/// Central alert dispatcher. Receives events via channel and routes them
/// to configured output destinations (JSON log, webhook, Slack, email).
struct AlertManager {
    config: AlertingConfig,
    hostname: String,
    dedup_cache: HashMap<u64, Instant>,
    rate_window: (u32, Instant),
    http_client: reqwest::Client,
    json_logger: Option<json_log::JsonLogger>,
    alert_metrics: Arc<metrics::AlertMetrics>,
}

impl AlertManager {
    async fn new(config: AlertingConfig, alert_metrics: Arc<metrics::AlertMetrics>) -> Self {
        let hostname = std::fs::read_to_string("/etc/hostname")
            .map(|h| h.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        let json_logger = if let Some(ref jl_config) = config.json_log {
            if jl_config.enabled {
                match json_log::JsonLogger::new(jl_config).await {
                    Ok(logger) => {
                        info!(
                            "JSON logging enabled: {}",
                            jl_config.path.as_deref().unwrap_or("stdout")
                        );
                        Some(logger)
                    }
                    Err(e) => {
                        error!("Failed to initialize JSON logger: {}", e);
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        AlertManager {
            config,
            hostname,
            dedup_cache: HashMap::new(),
            rate_window: (0, Instant::now()),
            http_client,
            json_logger,
            alert_metrics,
        }
    }

    /// Main processing loop: reads events from channel, applies dedup/throttle,
    /// dispatches to outputs.
    async fn run(&mut self, mut rx: mpsc::Receiver<AlertEvent>) {
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    self.process_event(event).await;
                }
                _ = cleanup_interval.tick() => {
                    self.cleanup_dedup_cache();
                }
            }
        }
    }

    async fn process_event(&mut self, event: AlertEvent) {
        let min_severity = Severity::from_str(
            self.config.min_severity.as_deref().unwrap_or("warning"),
        );

        // Global severity filter
        if event.severity < min_severity {
            return;
        }

        // Dedup check
        let dedup_window = Duration::from_secs(
            self.config.dedup_window_seconds.unwrap_or(300),
        );
        let key = event.dedup_key();
        if let Some(last_seen) = self.dedup_cache.get(&key) {
            if last_seen.elapsed() < dedup_window {
                return;
            }
        }
        self.dedup_cache.insert(key, Instant::now());

        // Rate limiting
        let rate_limit = self.config.rate_limit_per_minute.unwrap_or(100);
        let now = Instant::now();
        if now.duration_since(self.rate_window.1) > Duration::from_secs(60) {
            self.rate_window = (0, now);
        }
        if self.rate_window.0 >= rate_limit {
            return;
        }
        self.rate_window.0 += 1;

        // Dispatch to outputs
        self.dispatch(&event).await;
    }

    async fn dispatch(&mut self, event: &AlertEvent) {
        // JSON file logging
        if let Some(ref mut logger) = self.json_logger {
            if let Err(e) = logger.write_event(event, &self.hostname).await {
                error!("JSON log write error: {}", e);
                self.alert_metrics
                    .alerts_sent
                    .with_label_values(&["json_log", "error"])
                    .inc();
            } else {
                self.alert_metrics
                    .alerts_sent
                    .with_label_values(&["json_log", "success"])
                    .inc();
            }
        }

        // Webhook
        if let Some(ref wh_config) = self.config.webhook {
            if wh_config.enabled {
                let output_severity =
                    Severity::from_str(wh_config.min_severity.as_deref().unwrap_or("warning"));
                if event.severity >= output_severity {
                    match webhook::send_webhook(
                        &self.http_client,
                        wh_config,
                        event,
                        &self.hostname,
                    )
                    .await
                    {
                        Ok(()) => {
                            self.alert_metrics
                                .alerts_sent
                                .with_label_values(&["webhook", "success"])
                                .inc();
                        }
                        Err(e) => {
                            warn!("Webhook alert failed: {}", e);
                            self.alert_metrics
                                .alerts_sent
                                .with_label_values(&["webhook", "error"])
                                .inc();
                        }
                    }
                }
            }
        }

        // Slack
        if let Some(ref slack_config) = self.config.slack {
            if slack_config.enabled {
                let output_severity =
                    Severity::from_str(slack_config.min_severity.as_deref().unwrap_or("critical"));
                if event.severity >= output_severity {
                    match slack::send_slack_alert(
                        &self.http_client,
                        slack_config,
                        event,
                        &self.hostname,
                    )
                    .await
                    {
                        Ok(()) => {
                            self.alert_metrics
                                .alerts_sent
                                .with_label_values(&["slack", "success"])
                                .inc();
                        }
                        Err(e) => {
                            warn!("Slack alert failed: {}", e);
                            self.alert_metrics
                                .alerts_sent
                                .with_label_values(&["slack", "error"])
                                .inc();
                        }
                    }
                }
            }
        }

        // Email
        if let Some(ref email_config) = self.config.email {
            if email_config.enabled {
                let output_severity =
                    Severity::from_str(email_config.min_severity.as_deref().unwrap_or("critical"));
                if event.severity >= output_severity {
                    match email::send_email_alert(email_config, event, &self.hostname).await {
                        Ok(()) => {
                            self.alert_metrics
                                .alerts_sent
                                .with_label_values(&["email", "success"])
                                .inc();
                        }
                        Err(e) => {
                            warn!("Email alert failed: {}", e);
                            self.alert_metrics
                                .alerts_sent
                                .with_label_values(&["email", "error"])
                                .inc();
                        }
                    }
                }
            }
        }
    }

    fn cleanup_dedup_cache(&mut self) {
        let dedup_window = Duration::from_secs(
            self.config.dedup_window_seconds.unwrap_or(300),
        );
        self.dedup_cache
            .retain(|_, last_seen| last_seen.elapsed() < dedup_window);
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Start the alerting subsystem. Returns an AlertSender for event producers
/// and optionally starts a Prometheus metrics HTTP server.
pub async fn start(config: AlertingConfig) -> AlertSender {
    let alert_metrics = Arc::new(metrics::AlertMetrics::new());

    // Start Prometheus metrics server if configured
    if let Some(ref prom_config) = config.prometheus {
        if prom_config.enabled {
            let listen_addr = prom_config
                .listen_address
                .clone()
                .unwrap_or_else(|| "127.0.0.1:9090".to_string());
            let endpoint = prom_config
                .endpoint
                .clone()
                .unwrap_or_else(|| "/metrics".to_string());
            let metrics_clone = alert_metrics.clone();
            info!("Prometheus metrics server starting on {}", listen_addr);
            tokio::spawn(async move {
                if let Err(e) =
                    metrics::serve_metrics(&listen_addr, &endpoint, metrics_clone).await
                {
                    error!("Prometheus metrics server error: {}", e);
                }
            });
        }
    }

    let (tx, rx) = mpsc::channel(4096);
    let metrics_clone = alert_metrics.clone();

    tokio::spawn(async move {
        let mut manager = AlertManager::new(config, metrics_clone).await;
        manager.run(rx).await;
    });

    AlertSender {
        tx,
        metrics: alert_metrics,
        event_bus: None,
    }
}
