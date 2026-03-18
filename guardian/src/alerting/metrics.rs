use super::{AlertEvent, EventType};
use anyhow::Result;
use prometheus::{Encoder, IntCounter, IntCounterVec, Opts, Registry, TextEncoder};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

// =============================================================================
// Prometheus Metrics
// =============================================================================

/// Prometheus metrics tracked by the alerting subsystem.
/// Counters are updated synchronously from event processors for accuracy.
pub struct AlertMetrics {
    pub registry: Registry,
    pub file_events: IntCounterVec,
    pub exec_events: IntCounterVec,
    pub events_lost: IntCounter,
    pub alerts_sent: IntCounterVec,
    pub alerts_dropped: IntCounter,
}

impl AlertMetrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let file_events = IntCounterVec::new(
            Opts::new("guardian_file_events_total", "Total file access events observed")
                .namespace("guardian"),
            &["agent", "action"],
        )
        .expect("metric creation should not fail");

        let exec_events = IntCounterVec::new(
            Opts::new("guardian_exec_events_total", "Total exec attempt events observed")
                .namespace("guardian"),
            &["agent", "action"],
        )
        .expect("metric creation should not fail");

        let events_lost = IntCounter::with_opts(
            Opts::new("guardian_ebpf_events_lost_total", "Total eBPF events lost due to full perf buffer")
                .namespace("guardian"),
        )
        .expect("metric creation should not fail");

        let alerts_sent = IntCounterVec::new(
            Opts::new("guardian_alerts_sent_total", "Total alerts sent to output destinations")
                .namespace("guardian"),
            &["output", "status"],
        )
        .expect("metric creation should not fail");

        let alerts_dropped = IntCounter::with_opts(
            Opts::new("guardian_alerts_dropped_total", "Total alerts dropped due to full channel")
                .namespace("guardian"),
        )
        .expect("metric creation should not fail");

        for (name, collector) in [
            ("file_events", Box::new(file_events.clone()) as Box<dyn prometheus::core::Collector>),
            ("exec_events", Box::new(exec_events.clone())),
            ("events_lost", Box::new(events_lost.clone())),
            ("alerts_sent", Box::new(alerts_sent.clone())),
            ("alerts_dropped", Box::new(alerts_dropped.clone())),
        ] {
            if let Err(e) = registry.register(collector) {
                log::warn!("Failed to register Prometheus metric '{}': {}", name, e);
            }
        }

        AlertMetrics {
            registry,
            file_events,
            exec_events,
            events_lost,
            alerts_sent,
            alerts_dropped,
        }
    }

    /// Record an event in Prometheus counters. Called synchronously from event
    /// processors so metrics are accurate even if the alert channel is full.
    pub fn record_event(&self, event: &AlertEvent) {
        let action = event.action.to_string();
        match event.event_type {
            EventType::FileAccess => {
                self.file_events
                    .with_label_values(&[&event.agent_name, &action])
                    .inc();
            }
            EventType::ExecAttempt => {
                self.exec_events
                    .with_label_values(&[&event.agent_name, &action])
                    .inc();
            }
            _ => {}
        }
    }
}

// =============================================================================
// Prometheus HTTP Server
// =============================================================================

/// Serve Prometheus metrics over HTTP. Handles GET requests to the configured
/// endpoint path and returns metrics in Prometheus text exposition format.
pub async fn serve_metrics(
    listen_addr: &str,
    endpoint: &str,
    metrics: Arc<AlertMetrics>,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    let endpoint = endpoint.to_string();

    log::info!(
        "Prometheus metrics available at http://{}{}",
        listen_addr,
        endpoint
    );

    loop {
        let (mut stream, _addr) = listener.accept().await?;
        let metrics = metrics.clone();
        let endpoint = endpoint.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };

            let request = String::from_utf8_lossy(&buf[..n]);

            // Simple HTTP request parsing: check if it's a GET to our endpoint
            let is_metrics_request = request
                .lines()
                .next()
                .map(|line| {
                    line.starts_with("GET")
                        && (line.contains(&endpoint) || endpoint == "/")
                })
                .unwrap_or(false);

            let response = if is_metrics_request {
                let encoder = TextEncoder::new();
                let metric_families = metrics.registry.gather();
                let mut body = Vec::new();
                if let Err(e) = encoder.encode(&metric_families, &mut body) {
                    log::error!("Failed to encode Prometheus metrics: {}", e);
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_vec()
                } else {
                format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                     Content-Length: {}\r\n\
                     \r\n",
                    body.len()
                )
                .into_bytes()
                .into_iter()
                .chain(body)
                .collect::<Vec<u8>>()
                }
            } else {
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
            };

            let _ = stream.write_all(&response).await;
        });
    }
}
