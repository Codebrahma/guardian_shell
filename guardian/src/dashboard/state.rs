use crate::alerting::{AlertEvent, AlertSender};
use crate::dashboard::db::EventDb;
use crate::ipc::SharedIpcState;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Shared state available to all dashboard handlers.
pub struct DashboardState {
    pub ipc_state: SharedIpcState,
    pub alert_sender: AlertSender,
    pub event_bus: broadcast::Sender<AlertEvent>,
    pub config_path: PathBuf,
    pub db: Arc<EventDb>,
}
