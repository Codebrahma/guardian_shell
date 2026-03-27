use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::StreamExt;

use crate::dashboard::DashboardState;

pub async fn event_stream(
    State(state): State<Arc<DashboardState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let event_rx = state.event_bus.subscribe();
    let perm_rx = state.permission_bus.subscribe();

    // Stream for regular alert events
    let event_stream =
        tokio_stream::wrappers::BroadcastStream::new(event_rx).map(|result| match result {
            Ok(event) => {
                let json = serde_json::to_string(&event).unwrap_or_default();
                Ok(Event::default().event("event").data(json))
            }
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                let msg = format!("{{\"missed\": {}}}", n);
                Ok(Event::default().event("lag").data(msg))
            }
        });

    // Stream for permission request/resolution events
    let perm_stream =
        tokio_stream::wrappers::BroadcastStream::new(perm_rx).map(|result| match result {
            Ok(perm_event) => {
                let json = serde_json::to_string(&perm_event).unwrap_or_default();
                Ok(Event::default().event("permission").data(json))
            }
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(_)) => {
                let msg = r#"{"missed": 1}"#.to_string();
                Ok(Event::default().event("lag").data(msg))
            }
        });

    // Merge both streams so a single SSE connection delivers everything
    let merged = event_stream.merge(perm_stream);

    Sse::new(merged).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(5))
            .text("heartbeat"),
    )
}
