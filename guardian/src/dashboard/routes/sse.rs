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
    let rx = state.event_bus.subscribe();

    // Use `map` instead of `filter_map`: lag errors become real SSE events
    // so the stream never appears frozen to the client.
    // BroadcastStream internally calls resubscribe() after a Lagged error,
    // so the stream continues from the latest messages.
    let stream =
        tokio_stream::wrappers::BroadcastStream::new(rx).map(|result| match result {
            Ok(event) => {
                let json = serde_json::to_string(&event).unwrap_or_default();
                Ok(Event::default().event("event").data(json))
            }
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                let msg = format!("{{\"missed\": {}}}", n);
                Ok(Event::default().event("lag").data(msg))
            }
        });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(5))
            .text("heartbeat"),
    )
}
