pub mod db;
mod routes;
mod state;

pub use state::DashboardState;

use axum::Router;
use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::Response;
use log::{error, info};
use rust_embed::Embed;
use std::sync::Arc;

#[derive(Embed)]
#[folder = "static/"]
struct StaticFiles;

/// Build the dashboard axum router.
pub fn router(state: Arc<DashboardState>) -> Router {
    use axum::routing::{get, post, put};

    let has_auth = state.auth_token.is_some();
    let auth_state = state.clone();

    let app = Router::new()
        // Full pages
        .route("/", get(routes::pages::index))
        .route("/agents", get(routes::pages::agents))
        .route("/policy", get(routes::pages::policy))
        .route("/alerts", get(routes::pages::alerts))
        .route("/events", get(routes::pages::events))
        .route("/requests", get(routes::pages::requests))
        // JSON API endpoints
        .route("/api/events", get(routes::api::query_events))
        .route("/api/permissions/pending", get(routes::api::list_pending_permissions))
        .route("/api/permissions/resolved", get(routes::api::list_resolved_permissions))
        .route("/api/permissions/audit", get(routes::api::query_permission_audit))
        // htmx API endpoints
        .route("/api/agents/{name}/stop", post(routes::api::stop_agent))
        .route("/api/agents/{name}/grant", post(routes::api::grant_access))
        .route("/api/policy/{agent_name}", put(routes::api::update_policy))
        .route("/api/alerts", put(routes::api::update_alerts))
        .route("/api/config/reload", post(routes::api::reload_config))
        .route("/api/status", get(routes::api::status_summary))
        .route("/api/permissions/{id}/approve", post(routes::api::approve_permission))
        .route("/api/permissions/{id}/deny", post(routes::api::deny_permission))
        // SSE live event stream
        .route("/events/stream", get(routes::sse::event_stream))
        // Prometheus metrics (no auth — scrapers need direct access)
        .route("/metrics", get(routes::api::prometheus_metrics))
        // Static files
        .route("/static/{*path}", get(static_handler))
        .with_state(state);

    // Phase 8: Add auth middleware if token is configured
    if has_auth {
        app.layer(middleware::from_fn(move |req, next| {
            let state = auth_state.clone();
            auth_middleware(state, req, next)
        }))
    } else {
        app
    }
}

/// Authentication middleware: checks Bearer token in Authorization header
/// or `token` query parameter. Skips auth for /metrics and /static/ paths.
async fn auth_middleware(
    state: Arc<DashboardState>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();

    // Skip auth for metrics endpoint (Prometheus scrapers) and static files
    if path == "/metrics" || path.starts_with("/static/") {
        return next.run(req).await;
    }

    let expected = match &state.auth_token {
        Some(t) => t.as_str(),
        None => return next.run(req).await,
    };

    // Check Authorization: Bearer <token> header
    if let Some(auth_header) = req.headers().get("authorization") {
        if let Ok(val) = auth_header.to_str() {
            if let Some(token) = val.strip_prefix("Bearer ") {
                if token == expected {
                    return next.run(req).await;
                }
            }
        }
    }

    // Check ?token=<token> query parameter
    if let Some(query) = req.uri().query() {
        for param in query.split('&') {
            if let Some(token) = param.strip_prefix("token=") {
                if token == expected {
                    return next.run(req).await;
                }
            }
        }
    }

    log::warn!(
        "Unauthorized dashboard access attempt: {} {} (no valid token)",
        req.method(), path
    );
    (axum::http::StatusCode::UNAUTHORIZED, "Unauthorized: provide Bearer token or ?token= query parameter").into_response()
}

async fn static_handler(
    axum::extract::Path(path): axum::extract::Path<String>,
) -> impl axum::response::IntoResponse {
    match StaticFiles::get(&path) {
        Some(file) => {
            let mime = if path.ends_with(".js") {
                "application/javascript"
            } else if path.ends_with(".css") {
                "text/css"
            } else {
                "application/octet-stream"
            };
            (
                [(axum::http::header::CONTENT_TYPE, mime)],
                file.data.to_vec(),
            )
                .into_response()
        }
        None => (axum::http::StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

use axum::response::IntoResponse;

/// Start the dashboard HTTP server.
pub async fn start(state: Arc<DashboardState>, listen_addr: String) {
    let app = router(state);

    let listener = match tokio::net::TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Dashboard failed to bind {}: {}", listen_addr, e);
            return;
        }
    };

    info!("Dashboard available at http://{}", listen_addr);

    if let Err(e) = axum::serve(listener, app).await {
        error!("Dashboard server error: {}", e);
    }
}
