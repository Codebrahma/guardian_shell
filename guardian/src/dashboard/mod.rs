pub mod db;
pub mod routes;
mod state;

pub use state::DashboardState;

use axum::Router;
use axum::extract::Request;
use axum::http::Method;
use axum::middleware::{self, Next};
use axum::response::Response;
use log::{error, info};
use rust_embed::Embed;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Embed)]
#[folder = "static/"]
struct StaticFiles;

/// Maximum failed auth attempts before temporary lockout.
const AUTH_MAX_FAILURES: u64 = 10;
/// Lockout duration in seconds after exceeding max failures.
const AUTH_LOCKOUT_SECS: u64 = 60;

/// Tracks failed authentication attempts for rate limiting.
struct AuthRateLimiter {
    /// Number of consecutive failed attempts.
    failures: AtomicU64,
    /// Epoch seconds when lockout started (0 = not locked out).
    lockout_start: AtomicU64,
}

impl AuthRateLimiter {
    const fn new() -> Self {
        Self {
            failures: AtomicU64::new(0),
            lockout_start: AtomicU64::new(0),
        }
    }

    /// Check if requests are currently locked out. Returns true if locked.
    fn is_locked_out(&self) -> bool {
        let start = self.lockout_start.load(Ordering::Relaxed);
        if start == 0 {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now - start < AUTH_LOCKOUT_SECS {
            return true;
        }
        // Lockout expired — reset
        self.lockout_start.store(0, Ordering::Relaxed);
        self.failures.store(0, Ordering::Relaxed);
        false
    }

    /// Record a failed authentication attempt.
    fn record_failure(&self) {
        let count = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if count >= AUTH_MAX_FAILURES {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.lockout_start.store(now, Ordering::Relaxed);
            log::warn!(
                "Dashboard auth locked out for {}s after {} failed attempts",
                AUTH_LOCKOUT_SECS, count
            );
        }
    }

    /// Reset failure counter on successful auth.
    fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        self.lockout_start.store(0, Ordering::Relaxed);
    }
}

/// Global auth rate limiter (dashboard is single-instance).
static AUTH_RATE_LIMITER: AuthRateLimiter = AuthRateLimiter::new();

/// Constant-time comparison to prevent timing attacks on auth tokens.
/// Always compares all bytes even if a mismatch is found early.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Build the dashboard axum router.
pub fn router(state: Arc<DashboardState>) -> Router {
    use axum::routing::{delete, get, post, put};

    let has_auth = state.auth_token.is_some();
    let auth_state = state.clone();
    let csrf_state = state.clone();

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
        .route("/api/agents", post(routes::api::create_agent))
        .route("/api/agents/{name}", delete(routes::api::delete_agent))
        .route("/api/agents/{name}/stop", post(routes::api::stop_agent))
        .route("/api/agents/{name}/grant", post(routes::api::grant_access))
        .route("/api/policy/{agent_name}", put(routes::api::update_policy).post(routes::api::update_policy))
        .route("/api/alerts", put(routes::api::update_alerts))
        .route("/api/config/reload", post(routes::api::reload_config))
        .route("/api/status", get(routes::api::status_summary))
        .route("/api/permissions/{id}/approve", post(routes::api::approve_permission))
        .route("/api/permissions/{id}/deny", post(routes::api::deny_permission))
        // SSE live event stream
        .route("/events/stream", get(routes::sse::event_stream))
        // Prometheus metrics
        .route("/metrics", get(routes::api::prometheus_metrics))
        // Static files
        .route("/static/{*path}", get(static_handler))
        .with_state(state);

    // CSRF middleware is applied first (outermost layer, runs after auth).
    // Auth middleware is applied second (innermost layer, runs before CSRF).
    // Execution order: auth_middleware -> csrf_middleware -> handler.
    let app = app.layer(middleware::from_fn(move |req, next| {
        let state = csrf_state.clone();
        csrf_middleware(state, req, next)
    }));

    // Add auth middleware if token is configured
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
/// or `token` query parameter. Only skips auth for /static/ paths (CSS/JS).
/// /metrics now requires auth when token is configured to prevent information disclosure.
async fn auth_middleware(
    state: Arc<DashboardState>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();

    // Skip auth only for static files (CSS/JS needed to render login pages).
    // /metrics now requires auth to prevent information disclosure.
    if path.starts_with("/static/") {
        return next.run(req).await;
    }

    let expected = match &state.auth_token {
        Some(t) => t.as_str(),
        None => return next.run(req).await,
    };

    // Check rate limiter — reject immediately if locked out
    if AUTH_RATE_LIMITER.is_locked_out() {
        return (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "Too many failed authentication attempts. Try again later."
        ).into_response();
    }

    // Check Authorization: Bearer <token> header
    if let Some(auth_header) = req.headers().get("authorization") {
        if let Ok(val) = auth_header.to_str() {
            if let Some(token) = val.strip_prefix("Bearer ") {
                if constant_time_eq(token.as_bytes(), expected.as_bytes()) {
                    AUTH_RATE_LIMITER.record_success();
                    return next.run(req).await;
                }
            }
        }
    }

    // Check ?token=<token> query parameter
    if let Some(query) = req.uri().query() {
        for param in query.split('&') {
            if let Some(token) = param.strip_prefix("token=") {
                if constant_time_eq(token.as_bytes(), expected.as_bytes()) {
                    AUTH_RATE_LIMITER.record_success();
                    return next.run(req).await;
                }
            }
        }
    }

    AUTH_RATE_LIMITER.record_failure();
    log::warn!(
        "Unauthorized dashboard access attempt: {} {} (no valid token)",
        req.method(), path
    );
    (axum::http::StatusCode::UNAUTHORIZED, "Unauthorized: provide Bearer token or ?token= query parameter").into_response()
}

/// CSRF protection middleware: validates that state-changing requests (POST, PUT, DELETE)
/// originate from legitimate sources. htmx automatically sends the `HX-Request: true` header
/// on all requests, and browsers prevent cross-origin scripts from setting custom headers,
/// so checking for this header provides CSRF protection.
///
/// Requests pass CSRF validation if ANY of these conditions are met:
/// - The HTTP method is GET, HEAD, or OPTIONS (safe/read-only methods)
/// - The request has the `HX-Request: true` header (htmx request from same origin)
/// - The request has a valid Bearer auth token (authenticated API client)
///
/// This runs after auth middleware, so authenticated requests with a valid token
/// are allowed as defense-in-depth (API clients may not send HX-Request).
async fn csrf_middleware(
    state: Arc<DashboardState>,
    req: Request,
    next: Next,
) -> Response {
    // Safe methods don't need CSRF protection
    let method = req.method().clone();
    if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
        return next.run(req).await;
    }

    // Check for htmx header — browsers prevent cross-origin custom headers,
    // so presence of HX-Request proves same-origin.
    if req.headers().get("hx-request")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "true")
        .unwrap_or(false)
    {
        return next.run(req).await;
    }

    // Check for valid Bearer auth token — API clients authenticate explicitly,
    // so a valid token proves the request is intentional (not a CSRF attack).
    if let Some(ref expected) = state.auth_token {
        if let Some(auth_header) = req.headers().get("authorization") {
            if let Ok(val) = auth_header.to_str() {
                if let Some(token) = val.strip_prefix("Bearer ") {
                    if constant_time_eq(token.as_bytes(), expected.as_bytes()) {
                        return next.run(req).await;
                    }
                }
            }
        }
    }

    // No CSRF token present — reject the request
    log::warn!(
        "CSRF validation failed: {} {} (no HX-Request header or valid auth token)",
        method, req.uri().path()
    );
    (
        axum::http::StatusCode::FORBIDDEN,
        axum::response::Html(r#"<div class="toast-error">CSRF validation failed. Ensure JavaScript is enabled and reload the page.</div>"#),
    ).into_response()
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
            // Avoid .to_vec() allocation for embedded static files (Cow::Borrowed)
            let body: bytes::Bytes = match file.data {
                std::borrow::Cow::Borrowed(b) => bytes::Bytes::from_static(b),
                std::borrow::Cow::Owned(v) => bytes::Bytes::from(v),
            };
            (
                [(axum::http::header::CONTENT_TYPE, mime)],
                body,
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
