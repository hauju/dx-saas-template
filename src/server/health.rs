//! Health probe for container orchestrators and uptime checks.
//!
//! `GET /health` is a *readiness* probe, not just a liveness one: it round-trips
//! a query to PostgreSQL, so a container whose process is alive but whose
//! database is unreachable reports unhealthy instead of accepting traffic it
//! can only fail. The response body is deliberately generic — this endpoint is
//! unauthenticated, so it must never leak connection strings or error detail
//! (the specifics go to the log instead).

use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::server::state::AppState;

/// Budget for the probe query.
///
/// Must stay comfortably under the orchestrator's own probe timeout (the
/// Dockerfile allows 5s). Without it the query inherits the pool's 30s acquire
/// timeout, so an unreachable database would hang the probe until the
/// orchestrator killed it rather than answering `503` promptly.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

pub fn health_router() -> Router {
    Router::new().route("/health", get(health))
}

async fn health(state: AppState) -> Response {
    let probe = sqlx::query!("SELECT 1 as one").fetch_one(&state.db.pool);

    match tokio::time::timeout(PROBE_TIMEOUT, probe).await {
        Ok(Ok(_)) => (StatusCode::OK, "ok").into_response(),
        Ok(Err(e)) => {
            tracing::error!("health check failed: database error: {e}");
            (StatusCode::SERVICE_UNAVAILABLE, "unhealthy").into_response()
        }
        Err(_) => {
            tracing::error!(
                "health check failed: database did not respond within {PROBE_TIMEOUT:?}"
            );
            (StatusCode::SERVICE_UNAVAILABLE, "unhealthy").into_response()
        }
    }
}
