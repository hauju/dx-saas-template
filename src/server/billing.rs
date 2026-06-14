//! Polar billing: webhook ingestion → user subscription state, plus a gating
//! helper for premium features.
//!
//! Checkout must set the subscription `metadata.reference_id` to the user's id so
//! webhooks can link a subscription back to a user.

use axum::Extension;
use axum::Router;
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::Deserialize;

use crate::models::AppError;
use crate::models::subscription::SubscriptionInfo;
use crate::server::db::Database;
use crate::server::security::{IpRateLimiter, ip_rate_limit};
use crate::server::state::AppState;

pub fn billing_router(trust_proxy_headers: bool) -> Router {
    let limiter = IpRateLimiter::per_minute(120, trust_proxy_headers);
    Router::new()
        .route("/webhooks/polar", post(polar_webhook))
        .layer(axum::middleware::from_fn(ip_rate_limit))
        .layer(Extension(limiter))
}

/// Require an active subscription, else `402 Payment Required`.
///
/// Use in server functions / handlers to gate premium features:
/// `billing::require_active(&user.subscription)?;`
pub fn require_active(subscription: &Option<SubscriptionInfo>) -> Result<(), AppError> {
    match subscription {
        Some(s) if s.is_active() => Ok(()),
        _ => Err(AppError::SubscriptionRequired(
            "An active subscription is required.".to_string(),
        )),
    }
}

// Lenient view of Polar's subscription payload: we only read what we persist, so
// unrelated schema changes don't break ingestion.
#[derive(Debug, Deserialize)]
struct SubscriptionData {
    id: String,
    #[serde(default)]
    customer_id: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    current_period_end: Option<String>,
    #[serde(default)]
    metadata: SubscriptionMeta,
    #[serde(default)]
    product: Option<ProductData>,
}

#[derive(Debug, Default, Deserialize)]
struct SubscriptionMeta {
    /// Set to the user id at checkout; links the subscription back to a user.
    #[serde(default)]
    reference_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProductData {
    #[serde(default)]
    metadata: serde_json::Value,
}

async fn polar_webhook(state: AppState, headers: HeaderMap, body: Bytes) -> Response {
    let Some(secret) = state.secrets.polar_webhook_secret.as_deref() else {
        tracing::warn!("received Polar webhook but POLAR_WEBHOOK_SECRET is not configured");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };

    if let Err(e) = polar::verify_webhook(secret, &headers, &body) {
        tracing::warn!("Polar webhook signature verification failed: {e}");
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let event: polar::PolarWebhookEvent = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("could not parse Polar webhook body: {e}");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    match event.r#type.as_str() {
        "subscription.created"
        | "subscription.updated"
        | "subscription.active"
        | "subscription.canceled"
        | "subscription.revoked"
        | "subscription.uncanceled" => {
            if let Err(e) = apply_subscription(&state.db, event.data).await {
                tracing::error!("failed to apply Polar subscription event: {e}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
        other => tracing::info!("ignoring Polar event: {other}"),
    }

    StatusCode::OK.into_response()
}

async fn apply_subscription(db: &Database, data: serde_json::Value) -> Result<(), AppError> {
    let data: SubscriptionData = serde_json::from_value(data)
        .map_err(|e| AppError::Validation(format!("bad subscription payload: {e}")))?;

    let Some(reference_id) = data.metadata.reference_id.as_deref() else {
        tracing::warn!(subscription_id = %data.id, "subscription event without reference_id; cannot link to a user");
        return Ok(());
    };
    let Ok(user_id) = bson::oid::ObjectId::parse_str(reference_id) else {
        tracing::warn!(
            reference_id,
            "subscription reference_id is not a valid user id"
        );
        return Ok(());
    };

    let tier = data
        .product
        .as_ref()
        .and_then(|p| p.metadata.get("TIER").or_else(|| p.metadata.get("tier")))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let info = SubscriptionInfo {
        subscription_id: data.id,
        customer_id: data.customer_id.unwrap_or_default(),
        status: data.status.unwrap_or_else(|| "unknown".to_string()),
        tier,
        current_period_end: polar::parse_polar_timestamp_to_ms(&data.current_period_end),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    let bson_info = bson::to_bson(&info)
        .map_err(|e| AppError::Internal(format!("serialize subscription: {e}")))?;

    db.users
        .update_one(
            bson::doc! { "_id": user_id },
            bson::doc! { "$set": { "subscription": bson_info, "updated_at": bson::DateTime::now() } },
        )
        .await?;

    tracing::info!(user_id = %user_id, status = %info.status, "subscription updated from Polar");
    Ok(())
}
