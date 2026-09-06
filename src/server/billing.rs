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

pub fn billing_router(pool: sqlx::PgPool, trust_proxy_headers: bool) -> Router {
    let limiter = IpRateLimiter::shared_per_minute(pool, "webhooks", 120, trust_proxy_headers);
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
    /// When Polar last changed this subscription; `created_at` for a brand-new
    /// one. The ordering key: a delivery describing an older state than what
    /// is stored is dropped, whichever order the network delivered them in.
    #[serde(default)]
    modified_at: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
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

    // The signature just verified covers this id, so it is present and
    // Polar's own; it is what makes a redelivery recognisable.
    let Some(webhook_id) = headers
        .get("webhook-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
    else {
        tracing::warn!("Polar webhook without a webhook-id header");
        return StatusCode::BAD_REQUEST.into_response();
    };

    match event.r#type.as_str() {
        "subscription.created"
        | "subscription.updated"
        | "subscription.active"
        | "subscription.canceled"
        | "subscription.revoked"
        | "subscription.uncanceled" => {
            if let Err(e) = apply_subscription(&state.db, webhook_id, event.data).await {
                tracing::error!("failed to apply Polar subscription event: {e}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
        other => tracing::info!("ignoring Polar event: {other}"),
    }

    StatusCode::OK.into_response()
}

/// Apply one delivery, exactly once and never backwards.
///
/// The delivery id and the user's row change in one transaction: a retry of a
/// delivery we already applied finds its id and does nothing, and a delivery
/// we failed to apply leaves no id behind, so Polar's retry gets a clean run.
/// Within that, the event's own timestamp is compared to the stored one, so a
/// late delivery of an older state (a `canceled` overtaken by an `active`, or
/// the reverse) cannot roll the user back.
async fn apply_subscription(
    db: &Database,
    webhook_id: &str,
    data: serde_json::Value,
) -> Result<(), AppError> {
    let data: SubscriptionData = serde_json::from_value(data)
        .map_err(|e| AppError::Validation(format!("bad subscription payload: {e}")))?;

    let Some(reference_id) = data.metadata.reference_id.as_deref() else {
        tracing::warn!(subscription_id = %data.id, "subscription event without reference_id; cannot link to a user");
        return Ok(());
    };
    let Ok(user_id) = uuid::Uuid::parse_str(reference_id) else {
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

    // Polar's timestamp, not ours: arrival order says nothing about which
    // state is newer. Without one (not seen from Polar, but the field is
    // optional) the delivery counts as current, which is what it used to be.
    let event_time = data
        .modified_at
        .or(data.created_at)
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(&t).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339();

    let info = SubscriptionInfo {
        subscription_id: data.id,
        customer_id: data.customer_id.unwrap_or_default(),
        status: data.status.unwrap_or_else(|| "unknown".to_string()),
        tier,
        current_period_end: polar::parse_polar_timestamp_to_ms(&data.current_period_end),
        updated_at: event_time.clone(),
    };

    let json_info = serde_json::to_value(&info)
        .map_err(|e| AppError::Internal(format!("serialize subscription: {e}")))?;

    let mut tx = db.pool.begin().await?;

    // Sweep deliveries past Polar's retry horizon, then claim this one.
    sqlx::query!("DELETE FROM polar_webhook_events WHERE received_at < NOW() - interval '30 days'")
        .execute(&mut *tx)
        .await?;
    let claimed = sqlx::query_scalar!(
        "INSERT INTO polar_webhook_events (id) VALUES ($1) ON CONFLICT (id) DO NOTHING RETURNING id",
        webhook_id
    )
    .fetch_optional(&mut *tx)
    .await?;
    if claimed.is_none() {
        tx.commit().await?;
        tracing::info!(webhook_id, "duplicate Polar delivery ignored");
        return Ok(());
    }

    // Older than what is stored: claim the id, keep the state. Equal times
    // apply, so a re-sent identical state is harmless either way.
    let applied = sqlx::query!(
        r#"UPDATE users SET subscription = $1, updated_at = NOW()
           WHERE id = $2
             AND (subscription IS NULL
                  OR (subscription->>'updated_at')::timestamptz <= ($3::text)::timestamptz)"#,
        json_info,
        user_id,
        event_time
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    if applied.rows_affected() == 0 {
        tracing::info!(user_id = %user_id, webhook_id, "stale Polar delivery ignored (older than stored state)");
    } else {
        tracing::info!(user_id = %user_id, status = %info.status, "subscription updated from Polar");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::db::Database;
    use crate::server::test_support::seed_user;
    use crate::server::user;
    use sqlx::PgPool;

    fn event(reference_id: &str, status: &str) -> serde_json::Value {
        serde_json::json!({
            "id": "sub_test",
            "customer_id": "cus_test",
            "status": status,
            "current_period_end": "2027-01-01T00:00:00Z",
            "metadata": { "reference_id": reference_id },
            "product": { "metadata": { "TIER": "pro" } },
        })
    }

    fn event_at(reference_id: &str, status: &str, modified_at: &str) -> serde_json::Value {
        let mut e = event(reference_id, status);
        e["modified_at"] = serde_json::json!(modified_at);
        e
    }

    async fn status_of(db: &Database, id: uuid::Uuid) -> Option<String> {
        user::find_by_id(db, id)
            .await
            .unwrap()
            .unwrap()
            .subscription
            .map(|s| s.status)
    }

    #[sqlx::test]
    async fn a_subscription_event_lands_on_the_user(pool: PgPool) {
        let db = Database::from_pool(pool);
        let id = seed_user(&db, "billing").await;

        apply_subscription(&db, "wh-1", event(&id.to_string(), "active"))
            .await
            .unwrap();

        let stored = user::find_by_id(&db, id)
            .await
            .unwrap()
            .unwrap()
            .subscription
            .unwrap();
        assert_eq!(stored.subscription_id, "sub_test");
        assert_eq!(stored.customer_id, "cus_test");
        assert_eq!(stored.status, "active");
        assert_eq!(
            stored.tier.as_deref(),
            Some("pro"),
            "tier is read from product metadata"
        );
        assert!(
            stored.current_period_end.is_some(),
            "the period end is parsed to millis"
        );
        assert!(
            require_active(&Some(stored)).is_ok(),
            "an active subscription unlocks gating"
        );
    }

    #[sqlx::test]
    async fn a_cancelled_subscription_closes_the_gate(pool: PgPool) {
        let db = Database::from_pool(pool);
        let id = seed_user(&db, "cancel").await;

        apply_subscription(&db, "wh-1", event(&id.to_string(), "active"))
            .await
            .unwrap();
        apply_subscription(&db, "wh-2", event(&id.to_string(), "canceled"))
            .await
            .unwrap();

        let stored = user::find_by_id(&db, id)
            .await
            .unwrap()
            .unwrap()
            .subscription
            .unwrap();
        assert_eq!(stored.status, "canceled", "the later event wins");
        assert!(
            matches!(
                require_active(&Some(stored)),
                Err(AppError::SubscriptionRequired(_))
            ),
            "a cancelled subscription must fail the gate"
        );
    }

    #[sqlx::test]
    async fn an_unlinkable_event_is_ignored_rather_than_failing(pool: PgPool) {
        let db = Database::from_pool(pool);
        let id = seed_user(&db, "unlinkable").await;

        // Polar retries failed webhooks, so events we can't attribute must be
        // accepted and dropped rather than 500ing forever.
        apply_subscription(&db, "wh-1", event("not-a-uuid", "active"))
            .await
            .unwrap();
        apply_subscription(
            &db,
            "wh-2",
            event(&uuid::Uuid::new_v4().to_string(), "active"),
        )
        .await
        .unwrap();

        let mut no_reference = event(&id.to_string(), "active");
        no_reference["metadata"] = serde_json::json!({});
        apply_subscription(&db, "wh-3", no_reference).await.unwrap();

        assert!(
            user::find_by_id(&db, id)
                .await
                .unwrap()
                .unwrap()
                .subscription
                .is_none(),
            "no user should have been touched"
        );
    }

    #[sqlx::test]
    async fn a_malformed_payload_is_a_validation_error(pool: PgPool) {
        let db = Database::from_pool(pool);
        let err = apply_subscription(&db, "wh-1", serde_json::json!({ "nonsense": true }))
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn gating_rejects_a_missing_subscription() {
        assert!(matches!(
            require_active(&None),
            Err(AppError::SubscriptionRequired(_))
        ));
    }

    #[sqlx::test]
    async fn a_redelivered_event_is_applied_once(pool: PgPool) {
        // Polar retries on any non-2xx and may redeliver on its own. The same
        // webhook-id must not apply twice, even if the retried body differs.
        let db = Database::from_pool(pool);
        let id = seed_user(&db, "redelivery").await;

        apply_subscription(&db, "wh-same", event(&id.to_string(), "active"))
            .await
            .unwrap();
        apply_subscription(&db, "wh-same", event(&id.to_string(), "canceled"))
            .await
            .unwrap();

        assert_eq!(status_of(&db, id).await.as_deref(), Some("active"));
    }

    #[sqlx::test]
    async fn a_late_older_event_does_not_roll_the_user_back(pool: PgPool) {
        let db = Database::from_pool(pool);
        let id = seed_user(&db, "reordered").await;
        let user = id.to_string();

        // Delivered in order: active, then canceled.
        apply_subscription(
            &db,
            "wh-1",
            event_at(&user, "active", "2026-09-01T10:00:00Z"),
        )
        .await
        .unwrap();
        apply_subscription(
            &db,
            "wh-2",
            event_at(&user, "canceled", "2026-09-01T11:00:00Z"),
        )
        .await
        .unwrap();
        assert_eq!(status_of(&db, id).await.as_deref(), Some("canceled"));

        // A delivery describing the earlier state arrives late.
        apply_subscription(
            &db,
            "wh-3",
            event_at(&user, "active", "2026-09-01T10:30:00Z"),
        )
        .await
        .unwrap();
        assert_eq!(
            status_of(&db, id).await.as_deref(),
            Some("canceled"),
            "an older state must not overwrite a newer one"
        );

        // And in the other direction: the newer state wins whenever it arrives.
        apply_subscription(
            &db,
            "wh-4",
            event_at(&user, "active", "2026-09-01T12:00:00Z"),
        )
        .await
        .unwrap();
        assert_eq!(status_of(&db, id).await.as_deref(), Some("active"));
    }
}
