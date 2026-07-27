//! Cross-replica rate limiting backed by PostgreSQL.
//!
//! The in-process [`governor`](crate::server::security::IpRateLimiter) limiter
//! keeps one set of token buckets per process, so running N replicas silently
//! allows N× the intended quota. That is acceptable for the global backstop —
//! it exists to blunt floods, not to be exact — but not for the endpoints that
//! guard credentials and token issuance.
//!
//! This limiter keeps the counter in the database instead, so all replicas
//! share one quota. It uses a fixed window (not a sliding one): a caller can
//! burst up to `2 × limit` across a window boundary. That is a deliberate
//! trade for a single indexed upsert per request, and it is only applied to
//! low-volume routes.

use std::time::Duration;

use sqlx::PgPool;

use crate::models::AppError;

/// A shared, per-key fixed-window counter.
#[derive(Clone)]
pub struct SharedRateLimiter {
    pool: PgPool,
    /// Namespaces keys so routers with different quotas don't share a bucket.
    scope: String,
    limit: i32,
    window_secs: f64,
}

impl SharedRateLimiter {
    /// Allow `per_minute` requests per key per minute, across all replicas.
    pub fn per_minute(pool: PgPool, scope: &str, per_minute: u32) -> Self {
        Self {
            pool,
            scope: scope.to_string(),
            limit: per_minute as i32,
            window_secs: 60.0,
        }
    }

    /// Bump `key`'s counter for the current window and report whether the
    /// request is within quota.
    ///
    /// `window_start` is computed in SQL from the database clock, so replicas
    /// with skewed clocks still agree on which window they're writing to.
    pub async fn check(&self, key: &str) -> Result<bool, AppError> {
        let scoped = format!("{}:{}", self.scope, key);

        // `extract(epoch …)` yields NUMERIC, so the window parameter must be cast
        // explicitly — otherwise Postgres infers `$2` as NUMERIC and rejects the
        // f64 bind at runtime.
        let count = sqlx::query_scalar!(
            "INSERT INTO rate_limits (key, window_start, count) \
             VALUES ($1, to_timestamp(floor(extract(epoch from now()) / $2::float8) * $2::float8), 1) \
             ON CONFLICT (key, window_start) DO UPDATE SET count = rate_limits.count + 1 \
             RETURNING count",
            scoped,
            self.window_secs,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count <= self.limit)
    }
}

/// Delete elapsed windows periodically so the table stays small.
///
/// Rows are only read for the window they belong to, so anything older than a
/// few minutes is dead weight; an hour of slack keeps the sweep well clear of
/// in-flight windows.
pub fn spawn_sweeper(pool: PgPool) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(10 * 60));
        loop {
            ticker.tick().await;
            if let Err(e) = sqlx::query!(
                "DELETE FROM rate_limits WHERE window_start < now() - interval '1 hour'"
            )
            .execute(&pool)
            .await
            {
                tracing::warn!("rate limit sweep failed: {e}");
            }
        }
    });
}

/// Adapts [`SharedRateLimiter`] to the auth crate's store trait, so auth
/// endpoints get the same cross-replica quota without the crate taking a
/// dependency on `sqlx` or on this app's `Database`.
pub struct AppAuthRateLimitStore {
    limiter: SharedRateLimiter,
}

impl AppAuthRateLimitStore {
    pub fn new(pool: PgPool, per_minute: u32) -> Self {
        Self {
            limiter: SharedRateLimiter::per_minute(pool, "auth", per_minute),
        }
    }
}

#[async_trait::async_trait]
impl auth::AuthRateLimitStore for AppAuthRateLimitStore {
    async fn check(&self, key: &str) -> bool {
        match self.limiter.check(key).await {
            Ok(allowed) => allowed,
            // Fail open. Every route behind this limiter needs the same database
            // to do anything useful, so refusing traffic here would turn a
            // database blip into a hard outage without denying an attacker
            // anything they could otherwise achieve. The in-process global
            // backstop still applies, so this is a downgrade in precision, not
            // a removal of protection.
            Err(e) => {
                tracing::error!("auth rate limit check failed, allowing request: {e}");
                true
            }
        }
    }
}
