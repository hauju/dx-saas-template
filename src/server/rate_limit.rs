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
        Self::per_window(pool, scope, per_minute, 60.0)
    }

    /// Allow `limit` requests per key per `window_secs`.
    ///
    /// Tests use a long window so a case can't straddle a window boundary
    /// mid-assertion and see the counter reset under it.
    pub fn per_window(pool: PgPool, scope: &str, limit: u32, window_secs: f64) -> Self {
        Self {
            pool,
            scope: scope.to_string(),
            limit: limit as i32,
            window_secs,
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

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    /// An hour-long window: long enough that a test can't straddle a boundary
    /// and watch the counter reset mid-assertion.
    const WINDOW: f64 = 3600.0;

    #[sqlx::test]
    async fn allows_up_to_the_limit_then_denies(pool: PgPool) {
        let limiter = SharedRateLimiter::per_window(pool, "test", 3, WINDOW);

        for i in 1..=3 {
            assert!(
                limiter.check("ip").await.unwrap(),
                "request {i} is within quota"
            );
        }
        assert!(
            !limiter.check("ip").await.unwrap(),
            "the 4th exceeds a quota of 3"
        );
        assert!(!limiter.check("ip").await.unwrap(), "and it stays denied");
    }

    #[sqlx::test]
    async fn keys_are_counted_independently(pool: PgPool) {
        let limiter = SharedRateLimiter::per_window(pool, "test", 2, WINDOW);

        assert!(limiter.check("ip-a").await.unwrap());
        assert!(limiter.check("ip-a").await.unwrap());
        assert!(!limiter.check("ip-a").await.unwrap(), "ip-a is exhausted");

        // One caller must not be able to rate-limit everyone else.
        assert!(
            limiter.check("ip-b").await.unwrap(),
            "ip-b has its own budget"
        );
    }

    #[sqlx::test]
    async fn scopes_do_not_share_a_budget(pool: PgPool) {
        // This is what stops OAuth discovery traffic from draining the budget
        // that protects token issuance.
        let discovery = SharedRateLimiter::per_window(pool.clone(), "discovery", 2, WINDOW);
        let tokens = SharedRateLimiter::per_window(pool, "tokens", 2, WINDOW);

        assert!(discovery.check("ip").await.unwrap());
        assert!(discovery.check("ip").await.unwrap());
        assert!(
            !discovery.check("ip").await.unwrap(),
            "discovery is exhausted"
        );

        assert!(
            tokens.check("ip").await.unwrap(),
            "token budget is untouched"
        );
        assert!(tokens.check("ip").await.unwrap());
    }

    #[sqlx::test]
    async fn separate_windows_get_separate_counters(pool: PgPool) {
        // A 1-second window: sleeping past it must reset the count. This is the
        // fixed-window behaviour the shared limiter documents.
        let limiter = SharedRateLimiter::per_window(pool.clone(), "test", 1, 1.0);

        // Align to just after a boundary first. Without this the two in-window
        // calls below can land either side of one, both be allowed, and the test
        // fails for a reason that has nothing to do with the limiter.
        let until_next: f64 = sqlx::query_scalar(
            "SELECT 1.0 - (extract(epoch from now())::float8 \
                           - floor(extract(epoch from now())::float8))",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_secs_f64(until_next + 0.05)).await;

        assert!(limiter.check("ip").await.unwrap());
        assert!(
            !limiter.check("ip").await.unwrap(),
            "second request in the same window is denied"
        );

        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(
            limiter.check("ip").await.unwrap(),
            "a new window starts a new count"
        );
    }

    #[sqlx::test]
    async fn concurrent_checks_do_not_overshoot_the_quota(pool: PgPool) {
        // The upsert is atomic, so 20 simultaneous requests against a quota of 5
        // must yield exactly 5 allowances — never more.
        let limiter = SharedRateLimiter::per_window(pool, "test", 5, WINDOW);

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..20 {
            let limiter = limiter.clone();
            set.spawn(async move { limiter.check("ip").await.unwrap() });
        }

        let mut allowed = 0;
        while let Some(res) = set.join_next().await {
            if res.unwrap() {
                allowed += 1;
            }
        }
        assert_eq!(
            allowed, 5,
            "an atomic counter must not let extra requests through"
        );
    }

    #[sqlx::test]
    async fn sweeping_drops_only_elapsed_windows(pool: PgPool) {
        let limiter = SharedRateLimiter::per_window(pool.clone(), "test", 10, WINDOW);
        limiter.check("current").await.unwrap();

        // A window from well before the sweep horizon.
        sqlx::query(
            "INSERT INTO rate_limits (key, window_start, count) \
             VALUES ('test:stale', now() - interval '3 hours', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query("DELETE FROM rate_limits WHERE window_start < now() - interval '1 hour'")
            .execute(&pool)
            .await
            .unwrap();

        let remaining: Vec<String> = sqlx::query_scalar("SELECT key FROM rate_limits")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(
            remaining,
            vec!["test:current"],
            "the live window must survive the sweep"
        );
    }
}
