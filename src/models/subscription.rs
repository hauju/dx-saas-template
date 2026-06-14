//! Subscription state, kept in sync from Polar webhooks and embedded on the user.

use serde::{Deserialize, Serialize};

/// A user's current subscription, as last reported by Polar.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubscriptionInfo {
    pub subscription_id: String,
    pub customer_id: String,
    /// Raw Polar status, e.g. "active", "trialing", "canceled", "past_due".
    pub status: String,
    /// Tier label from the product metadata, if present.
    pub tier: Option<String>,
    /// End of the current period (unix milliseconds), if known.
    pub current_period_end: Option<i64>,
    /// When we last applied a webhook for this subscription (RFC 3339).
    pub updated_at: String,
}

impl SubscriptionInfo {
    /// Whether the subscription currently grants access.
    pub fn is_active(&self) -> bool {
        matches!(self.status.as_str(), "active" | "trialing")
    }
}
