//! Polar API types for requests and responses.

use serde::{Deserialize, Serialize};

// =============================================================================
// Domain Types (previously from seggwat_core)
// =============================================================================

/// Subscription tier levels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubscriptionTier {
    Solo,
}

/// Subscription state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubscriptionState {
    Trialing,
    Active,
    Canceled,
    PastDue,
    Unknown(String),
}

// =============================================================================
// Customer Types
// =============================================================================

/// Polar customer response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolarCustomer {
    /// Customer ID
    pub id: String,
    /// Customer email
    pub email: String,
    /// Additional metadata
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Request payload for creating a customer.
#[derive(Debug, Serialize)]
pub(crate) struct CreateCustomerRequest {
    pub email: String,
    pub metadata: CustomerMetadata,
}

/// Customer metadata containing user reference.
#[derive(Debug, Serialize)]
pub(crate) struct CustomerMetadata {
    pub user_id: String,
}

// =============================================================================
// Subscription Types
// =============================================================================

/// Polar subscription response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolarSubscription {
    /// Subscription ID
    pub id: String,
    /// Customer ID
    pub customer_id: String,
    /// Product ID
    pub product_id: String,
    /// Subscription status (trialing, active, canceled, past_due, etc.)
    pub status: String,
    /// When the trial period ends (ISO8601 timestamp)
    #[serde(default)]
    pub trial_ends_at: Option<String>,
    /// When the current billing period ends (ISO8601 timestamp)
    #[serde(default)]
    pub current_period_end: Option<String>,
}

/// Subscription list item (lighter version for list responses).
#[derive(Debug, Clone, Deserialize)]
pub struct PolarSubscriptionListItem {
    /// Subscription ID
    pub id: String,
    /// Subscription status
    pub status: String,
    /// When the trial period ends
    #[serde(default)]
    pub trial_ends_at: Option<String>,
}

/// Request payload for creating a subscription.
#[derive(Debug, Serialize)]
pub(crate) struct CreateSubscriptionRequest {
    pub product_id: String,
    pub customer_id: String,
    pub metadata: SubscriptionMetadata,
}

/// Subscription metadata containing reference ID.
#[derive(Debug, Serialize)]
pub(crate) struct SubscriptionMetadata {
    /// Reference ID points to user_id, used by webhooks to link subscription to user
    pub reference_id: String,
}

// =============================================================================
// Checkout Types
// =============================================================================

/// Polar checkout session response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolarCheckoutSession {
    /// Checkout session ID
    pub id: String,
    /// Checkout URL
    pub url: String,
    /// Session status
    pub status: String,
    /// Customer ID (if associated with existing customer)
    #[serde(default)]
    pub customer_id: Option<String>,
}

/// Checkout metadata containing reference ID.
#[derive(Debug, Serialize)]
pub(crate) struct CheckoutMetadata {
    /// Reference ID points to user_id, used by webhooks to link subscription to user
    pub reference_id: String,
}

/// Request payload for creating a redirect checkout session.
#[derive(Debug, Serialize)]
pub(crate) struct CreateRedirectCheckoutRequest {
    pub product_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_email: Option<String>,
    pub metadata: CheckoutMetadata,
    pub success_url: String,
    /// Whether to allow trial period. Set to false if customer already used trial.
    pub allow_trial: bool,
}

// =============================================================================
// Customer Portal Types
// =============================================================================

/// Response from creating a customer portal session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerPortalSession {
    /// URL to redirect customer to
    pub customer_portal_url: String,
}

/// Request payload for creating a customer portal session.
#[derive(Debug, Serialize)]
pub(crate) struct CreateCustomerPortalRequest {
    pub return_url: String,
    pub customer_id: String,
}

// =============================================================================
// Webhook Event Types
// =============================================================================

/// Polar webhook event wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolarWebhookEvent {
    /// Event type (e.g., "subscription.created", "subscription.canceled")
    pub r#type: String,
    /// Event timestamp
    pub timestamp: String,
    /// Event data (varies by event type)
    pub data: serde_json::Value,
}

/// Subscription event types.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolarEventType {
    #[serde(rename = "subscription.created")]
    SubscriptionCreated,
    #[serde(rename = "subscription.updated")]
    SubscriptionUpdated,
    #[serde(rename = "subscription.canceled")]
    SubscriptionCanceled,
    #[serde(rename = "subscription.revoked")]
    SubscriptionRevoked,
}

/// Subscription data from webhook events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookSubscription {
    /// Subscription ID
    pub id: String,
    /// Customer ID
    pub customer_id: String,
    /// Product ID
    pub product_id: String,
    /// Subscription status
    pub status: String,
    /// Trial end date
    #[serde(default)]
    pub trial_ends_at: Option<String>,
    /// Current period end date
    #[serde(default)]
    pub current_period_end: Option<String>,
    /// Subscription metadata
    pub metadata: WebhookSubscriptionMetadata,
    /// Product details
    pub product: WebhookProduct,
}

/// Metadata in subscription webhook events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookSubscriptionMetadata {
    /// Reference ID (user_id)
    pub reference_id: Option<String>,
}

/// Product details in webhook events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookProduct {
    /// Product metadata
    pub metadata: WebhookProductMetadata,
}

/// Product metadata in webhook events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookProductMetadata {
    /// Subscription tier
    #[serde(rename = "TIER")]
    pub tier: SubscriptionTier,
}

/// Customer cancellation webhook payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolarSubscriptionCanceled {
    /// Subscription ID
    pub id: String,
    /// Customer ID
    pub customer_id: String,
    /// Customer email
    pub customer_email: Option<String>,
    /// Product details
    pub product: Option<PolarCanceledProduct>,
    /// Cancellation reason
    pub customer_cancellation_reason: Option<String>,
    /// Cancellation comment
    pub customer_cancellation_comment: Option<String>,
    /// When canceled
    pub canceled_at: Option<String>,
}

/// Product in cancellation webhook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolarCanceledProduct {
    /// Product name
    pub name: Option<String>,
}

// =============================================================================
// Order Types
// =============================================================================

/// Polar order response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolarOrder {
    pub id: String,
    pub created_at: String,
    /// Order status (e.g. "paid", "refunded", "partially_refunded")
    pub status: String,
    /// Subtotal in cents
    #[serde(default)]
    pub subtotal_amount: Option<i64>,
    /// Discount in cents
    #[serde(default)]
    pub discount_amount: Option<i64>,
    /// Net amount in cents
    #[serde(default)]
    pub net_amount: Option<i64>,
    /// Tax in cents
    #[serde(default)]
    pub tax_amount: Option<i64>,
    /// Total in cents
    pub total_amount: i64,
    pub currency: String,
    #[serde(default)]
    pub invoice_number: Option<String>,
    #[serde(default)]
    pub subscription_id: Option<String>,
    #[serde(default)]
    pub billing_reason: Option<String>,
    #[serde(default)]
    pub product: Option<OrderProduct>,
    #[serde(default)]
    pub is_invoice_generated: bool,
}

/// Product embedded in an order response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderProduct {
    pub id: String,
    pub name: String,
}

/// Invoice URL response from Polar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderInvoice {
    pub url: String,
}

// =============================================================================
// Response Wrapper Types
// =============================================================================

/// Generic list response wrapper from Polar API.
#[derive(Debug, Deserialize)]
pub(crate) struct PolarListResponse<T> {
    pub items: Vec<T>,
}

/// Paginated list response from Polar API.
#[derive(Debug, Deserialize)]
pub(crate) struct PolarPaginatedListResponse<T> {
    pub items: Vec<T>,
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Parse ISO8601 timestamp to Unix milliseconds.
///
/// Returns None if the timestamp is None, empty, or invalid.
pub fn parse_polar_timestamp_to_ms(timestamp: &Option<String>) -> Option<i64> {
    timestamp.as_ref().and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.timestamp_millis())
    })
}

/// Parse Polar status string to SubscriptionState.
///
/// Unknown statuses default to Active with a warning log.
pub fn parse_polar_status(status: &str) -> SubscriptionState {
    match status {
        "trialing" => SubscriptionState::Trialing,
        "active" => SubscriptionState::Active,
        "canceled" => SubscriptionState::Canceled,
        "past_due" => SubscriptionState::PastDue,
        status => {
            tracing::warn!(status = %status, "Unknown Polar subscription status");
            SubscriptionState::Unknown(status.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================
    // Tests for parse_polar_timestamp_to_ms
    // ============================================================
    mod parse_polar_timestamp {
        use super::*;

        #[test]
        fn valid_timestamp_converts_to_millis() {
            let timestamp = Some("2024-01-15T10:30:00Z".to_string());
            let result = parse_polar_timestamp_to_ms(&timestamp);
            assert!(result.is_some());
            // 2024-01-15T10:30:00Z = 1705314600000 ms
            assert_eq!(result.unwrap(), 1705314600000);
        }

        #[test]
        fn timestamp_with_offset_converts_correctly() {
            let timestamp = Some("2024-01-15T10:30:00+02:00".to_string());
            let result = parse_polar_timestamp_to_ms(&timestamp);
            assert!(result.is_some());
            // +02:00 means UTC time is 08:30:00 = 1705307400000 ms
            assert_eq!(result.unwrap(), 1705307400000);
        }

        #[test]
        fn timestamp_with_negative_offset_converts_correctly() {
            let timestamp = Some("2024-01-15T10:30:00-05:00".to_string());
            let result = parse_polar_timestamp_to_ms(&timestamp);
            assert!(result.is_some());
            // -05:00 means UTC time is 15:30:00 = 1705332600000 ms
            assert_eq!(result.unwrap(), 1705332600000);
        }

        #[test]
        fn timestamp_with_fractional_seconds() {
            let timestamp = Some("2024-01-15T10:30:00.123Z".to_string());
            let result = parse_polar_timestamp_to_ms(&timestamp);
            assert!(result.is_some());
            // Should include the 123 milliseconds
            assert_eq!(result.unwrap(), 1705314600123);
        }

        #[test]
        fn invalid_timestamp_returns_none() {
            let timestamp = Some("not-a-timestamp".to_string());
            let result = parse_polar_timestamp_to_ms(&timestamp);
            assert!(result.is_none());
        }

        #[test]
        fn empty_string_returns_none() {
            let timestamp = Some("".to_string());
            let result = parse_polar_timestamp_to_ms(&timestamp);
            assert!(result.is_none());
        }

        #[test]
        fn none_input_returns_none() {
            let timestamp: Option<String> = None;
            let result = parse_polar_timestamp_to_ms(&timestamp);
            assert!(result.is_none());
        }

        #[test]
        fn partial_timestamp_returns_none() {
            // Missing time component
            let timestamp = Some("2024-01-15".to_string());
            let result = parse_polar_timestamp_to_ms(&timestamp);
            assert!(result.is_none());
        }

        #[test]
        fn invalid_date_returns_none() {
            // Invalid month
            let timestamp = Some("2024-13-15T10:30:00Z".to_string());
            let result = parse_polar_timestamp_to_ms(&timestamp);
            assert!(result.is_none());
        }
    }

    // ============================================================
    // Tests for parse_polar_status
    // ============================================================
    mod parse_polar_status_tests {
        use super::*;

        #[test]
        fn trialing_maps_to_trialing() {
            let result = parse_polar_status("trialing");
            assert_eq!(result, SubscriptionState::Trialing);
        }

        #[test]
        fn active_maps_to_active() {
            let result = parse_polar_status("active");
            assert_eq!(result, SubscriptionState::Active);
        }

        #[test]
        fn canceled_maps_to_canceled() {
            let result = parse_polar_status("canceled");
            assert_eq!(result, SubscriptionState::Canceled);
        }

        #[test]
        fn past_due_maps_to_past_due() {
            let result = parse_polar_status("past_due");
            assert_eq!(result, SubscriptionState::PastDue);
        }

        #[test]
        fn unknown_status_returns_unknown() {
            let result = parse_polar_status("unknown_status");
            assert_eq!(
                result,
                SubscriptionState::Unknown("unknown_status".to_string())
            );
        }

        #[test]
        fn empty_string_returns_unknown() {
            let result = parse_polar_status("");
            assert_eq!(result, SubscriptionState::Unknown("".to_string()));
        }

        #[test]
        fn case_sensitive_uppercase_returns_unknown() {
            // Status should be exact match
            let result = parse_polar_status("ACTIVE");
            assert_eq!(result, SubscriptionState::Unknown("ACTIVE".to_string()));
        }

        #[test]
        fn suspended_returns_unknown() {
            // Polar might send other statuses not explicitly handled
            let result = parse_polar_status("suspended");
            assert_eq!(result, SubscriptionState::Unknown("suspended".to_string()));
        }
    }
}
