//! Webhook signature verification for Polar webhooks.
//!
//! Polar uses the Standard Webhooks protocol for webhook delivery.
//! The webhook secret needs special handling: Polar SDK encodes the ENTIRE secret
//! (including any prefix like `polar_whs_`) as base64, then the standardwebhooks
//! library expects a `whsec_` prefix.

use crate::error::{PolarError, PolarResult};
use base64::Engine;
use http::HeaderMap;

/// Normalize a Polar webhook secret for use with the standardwebhooks library.
///
/// Polar SDK encodes the ENTIRE secret (including any prefix) as base64:
/// `Buffer.from(secret, "utf-8").toString("base64")`
///
/// Then standardwebhooks expects a `whsec_` prefix before the base64 payload.
///
/// # Example
///
/// ```
/// use polar::normalize_polar_webhook_secret;
///
/// let secret = "polar_whs_abc123";
/// let normalized = normalize_polar_webhook_secret(secret);
/// assert!(normalized.starts_with("whsec_"));
/// ```
pub fn normalize_polar_webhook_secret(secret: &str) -> String {
    let base64_encoded = base64::engine::general_purpose::STANDARD.encode(secret.trim().as_bytes());
    format!("whsec_{}", base64_encoded)
}

/// Verify a Polar webhook signature using the Standard Webhooks protocol.
///
/// # Arguments
///
/// * `secret` - The raw webhook secret from Polar (will be normalized internally)
/// * `headers` - The HTTP headers from the webhook request
/// * `body` - The raw request body bytes
///
/// # Required Headers
///
/// * `webhook-id` - Unique identifier for the webhook event
/// * `webhook-timestamp` - Unix timestamp when the webhook was sent
/// * `webhook-signature` - The signature to verify
///
/// # Errors
///
/// Returns `PolarError::MissingWebhookHeaders` if required headers are missing.
/// Returns `PolarError::InvalidSignature` if signature verification fails.
///
/// # Example
///
/// ```rust,ignore
/// use polar::verify_webhook;
/// use http::HeaderMap;
///
/// fn handle_webhook(headers: HeaderMap, body: &[u8], secret: &str) -> Result<(), PolarError> {
///     verify_webhook(secret, &headers, body)?;
///     // Process the webhook...
///     Ok(())
/// }
/// ```
pub fn verify_webhook(secret: &str, headers: &HeaderMap, body: &[u8]) -> PolarResult<()> {
    // Extract required headers
    let webhook_id = headers.get("webhook-id").and_then(|v| v.to_str().ok());
    let webhook_timestamp = headers
        .get("webhook-timestamp")
        .and_then(|v| v.to_str().ok());
    let webhook_signature = headers
        .get("webhook-signature")
        .and_then(|v| v.to_str().ok());

    tracing::debug!(
        "Webhook headers - id: {:?}, timestamp: {:?}, signature: {:?}",
        webhook_id,
        webhook_timestamp,
        webhook_signature.map(|s| if s.len() > 20 {
            format!("{}...", &s[..20])
        } else {
            s.to_string()
        })
    );

    // Check all required headers are present
    if webhook_id.is_none() || webhook_timestamp.is_none() || webhook_signature.is_none() {
        let missing = [
            ("webhook-id", webhook_id.is_none()),
            ("webhook-timestamp", webhook_timestamp.is_none()),
            ("webhook-signature", webhook_signature.is_none()),
        ]
        .iter()
        .filter(|(_, missing)| *missing)
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(", ");

        tracing::error!("Missing required webhook headers: {}", missing);
        return Err(PolarError::MissingWebhookHeaders(missing));
    }

    // Normalize the secret for standardwebhooks
    let normalized_secret = normalize_polar_webhook_secret(secret);

    tracing::debug!(
        "Original secret len: {}, Encoded len: {}",
        secret.trim().len(),
        normalized_secret.len() - 6 // subtract "whsec_" prefix length
    );

    // Initialize webhook verifier
    let wh = standardwebhooks::Webhook::new(&normalized_secret).map_err(|e| {
        tracing::error!("Failed to initialize Webhook verification: {:?}", e);
        PolarError::WebhookVerification(format!("Failed to initialize verifier: {}", e))
    })?;

    // Verify the signature
    wh.verify(body, headers).map_err(|e| {
        tracing::error!(
            "Failed to verify webhook signature: {:?}. Ensure the webhook secret matches the secret in your Polar dashboard.",
            e
        );
        PolarError::InvalidSignature(format!("{}", e))
    })?;

    tracing::debug!("Webhook signature verified successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_secret_with_prefix() {
        let secret = "polar_whs_test123";
        let normalized = normalize_polar_webhook_secret(secret);
        assert!(normalized.starts_with("whsec_"));

        // Decode to verify
        let encoded_part = &normalized[6..]; // Remove "whsec_" prefix
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded_part)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "polar_whs_test123");
    }

    #[test]
    fn normalize_secret_without_prefix() {
        let secret = "mysecret";
        let normalized = normalize_polar_webhook_secret(secret);
        assert!(normalized.starts_with("whsec_"));

        let encoded_part = &normalized[6..];
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded_part)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "mysecret");
    }

    #[test]
    fn normalize_secret_trims_whitespace() {
        let secret = "  mysecret  ";
        let normalized = normalize_polar_webhook_secret(secret);

        let encoded_part = &normalized[6..];
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded_part)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "mysecret");
    }

    #[test]
    fn verify_missing_headers_returns_error() {
        let headers = HeaderMap::new();
        let result = verify_webhook("secret", &headers, b"body");

        assert!(matches!(result, Err(PolarError::MissingWebhookHeaders(_))));
        if let Err(PolarError::MissingWebhookHeaders(missing)) = result {
            assert!(missing.contains("webhook-id"));
            assert!(missing.contains("webhook-timestamp"));
            assert!(missing.contains("webhook-signature"));
        }
    }

    #[test]
    fn verify_partial_headers_returns_error() {
        let mut headers = HeaderMap::new();
        headers.insert("webhook-id", "test-id".parse().unwrap());
        // Missing webhook-timestamp and webhook-signature

        let result = verify_webhook("secret", &headers, b"body");

        assert!(matches!(result, Err(PolarError::MissingWebhookHeaders(_))));
        if let Err(PolarError::MissingWebhookHeaders(missing)) = result {
            assert!(!missing.contains("webhook-id"));
            assert!(missing.contains("webhook-timestamp"));
            assert!(missing.contains("webhook-signature"));
        }
    }
}
