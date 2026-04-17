//! Polar API client for customer and subscription management.

use crate::config::PolarConfig;
use crate::error::{PolarError, PolarResult};
use crate::types::*;
use reqwest::StatusCode;

/// Client for interacting with the Polar API.
///
/// This client provides methods for:
/// - Customer management (create, lookup, check subscriptions)
/// - Subscription management (create trials)
/// - Checkout session creation
/// - Customer portal access
#[derive(Debug, Clone)]
pub struct PolarClient {
    config: PolarConfig,
    http_client: reqwest::Client,
}

impl PolarClient {
    /// Create a new Polar client with the given configuration.
    pub fn new(config: PolarConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
        }
    }

    /// Get the product ID for a given plan.
    ///
    /// Plan IDs should be in the format: `solo_monthly` or `solo_yearly`
    pub fn get_product_id_for_plan(&self, plan_id: &str) -> PolarResult<String> {
        // Normalize the plan_id to use underscores
        let normalized = plan_id.replace('-', "_");

        match normalized.as_str() {
            "solo_monthly" => Ok(self.config.solo_monthly_product_id.clone()),
            "solo_yearly" => Ok(self.config.solo_yearly_product_id.clone()),
            _ => Err(PolarError::Validation(format!(
                "Unknown plan: {}. Valid plans: solo_monthly, solo_yearly",
                plan_id
            ))),
        }
    }

    // =========================================================================
    // Customer Operations
    // =========================================================================

    /// Look up an existing Polar customer by email.
    ///
    /// Returns the customer if found, None if not found.
    pub async fn get_customer_by_email(&self, email: &str) -> PolarResult<Option<PolarCustomer>> {
        let resp = self
            .http_client
            .get(format!("{}/customers/", self.config.api_url))
            .bearer_auth(&self.config.access_token)
            .query(&[("email", email)])
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let error_body = resp.text().await.unwrap_or_default();
            tracing::error!(
                "Polar API error looking up customer: status={}, body={}",
                status,
                error_body
            );
            return Err(PolarError::Api {
                status: status.as_u16(),
                message: error_body,
            });
        }

        let list_response: PolarListResponse<PolarCustomer> = resp.json().await?;
        Ok(list_response.items.into_iter().next())
    }

    /// Create a Polar customer for a user, or return existing customer if email already exists.
    ///
    /// This creates a customer record in Polar with the user ID stored in metadata.
    /// If a customer with this email already exists, it returns the existing customer.
    pub async fn create_customer(&self, user_id: &str, email: &str) -> PolarResult<PolarCustomer> {
        let request = CreateCustomerRequest {
            email: email.to_string(),
            metadata: CustomerMetadata {
                user_id: user_id.to_string(),
            },
        };

        let resp = self
            .http_client
            .post(format!("{}/customers/", self.config.api_url))
            .bearer_auth(&self.config.access_token)
            .json(&request)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            // Handle 422 — most likely "customer already exists", attempt lookup
            if status == StatusCode::UNPROCESSABLE_ENTITY {
                let error_body = resp.text().await.unwrap_or_default();
                tracing::info!(
                    "Polar 422 creating customer for {}, attempting email lookup: {}",
                    email,
                    error_body
                );
                // Try to find the existing customer by email
                if let Some(existing_customer) = self.get_customer_by_email(email).await? {
                    tracing::info!(
                        "Found existing Polar customer {} for email {}",
                        existing_customer.id,
                        email
                    );
                    return Ok(existing_customer);
                }
                // Lookup returned nothing — this was a different 422 error
                return Err(PolarError::Api {
                    status: status.as_u16(),
                    message: error_body,
                });
            }

            let error_body = resp.text().await.unwrap_or_default();
            tracing::error!(
                "Polar API error creating customer: status={}, body={}",
                status,
                error_body
            );
            return Err(PolarError::Api {
                status: status.as_u16(),
                message: error_body,
            });
        }

        let customer: PolarCustomer = resp.json().await?;
        tracing::info!(
            "Created Polar customer {} for user {}",
            customer.id,
            user_id
        );
        Ok(customer)
    }

    /// Delete a Polar customer by ID.
    ///
    /// This is used as a compensating transaction when subscription creation fails
    /// after the customer has already been created.
    pub async fn delete_customer(&self, customer_id: &str) -> PolarResult<()> {
        let resp = self
            .http_client
            .delete(format!("{}/customers/{}", self.config.api_url, customer_id))
            .bearer_auth(&self.config.access_token)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let error_body = resp.text().await.unwrap_or_default();
            tracing::error!(
                "Polar API error deleting customer: status={}, body={}",
                status,
                error_body
            );
            return Err(PolarError::Api {
                status: status.as_u16(),
                message: error_body,
            });
        }

        tracing::info!("Deleted Polar customer {}", customer_id);
        Ok(())
    }

    /// Check if a Polar customer has any subscriptions (past or present).
    ///
    /// This is used to determine if the customer has already used their trial.
    /// Returns true if they have any subscription history.
    pub async fn customer_has_subscriptions(&self, customer_id: &str) -> PolarResult<bool> {
        let resp = self
            .http_client
            .get(format!("{}/subscriptions/", self.config.api_url))
            .bearer_auth(&self.config.access_token)
            .query(&[("customer_id", customer_id), ("limit", "1")])
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let error_body = resp.text().await.unwrap_or_default();
            tracing::error!(
                "Polar API error listing subscriptions: status={}, body={}",
                status,
                error_body
            );
            return Err(PolarError::Api {
                status: status.as_u16(),
                message: error_body,
            });
        }

        let list_response: PolarListResponse<PolarSubscriptionListItem> = resp.json().await?;
        let has_subscriptions = !list_response.items.is_empty();
        tracing::info!(
            "Customer {} has_subscriptions: {}",
            customer_id,
            has_subscriptions
        );

        Ok(has_subscriptions)
    }

    // =========================================================================
    // Subscription Operations
    // =========================================================================

    /// Create a Polar subscription with trial for a customer.
    ///
    /// This creates a subscription using the Solo Yearly product with a trial period.
    /// The user ID is stored in metadata.reference_id for webhook handling.
    pub async fn create_trial_subscription(
        &self,
        customer_id: &str,
        user_id: &str,
    ) -> PolarResult<PolarSubscription> {
        // Trials use yearly billing by default (better value for users)
        let product_id = &self.config.solo_yearly_product_id;

        let request = CreateSubscriptionRequest {
            product_id: product_id.to_string(),
            customer_id: customer_id.to_string(),
            metadata: SubscriptionMetadata {
                reference_id: user_id.to_string(),
            },
        };

        let resp = self
            .http_client
            .post(format!("{}/subscriptions/", self.config.api_url))
            .bearer_auth(&self.config.access_token)
            .json(&request)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let error_body = resp.text().await.unwrap_or_default();
            tracing::error!(
                "Polar API error creating subscription: status={}, body={}",
                status,
                error_body
            );
            return Err(PolarError::Api {
                status: status.as_u16(),
                message: error_body,
            });
        }

        let subscription: PolarSubscription = resp.json().await?;
        tracing::info!(
            "Created Polar subscription {} with trial for user {}",
            subscription.id,
            user_id
        );

        Ok(subscription)
    }

    // =========================================================================
    // Checkout Operations
    // =========================================================================

    /// Create a checkout session for redirect.
    ///
    /// This creates a checkout session that will redirect back to the app after completion.
    /// The user_id is stored in metadata.reference_id for webhook handling.
    ///
    /// If the customer already exists in Polar (by email lookup), we pass their customer_id
    /// and check if they have any subscription history. If they do, we set `allow_trial: false`
    /// to prevent the "trial already used" error message on checkout.
    pub async fn create_redirect_checkout_session(
        &self,
        product_id: &str,
        customer_email: &str,
        user_id: &str,
    ) -> PolarResult<PolarCheckoutSession> {
        // Look up existing customer to pass customer_id and check trial eligibility
        let existing_customer = self
            .get_customer_by_email(customer_email)
            .await
            .ok()
            .flatten();

        let (customer_id, customer_email_opt, allow_trial) = match existing_customer {
            Some(customer) => {
                // Check if customer has any subscription history (meaning they've used trial)
                let has_subscriptions = self
                    .customer_has_subscriptions(&customer.id)
                    .await
                    .unwrap_or(false);

                tracing::info!(
                    "Found existing Polar customer {} for checkout, has_subscriptions={}, allow_trial={}",
                    customer.id,
                    has_subscriptions,
                    !has_subscriptions
                );

                (Some(customer.id), None, !has_subscriptions)
            }
            None => {
                tracing::info!(
                    "No existing Polar customer found, using customer_email for checkout with trial enabled"
                );
                (None, Some(customer_email.to_string()), true)
            }
        };

        let request = CreateRedirectCheckoutRequest {
            product_id: product_id.to_string(),
            customer_id,
            customer_email: customer_email_opt,
            metadata: CheckoutMetadata {
                reference_id: user_id.to_string(),
            },
            success_url: format!(
                "{}/checkout/return?checkout_id={{CHECKOUT_ID}}",
                self.config.base_url
            ),
            allow_trial,
        };

        let resp = self
            .http_client
            .post(format!("{}/checkouts/", self.config.api_url))
            .bearer_auth(&self.config.access_token)
            .json(&request)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let error_body = resp.text().await.unwrap_or_default();
            tracing::error!(
                "Polar API error creating redirect checkout session: status={}, body={}",
                status,
                error_body
            );
            return Err(PolarError::Api {
                status: status.as_u16(),
                message: error_body,
            });
        }

        let checkout: PolarCheckoutSession = resp.json().await?;
        tracing::info!(
            "Created Polar redirect checkout session {} for user {}",
            checkout.id,
            user_id
        );

        Ok(checkout)
    }

    // =========================================================================
    // Customer Portal Operations
    // =========================================================================

    // =========================================================================
    // Order Operations
    // =========================================================================

    /// List orders for a customer, sorted by most recent first.
    pub async fn list_customer_orders(
        &self,
        customer_id: &str,
        limit: u32,
    ) -> PolarResult<Vec<PolarOrder>> {
        let resp = self
            .http_client
            .get(format!("{}/orders/", self.config.api_url))
            .bearer_auth(&self.config.access_token)
            .query(&[
                ("customer_id", customer_id),
                ("sorting", "-created_at"),
                ("limit", &limit.to_string()),
            ])
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let error_body = resp.text().await.unwrap_or_default();
            tracing::error!(
                "Polar API error listing customer orders: status={}, body={}",
                status,
                error_body
            );
            return Err(PolarError::Api {
                status: status.as_u16(),
                message: error_body,
            });
        }

        let list_response: PolarPaginatedListResponse<PolarOrder> = resp.json().await?;
        Ok(list_response.items)
    }

    /// Get the invoice download URL for an order.
    ///
    /// Returns `None` if the order has no invoice (404).
    pub async fn get_order_invoice_url(&self, order_id: &str) -> PolarResult<Option<String>> {
        let resp = self
            .http_client
            .get(format!(
                "{}/orders/{}/invoice",
                self.config.api_url, order_id
            ))
            .bearer_auth(&self.config.access_token)
            .send()
            .await?;

        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            let error_body = resp.text().await.unwrap_or_default();
            tracing::error!(
                "Polar API error getting order invoice: status={}, body={}",
                status,
                error_body
            );
            return Err(PolarError::Api {
                status: status.as_u16(),
                message: error_body,
            });
        }

        let invoice: OrderInvoice = resp.json().await?;
        Ok(Some(invoice.url))
    }

    // =========================================================================
    // Customer Portal Operations
    // =========================================================================

    /// Create a customer portal session.
    ///
    /// Returns the URL to redirect the customer to for managing their subscription.
    pub async fn create_customer_portal_session(
        &self,
        customer_id: &str,
        return_url: &str,
    ) -> PolarResult<CustomerPortalSession> {
        let request = CreateCustomerPortalRequest {
            return_url: return_url.to_string(),
            customer_id: customer_id.to_string(),
        };

        let resp = self
            .http_client
            .post(format!("{}/customer-sessions/", self.config.api_url))
            .bearer_auth(&self.config.access_token)
            .json(&request)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let error_body = resp.text().await.unwrap_or_default();
            tracing::error!(
                "Polar API error creating customer portal session: status={}, body={}",
                status,
                error_body
            );
            return Err(PolarError::Api {
                status: status.as_u16(),
                message: error_body,
            });
        }

        let session: CustomerPortalSession = resp.json().await?;
        tracing::info!(
            "Created Polar customer portal session for customer {}",
            customer_id
        );

        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{bearer_token, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config(api_url: &str) -> PolarConfig {
        PolarConfig {
            api_url: api_url.to_string(),
            access_token: "test_polar_token".to_string(),
            base_url: "http://localhost:8080".to_string(),
            solo_monthly_product_id: "prod_solo_monthly".to_string(),
            solo_yearly_product_id: "prod_solo_yearly".to_string(),
        }
    }

    // ============================================================
    // Tests for get_product_id_for_plan
    // ============================================================
    mod get_product_id {
        use super::*;

        #[test]
        fn solo_monthly_returns_correct_id() {
            let client = PolarClient::new(test_config("http://unused"));
            let result = client.get_product_id_for_plan("solo_monthly");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "prod_solo_monthly");
        }

        #[test]
        fn solo_yearly_returns_correct_id() {
            let client = PolarClient::new(test_config("http://unused"));
            let result = client.get_product_id_for_plan("solo_yearly");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "prod_solo_yearly");
        }

        #[test]
        fn hyphenated_solo_yearly_normalizes_correctly() {
            let client = PolarClient::new(test_config("http://unused"));
            let result = client.get_product_id_for_plan("solo-yearly");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "prod_solo_yearly");
        }

        #[test]
        fn invalid_plan_returns_validation_error() {
            let client = PolarClient::new(test_config("http://unused"));
            let result = client.get_product_id_for_plan("invalid_plan");
            assert!(result.is_err());
            match result {
                Err(PolarError::Validation(msg)) => {
                    assert!(msg.contains("Unknown plan"));
                    assert!(msg.contains("invalid_plan"));
                }
                _ => panic!("Expected Validation error"),
            }
        }

        #[test]
        fn empty_plan_returns_validation_error() {
            let client = PolarClient::new(test_config("http://unused"));
            let result = client.get_product_id_for_plan("");
            assert!(result.is_err());
        }

        #[test]
        fn enterprise_plan_returns_validation_error() {
            let client = PolarClient::new(test_config("http://unused"));
            let result = client.get_product_id_for_plan("enterprise_yearly");
            assert!(result.is_err());
        }
    }

    // ============================================================
    // Tests for get_customer_by_email
    // ============================================================
    mod get_customer_by_email {
        use super::*;

        #[tokio::test]
        async fn returns_customer_when_found() {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/customers/"))
                .and(query_param("email", "test@example.com"))
                .and(bearer_token("test_polar_token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "items": [{
                        "id": "cust_123",
                        "email": "test@example.com",
                        "metadata": {"org_id": "org_456"}
                    }]
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client.get_customer_by_email("test@example.com").await;

            assert!(result.is_ok());
            let customer = result.unwrap();
            assert!(customer.is_some());
            let customer = customer.unwrap();
            assert_eq!(customer.id, "cust_123");
            assert_eq!(customer.email, "test@example.com");
        }

        #[tokio::test]
        async fn returns_none_when_not_found() {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/customers/"))
                .and(query_param("email", "unknown@example.com"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "items": []
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client.get_customer_by_email("unknown@example.com").await;

            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }

        #[tokio::test]
        async fn returns_error_on_api_failure() {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/customers/"))
                .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client.get_customer_by_email("test@example.com").await;

            assert!(result.is_err());
            match result {
                Err(PolarError::Api { status, .. }) => {
                    assert_eq!(status, 500);
                }
                _ => panic!("Expected Api error"),
            }
        }

        #[tokio::test]
        async fn returns_error_on_unauthorized() {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/customers/"))
                .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client.get_customer_by_email("test@example.com").await;

            assert!(result.is_err());
            match result {
                Err(PolarError::Api { status, .. }) => {
                    assert_eq!(status, 401);
                }
                _ => panic!("Expected Api error"),
            }
        }
    }

    // ============================================================
    // Tests for create_customer
    // ============================================================
    mod create_customer {
        use super::*;

        #[tokio::test]
        async fn creates_customer_successfully() {
            let mock_server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/customers/"))
                .and(bearer_token("test_polar_token"))
                .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "id": "cust_new_123",
                    "email": "new@example.com",
                    "metadata": {"org_id": "org_789"}
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client.create_customer("org_789", "new@example.com").await;

            assert!(result.is_ok());
            let customer = result.unwrap();
            assert_eq!(customer.id, "cust_new_123");
            assert_eq!(customer.email, "new@example.com");
        }

        #[tokio::test]
        async fn handles_422_already_exists_by_looking_up() {
            let mock_server = MockServer::start().await;

            // First call: POST returns 422 "already exists"
            Mock::given(method("POST"))
                .and(path("/customers/"))
                .respond_with(
                    ResponseTemplate::new(422)
                        .set_body_string(r#"{"detail": "Customer with email already exists"}"#),
                )
                .expect(1)
                .mount(&mock_server)
                .await;

            // Second call: GET to look up existing customer
            Mock::given(method("GET"))
                .and(path("/customers/"))
                .and(query_param("email", "existing@example.com"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "items": [{
                        "id": "cust_existing_456",
                        "email": "existing@example.com",
                        "metadata": {"org_id": "org_111"}
                    }]
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client
                .create_customer("org_111", "existing@example.com")
                .await;

            assert!(result.is_ok());
            let customer = result.unwrap();
            assert_eq!(customer.id, "cust_existing_456");
            assert_eq!(customer.email, "existing@example.com");
        }

        #[tokio::test]
        async fn handles_422_other_error() {
            let mock_server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/customers/"))
                .respond_with(
                    ResponseTemplate::new(422)
                        .set_body_string(r#"{"detail": "Invalid email format"}"#),
                )
                .expect(1)
                .mount(&mock_server)
                .await;

            // On any 422 we now attempt an email lookup; mock it returning empty
            Mock::given(method("GET"))
                .and(path("/customers/"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "items": []
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client.create_customer("org_123", "invalid-email").await;

            assert!(result.is_err());
            match result {
                Err(PolarError::Api { status, .. }) => {
                    assert_eq!(status, 422);
                }
                _ => panic!("Expected Api error"),
            }
        }

        #[tokio::test]
        async fn handles_422_exists_but_lookup_fails() {
            let mock_server = MockServer::start().await;

            // POST returns 422 "already exists"
            Mock::given(method("POST"))
                .and(path("/customers/"))
                .respond_with(
                    ResponseTemplate::new(422)
                        .set_body_string(r#"{"detail": "Customer with email already exists"}"#),
                )
                .expect(1)
                .mount(&mock_server)
                .await;

            // GET returns empty list (customer not found somehow)
            Mock::given(method("GET"))
                .and(path("/customers/"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "items": []
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client.create_customer("org_123", "ghost@example.com").await;

            assert!(result.is_err());
            match result {
                Err(PolarError::Api { status, message }) => {
                    assert_eq!(status, 422);
                    assert!(message.contains("already exists"));
                }
                _ => panic!("Expected Api error"),
            }
        }

        #[tokio::test]
        async fn handles_500_error() {
            let mock_server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/customers/"))
                .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client.create_customer("org_123", "test@example.com").await;

            assert!(result.is_err());
            match result {
                Err(PolarError::Api { status, .. }) => {
                    assert_eq!(status, 500);
                }
                _ => panic!("Expected Api error"),
            }
        }
    }

    // ============================================================
    // Tests for delete_customer
    // ============================================================
    mod delete_customer {
        use super::*;

        #[tokio::test]
        async fn deletes_customer_successfully() {
            let mock_server = MockServer::start().await;

            Mock::given(method("DELETE"))
                .and(path("/customers/cust_123"))
                .and(bearer_token("test_polar_token"))
                .respond_with(ResponseTemplate::new(204))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client.delete_customer("cust_123").await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn handles_not_found() {
            let mock_server = MockServer::start().await;

            Mock::given(method("DELETE"))
                .and(path("/customers/nonexistent"))
                .respond_with(
                    ResponseTemplate::new(404)
                        .set_body_string(r#"{"detail": "Customer not found"}"#),
                )
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client.delete_customer("nonexistent").await;

            assert!(result.is_err());
            match result {
                Err(PolarError::Api { status, .. }) => {
                    assert_eq!(status, 404);
                }
                _ => panic!("Expected Api error"),
            }
        }

        #[tokio::test]
        async fn handles_server_error() {
            let mock_server = MockServer::start().await;

            Mock::given(method("DELETE"))
                .and(path("/customers/cust_123"))
                .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client.delete_customer("cust_123").await;

            assert!(result.is_err());
            match result {
                Err(PolarError::Api { status, .. }) => {
                    assert_eq!(status, 500);
                }
                _ => panic!("Expected Api error"),
            }
        }
    }

    // ============================================================
    // Tests for create_trial_subscription
    // ============================================================
    mod create_subscription {
        use super::*;

        #[tokio::test]
        async fn creates_subscription_successfully() {
            let mock_server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/subscriptions/"))
                .and(bearer_token("test_polar_token"))
                .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "id": "sub_123",
                    "customer_id": "cust_456",
                    "product_id": "prod_solo_yearly",
                    "status": "trialing",
                    "trial_ends_at": "2024-02-15T10:30:00Z",
                    "current_period_end": "2025-01-15T10:30:00Z"
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client
                .create_trial_subscription("cust_456", "org_789")
                .await;

            assert!(result.is_ok());
            let subscription = result.unwrap();
            assert_eq!(subscription.id, "sub_123");
            assert_eq!(subscription.customer_id, "cust_456");
            assert_eq!(subscription.status, "trialing");
            assert_eq!(
                subscription.trial_ends_at,
                Some("2024-02-15T10:30:00Z".to_string())
            );
        }

        #[tokio::test]
        async fn handles_api_error() {
            let mock_server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/subscriptions/"))
                .respond_with(
                    ResponseTemplate::new(400)
                        .set_body_string(r#"{"detail": "Invalid customer_id"}"#),
                )
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client
                .create_trial_subscription("invalid_customer", "org_123")
                .await;

            assert!(result.is_err());
            match result {
                Err(PolarError::Api { status, .. }) => {
                    assert_eq!(status, 400);
                }
                _ => panic!("Expected Api error"),
            }
        }

        #[tokio::test]
        async fn handles_unauthorized() {
            let mock_server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/subscriptions/"))
                .respond_with(ResponseTemplate::new(401).set_body_string("Invalid token"))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client
                .create_trial_subscription("cust_123", "org_456")
                .await;

            assert!(result.is_err());
        }
    }

    // ============================================================
    // Tests for create_redirect_checkout_session
    // ============================================================
    mod create_checkout_session {
        use super::*;

        #[tokio::test]
        async fn creates_checkout_session_with_new_customer() {
            let mock_server = MockServer::start().await;

            // Mock customer lookup - returns empty (no existing customer)
            Mock::given(method("GET"))
                .and(path("/customers/"))
                .and(query_param("email", "user@example.com"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "items": []
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            // Mock checkout creation
            Mock::given(method("POST"))
                .and(path("/checkouts/"))
                .and(bearer_token("test_polar_token"))
                .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "id": "checkout_123",
                    "url": "https://checkout.polar.sh/checkout_123",
                    "status": "open",
                    "customer_id": null
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client
                .create_redirect_checkout_session(
                    "prod_starter_monthly",
                    "user@example.com",
                    "org_123",
                )
                .await;

            assert!(result.is_ok());
            let checkout = result.unwrap();
            assert_eq!(checkout.id, "checkout_123");
            assert_eq!(checkout.url, "https://checkout.polar.sh/checkout_123");
            assert_eq!(checkout.status, "open");
        }

        #[tokio::test]
        async fn creates_checkout_with_trial_for_new_polar_customer() {
            let mock_server = MockServer::start().await;

            // Mock customer lookup - returns existing customer (new to Polar)
            Mock::given(method("GET"))
                .and(path("/customers/"))
                .and(query_param("email", "new_polar@example.com"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "items": [{
                        "id": "cust_new_polar_123",
                        "email": "new_polar@example.com",
                        "metadata": {}
                    }]
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            // Mock subscription lookup - returns empty (no prior subscriptions)
            Mock::given(method("GET"))
                .and(path("/subscriptions/"))
                .and(query_param("customer_id", "cust_new_polar_123"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "items": []
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            // Mock checkout creation (should have allow_trial: true)
            Mock::given(method("POST"))
                .and(path("/checkouts/"))
                .and(bearer_token("test_polar_token"))
                .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "id": "checkout_new",
                    "url": "https://checkout.polar.sh/checkout_new",
                    "status": "open",
                    "customer_id": "cust_new_polar_123"
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client
                .create_redirect_checkout_session(
                    "prod_starter_monthly",
                    "new_polar@example.com",
                    "org_123",
                )
                .await;

            assert!(result.is_ok());
            let checkout = result.unwrap();
            assert_eq!(checkout.id, "checkout_new");
        }

        #[tokio::test]
        async fn creates_checkout_without_trial_for_existing_subscriber() {
            let mock_server = MockServer::start().await;

            // Mock customer lookup - returns existing customer
            Mock::given(method("GET"))
                .and(path("/customers/"))
                .and(query_param("email", "existing@example.com"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "items": [{
                        "id": "cust_existing_123",
                        "email": "existing@example.com",
                        "metadata": {}
                    }]
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            // Mock subscription lookup - returns existing subscription (trial already used)
            Mock::given(method("GET"))
                .and(path("/subscriptions/"))
                .and(query_param("customer_id", "cust_existing_123"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "items": [{
                        "id": "sub_old_123",
                        "status": "canceled",
                        "trial_ends_at": "2024-01-15T10:30:00Z"
                    }]
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            // Mock checkout creation (should have allow_trial: false)
            Mock::given(method("POST"))
                .and(path("/checkouts/"))
                .and(bearer_token("test_polar_token"))
                .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "id": "checkout_456",
                    "url": "https://checkout.polar.sh/checkout_456",
                    "status": "open",
                    "customer_id": "cust_existing_123"
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client
                .create_redirect_checkout_session(
                    "prod_starter_monthly",
                    "existing@example.com",
                    "org_123",
                )
                .await;

            assert!(result.is_ok());
            let checkout = result.unwrap();
            assert_eq!(checkout.id, "checkout_456");
            assert_eq!(checkout.customer_id, Some("cust_existing_123".to_string()));
        }

        #[tokio::test]
        async fn handles_api_error() {
            let mock_server = MockServer::start().await;

            // Mock customer lookup - returns empty
            Mock::given(method("GET"))
                .and(path("/customers/"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "items": []
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            Mock::given(method("POST"))
                .and(path("/checkouts/"))
                .respond_with(
                    ResponseTemplate::new(400)
                        .set_body_string(r#"{"detail": "Invalid product_id"}"#),
                )
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client
                .create_redirect_checkout_session("invalid_product", "user@example.com", "org_123")
                .await;

            assert!(result.is_err());
            match result {
                Err(PolarError::Api { status, .. }) => {
                    assert_eq!(status, 400);
                }
                _ => panic!("Expected Api error"),
            }
        }

        #[tokio::test]
        async fn handles_server_error() {
            let mock_server = MockServer::start().await;

            // Mock customer lookup - returns empty
            Mock::given(method("GET"))
                .and(path("/customers/"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "items": []
                })))
                .expect(1)
                .mount(&mock_server)
                .await;

            Mock::given(method("POST"))
                .and(path("/checkouts/"))
                .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
                .expect(1)
                .mount(&mock_server)
                .await;

            let client = PolarClient::new(test_config(&mock_server.uri()));
            let result = client
                .create_redirect_checkout_session(
                    "prod_starter_monthly",
                    "user@example.com",
                    "org_123",
                )
                .await;

            assert!(result.is_err());
            match result {
                Err(PolarError::Api { status, .. }) => {
                    assert_eq!(status, 503);
                }
                _ => panic!("Expected Api error"),
            }
        }
    }
}
