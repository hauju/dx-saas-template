//! JWKS fetching, caching, and JWT validation for FerrisKey-issued access tokens.
//!
//! Used to validate id_tokens received from the OIDC token endpoint after a
//! successful authorization-code exchange, and Bearer tokens from mobile
//! clients (currently stubbed on this branch).

use serde::Deserialize;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const JWKS_CACHE_TTL: Duration = Duration::from_secs(3600); // 1 hour
const CLOCK_LEEWAY_SECONDS: u64 = 60;

/// Claims extracted from a validated FerrisKey JWT.
#[derive(Debug, Deserialize)]
pub struct OidcJwtClaims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    pub iss: String,
    pub exp: u64,
    pub iat: u64,
    /// OIDC `nonce` claim. Echoed by the IdP from the auth request — the
    /// caller compares it against the per-flow nonce to bind the id_token
    /// to the original request. Optional here because not every issuer
    /// includes it and validation happens at the call site.
    #[serde(default)]
    pub nonce: Option<String>,
}

struct CachedJwks {
    jwks: jsonwebtoken::jwk::JwkSet,
    fetched_at: Instant,
}

/// Thread-safe JWKS cache with automatic refresh on unknown key IDs.
pub struct JwksCache {
    jwks_url: String,
    expected_issuers: Vec<String>,
    expected_audience: String,
    cache: RwLock<Option<CachedJwks>>,
    http: reqwest::Client,
}

impl JwksCache {
    /// Create a new JWKS cache for the given FerrisKey realm.
    ///
    /// `ferriskey_url` is the FerrisKey API base URL used for JWKS fetches.
    /// `issuer_url` is the configured public OIDC issuer base URL. FerrisKey
    /// deployments can differ on whether the `/api` mount appears in `iss`, so
    /// accept the same realm on both the configured issuer base and API base,
    /// with a stripped-`/api` variant for backwards compatibility.
    pub fn new(ferriskey_url: &str, issuer_url: &str, realm: &str, client_id: &str) -> Self {
        let base = ferriskey_url.trim_end_matches('/');
        let issuer = issuer_url.trim_end_matches('/');
        let mut expected_issuers = Vec::new();
        for candidate in [
            issuer,
            issuer.strip_suffix("/api").unwrap_or(issuer),
            base,
            base.strip_suffix("/api").unwrap_or(base),
        ] {
            let expected = format!("{candidate}/realms/{realm}");
            if !expected_issuers.contains(&expected) {
                expected_issuers.push(expected);
            }
        }

        Self {
            jwks_url: format!("{base}/realms/{realm}/protocol/openid-connect/certs"),
            expected_issuers,
            expected_audience: client_id.to_string(),
            cache: RwLock::new(None),
            http: reqwest::Client::new(),
        }
    }

    /// Validate a JWT token and return the extracted claims.
    ///
    /// On unknown `kid`, attempts a single JWKS refresh to handle key rotation.
    pub async fn validate_token(&self, token: &str) -> Result<OidcJwtClaims, JwtError> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| JwtError::InvalidToken)?;
        let kid = header.kid.as_deref().ok_or(JwtError::MissingKid)?;

        // Try cached key first
        if let Some(key) = self.find_key(kid) {
            return self.decode_with_key(token, &key);
        }

        // Key not found or cache expired — refresh JWKS (handles key rotation)
        self.refresh_jwks().await?;

        let key = self.find_key(kid).ok_or(JwtError::UnknownKid)?;
        self.decode_with_key(token, &key)
    }

    fn find_key(&self, kid: &str) -> Option<jsonwebtoken::DecodingKey> {
        let cache = self.cache.read().ok()?;
        let cached = cache.as_ref()?;

        if cached.fetched_at.elapsed() > JWKS_CACHE_TTL {
            return None;
        }

        cached
            .jwks
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid))
            .and_then(|jwk| jsonwebtoken::DecodingKey::from_jwk(jwk).ok())
    }

    async fn refresh_jwks(&self) -> Result<(), JwtError> {
        let jwks: jsonwebtoken::jwk::JwkSet = self
            .http
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch JWKS from {}: {:?}", self.jwks_url, e);
                JwtError::JwksFetchFailed
            })?
            .json()
            .await
            .map_err(|e| {
                tracing::error!("Failed to parse JWKS response: {:?}", e);
                JwtError::JwksFetchFailed
            })?;

        tracing::info!(
            "Refreshed JWKS cache ({} keys) from {}",
            jwks.keys.len(),
            self.jwks_url
        );

        let mut cache = self.cache.write().map_err(|_| JwtError::CacheLockError)?;
        *cache = Some(CachedJwks {
            jwks,
            fetched_at: Instant::now(),
        });
        Ok(())
    }

    fn decode_with_key(
        &self,
        token: &str,
        key: &jsonwebtoken::DecodingKey,
    ) -> Result<OidcJwtClaims, JwtError> {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        let issuers = self
            .expected_issuers
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        validation.set_issuer(&issuers);
        validation.set_audience(&[&self.expected_audience]);
        // `set_required_spec_claims` enforces that these fields are present
        // in the payload (deserialization would fail anyway for the
        // non-Option fields, but this rejects tokens missing `exp`/`iat`
        // before they can be considered valid). Nonce isn't on the OIDC
        // spec list but is checked separately at the call site.
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = CLOCK_LEEWAY_SECONDS;

        let token_data =
            jsonwebtoken::decode::<OidcJwtClaims>(token, key, &validation).map_err(|e| {
                tracing::warn!(
                    expected_issuers = ?self.expected_issuers,
                    expected_audience = %self.expected_audience,
                    "JWT validation failed: {:?}",
                    e
                );
                JwtError::ValidationFailed
            })?;

        Ok(token_data.claims)
    }
}

#[derive(Debug)]
pub enum JwtError {
    InvalidToken,
    MissingKid,
    UnknownKid,
    JwksFetchFailed,
    ValidationFailed,
    CacheLockError,
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::InvalidToken => write!(f, "Invalid JWT token"),
            JwtError::MissingKid => write!(f, "JWT missing kid header"),
            JwtError::UnknownKid => write!(f, "Unknown key ID in JWT"),
            JwtError::JwksFetchFailed => write!(f, "Failed to fetch JWKS"),
            JwtError::ValidationFailed => write!(f, "JWT validation failed"),
            JwtError::CacheLockError => write!(f, "JWKS cache lock error"),
        }
    }
}

impl std::error::Error for JwtError {}
