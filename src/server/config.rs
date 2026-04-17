use crate::models::AppError;

/// Non-sensitive application configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub db_url: String,
    pub redis_url: String,
    pub base_url: String,
    pub zitadel_domain: String,
    pub zitadel_org_id: Option<String>,
    pub secure_cookies: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_from: String,
    pub smtp_insecure: bool,
}

impl Config {
    pub fn load_from_env() -> Result<Self, AppError> {
        let _ = dotenvy::dotenv();

        Ok(Self {
            db_url: get_env("DATABASE_URL")?,
            redis_url: get_env("REDIS_URL")?,
            base_url: get_env("BASE_URL")?,
            zitadel_domain: get_env("ZITADEL_DOMAIN")?,
            zitadel_org_id: get_env_optional("ZITADEL_ORG_ID"),
            secure_cookies: get_env_optional("SECURE_COOKIES")
                .map(|v| v == "true")
                .unwrap_or(true),
            smtp_host: get_env("SMTP_HOST")?,
            smtp_port: get_env("SMTP_PORT")?
                .parse()
                .map_err(|_| AppError::Internal("Invalid SMTP_PORT".to_string()))?,
            smtp_from: get_env("SMTP_FROM")?,
            smtp_insecure: {
                let host = std::env::var("SMTP_HOST").unwrap_or_default();
                get_env_optional("SMTP_INSECURE")
                    .map(|v| v == "true")
                    .unwrap_or_else(|| is_local_smtp_host(&host))
            },
        })
    }
}

/// Sensitive secrets loaded from environment variables.
#[derive(Clone)]
pub struct Secrets {
    pub session_secret: Vec<u8>,
    pub encryption_key: Option<[u8; 32]>,
    pub zitadel_service_user_token: Option<String>,
    pub smtp_user: secrecy::SecretString,
    pub smtp_password: secrecy::SecretString,
    pub polar_access_token: Option<String>,
    pub polar_webhook_secret: Option<String>,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("session_secret", &"[REDACTED]")
            .finish()
    }
}

impl Secrets {
    pub fn load_from_env() -> Result<Self, AppError> {
        let _ = dotenvy::dotenv();

        let session_secret_hex = get_env("SESSION_SECRET")?;
        let session_secret = hex::decode(&session_secret_hex).map_err(|e| {
            AppError::Internal(format!("SESSION_SECRET must be valid hex: {e}"))
        })?;

        if session_secret.len() < 64 {
            return Err(AppError::Internal(
                "SESSION_SECRET must be at least 64 bytes (128 hex chars)".to_string(),
            ));
        }

        let encryption_key = get_env_optional("ENCRYPTION_KEY")
            .map(|k| {
                crypto::encryption::parse_key(&k)
                    .map_err(|e| AppError::Internal(format!("Invalid ENCRYPTION_KEY: {e}")))
            })
            .transpose()?;

        Ok(Self {
            session_secret,
            encryption_key,
            zitadel_service_user_token: get_env_optional("ZITADEL_SERVICE_USER_TOKEN"),
            smtp_user: secrecy::SecretString::from(
                get_env_optional("SMTP_USER").unwrap_or_default(),
            ),
            smtp_password: secrecy::SecretString::from(
                get_env_optional("SMTP_PASSWORD").unwrap_or_default(),
            ),
            polar_access_token: get_env_optional("POLAR_ACCESS_TOKEN"),
            polar_webhook_secret: get_env_optional("POLAR_WEBHOOK_SECRET"),
        })
    }
}

fn get_env(key: &str) -> Result<String, AppError> {
    std::env::var(key)
        .map_err(|_| AppError::Internal(format!("Missing required env var: {key}")))
}

fn get_env_optional(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn is_local_smtp_host(host: &str) -> bool {
    let h = host.to_lowercase();
    h == "localhost" || h == "mailpit" || h == "127.0.0.1" || h == "::1"
}
