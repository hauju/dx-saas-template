use crate::models::AppError;

/// Which login flow the auth routes run (`AUTH_MODE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// dx-auth's self-owned login: email OTP proves the address and creates
    /// the account, passkeys authenticate against this app's own database.
    /// No identity provider; needs only SMTP.
    Local,
    /// FerrisKey OIDC behind the same custom login UI, for apps that share a
    /// realm. Requires the `FERRISKEY_*` variables.
    Ferriskey,
}

/// Non-sensitive application configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub db_url: String,
    pub base_url: String,
    pub auth_mode: AuthMode,
    /// Terms version users must have accepted (`TOS_VERSION`), or `None` for
    /// no acceptance step. Changing it re-prompts everyone whose stored
    /// version differs.
    pub tos_version: Option<String>,
    /// FerrisKey settings, present only when `AUTH_MODE=ferriskey`; the
    /// fields dx-auth wants are filled with empty strings otherwise, which its
    /// local flow never reads.
    pub ferriskey_url: String,
    pub ferriskey_issuer_url: Option<String>,
    pub ferriskey_realm: String,
    pub ferriskey_client_id: String,
    pub secure_cookies: bool,
    pub trust_proxy_headers: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_from: String,
    pub smtp_security: smtp::SmtpSecurity,
    /// Let any address create an account (`OPEN_REGISTRATION`). Off, dx-auth
    /// admits only the allowlists below, or the very first account when both
    /// are empty.
    pub open_registration: bool,
    pub allowed_registration_emails: Vec<String>,
    pub allowed_registration_domains: Vec<String>,
    /// Bollwark captcha in front of new-user registration, as
    /// `(server_url, site_key)`. dx-auth reads `CAPTCHA_URL` / `CAPTCHA_SITE_KEY`
    /// / `CAPTCHA_SECRET_KEY` itself and requires all three; this copy is what
    /// the login page needs to mount the widget, so it is `Some` under the
    /// same condition.
    pub captcha: Option<(String, String)>,
    /// `COMING_SOON=true`: `/` is the coming-soon page with the waitlist
    /// instead of the landing page. Off unless set, so a launched site can
    /// never hide itself by losing a variable.
    pub coming_soon: bool,
}

impl Config {
    pub fn load_from_env() -> Result<Self, AppError> {
        let _ = dotenvy::dotenv();

        let auth_mode = match get_env_optional("AUTH_MODE").as_deref() {
            None | Some("local") => AuthMode::Local,
            Some("ferriskey") => AuthMode::Ferriskey,
            Some(other) => {
                return Err(AppError::Internal(format!(
                    "Invalid AUTH_MODE: {other} (expected local or ferriskey)"
                )));
            }
        };
        // Required in FerrisKey mode, ignored otherwise.
        let ferriskey = |key: &str| match auth_mode {
            AuthMode::Ferriskey => get_env(key),
            AuthMode::Local => Ok(get_env_optional(key).unwrap_or_default()),
        };

        Ok(Self {
            db_url: get_env("DATABASE_URL")?,
            base_url: get_env("BASE_URL")?,
            auth_mode,
            tos_version: get_env_optional("TOS_VERSION"),
            ferriskey_url: ferriskey("FERRISKEY_URL")?,
            ferriskey_issuer_url: get_env_optional("FERRISKEY_ISSUER_URL"),
            ferriskey_realm: ferriskey("FERRISKEY_REALM")?,
            ferriskey_client_id: ferriskey("FERRISKEY_CLIENT_ID")?,
            secure_cookies: get_env_optional("SECURE_COOKIES")
                .map(|v| v == "true")
                .unwrap_or(true),
            trust_proxy_headers: get_env_optional("TRUST_PROXY_HEADERS")
                .map(|v| v == "true")
                .unwrap_or(false),
            smtp_host: get_env("SMTP_HOST")?,
            smtp_port: get_env("SMTP_PORT")?
                .parse()
                .map_err(|_| AppError::Internal("Invalid SMTP_PORT".to_string()))?,
            smtp_from: get_env("SMTP_FROM")?,
            smtp_security: match get_env_optional("SMTP_SECURITY").as_deref() {
                Some("tls") => smtp::SmtpSecurity::Tls,
                Some("starttls") => smtp::SmtpSecurity::StartTls,
                Some("none") => smtp::SmtpSecurity::None,
                Some(other) => {
                    return Err(AppError::Internal(format!(
                        "Invalid SMTP_SECURITY: {other} (expected tls, starttls, or none)"
                    )));
                }
                None => {
                    let host = std::env::var("SMTP_HOST").unwrap_or_default();
                    if is_local_smtp_host(&host) {
                        smtp::SmtpSecurity::None
                    } else {
                        smtp::SmtpSecurity::Tls
                    }
                }
            },
            open_registration: get_env_optional("OPEN_REGISTRATION")
                .map(|v| v == "true")
                .unwrap_or(false),
            allowed_registration_emails: parse_csv_lower(get_env_optional(
                "ALLOWED_REGISTRATION_EMAILS",
            )),
            allowed_registration_domains: parse_csv_lower(get_env_optional(
                "ALLOWED_REGISTRATION_DOMAINS",
            )),
            captcha: get_env_optional("CAPTCHA_URL")
                .zip(get_env_optional("CAPTCHA_SITE_KEY"))
                .filter(|_| get_env_optional("CAPTCHA_SECRET_KEY").is_some()),
            coming_soon: get_env_optional("COMING_SOON")
                .map(|v| v == "true")
                .unwrap_or(false),
        })
    }
}

/// Sensitive secrets loaded from environment variables.
///
/// Some fields are loaded but not yet read by the template binary itself —
/// they're placeholders ready to wire into downstream features.
#[derive(Clone)]
#[allow(dead_code)]
pub struct Secrets {
    pub session_secret: Vec<u8>,
    pub encryption_key: Option<[u8; 32]>,
    pub ferriskey_client_secret: Option<String>,
    pub smtp_user: secrecy::SecretString,
    pub smtp_password: secrecy::SecretString,
    pub polar_access_token: Option<String>,
    pub polar_webhook_secret: Option<String>,
    /// Bollwark secret for verifying the app's own forms (`server::captcha`);
    /// dx-auth reads the same variable itself for the login page.
    pub captcha_secret_key: Option<String>,
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
        let session_secret = hex::decode(&session_secret_hex)
            .map_err(|e| AppError::Internal(format!("SESSION_SECRET must be valid hex: {e}")))?;

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
            ferriskey_client_secret: get_env_optional("FERRISKEY_CLIENT_SECRET"),
            smtp_user: secrecy::SecretString::from(
                get_env_optional("SMTP_USER").unwrap_or_default(),
            ),
            smtp_password: secrecy::SecretString::from(
                get_env_optional("SMTP_PASSWORD").unwrap_or_default(),
            ),
            polar_access_token: get_env_optional("POLAR_ACCESS_TOKEN"),
            polar_webhook_secret: get_env_optional("POLAR_WEBHOOK_SECRET"),
            captcha_secret_key: get_env_optional("CAPTCHA_SECRET_KEY"),
        })
    }
}

fn get_env(key: &str) -> Result<String, AppError> {
    std::env::var(key).map_err(|_| AppError::Internal(format!("Missing required env var: {key}")))
}

fn get_env_optional(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Comma-separated list → trimmed, lowercased, empties dropped.
fn parse_csv_lower(value: Option<String>) -> Vec<String> {
    value
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn is_local_smtp_host(host: &str) -> bool {
    let h = host.to_lowercase();
    h == "localhost" || h == "mailpit" || h == "127.0.0.1" || h == "::1"
}
