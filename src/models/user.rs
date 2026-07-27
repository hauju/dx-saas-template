use serde::{Deserialize, Serialize};

#[cfg(feature = "server")]
use uuid::Uuid;

/// User entity stored in PostgreSQL.
#[cfg(feature = "server")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntity {
    pub id: Uuid,

    /// OIDC subject identifier (from FerrisKey)
    pub sub: String,

    /// User email address
    pub email: String,

    /// Display name
    pub name: Option<String>,

    /// Avatar URL
    pub avatar_url: Option<String>,

    /// Current subscription state, synced from Polar webhooks.
    #[serde(default)]
    pub subscription: Option<crate::models::subscription::SubscriptionInfo>,

    /// When the user was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When the user was last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Logged-in user data available on both client and server.
/// Mirrors `auth::LoggedInData` but is available on both compilation targets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoggedInData {
    pub id: String,
    pub sub: String,
    pub email: String,
    pub username: String,
    pub avatar_url: Option<String>,
}

#[cfg(feature = "server")]
impl From<auth::LoggedInData> for LoggedInData {
    fn from(data: auth::LoggedInData) -> Self {
        Self {
            id: data.id,
            sub: data.sub,
            email: data.email,
            username: data.username,
            avatar_url: data.avatar_url,
        }
    }
}
