//! Passkey metadata for the Settings card. The credential itself never leaves
//! the server; this is what a user needs to recognise and remove one.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PasskeySummary {
    pub id: String,
    /// Label given at enrollment; empty for passkeys enrolled from the login
    /// page's one-time offer.
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    /// Synced to the provider's cloud (iCloud Keychain, Google Password
    /// Manager), so it survives losing the device.
    pub backed_up: bool,
}
