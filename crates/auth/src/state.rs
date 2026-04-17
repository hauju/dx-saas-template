//! Auth state: trait-object holders for user store and email sender.

use crate::traits::{AuthEmailSender, AuthUserStore};
use std::sync::Arc;

/// Replaces `Extension<AppState>` in auth handlers.
///
/// Holds trait objects so the auth crate stays independent of
/// dashboard-specific types (`Database`, `AppState`, etc.).
#[derive(Clone)]
pub struct AuthState {
    pub user_store: Arc<dyn AuthUserStore>,
    pub email_sender: Arc<dyn AuthEmailSender>,
}
