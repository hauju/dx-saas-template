//! HTTP handlers for authentication flows.

mod session_auth;
mod shared;

pub use session_auth::*;
pub use shared::{AuthUserInfo, determine_post_login_redirect, lookup_or_create_user};
