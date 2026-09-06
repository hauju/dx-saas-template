pub mod api_key;
pub mod error;
pub mod passkey;
pub mod subscription;
pub mod user;
pub mod waitlist;

#[cfg(feature = "server")]
pub use error::AppError;

/// Check if an error is an authentication error (user not logged in).
/// Useful on the client side to detect when to redirect to login.
#[allow(dead_code)]
pub fn is_auth_error<E: std::fmt::Debug>(error: &E) -> bool {
    let err_str = format!("{:?}", error);
    err_str.contains("UserNotLoggedIn") || err_str.contains("Not logged in")
}
