//! Session management: UserSession extractor, login/logout helpers.

mod extractor;
mod login;
mod logout;

pub use extractor::{LoggedInData, UserSession};
pub use login::{LOGGED_IN_USER_SESSION_KEY, login};
pub use logout::logout;
