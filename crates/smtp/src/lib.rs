mod client;
pub mod error;
mod types;

pub use client::{AsyncSmtpClient, AsyncSmtpClientImpl, SmtpClient, SmtpClientImpl};
pub use lettre::message::Mailbox;
pub use types::{Email, EmailAttachment, EmailBuilder, SmtpConfig};
