use std::future::Future;

use lettre::message::{Attachment, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, SmtpTransport, Tokio1Executor, Transport,
};
use secrecy::ExposeSecret;

use crate::error::{Error, Result};
use crate::types::{Email, SmtpConfig};

const MAX_RETRIES: u32 = 3;
const INITIAL_BACKOFF_MS: u64 = 1000;

const FALLBACK_TEXT: &str = "If this message isn't displaying correctly, please enable HTML in your email settings or try a different email client.";

/// Builds a lettre `Message` from an `Email` and sender address.
fn build_message(email: Email, from: &str) -> Result<Message> {
    let mut multipart = MultiPart::mixed().multipart(MultiPart::alternative_plain_html(
        FALLBACK_TEXT.to_string(),
        email.body,
    ));

    for attachment in email.attachments {
        let attachment = Attachment::new(attachment.filename)
            .body(attachment.data, attachment.content_type.parse()?);
        multipart = multipart.singlepart(attachment);
    }

    let from = from.parse()?;
    let message = Message::builder()
        .from(from)
        .to(email.to)
        .subject(email.subject)
        .multipart(multipart)?;

    Ok(message)
}

/// Returns true if the error is a transport-level error worth retrying.
fn is_retryable(err: &Error) -> bool {
    matches!(err, Error::SmtpTransportError(_))
}

// ============================================================================
// Sync Client
// ============================================================================

pub trait SmtpClient: Send + Sync + 'static {
    fn send_email(&self, email: Email) -> Result<()>;
}

/// Synchronous SMTP client implementation using lettre.
///
/// The inner `SmtpTransport` uses connection pooling when the `pool` feature is enabled.
pub struct SmtpClientImpl {
    transport: SmtpTransport,
    from: String,
}

impl SmtpClientImpl {
    pub fn new(config: SmtpConfig) -> Result<Self> {
        let transport = if config.insecure {
            SmtpTransport::builder_dangerous(&config.host)
                .port(config.port)
                .build()
        } else {
            let username = config.user.expose_secret().to_string();
            let password = config.password.expose_secret().to_string();
            let creds = Credentials::new(username, password);
            SmtpTransport::relay(&config.host)?
                .credentials(creds)
                .build()
        };

        Ok(SmtpClientImpl {
            transport,
            from: config.from,
        })
    }
}

impl SmtpClient for SmtpClientImpl {
    fn send_email(&self, email: Email) -> Result<()> {
        let message = build_message(email, &self.from)?;

        let mut last_err = None;
        for attempt in 0..MAX_RETRIES {
            match self.transport.send(&message) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    let err = Error::SmtpTransportError(e);
                    if !is_retryable(&err) || attempt + 1 == MAX_RETRIES {
                        return Err(err);
                    }
                    let backoff = INITIAL_BACKOFF_MS * 2u64.pow(attempt);
                    tracing::warn!(
                        attempt = attempt + 1,
                        max = MAX_RETRIES,
                        backoff_ms = backoff,
                        "SMTP send failed, retrying"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(backoff));
                    last_err = Some(err);
                }
            }
        }

        Err(last_err.unwrap())
    }
}

// ============================================================================
// Async Client
// ============================================================================

pub trait AsyncSmtpClient: Send + Sync + 'static {
    fn send_email(&self, email: Email) -> impl Future<Output = Result<()>> + Send;
}

/// Asynchronous SMTP client implementation using lettre with Tokio.
///
/// The inner `AsyncSmtpTransport` uses connection pooling when the `pool` feature is enabled.
pub struct AsyncSmtpClientImpl {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: String,
}

impl AsyncSmtpClientImpl {
    pub fn new(config: SmtpConfig) -> Result<Self> {
        let transport = if config.insecure {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
                .port(config.port)
                .build()
        } else {
            let username = config.user.expose_secret().to_string();
            let password = config.password.expose_secret().to_string();
            let creds = Credentials::new(username, password);
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)?
                .credentials(creds)
                .build()
        };

        Ok(AsyncSmtpClientImpl {
            transport,
            from: config.from,
        })
    }
}

impl AsyncSmtpClient for AsyncSmtpClientImpl {
    async fn send_email(&self, email: Email) -> Result<()> {
        let message = build_message(email, &self.from)?;

        let mut last_err = None;
        for attempt in 0..MAX_RETRIES {
            match self.transport.send(message.clone()).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    let err = Error::SmtpTransportError(e);
                    if !is_retryable(&err) || attempt + 1 == MAX_RETRIES {
                        return Err(err);
                    }
                    let backoff = INITIAL_BACKOFF_MS * 2u64.pow(attempt);
                    tracing::warn!(
                        attempt = attempt + 1,
                        max = MAX_RETRIES,
                        backoff_ms = backoff,
                        "SMTP send failed, retrying"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
                    last_err = Some(err);
                }
            }
        }

        Err(last_err.unwrap())
    }
}
