use lettre::message::Mailbox;
use secrecy::SecretString;

/// Represents an email message.
#[derive(Debug, Clone)]
pub struct Email {
    /// Recipient email address
    pub to: Mailbox,
    /// Subject of the email
    pub subject: String,
    /// Body of the email (HTML)
    pub body: String,
    /// Attachments
    pub attachments: Vec<EmailAttachment>,
}

impl Email {
    /// Creates a new `EmailBuilder` for constructing an email.
    pub fn builder(to: Mailbox) -> EmailBuilder {
        EmailBuilder::new(to)
    }
}

/// Builder for constructing `Email` instances.
#[derive(Debug, Clone)]
pub struct EmailBuilder {
    to: Mailbox,
    subject: Option<String>,
    body: Option<String>,
    attachments: Vec<EmailAttachment>,
}

impl EmailBuilder {
    /// Creates a new builder with the recipient address.
    pub fn new(to: Mailbox) -> Self {
        Self {
            to,
            subject: None,
            body: None,
            attachments: Vec::new(),
        }
    }

    /// Sets the email subject.
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Sets the email body (HTML content).
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Adds an attachment to the email.
    pub fn attachment(mut self, attachment: EmailAttachment) -> Self {
        self.attachments.push(attachment);
        self
    }

    /// Adds multiple attachments to the email.
    pub fn attachments(mut self, attachments: impl IntoIterator<Item = EmailAttachment>) -> Self {
        self.attachments.extend(attachments);
        self
    }

    /// Builds the `Email` instance.
    ///
    /// # Panics
    /// Panics if `subject` or `body` are not set.
    pub fn build(self) -> Email {
        Email {
            to: self.to,
            subject: self.subject.expect("subject is required"),
            body: self.body.expect("body is required"),
            attachments: self.attachments,
        }
    }

    /// Attempts to build the `Email` instance, returning `None` if required fields are missing.
    pub fn try_build(self) -> Option<Email> {
        Some(Email {
            to: self.to,
            subject: self.subject?,
            body: self.body?,
            attachments: self.attachments,
        })
    }
}

/// Represents an email attachment.
#[derive(Debug, Clone)]
pub struct EmailAttachment {
    /// Filename of the attachment
    pub filename: String,
    /// Content type of the attachment
    /// e.g. "application/pdf"
    pub content_type: String,
    /// data
    pub data: Vec<u8>,
}

/// SMTP configuration for sending emails.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// Sender email address
    pub from: String,
    /// SMTP host
    pub host: String,
    /// SMTP port
    pub port: u16,
    /// SMTP user
    pub user: SecretString,
    /// SMTP password
    pub password: SecretString,
    /// Use insecure (unencrypted, no auth) connection — for local dev servers like Mailpit
    pub insecure: bool,
}
