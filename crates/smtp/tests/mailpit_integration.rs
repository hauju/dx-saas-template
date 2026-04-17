//! Integration tests for SMTP client using Mailpit
//!
//! Prerequisites:
//! - Mailpit running on localhost:1025 (SMTP) and localhost:8025 (HTTP API)
//! - Run with: `cargo test -p smtp --test mailpit_integration -- --ignored`

use secrecy::SecretString;
use smtp::{
    AsyncSmtpClient, AsyncSmtpClientImpl, Email, EmailAttachment, SmtpClient, SmtpClientImpl,
    SmtpConfig,
};

fn mailpit_config() -> SmtpConfig {
    SmtpConfig {
        from: "test@example.com".to_string(),
        host: "localhost".to_string(),
        port: 1025,
        user: SecretString::from(""),
        password: SecretString::from(""),
        insecure: true,
    }
}

// ============================================================================
// Sync Tests
// ============================================================================

#[test]
#[ignore = "requires mailpit running on localhost:1025"]
fn test_send_simple_email() {
    let client = SmtpClientImpl::new(mailpit_config()).unwrap();

    let email = Email::builder("recipient@example.com".parse().unwrap())
        .subject("Test Email")
        .body("<h1>Hello!</h1><p>This is a test email from the SMTP integration test.</p>")
        .build();

    let result = client.send_email(email);
    assert!(result.is_ok(), "Failed to send email: {:?}", result.err());
}

#[test]
#[ignore = "requires mailpit running on localhost:1025"]
fn test_send_email_with_attachment() {
    let client = SmtpClientImpl::new(mailpit_config()).unwrap();

    let attachment = EmailAttachment {
        filename: "test.txt".to_string(),
        content_type: "text/plain".to_string(),
        data: b"Hello, this is a test attachment!".to_vec(),
    };

    let email = Email::builder("recipient@example.com".parse().unwrap())
        .subject("Test Email with Attachment")
        .body("<h1>Attachment Test</h1><p>This email includes an attachment.</p>")
        .attachment(attachment)
        .build();

    let result = client.send_email(email);
    assert!(result.is_ok(), "Failed to send email: {:?}", result.err());
}

#[test]
#[ignore = "requires mailpit running on localhost:1025"]
fn test_send_email_with_multiple_attachments() {
    let client = SmtpClientImpl::new(mailpit_config()).unwrap();

    let attachments = vec![
        EmailAttachment {
            filename: "file1.txt".to_string(),
            content_type: "text/plain".to_string(),
            data: b"Content of file 1".to_vec(),
        },
        EmailAttachment {
            filename: "file2.json".to_string(),
            content_type: "application/json".to_string(),
            data: br#"{"key": "value"}"#.to_vec(),
        },
    ];

    let email = Email::builder("recipient@example.com".parse().unwrap())
        .subject("Test Email with Multiple Attachments")
        .body("<h1>Multiple Attachments</h1><p>This email has two attachments.</p>")
        .attachments(attachments)
        .build();

    let result = client.send_email(email);
    assert!(result.is_ok(), "Failed to send email: {:?}", result.err());
}

#[test]
#[ignore = "requires mailpit running on localhost:1025"]
fn test_send_email_with_special_characters_in_subject() {
    let client = SmtpClientImpl::new(mailpit_config()).unwrap();

    let email = Email::builder("recipient@example.com".parse().unwrap())
        .subject("Test: Special Characters! @#$%^&*() and Unicode")
        .body("<p>Testing special characters in subject line.</p>")
        .build();

    let result = client.send_email(email);
    assert!(result.is_ok(), "Failed to send email: {:?}", result.err());
}

// ============================================================================
// Async Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires mailpit running on localhost:1025"]
async fn test_async_send_simple_email() {
    let client = AsyncSmtpClientImpl::new(mailpit_config()).unwrap();

    let email = Email::builder("recipient@example.com".parse().unwrap())
        .subject("Async Test Email")
        .body("<h1>Hello!</h1><p>This is an async test email.</p>")
        .build();

    let result: smtp::error::Result<()> = client.send_email(email).await;
    assert!(result.is_ok(), "Failed to send email: {:?}", result.err());
}

#[tokio::test]
#[ignore = "requires mailpit running on localhost:1025"]
async fn test_async_send_email_with_attachment() {
    let client = AsyncSmtpClientImpl::new(mailpit_config()).unwrap();

    let attachment = EmailAttachment {
        filename: "async_test.txt".to_string(),
        content_type: "text/plain".to_string(),
        data: b"Hello from async test!".to_vec(),
    };

    let email = Email::builder("recipient@example.com".parse().unwrap())
        .subject("Async Test Email with Attachment")
        .body("<h1>Async Attachment Test</h1><p>This email includes an attachment.</p>")
        .attachment(attachment)
        .build();

    let result: smtp::error::Result<()> = client.send_email(email).await;
    assert!(result.is_ok(), "Failed to send email: {:?}", result.err());
}

#[tokio::test]
#[ignore = "requires mailpit running on localhost:1025"]
async fn test_async_send_email_with_multiple_attachments() {
    let client = AsyncSmtpClientImpl::new(mailpit_config()).unwrap();

    let attachments = vec![
        EmailAttachment {
            filename: "async_file1.txt".to_string(),
            content_type: "text/plain".to_string(),
            data: b"Async content of file 1".to_vec(),
        },
        EmailAttachment {
            filename: "async_file2.json".to_string(),
            content_type: "application/json".to_string(),
            data: br#"{"async": true}"#.to_vec(),
        },
    ];

    let email = Email::builder("recipient@example.com".parse().unwrap())
        .subject("Async Test Email with Multiple Attachments")
        .body("<h1>Async Multiple Attachments</h1><p>This email has two attachments.</p>")
        .attachments(attachments)
        .build();

    let result: smtp::error::Result<()> = client.send_email(email).await;
    assert!(result.is_ok(), "Failed to send email: {:?}", result.err());
}
