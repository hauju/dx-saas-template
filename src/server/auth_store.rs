use crate::models::user::UserEntity;
use crate::server::state::AppState;
use auth::types::{AuthTosAcceptance, AuthUser, NewAuthUser};
use auth::{AuthEmailSender, AuthError, AuthResult, AuthUserStore};

/// Implements `AuthUserStore` by reading/writing to MongoDB.
pub struct AppAuthUserStore {
    state: AppState,
}

impl AppAuthUserStore {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[async_trait::async_trait]
impl AuthUserStore for AppAuthUserStore {
    async fn get_user_by_sub(&self, sub: &str) -> AuthResult<Option<AuthUser>> {
        let user = self
            .state
            .db
            .users
            .find_one(bson::doc! { "sub": sub })
            .await
            .map_err(|e| AuthError::ServerStateError(format!("DB error: {e}")))?;

        Ok(user.map(user_entity_to_auth_user))
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> {
        let user = self
            .state
            .db
            .users
            .find_one(bson::doc! { "email": email })
            .await
            .map_err(|e| AuthError::ServerStateError(format!("DB error: {e}")))?;

        Ok(user.map(user_entity_to_auth_user))
    }

    async fn create_user(&self, user: NewAuthUser) -> AuthResult<AuthUser> {
        let now = chrono::Utc::now();
        let entity = UserEntity {
            id: bson::oid::ObjectId::new(),
            sub: user.sub,
            email: user.email,
            name: None,
            avatar_url: None,
            subscription: None,
            created_at: now,
            updated_at: now,
        };

        self.state
            .db
            .users
            .insert_one(&entity)
            .await
            .map_err(|e| AuthError::ServerStateError(format!("DB insert error: {e}")))?;

        Ok(user_entity_to_auth_user(entity))
    }

    async fn update_user_sub(&self, user_id: &str, new_sub: &str) -> AuthResult<()> {
        let oid = bson::oid::ObjectId::parse_str(user_id)
            .map_err(|e| AuthError::ServerStateError(format!("Invalid user ID: {e}")))?;

        self.state
            .db
            .users
            .update_one(
                bson::doc! { "_id": oid },
                bson::doc! { "$set": { "sub": new_sub, "updated_at": bson::DateTime::now() } },
            )
            .await
            .map_err(|e| AuthError::ServerStateError(format!("DB update error: {e}")))?;

        Ok(())
    }

    async fn create_personal_organization(&self, _user_id: &str, _email: &str) -> AuthResult<()> {
        // No-op for now — placeholder for future org support
        Ok(())
    }

    async fn update_tos_acceptance(
        &self,
        _user_id: &str,
        _tos: AuthTosAcceptance,
    ) -> AuthResult<()> {
        // No-op for now — placeholder for future TOS tracking
        Ok(())
    }

    async fn determine_post_login_redirect(
        &self,
        _user_id: &str,
        default_url: &str,
    ) -> AuthResult<String> {
        Ok(default_url.to_string())
    }
}

/// Implements `AuthEmailSender` using the smtp crate.
pub struct AppEmailSender {
    state: AppState,
}

impl AppEmailSender {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[async_trait::async_trait]
impl AuthEmailSender for AppEmailSender {
    async fn send_verification_code(
        &self,
        to_email: &str,
        code: &str,
        expires_in_minutes: u32,
    ) -> AuthResult<()> {
        let config = &self.state.config;
        let secrets = &self.state.secrets;

        let smtp_config = smtp::SmtpConfig {
            from: config.smtp_from.clone(),
            host: config.smtp_host.clone(),
            port: config.smtp_port,
            user: secrets.smtp_user.clone(),
            password: secrets.smtp_password.clone(),
            insecure: config.smtp_insecure,
        };

        let client = smtp::AsyncSmtpClientImpl::new(smtp_config).map_err(|e| {
            AuthError::ServerStateError(format!("Failed to create SMTP client: {e}"))
        })?;

        let to_mailbox: smtp::Mailbox = to_email
            .parse()
            .map_err(|e| AuthError::BadRequest(format!("Invalid email: {e}")))?;

        let body = format!(
            "<h2>Your verification code</h2>\
             <p>Your code is: <strong>{code}</strong></p>\
             <p>This code expires in {expires_in_minutes} minutes.</p>"
        );

        let email = smtp::Email::builder(to_mailbox)
            .subject("Your verification code")
            .body(body)
            .build();

        smtp::AsyncSmtpClient::send_email(&client, email)
            .await
            .map_err(|e| AuthError::ServerStateError(format!("Failed to send email: {e}")))?;

        Ok(())
    }
}

fn user_entity_to_auth_user(entity: UserEntity) -> AuthUser {
    AuthUser {
        id: entity.id.to_hex(),
        sub: entity.sub,
        email: entity.email,
        display_name: entity.name,
        tos_acceptance: None,
    }
}
