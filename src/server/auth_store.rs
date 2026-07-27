use uuid::Uuid;

use crate::models::user::UserEntity;
use crate::server::state::AppState;
use crate::server::user;
use auth::types::{AuthTosAcceptance, AuthUser, NewAuthUser};
use auth::{AuthEmailSender, AuthError, AuthResult, AuthUserStore};

/// Implements `AuthUserStore` by reading/writing to PostgreSQL.
pub struct AppAuthUserStore {
    state: AppState,
}

impl AppAuthUserStore {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    /// Re-read the user that won a concurrent-creation race.
    ///
    /// Matches the lookup order in `lookup_or_create_user`: by `sub` first, then
    /// by `email` (the IdP-migration case, where the winner may hold a different
    /// subject for the same address).
    async fn adopt_existing(&self, user: &NewAuthUser) -> AuthResult<AuthUser> {
        let db_err = |e| AuthError::ServerStateError(format!("DB error: {e}"));

        if let Some(existing) = user::find_by_sub(&self.state.db, &user.sub)
            .await
            .map_err(db_err)?
        {
            return Ok(user_entity_to_auth_user(existing));
        }

        if let Some(existing) = user::find_by_email(&self.state.db, &user.email)
            .await
            .map_err(db_err)?
        {
            return Ok(user_entity_to_auth_user(existing));
        }

        // The insert was rejected for a uniqueness reason we can't attribute —
        // don't paper over it.
        Err(AuthError::ServerStateError(
            "user creation conflicted but no matching user was found".to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl AuthUserStore for AppAuthUserStore {
    async fn get_user_by_sub(&self, sub: &str) -> AuthResult<Option<AuthUser>> {
        let user = user::find_by_sub(&self.state.db, sub)
            .await
            .map_err(|e| AuthError::ServerStateError(format!("DB error: {e}")))?;

        Ok(user.map(user_entity_to_auth_user))
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> {
        let user = user::find_by_email(&self.state.db, email)
            .await
            .map_err(|e| AuthError::ServerStateError(format!("DB error: {e}")))?;

        Ok(user.map(user_entity_to_auth_user))
    }

    async fn create_user(&self, user: NewAuthUser) -> AuthResult<AuthUser> {
        let id = Uuid::new_v4();

        // created_at / updated_at come from the column defaults, so the database
        // clock stays authoritative (see server::user for the same reasoning).
        let row = sqlx::query!(
            r#"INSERT INTO users (id, sub, email) VALUES ($1, $2, $3)
               RETURNING created_at as "created_at: chrono::DateTime<chrono::Utc>",
                         updated_at as "updated_at: chrono::DateTime<chrono::Utc>""#,
            id,
            user.sub,
            user.email,
        )
        .fetch_one(&self.state.db.pool)
        .await;

        let row = match row {
            Ok(row) => row,
            // `lookup_or_create_user` checks for an existing user before calling
            // us, but two concurrent first-time logins for the same account can
            // both pass that check and both insert. The unique constraints on
            // `sub` and `email` mean exactly one wins. The loser's user does now
            // exist, so adopt it rather than failing an otherwise valid login.
            Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
                tracing::info!("concurrent user creation lost the race; adopting existing row");
                return self.adopt_existing(&user).await;
            }
            Err(e) => {
                return Err(AuthError::ServerStateError(format!("DB insert error: {e}")));
            }
        };

        let entity = UserEntity {
            id,
            sub: user.sub,
            email: user.email,
            name: None,
            avatar_url: None,
            subscription: None,
            created_at: row.created_at,
            updated_at: row.updated_at,
        };

        Ok(user_entity_to_auth_user(entity))
    }

    async fn update_user_sub(&self, user_id: &str, new_sub: &str) -> AuthResult<()> {
        let id = Uuid::parse_str(user_id)
            .map_err(|e| AuthError::ServerStateError(format!("Invalid user ID: {e}")))?;

        sqlx::query!(
            "UPDATE users SET sub = $1, updated_at = NOW() WHERE id = $2",
            new_sub,
            id
        )
        .execute(&self.state.db.pool)
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
        id: entity.id.to_string(),
        sub: entity.sub,
        email: entity.email,
        display_name: entity.name,
        tos_acceptance: None,
    }
}

