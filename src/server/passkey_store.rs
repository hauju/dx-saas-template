//! `AuthPasskeyStore` for `AUTH_MODE=local`: WebAuthn credentials in
//! `user_passkeys`, keyed by the authenticator's credential id.

use sqlx::types::Json;
use uuid::Uuid;

use auth::{AuthError, AuthPasskeyStore, AuthResult, NewPasskey, StoredPasskey};

use crate::server::state::AppState;

pub struct AppAuthPasskeyStore {
    state: AppState,
}

impl AppAuthPasskeyStore {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

struct PasskeyRow {
    id: Uuid,
    user_id: Uuid,
    credential_id: String,
    public_key: Vec<u8>,
    sign_count: i64,
    transports: Json<Vec<String>>,
    name: String,
}

impl From<PasskeyRow> for StoredPasskey {
    fn from(r: PasskeyRow) -> Self {
        StoredPasskey {
            id: r.id.to_string(),
            user_id: r.user_id.to_string(),
            credential_id: r.credential_id,
            public_key_cose: r.public_key,
            sign_count: r.sign_count,
            transports: r.transports.0,
            name: r.name,
        }
    }
}

fn db_err(e: sqlx::Error) -> AuthError {
    AuthError::ServerStateError(format!("DB error: {e}"))
}

#[async_trait::async_trait]
impl AuthPasskeyStore for AppAuthPasskeyStore {
    async fn list_passkeys(&self, user_id: &str) -> AuthResult<Vec<StoredPasskey>> {
        let Ok(uid) = Uuid::parse_str(user_id) else {
            return Ok(Vec::new());
        };
        let rows = sqlx::query_as!(
            PasskeyRow,
            r#"SELECT id, user_id, credential_id, public_key, sign_count,
                      transports as "transports: Json<Vec<String>>", name
               FROM user_passkeys WHERE user_id = $1 ORDER BY created_at"#,
            uid
        )
        .fetch_all(&self.state.db.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<StoredPasskey>> {
        let row = sqlx::query_as!(
            PasskeyRow,
            r#"SELECT id, user_id, credential_id, public_key, sign_count,
                      transports as "transports: Json<Vec<String>>", name
               FROM user_passkeys WHERE credential_id = $1"#,
            credential_id
        )
        .fetch_optional(&self.state.db.pool)
        .await
        .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn insert_passkey(&self, user_id: &str, passkey: NewPasskey) -> AuthResult<()> {
        let uid = Uuid::parse_str(user_id)
            .map_err(|e| AuthError::ServerStateError(format!("Invalid user ID: {e}")))?;
        sqlx::query!(
            "INSERT INTO user_passkeys
                 (user_id, credential_id, public_key, sign_count, transports, name, backed_up)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            uid,
            passkey.credential_id,
            passkey.public_key_cose,
            passkey.sign_count,
            Json(passkey.transports) as _,
            passkey.name,
            passkey.backed_up,
        )
        .execute(&self.state.db.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn touch_passkey(
        &self,
        credential_id: &str,
        sign_count: i64,
        backed_up: bool,
    ) -> AuthResult<()> {
        sqlx::query!(
            "UPDATE user_passkeys SET sign_count = $1, backed_up = $2, last_used_at = NOW()
             WHERE credential_id = $3",
            sign_count,
            backed_up,
            credential_id
        )
        .execute(&self.state.db.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn delete_passkey(&self, user_id: &str, passkey_id: &str) -> AuthResult<bool> {
        let (Ok(uid), Ok(pid)) = (Uuid::parse_str(user_id), Uuid::parse_str(passkey_id)) else {
            return Ok(false);
        };
        let res = sqlx::query!(
            "DELETE FROM user_passkeys WHERE id = $1 AND user_id = $2",
            pid,
            uid
        )
        .execute(&self.state.db.pool)
        .await
        .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::db::Database;
    use crate::server::test_support::{seed_user, test_state};
    use sqlx::PgPool;

    fn new_passkey(credential_id: &str) -> NewPasskey {
        NewPasskey {
            credential_id: credential_id.to_string(),
            public_key_cose: vec![1, 2, 3],
            sign_count: 0,
            transports: vec!["internal".to_string()],
            name: "Laptop".to_string(),
            backed_up: false,
        }
    }

    #[sqlx::test]
    async fn passkeys_round_trip_and_stay_scoped_to_their_owner(pool: PgPool) {
        let db = Database::from_pool(pool);
        let owner = seed_user(&db, "owner").await.to_string();
        let other = seed_user(&db, "other").await.to_string();
        let store = AppAuthPasskeyStore::new(test_state(db));

        store
            .insert_passkey(&owner, new_passkey("cred-1"))
            .await
            .unwrap();

        // The login path looks a credential up by id alone, before any email.
        let found = store
            .find_passkey_by_credential_id("cred-1")
            .await
            .unwrap()
            .expect("stored");
        assert_eq!(found.user_id, owner);
        assert_eq!(found.transports, vec!["internal".to_string()]);
        assert_eq!(found.public_key_cose, vec![1, 2, 3]);

        // A successful assertion advances the counter the no-regress check reads.
        store.touch_passkey("cred-1", 7, true).await.unwrap();
        let listed = store.list_passkeys(&owner).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].sign_count, 7);

        // Deleting is scoped by owner: another user cannot remove it by id.
        assert!(!store.delete_passkey(&other, &found.id).await.unwrap());
        assert!(store.delete_passkey(&owner, &found.id).await.unwrap());
        assert!(store.list_passkeys(&owner).await.unwrap().is_empty());
    }
}
