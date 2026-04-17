//! Zitadel gRPC + REST client functions.

use crate::error::{AuthError, AuthResult};
use crate::zitadel::types::*;
use tracing::info;

use zitadel::api::clients::ClientBuilder;
use zitadel::api::interceptors::AccessTokenInterceptor;
use zitadel::api::zitadel::object::v2 as object_v2;
use zitadel::api::zitadel::session::v2 as session_v2;
use zitadel::api::zitadel::user::v2 as user_v2;

type GrpcService = tonic::service::interceptor::InterceptedService<
    tonic::transport::Channel,
    AccessTokenInterceptor,
>;

// ── Helpers ──────────────────────────────────────────────────────────

/// Returns "http" for localhost/127.0.0.1, "https" otherwise.
pub fn zitadel_protocol(domain: &str) -> &'static str {
    if domain.starts_with("localhost") || domain.starts_with("127.0.0.1") {
        "http"
    } else {
        "https"
    }
}

fn base_url(domain: &str) -> String {
    format!("{}://{}", zitadel_protocol(domain), domain)
}

/// Convert a protobuf `Struct` to `serde_json::Value`.
fn struct_to_json(s: &pbjson_types::Struct) -> serde_json::Value {
    serde_json::to_value(s).unwrap_or(serde_json::Value::Null)
}

/// Convert `serde_json::Value` to a protobuf `Struct`.
fn json_to_struct(v: &serde_json::Value) -> Option<pbjson_types::Struct> {
    serde_json::from_value(v.clone()).ok()
}

/// Convert gRPC `Challenges` (response) into our adapter type.
fn convert_challenges(c: session_v2::Challenges) -> SessionChallengesResponse {
    SessionChallengesResponse {
        web_auth_n: c.web_auth_n.and_then(|w| {
            w.public_key_credential_request_options
                .as_ref()
                .map(|opts| WebAuthNChallengeResponse {
                    public_key_credential_request_options: struct_to_json(opts),
                })
        }),
        otp_email: c.otp_email,
    }
}

/// Build a session gRPC client with a personal access token.
async fn session_client(
    domain: &str,
    token: &str,
) -> AuthResult<session_v2::session_service_client::SessionServiceClient<GrpcService>> {
    ClientBuilder::new(&base_url(domain))
        .with_access_token(token)
        .build_session_client()
        .await
        .map_err(|e| {
            AuthError::ServerStateError(format!("Failed to build session gRPC client: {e}"))
        })
}

/// Build a user gRPC client with a personal access token.
async fn user_client(
    domain: &str,
    token: &str,
) -> AuthResult<user_v2::user_service_client::UserServiceClient<GrpcService>> {
    ClientBuilder::new(&base_url(domain))
        .with_access_token(token)
        .build_user_client()
        .await
        .map_err(|e| AuthError::ServerStateError(format!("Failed to build user gRPC client: {e}")))
}

// ── Session API functions ────────────────────────────────────────────

/// Create a Zitadel session with a user check and passkey (WebAuthN) challenge.
pub async fn create_session_with_passkey_challenge(
    domain: &str,
    token: &str,
    login_name: &str,
    rp_domain: &str,
    user_id: Option<&str>,
) -> AuthResult<CreateSessionResponse> {
    info!(
        "Creating Zitadel session with passkey challenge for '{}' (user_id={:?})",
        login_name, user_id
    );

    let user_check = if let Some(uid) = user_id {
        session_v2::CheckUser {
            search: Some(session_v2::check_user::Search::UserId(uid.to_string())),
        }
    } else {
        session_v2::CheckUser {
            search: Some(session_v2::check_user::Search::LoginName(
                login_name.to_string(),
            )),
        }
    };

    let req = session_v2::CreateSessionRequest {
        checks: Some(session_v2::Checks {
            user: Some(user_check),
            web_auth_n: None,
            password: None,
            idp_intent: None,
            totp: None,
            otp_sms: None,
            otp_email: None,
        }),
        challenges: Some(session_v2::RequestChallenges {
            web_auth_n: Some(session_v2::request_challenges::WebAuthN {
                domain: rp_domain.to_string(),
                user_verification_requirement: session_v2::UserVerificationRequirement::Required
                    .into(),
            }),
            otp_sms: None,
            otp_email: None,
        }),
        ..Default::default()
    };

    let mut client = session_client(domain, token).await?;
    let resp = client.create_session(req).await?.into_inner();

    Ok(CreateSessionResponse {
        session_id: resp.session_id,
        session_token: resp.session_token,
        challenges: resp.challenges.map(convert_challenges),
    })
}

/// Create a Zitadel session with user check only (no challenges).
pub async fn create_session_user_check_only(
    domain: &str,
    token: &str,
    user_id: &str,
) -> AuthResult<CreateSessionResponse> {
    info!(
        "Creating Zitadel session with user check only for user_id={}",
        user_id
    );

    let req = session_v2::CreateSessionRequest {
        checks: Some(session_v2::Checks {
            user: Some(session_v2::CheckUser {
                search: Some(session_v2::check_user::Search::UserId(user_id.to_string())),
            }),
            web_auth_n: None,
            password: None,
            idp_intent: None,
            totp: None,
            otp_sms: None,
            otp_email: None,
        }),
        challenges: None,
        ..Default::default()
    };

    let mut client = session_client(domain, token).await?;
    let resp = client.create_session(req).await?.into_inner();

    Ok(CreateSessionResponse {
        session_id: resp.session_id,
        session_token: resp.session_token,
        challenges: resp.challenges.map(convert_challenges),
    })
}

/// Verify a passkey (WebAuthN) assertion against a Zitadel session.
pub async fn verify_passkey(
    domain: &str,
    token: &str,
    session_id: &str,
    session_token: &str,
    credential_assertion_data: serde_json::Value,
) -> AuthResult<UpdateSessionResponse> {
    info!("Verifying passkey for session {}", session_id);

    let req = session_v2::SetSessionRequest {
        session_id: session_id.to_string(),
        session_token: session_token.to_string(),
        checks: Some(session_v2::Checks {
            user: None,
            password: None,
            web_auth_n: Some(session_v2::CheckWebAuthN {
                credential_assertion_data: json_to_struct(&credential_assertion_data),
            }),
            idp_intent: None,
            totp: None,
            otp_sms: None,
            otp_email: None,
        }),
        ..Default::default()
    };

    let mut client = session_client(domain, token).await?;
    let resp = client.set_session(req).await?.into_inner();

    Ok(UpdateSessionResponse {
        session_token: resp.session_token,
        challenges: resp.challenges.map(convert_challenges),
    })
}

/// Get session details from Zitadel.
pub async fn get_session(
    domain: &str,
    token: &str,
    session_id: &str,
) -> AuthResult<GetSessionResponse> {
    let mut client = session_client(domain, token).await?;
    let resp = client
        .get_session(session_v2::GetSessionRequest {
            session_id: session_id.to_string(),
            session_token: None,
        })
        .await?
        .into_inner();

    let session = resp.session.ok_or_else(|| {
        AuthError::ServerStateError(format!("Zitadel returned no session for id {session_id}"))
    })?;

    let factors = session.factors.map(|f| {
        let user = f.user.map(|u| SessionUserFactor {
            id: if u.id.is_empty() { None } else { Some(u.id) },
            login_name: if u.login_name.is_empty() {
                None
            } else {
                Some(u.login_name)
            },
            display_name: if u.display_name.is_empty() {
                None
            } else {
                Some(u.display_name)
            },
        });
        SessionFactors { user }
    });

    Ok(GetSessionResponse {
        session: SessionInfo {
            id: session.id,
            factors,
        },
    })
}

// ── User API functions ───────────────────────────────────────────────

/// Find a user by login name (email) in Zitadel.
pub async fn find_user_by_login_name(
    domain: &str,
    token: &str,
    login_name: &str,
    org_id: Option<&str>,
) -> AuthResult<Option<ZitadelUser>> {
    let mut queries = vec![user_v2::SearchQuery {
        query: Some(user_v2::search_query::Query::LoginNameQuery(
            user_v2::LoginNameQuery {
                login_name: login_name.to_string(),
                method: object_v2::TextQueryMethod::Equals.into(),
            },
        )),
    }];
    if let Some(oid) = org_id {
        queries.push(user_v2::SearchQuery {
            query: Some(user_v2::search_query::Query::OrganizationIdQuery(
                user_v2::OrganizationIdQuery {
                    organization_id: oid.to_string(),
                },
            )),
        });
    }

    let req = user_v2::ListUsersRequest {
        queries,
        ..Default::default()
    };

    let mut client = user_client(domain, token).await?;
    let resp = client.list_users(req).await?.into_inner();

    Ok(resp.result.into_iter().next().map(convert_user))
}

/// Find a user by email address in Zitadel.
pub async fn find_user_by_email(
    domain: &str,
    token: &str,
    email: &str,
    org_id: Option<&str>,
) -> AuthResult<Option<ZitadelUser>> {
    let mut queries = vec![user_v2::SearchQuery {
        query: Some(user_v2::search_query::Query::EmailQuery(
            user_v2::EmailQuery {
                email_address: email.to_string(),
                method: object_v2::TextQueryMethod::Equals.into(),
            },
        )),
    }];
    if let Some(oid) = org_id {
        queries.push(user_v2::SearchQuery {
            query: Some(user_v2::search_query::Query::OrganizationIdQuery(
                user_v2::OrganizationIdQuery {
                    organization_id: oid.to_string(),
                },
            )),
        });
    }

    let req = user_v2::ListUsersRequest {
        queries,
        ..Default::default()
    };

    let mut client = user_client(domain, token).await?;
    let resp = client.list_users(req).await?.into_inner();

    Ok(resp.result.into_iter().next().map(convert_user))
}

/// Convert a protobuf `User` into our adapter `ZitadelUser`.
fn convert_user(u: user_v2::User) -> ZitadelUser {
    let human = u.r#type.and_then(|t| match t {
        user_v2::user::Type::Human(h) => Some(ZitadelHumanUser {
            profile: h.profile.map(|p| ZitadelProfile {
                given_name: if p.given_name.is_empty() {
                    None
                } else {
                    Some(p.given_name)
                },
                family_name: if p.family_name.is_empty() {
                    None
                } else {
                    Some(p.family_name)
                },
                display_name: p.display_name,
            }),
            email: h.email.map(|e| ZitadelEmail {
                email: if e.email.is_empty() {
                    None
                } else {
                    Some(e.email)
                },
                is_verified: Some(e.is_verified),
            }),
        }),
        user_v2::user::Type::Machine(_) => None,
    });

    ZitadelUser {
        user_id: u.user_id,
        username: if u.username.is_empty() {
            None
        } else {
            Some(u.username)
        },
        human,
    }
}

/// Create a new human user in Zitadel (for registration flow).
pub async fn create_human_user(
    domain: &str,
    token: &str,
    email: &str,
    org_id: Option<&str>,
) -> AuthResult<CreateHumanUserResponse> {
    info!("Creating Zitadel user for '{}'", email);

    let local_part = email.split('@').next().unwrap_or("User");

    let organization = org_id.map(|oid| object_v2::Organization {
        org: Some(object_v2::organization::Org::OrgId(oid.to_string())),
    });

    let req = user_v2::AddHumanUserRequest {
        username: Some(email.to_string()),
        organization,
        profile: Some(user_v2::SetHumanProfile {
            given_name: local_part.to_string(),
            family_name: "-".to_string(),
            ..Default::default()
        }),
        email: Some(user_v2::SetHumanEmail {
            email: email.to_string(),
            verification: Some(user_v2::set_human_email::Verification::IsVerified(false)),
        }),
        ..Default::default()
    };

    let mut client = user_client(domain, token).await?;
    match client.add_human_user(req).await {
        Ok(resp) => {
            let inner = resp.into_inner();
            Ok(CreateHumanUserResponse {
                user_id: inner.user_id,
            })
        }
        Err(status) if status.code() == tonic::Code::AlreadyExists => {
            info!(
                "Zitadel user '{}' already exists (ALREADY_EXISTS), proceeding",
                email
            );
            Ok(CreateHumanUserResponse {
                user_id: String::new(),
            })
        }
        Err(status) => Err(status.into()),
    }
}

/// Mark a Zitadel user's email as verified (called after OTP verification).
pub async fn set_user_email_verified(
    domain: &str,
    token: &str,
    user_id: &str,
    email: &str,
) -> AuthResult<()> {
    info!("Marking email as verified for Zitadel user {}", user_id);

    let req = user_v2::UpdateHumanUserRequest {
        user_id: user_id.to_string(),
        email: Some(user_v2::SetHumanEmail {
            email: email.to_string(),
            verification: Some(user_v2::set_human_email::Verification::IsVerified(true)),
        }),
        ..Default::default()
    };

    let mut client = user_client(domain, token).await?;
    client.update_human_user(req).await?;

    info!("Email marked as verified for user {}", user_id);
    Ok(())
}

/// Update a human user's profile (display name) in Zitadel.
pub async fn update_human_user_profile(
    domain: &str,
    token: &str,
    user_id: &str,
    display_name: &str,
) -> AuthResult<()> {
    info!("Updating profile for Zitadel user {}", user_id);

    let req = user_v2::UpdateHumanUserRequest {
        user_id: user_id.to_string(),
        profile: Some(user_v2::SetHumanProfile {
            given_name: display_name.to_string(),
            family_name: "-".to_string(),
            display_name: Some(display_name.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut client = user_client(domain, token).await?;
    client.update_human_user(req).await?;

    info!("Profile updated for user {}", user_id);
    Ok(())
}

/// Start passkey (WebAuthn) registration for a Zitadel user.
pub async fn start_passkey_registration(
    domain: &str,
    token: &str,
    user_id: &str,
    rp_domain: &str,
) -> AuthResult<PasskeyRegistrationResponse> {
    info!(
        "Starting passkey registration for Zitadel user {} (rp={})",
        user_id, rp_domain
    );

    let req = user_v2::RegisterPasskeyRequest {
        user_id: user_id.to_string(),
        code: None,
        authenticator: user_v2::PasskeyAuthenticator::Unspecified.into(),
        domain: rp_domain.to_string(),
    };

    let mut client = user_client(domain, token).await?;
    let resp = client.register_passkey(req).await?.into_inner();

    let creation_options = resp
        .public_key_credential_creation_options
        .as_ref()
        .map(struct_to_json)
        .unwrap_or(serde_json::Value::Null);

    if let Some(rp_id) = creation_options
        .pointer("/publicKey/rp/id")
        .or_else(|| creation_options.pointer("/rp/id"))
    {
        info!("Passkey registration response rp.id={:?}", rp_id);
    }

    Ok(PasskeyRegistrationResponse {
        passkey_id: resp.passkey_id,
        public_key_credential_creation_options: creation_options,
    })
}

/// List passkeys for a Zitadel user. Only returns passkeys in "Ready" state.
pub async fn list_passkeys(
    domain: &str,
    token: &str,
    user_id: &str,
) -> AuthResult<Vec<PasskeyInfo>> {
    info!("Listing passkeys for Zitadel user {}", user_id);

    let req = user_v2::ListPasskeysRequest {
        user_id: user_id.to_string(),
    };

    let mut client = user_client(domain, token).await?;
    let resp = client.list_passkeys(req).await?.into_inner();

    let passkeys = resp
        .result
        .into_iter()
        .filter(|p| p.state == user_v2::AuthFactorState::Ready as i32)
        .map(|p| PasskeyInfo {
            id: p.id,
            name: p.name,
        })
        .collect();

    Ok(passkeys)
}

/// Remove a passkey from a Zitadel user.
pub async fn remove_passkey(
    domain: &str,
    token: &str,
    user_id: &str,
    passkey_id: &str,
) -> AuthResult<()> {
    info!(
        "Removing passkey {} for Zitadel user {}",
        passkey_id, user_id
    );

    let req = user_v2::RemovePasskeyRequest {
        user_id: user_id.to_string(),
        passkey_id: passkey_id.to_string(),
    };

    let mut client = user_client(domain, token).await?;
    client.remove_passkey(req).await?;

    info!("Passkey {} removed for user {}", passkey_id, user_id);
    Ok(())
}

/// Verify a passkey (WebAuthn) registration by submitting the browser's credential response.
pub async fn verify_passkey_registration(
    domain: &str,
    token: &str,
    user_id: &str,
    passkey_id: &str,
    credential: serde_json::Value,
    name: &str,
) -> AuthResult<()> {
    info!(
        "Verifying passkey registration for user {} passkey {}",
        user_id, passkey_id
    );

    let req = user_v2::VerifyPasskeyRegistrationRequest {
        user_id: user_id.to_string(),
        passkey_id: passkey_id.to_string(),
        public_key_credential: json_to_struct(&credential),
        passkey_name: name.to_string(),
    };

    let mut client = user_client(domain, token).await?;
    client.verify_passkey_registration(req).await?;

    info!(
        "Passkey registration verified for user {} passkey {}",
        user_id, passkey_id
    );
    Ok(())
}
