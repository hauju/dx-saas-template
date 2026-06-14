//! Authorization endpoint, consent screen, and consent decision.
//!
//! Flow: `GET /oauth/authorize` validates the request and stashes it in the
//! session. If the user isn't logged in we bounce through `/login` and re-enter
//! at `GET /oauth/authorize/resume`. The consent screen `POST`s to
//! `/oauth/authorize/decision`, which (after CSRF checks) mints a short-lived
//! authorization code and redirects back to the client.

use axum::Form;
use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;

use super::store::{self, OAuthClientEntity};
use crate::server::state::AppState;

const PENDING_KEY: &str = "oauth_pending";
const CSRF_KEY: &str = "oauth_csrf";
const CODE_TTL_SECONDS: i64 = 60;

/// The validated authorize request, stashed in the session between the initial
/// request and the consent decision (so the consent form never carries
/// security-critical values).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingAuthorize {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    state: Option<String>,
    scope: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
    scope: Option<String>,
}

/// `GET /oauth/authorize`
pub async fn authorize(
    state: AppState,
    session: Session,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    let (Some(client_id), Some(redirect_uri)) = (q.client_id.clone(), q.redirect_uri.clone())
    else {
        return error_page("Missing client_id or redirect_uri.");
    };

    // Validate the client + redirect_uri BEFORE trusting them as a redirect
    // target — otherwise we'd be an open redirector for errors.
    let client = match store::find_client(&state.db, &client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return error_page("Unknown client_id."),
        Err(_) => return error_page("Internal error."),
    };
    if !client.redirect_uris.iter().any(|u| u == &redirect_uri) {
        return error_page("redirect_uri is not registered for this client.");
    }

    // From here, parameter errors can be safely redirected to the client.
    if q.response_type.as_deref() != Some("code") {
        return redirect_error(
            &redirect_uri,
            "unsupported_response_type",
            q.state.as_deref(),
        );
    }
    if q.code_challenge_method.as_deref() != Some("S256") {
        return redirect_error(&redirect_uri, "invalid_request", q.state.as_deref());
    }
    let Some(code_challenge) = q.code_challenge.filter(|c| !c.is_empty()) else {
        return redirect_error(&redirect_uri, "invalid_request", q.state.as_deref());
    };

    let pending = PendingAuthorize {
        client_id,
        redirect_uri,
        code_challenge,
        state: q.state,
        scope: q.scope.unwrap_or_else(|| "mcp".to_string()),
    };
    if session.insert(PENDING_KEY, &pending).await.is_err() {
        return error_page("Could not start authorization.");
    }

    render_consent_or_login(&session, &client).await
}

/// `GET /oauth/authorize/resume` — re-entry point after the login redirect.
pub async fn resume(state: AppState, session: Session) -> Response {
    let pending: Option<PendingAuthorize> = session.get(PENDING_KEY).await.ok().flatten();
    let Some(pending) = pending else {
        return error_page(
            "No pending authorization. Please restart the connection from your client.",
        );
    };
    let client = match store::find_client(&state.db, &pending.client_id).await {
        Ok(Some(c)) => c,
        _ => return error_page("Unknown client_id."),
    };
    render_consent_or_login(&session, &client).await
}

#[derive(Debug, Deserialize)]
pub struct DecisionForm {
    csrf_token: String,
    decision: String,
}

/// `POST /oauth/authorize/decision`
pub async fn decision(
    state: AppState,
    session: Session,
    headers: HeaderMap,
    Form(form): Form<DecisionForm>,
) -> Response {
    // CSRF: same-origin POST + one-shot session token.
    if !origin_ok(&headers, &state.config.base_url) {
        return (StatusCode::FORBIDDEN, "Bad origin").into_response();
    }
    let stored_csrf: Option<String> = session.get(CSRF_KEY).await.ok().flatten();
    let _ = session.remove::<String>(CSRF_KEY).await;
    if stored_csrf.as_deref() != Some(form.csrf_token.as_str()) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }

    let pending: Option<PendingAuthorize> = session.get(PENDING_KEY).await.ok().flatten();
    let _ = session.remove::<PendingAuthorize>(PENDING_KEY).await;
    let Some(pending) = pending else {
        return error_page("No pending authorization.");
    };

    let logged_in = current_user(&session).await;
    let Some(user) = logged_in else {
        return Redirect::to("/login?redirect_url=/oauth/authorize/resume").into_response();
    };

    if form.decision != "approve" {
        return redirect_error(
            &pending.redirect_uri,
            "access_denied",
            pending.state.as_deref(),
        );
    }

    let user_id = match bson::oid::ObjectId::parse_str(&user.id) {
        Ok(id) => id,
        Err(_) => return error_page("Invalid session."),
    };
    let code = match crypto::generate_invitation_token() {
        Ok(c) => c,
        Err(_) => return error_page("Internal error."),
    };
    let entity = store::OAuthCodeEntity {
        id: bson::oid::ObjectId::new(),
        code: code.clone(),
        client_id: pending.client_id,
        redirect_uri: pending.redirect_uri.clone(),
        code_challenge: pending.code_challenge,
        user_id,
        scope: pending.scope,
        expires_at: chrono::Utc::now() + chrono::Duration::seconds(CODE_TTL_SECONDS),
    };
    if store::insert_code(&state.db, &entity).await.is_err() {
        return error_page("Could not issue authorization code.");
    }

    redirect_success(&pending.redirect_uri, &code, pending.state.as_deref())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn current_user(session: &Session) -> Option<auth::LoggedInData> {
    session
        .get(auth::session::LOGGED_IN_USER_SESSION_KEY)
        .await
        .ok()
        .flatten()
}

async fn render_consent_or_login(session: &Session, client: &OAuthClientEntity) -> Response {
    match current_user(session).await {
        Some(user) => {
            let csrf = crypto::generate_csrf_token().unwrap_or_default();
            if session.insert(CSRF_KEY, &csrf).await.is_err() {
                return error_page("Could not render consent.");
            }
            consent_page(client, &user.email, &csrf)
        }
        None => Redirect::to("/login?redirect_url=/oauth/authorize/resume").into_response(),
    }
}

fn origin_ok(headers: &HeaderMap, base_url: &str) -> bool {
    let Some(value) = headers
        .get(header::ORIGIN)
        .or_else(|| headers.get(header::REFERER))
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    match (url::Url::parse(value), url::Url::parse(base_url)) {
        (Ok(o), Ok(b)) => {
            o.scheme() == b.scheme()
                && o.host() == b.host()
                && o.port_or_known_default() == b.port_or_known_default()
        }
        _ => false,
    }
}

fn redirect_with_params(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    match url::Url::parse(redirect_uri) {
        Ok(mut url) => {
            url.query_pairs_mut().extend_pairs(params.iter().copied());
            Redirect::to(url.as_str()).into_response()
        }
        Err(_) => error_page("Invalid redirect_uri."),
    }
}

fn redirect_success(redirect_uri: &str, code: &str, state: Option<&str>) -> Response {
    let mut params = vec![("code", code)];
    if let Some(s) = state {
        params.push(("state", s));
    }
    redirect_with_params(redirect_uri, &params)
}

fn redirect_error(redirect_uri: &str, error: &str, state: Option<&str>) -> Response {
    let mut params = vec![("error", error)];
    if let Some(s) = state {
        params.push(("state", s));
    }
    redirect_with_params(redirect_uri, &params)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn error_page(message: &str) -> Response {
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Authorization error</title></head>\
         <body style=\"font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem\">\
         <h1>Authorization error</h1><p>{}</p></body></html>",
        html_escape(message)
    );
    (StatusCode::BAD_REQUEST, Html(body)).into_response()
}

fn consent_page(client: &OAuthClientEntity, email: &str, csrf: &str) -> Response {
    let app_name = client
        .client_name
        .clone()
        .unwrap_or_else(|| client.client_id.clone());
    let body = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize {app}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 26rem; margin: 4rem auto; padding: 0 1rem; line-height: 1.5; }}
  .card {{ border: 1px solid #8883; border-radius: 14px; padding: 1.75rem; }}
  h1 {{ font-size: 1.25rem; margin: 0 0 .25rem; }}
  .muted {{ opacity: .7; font-size: .9rem; }}
  .scope {{ background: #8881; border-radius: 8px; padding: .75rem 1rem; margin: 1.25rem 0; font-size: .9rem; }}
  .row {{ display: flex; gap: .75rem; margin-top: 1.5rem; }}
  button {{ flex: 1; padding: .7rem 1rem; border-radius: 9px; border: 0; font-size: 1rem; cursor: pointer; }}
  .approve {{ background: #4f46e5; color: #fff; }}
  .deny {{ background: #8882; color: inherit; }}
</style>
</head>
<body>
  <div class="card">
    <h1>Authorize {app}</h1>
    <p class="muted">Signed in as {email}</p>
    <div class="scope">
      <strong>{app}</strong> is requesting access to your account via the Model Context Protocol.
    </div>
    <form method="post" action="/oauth/authorize/decision">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="row">
        <button class="deny" type="submit" name="decision" value="deny">Deny</button>
        <button class="approve" type="submit" name="decision" value="approve">Approve</button>
      </div>
    </form>
  </div>
</body>
</html>"#,
        app = html_escape(&app_name),
        email = html_escape(email),
        csrf = html_escape(csrf),
    );

    // Clickjacking defense in addition to the global headers.
    (
        [
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::CONTENT_SECURITY_POLICY, "frame-ancestors 'none'"),
        ],
        Html(body),
    )
        .into_response()
}
