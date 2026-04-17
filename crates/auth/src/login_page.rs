use crate::types::UserDataRefreshTrigger;
use dioxus::prelude::*;

/// Fire an Umami analytics event (no-op if Umami isn't loaded).
fn track(event: &str) {
    document::eval(&format!(
        r#"if (window.umami) {{ window.umami.track("{event}"); }}"#,
    ));
}

/// Multi-step login page: OTP-first with auto-passkey detection.
///
/// Flow: Email → Detecting → (PasskeyChallenge | OtpCodeInput) → Verifying → TOS? → Success
#[component]
pub fn LoginPage(
    redirect_url: String,
    #[props(default)] on_success: EventHandler<String>,
    /// When true, renders only the form content without the full-page wrapper,
    /// card, and built-in header. Use this to embed the login form into a
    /// custom-styled container.
    #[props(default = false)]
    embed: bool,
) -> Element {
    // Check if we arrived needing TOS acceptance
    let initial_step = if redirect_url.contains("accept_tos=true") {
        LoginStep::TosAcceptance
    } else {
        LoginStep::EmailInput
    };

    // Login state machine
    let mut step = use_signal(move || initial_step.clone());
    let mut email = use_signal(String::new);
    let mut otp_code = use_signal(String::new);
    let mut error_msg = use_signal(|| None::<String>);
    let mut success_msg = use_signal(|| None::<String>);
    let mut is_loading = use_signal(|| false);
    let is_new_user = use_signal(|| false);
    let mut tos_accepted = use_signal(|| false);

    // Store passkey options for the WebAuthn browser API
    let passkey_options = use_signal(|| None::<String>);

    // Trigger for App to re-fetch user data after login (avoids full page reload)
    let mut user_refresh: Signal<UserDataRefreshTrigger> = use_context();

    // Analytics: track login page view on mount
    use_effect(|| {
        track("login_started");
    });

    // Fire on_success callback immediately when step transitions to Success.
    // This lets the parent component navigate without waiting for the
    // resource chain (trigger → server fetch → auth state update → effect).
    use_effect(move || {
        if let LoginStep::Success { redirect_url } = step() {
            on_success.call(redirect_url);
        }
    });

    // ── Handlers ────────────────────────────────────────────────────

    // Submit email → go to Detecting step, POST to /auth/session/start
    let redirect_url_clone = redirect_url.clone();
    let on_email_submit = move |_| {
        let email_val = email().trim().to_lowercase();
        if email_val.is_empty() || !email_val.contains('@') {
            error_msg.set(Some("Please enter a valid email address.".to_string()));
            success_msg.set(None);
            return;
        }
        error_msg.set(None);
        success_msg.set(None);
        track("login_email_submitted");
        step.set(LoginStep::Detecting);

        #[cfg(feature = "web")]
        start_session_flow(
            email_val,
            redirect_url_clone.clone(),
            step,
            error_msg,
            is_new_user,
            is_loading,
            passkey_options,
            user_refresh,
        );
    };

    // Verify OTP code
    let on_otp_verify = move |_| {
        spawn(async move {
            let code = otp_code().trim().to_string();
            if code.is_empty() {
                error_msg.set(Some("Please enter the verification code.".to_string()));
                success_msg.set(None);
                return;
            }
            is_loading.set(true);
            error_msg.set(None);
            success_msg.set(None);
            step.set(LoginStep::Verifying);

            #[cfg(feature = "web")]
            {
                let result: std::result::Result<VerifyResp, String> = wasm_post_json(
                    "/auth/session/otp/verify",
                    Some(serde_json::json!({ "code": code })),
                )
                .await;
                match result {
                    Ok(resp) => {
                        if resp.success {
                            track("login_verified");
                            if resp.needs_tos_acceptance == Some(true) {
                                track("login_tos_shown");
                                step.set(LoginStep::TosAcceptance);
                                is_loading.set(false);
                            } else if let Some(url) = resp.redirect_url {
                                step.set(LoginStep::Success {
                                    redirect_url: url.clone(),
                                });
                                user_refresh.write().0 += 1;
                            }
                        } else {
                            let msg = resp
                                .error
                                .unwrap_or_else(|| "Verification failed".to_string());
                            error_msg.set(Some(msg));
                            step.set(LoginStep::OtpCodeInput);
                            is_loading.set(false);
                        }
                    }
                    Err(e) => {
                        error_msg.set(Some(e));
                        step.set(LoginStep::OtpCodeInput);
                        is_loading.set(false);
                    }
                }
            }

            #[cfg(not(feature = "web"))]
            {
                is_loading.set(false);
            }
        });
    };

    // Resend OTP
    let on_resend_otp = move |_| {
        spawn(async move {
            is_loading.set(true);
            error_msg.set(None);
            success_msg.set(None);

            #[cfg(feature = "web")]
            {
                let result: std::result::Result<VerifyResp, String> =
                    wasm_post_json("/auth/session/otp/resend", None).await;
                match result {
                    Ok(resp) => {
                        if resp.success {
                            success_msg
                                .set(Some("A new code has been sent to your email.".to_string()));
                        } else {
                            let msg = resp
                                .error
                                .unwrap_or_else(|| "Failed to resend code".to_string());
                            error_msg.set(Some(msg));
                        }
                    }
                    Err(e) => {
                        error_msg.set(Some(e));
                    }
                }
                is_loading.set(false);
            }

            #[cfg(not(feature = "web"))]
            {
                is_loading.set(false);
            }
        });
    };

    // "Use email code instead" — passkey fallback to OTP
    let on_use_email_code = move |_| {
        spawn(async move {
            is_loading.set(true);
            error_msg.set(None);
            success_msg.set(None);

            #[cfg(feature = "web")]
            {
                let result: std::result::Result<StartSessionResp, String> =
                    wasm_post_json("/auth/session/passkey-fallback-otp", None).await;
                match result {
                    Ok(_resp) => {
                        success_msg.set(Some("Verification code sent to your email.".to_string()));
                        otp_code.set(String::new());
                        step.set(LoginStep::OtpCodeInput);
                        is_loading.set(false);
                    }
                    Err(e) => {
                        error_msg.set(Some(e));
                        step.set(LoginStep::EmailInput);
                        is_loading.set(false);
                    }
                }
            }

            #[cfg(not(feature = "web"))]
            {
                is_loading.set(false);
            }
        });
    };

    // Accept TOS and continue to dashboard
    let on_tos_accept = move |_| {
        spawn(async move {
            is_loading.set(true);
            error_msg.set(None);

            #[cfg(feature = "web")]
            {
                let result: std::result::Result<VerifyResp, String> =
                    wasm_post_json("/auth/session/accept-tos", None).await;
                match result {
                    Ok(resp) => {
                        if resp.success {
                            track("login_tos_accepted");
                            if let Some(url) = resp.redirect_url {
                                step.set(LoginStep::Success {
                                    redirect_url: url.clone(),
                                });
                                user_refresh.write().0 += 1;
                            }
                        } else {
                            let msg = resp
                                .error
                                .unwrap_or_else(|| "Failed to accept terms".to_string());
                            error_msg.set(Some(msg));
                            is_loading.set(false);
                        }
                    }
                    Err(e) => {
                        error_msg.set(Some(e));
                        is_loading.set(false);
                    }
                }
            }

            #[cfg(not(feature = "web"))]
            {
                is_loading.set(false);
            }
        });
    };

    let on_back = move |_| {
        error_msg.set(None);
        success_msg.set(None);
        otp_code.set(String::new());
        step.set(LoginStep::EmailInput);
    };

    // ── Render ──────────────────────────────────────────────────────

    // ── Shared inner content (alerts + step forms) ──────────────────
    let inner_content = rsx! {
        // Success display
        if let Some(msg) = success_msg() {
            div { class: "alert alert-success mb-4",
                svg {
                    xmlns: "http://www.w3.org/2000/svg",
                    class: "stroke-current shrink-0 h-5 w-5",
                    fill: "none",
                    "viewBox": "0 0 24 24",
                    path {
                        "stroke-linecap": "round",
                        "stroke-linejoin": "round",
                        "stroke-width": "2",
                        d: "M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
                    }
                }
                span { "{msg}" }
            }
        }

        // Error display
        if let Some(err) = error_msg() {
            div { class: "alert alert-error mb-4",
                svg {
                    xmlns: "http://www.w3.org/2000/svg",
                    class: "stroke-current shrink-0 h-5 w-5",
                    fill: "none",
                    "viewBox": "0 0 24 24",
                    path {
                        "stroke-linecap": "round",
                        "stroke-linejoin": "round",
                        "stroke-width": "2",
                        d: "M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z",
                    }
                }
                span { "{err}" }
            }
        }

        // Step content
        match step() {
                        LoginStep::EmailInput => rsx!(
                            form {
                                onsubmit: on_email_submit,
                                class: "space-y-4",
                                fieldset {
                                    class: "fieldset",
                                    label { class: "fieldset-label", "Email address" }
                                    input {
                                        r#type: "email",
                                        class: "input input-bordered w-full",
                                        placeholder: "you@example.com",
                                        required: true,
                                        autofocus: true,
                                        value: "{email}",
                                        oninput: move |e| email.set(e.value()),
                                    }
                                }
                                button {
                                    r#type: "submit",
                                    class: "btn btn-primary w-full",
                                    disabled: is_loading(),
                                    if is_loading() {
                                        span { class: "loading loading-spinner loading-sm" }
                                    }
                                    "Continue"
                                }
                                p { class: "text-xs text-base-content/40 text-center mt-3",
                                    "No account yet? We'll create one for you."
                                }
                            }
                        ),

                        LoginStep::Detecting => rsx!(
                            div { class: "text-center space-y-4 py-4",
                                span { class: "loading loading-spinner loading-lg text-primary" }
                                p { class: "text-base-content/70", "Setting things up..." }
                            }
                        ),

                        LoginStep::PasskeyChallenge => rsx!(
                            div { class: "text-center space-y-4 py-4",
                                span { class: "loading loading-spinner loading-lg text-primary" }
                                p { class: "font-medium", "Waiting for authentication..." }
                                p { class: "text-sm text-base-content/50",
                                    "Follow the prompt from your browser or device."
                                }
                                button {
                                    class: "btn btn-ghost btn-sm mt-4",
                                    onclick: on_use_email_code,
                                    disabled: is_loading(),
                                    "Use email code instead"
                                }
                            }
                        ),

                        LoginStep::OtpCodeInput => rsx!(
                            div { class: "space-y-4",
                                div { class: "text-center",
                                    if is_new_user() {
                                        div { class: "badge badge-success badge-outline mb-2",
                                            "Account created"
                                        }
                                    }
                                    p { class: "text-sm text-base-content/70",
                                        "We sent a verification code to"
                                    }
                                    p { class: "font-medium text-sm", "{email}" }
                                }

                                form {
                                    onsubmit: on_otp_verify,
                                    class: "space-y-4",
                                    fieldset {
                                        class: "fieldset",
                                        label { class: "fieldset-label", "Verification code" }
                                        input {
                                            r#type: "text",
                                            class: "input input-bordered w-full text-center text-xl tracking-widest",
                                            placeholder: "000000",
                                            maxlength: "8",
                                            autofocus: true,
                                            autocomplete: "one-time-code",
                                            inputmode: "numeric",
                                            value: "{otp_code}",
                                            oninput: move |e| otp_code.set(e.value()),
                                        }
                                    }
                                    button {
                                        r#type: "submit",
                                        class: "btn btn-primary w-full",
                                        disabled: is_loading(),
                                        if is_loading() {
                                            span { class: "loading loading-spinner loading-sm" }
                                        }
                                        "Verify"
                                    }
                                }

                                div { class: "flex justify-between items-center text-sm",
                                    button {
                                        class: "btn btn-ghost btn-sm text-base-content/50",
                                        onclick: on_back,
                                        "Back"
                                    }
                                    button {
                                        class: "btn btn-ghost btn-sm text-primary",
                                        onclick: on_resend_otp,
                                        disabled: is_loading(),
                                        "Resend code"
                                    }
                                }
                            }
                        ),

                        LoginStep::TosAcceptance => rsx!(
                            div { class: "space-y-4",
                                div { class: "text-center",
                                    h2 { class: "text-lg font-semibold", "Almost there!" }
                                    p { class: "text-sm text-base-content/70 mt-1",
                                        "Please review and accept our terms to continue."
                                    }
                                }
                                label { class: "label cursor-pointer justify-start gap-3",
                                    input {
                                        r#type: "checkbox",
                                        class: "checkbox checkbox-primary",
                                        checked: tos_accepted(),
                                        onchange: move |evt: Event<FormData>| {
                                            tos_accepted.set(evt.checked());
                                        },
                                    }
                                    span { class: "label-text",
                                        "I agree to the "
                                        a {
                                            href: "/legal/terms",
                                            target: "_blank",
                                            class: "link link-primary",
                                            "Terms of Service"
                                        }
                                        " and "
                                        a {
                                            href: "/legal/privacy",
                                            target: "_blank",
                                            class: "link link-primary",
                                            "Privacy Policy"
                                        }
                                    }
                                }
                                button {
                                    class: "btn btn-primary w-full",
                                    disabled: !tos_accepted() || is_loading(),
                                    onclick: on_tos_accept,
                                    if is_loading() {
                                        span { class: "loading loading-spinner loading-sm" }
                                    }
                                    "Continue"
                                }
                            }
                        ),

                        LoginStep::Verifying => rsx!(
                            div { class: "text-center space-y-4 py-4",
                                span { class: "loading loading-spinner loading-lg text-primary" }
                                p { class: "text-base-content/70", "Verifying..." }
                            }
                        ),

                        LoginStep::Success { redirect_url: _ } => rsx!(
                            div { class: "text-center space-y-4 py-4",
                                div { class: "text-success text-4xl mb-2",
                                    svg {
                                        xmlns: "http://www.w3.org/2000/svg",
                                        class: "h-12 w-12 mx-auto",
                                        fill: "none",
                                        "viewBox": "0 0 24 24",
                                        "stroke-width": "2",
                                        stroke: "currentColor",
                                        path {
                                            "stroke-linecap": "round",
                                            "stroke-linejoin": "round",
                                            d: "M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
                                        }
                                    }
                                }
                                p { class: "font-medium", "Login successful!" }
                                p { class: "text-sm text-base-content/50", "Redirecting..." }
                                span { class: "loading loading-spinner loading-sm" }
                            }
                        ),
                    }
    };

    // In embed mode, return just the form content for custom containers.
    // Otherwise, render the full standalone page with wrapper + header.
    if embed {
        inner_content
    } else {
        rsx! {
            div { class: "min-h-screen flex flex-col items-center justify-center bg-base-200",
                div { class: "card w-full max-w-md bg-base-100 shadow-xl",
                    div { class: "card-body",
                        div { class: "text-center mb-6",
                            h1 { class: "text-2xl font-bold", "Sign in" }
                            p { class: "text-sm text-base-content/60 mt-1",
                                "Sign in or create an account"
                            }
                        }
                        {inner_content}
                    }
                }
            }
        }
    }
}

// ── Login step state machine ────────────────────────────────────────

#[derive(Clone, PartialEq)]
enum LoginStep {
    EmailInput,
    Detecting,
    PasskeyChallenge,
    OtpCodeInput,
    TosAcceptance,
    Verifying,
    Success { redirect_url: String },
}

// ── WASM HTTP helpers ───────────────────────────────────────────────

#[cfg(feature = "web")]
#[derive(serde::Deserialize)]
struct StartSessionResp {
    #[allow(dead_code)]
    session_id: String,
    public_key_options: Option<serde_json::Value>,
    otp_sent: bool,
    is_new_user: bool,
    #[allow(dead_code)]
    has_passkeys: bool,
    #[allow(dead_code)]
    needs_tos_acceptance: Option<bool>,
    #[allow(dead_code)]
    redirect_url: Option<String>,
}

#[cfg(feature = "web")]
#[derive(serde::Deserialize)]
struct VerifyResp {
    success: bool,
    redirect_url: Option<String>,
    needs_tos_acceptance: Option<bool>,
    error: Option<String>,
}

/// Generic WASM POST helper that sends JSON and deserializes the response.
#[cfg(feature = "web")]
async fn wasm_post_json<R: for<'de> serde::Deserialize<'de>>(
    url: &str,
    body: Option<serde_json::Value>,
) -> std::result::Result<R, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Headers, Request, RequestCredentials, RequestInit, Response, window};

    let opts = RequestInit::new();
    opts.set_method("POST");
    opts.set_credentials(RequestCredentials::SameOrigin);

    let headers = Headers::new().map_err(|_| "Failed to create headers".to_string())?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|_| "Failed to set header".to_string())?;
    opts.set_headers(&headers);

    if let Some(b) = body {
        opts.set_body(&wasm_bindgen::JsValue::from_str(&b.to_string()));
    }

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|_| "Failed to create request".to_string())?;

    let window = window().ok_or("No window".to_string())?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|_| "Network error".to_string())?;

    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| "Invalid response".to_string())?;

    if !resp.ok() {
        let text = JsFuture::from(
            resp.text()
                .map_err(|_| "Failed to read response".to_string())?,
        )
        .await
        .map_err(|_| "Failed to read response text".to_string())?;
        let msg = text
            .as_string()
            .unwrap_or_else(|| "Request failed".to_string());
        return Err(msg);
    }

    let json = JsFuture::from(
        resp.json()
            .map_err(|_| "Failed to parse response".to_string())?,
    )
    .await
    .map_err(|_| "Failed to parse JSON".to_string())?;

    serde_wasm_bindgen::from_value(json).map_err(|e| format!("Deserialization error: {}", e))
}

/// Start session flow: POST to /auth/session/start, then auto-trigger passkey or show OTP.
#[cfg(feature = "web")]
#[allow(clippy::too_many_arguments)]
fn start_session_flow(
    email_val: String,
    redirect_url: String,
    mut step: Signal<LoginStep>,
    mut error_msg: Signal<Option<String>>,
    mut is_new_user: Signal<bool>,
    mut is_loading: Signal<bool>,
    mut passkey_options: Signal<Option<String>>,
    user_refresh: Signal<UserDataRefreshTrigger>,
) {
    spawn(async move {
        is_loading.set(true);

        let mut body = serde_json::json!({ "email": email_val });
        if !redirect_url.is_empty() {
            body["redirect_url"] = serde_json::Value::String(redirect_url);
        }

        let result: std::result::Result<StartSessionResp, String> =
            wasm_post_json("/auth/session/start", Some(body)).await;

        match result {
            Ok(resp) => {
                is_new_user.set(resp.is_new_user);

                if let Some(pk_opts) = resp.public_key_options {
                    // Server detected passkeys → auto-trigger WebAuthn
                    track("login_passkey_challenge");
                    passkey_options.set(Some(pk_opts.to_string()));
                    step.set(LoginStep::PasskeyChallenge);
                    is_loading.set(false);

                    trigger_passkey_auth(
                        passkey_options,
                        step,
                        error_msg,
                        is_loading,
                        user_refresh,
                    );
                } else if resp.otp_sent {
                    // OTP flow
                    track("login_otp_sent");
                    step.set(LoginStep::OtpCodeInput);
                    is_loading.set(false);
                } else {
                    error_msg.set(Some("Unexpected response from server".to_string()));
                    step.set(LoginStep::EmailInput);
                    is_loading.set(false);
                }
            }
            Err(e) => {
                error_msg.set(Some(e));
                step.set(LoginStep::EmailInput);
                is_loading.set(false);
            }
        }
    });
}

/// Trigger the WebAuthn browser API to get a passkey assertion, then verify it.
/// On failure/cancel, transitions to OtpCodeInput via the fallback endpoint.
#[cfg(feature = "web")]
fn trigger_passkey_auth(
    passkey_options: Signal<Option<String>>,
    mut step: Signal<LoginStep>,
    mut error_msg: Signal<Option<String>>,
    mut is_loading: Signal<bool>,
    mut user_refresh: Signal<UserDataRefreshTrigger>,
) {
    spawn(async move {
        let Some(options_json) = passkey_options() else {
            error_msg.set(Some("No passkey challenge available".to_string()));
            step.set(LoginStep::EmailInput);
            return;
        };

        match crate::webauthn_helpers::browser_get_passkey(&options_json).await {
            Ok(assertion_data) => {
                step.set(LoginStep::Verifying);
                let verify_result: std::result::Result<VerifyResp, String> = wasm_post_json(
                    "/auth/session/passkey/verify",
                    Some(serde_json::json!({ "credential_assertion_data": assertion_data })),
                )
                .await;
                match verify_result {
                    Ok(resp) => {
                        if resp.success {
                            track("login_verified");
                            if resp.needs_tos_acceptance == Some(true) {
                                track("login_tos_shown");
                                step.set(LoginStep::TosAcceptance);
                                is_loading.set(false);
                            } else if let Some(url) = resp.redirect_url {
                                step.set(LoginStep::Success {
                                    redirect_url: url.clone(),
                                });
                                user_refresh.write().0 += 1;
                            }
                        } else {
                            let msg = resp
                                .error
                                .unwrap_or_else(|| "Verification failed".to_string());
                            error_msg.set(Some(msg));
                            step.set(LoginStep::PasskeyChallenge);
                            is_loading.set(false);
                        }
                    }
                    Err(e) => {
                        error_msg.set(Some(e));
                        step.set(LoginStep::PasskeyChallenge);
                        is_loading.set(false);
                    }
                }
            }
            Err(e) => {
                // Passkey failed (cancelled, not available, wrong device)
                // Auto-fallback to OTP
                let fallback_result: std::result::Result<StartSessionResp, String> =
                    wasm_post_json("/auth/session/passkey-fallback-otp", None).await;
                match fallback_result {
                    Ok(_resp) => {
                        error_msg.set(None);
                        step.set(LoginStep::OtpCodeInput);
                        is_loading.set(false);
                        // Don't show original passkey error, just silently fall back
                        if e.contains("cancelled") || e.contains("timed out") {
                            // Silent fallback — user intentionally cancelled
                        } else {
                            // Show a subtle info message
                            error_msg.set(Some(
                                "Passkey unavailable, verification code sent to your email."
                                    .to_string(),
                            ));
                        }
                    }
                    Err(fallback_err) => {
                        error_msg.set(Some(format!("Failed to send email code: {}", fallback_err)));
                        step.set(LoginStep::EmailInput);
                        is_loading.set(false);
                    }
                }
            }
        }
    });
}
