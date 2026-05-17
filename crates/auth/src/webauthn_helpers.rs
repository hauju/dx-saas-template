//! Shared WebAuthn browser helpers (WASM only).
//!
//! Provides async functions that invoke `navigator.credentials.create()` / `.get()`
//! via `js_sys::eval` and poll `window.__auth_*` globals for the result.
//! Used by both the login page and the profile passkey management UI.

/// Call `navigator.credentials.get()` with the given request options JSON.
/// Returns the assertion data as a JSON `Value`, or an error string.
///
/// Includes a guard: if `navigator.credentials` is unavailable (non-secure context),
/// returns an error immediately instead of crashing.
pub async fn browser_get_passkey(request_options_json: &str) -> Result<serde_json::Value, String> {
    let js_code = format!(
        r#"
        (async function() {{
            try {{
                if (!navigator.credentials || !navigator.credentials.get) {{
                    window.__auth_passkey_result = null;
                    window.__auth_passkey_error = 'Passkeys are not supported in this browser or context.';
                    return;
                }}
                const raw = {request_options_json};
                // FerrisKey returns the unwrapped W3C PublicKeyCredentialRequestOptions
                // shape directly; tolerate a `publicKey` wrapper for forward compat.
                const options = raw.publicKey || raw;

                function b64urlToBuffer(b64url) {{
                    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
                    const pad = b64.length % 4;
                    const padded = pad ? b64 + '='.repeat(4 - pad) : b64;
                    const binary = atob(padded);
                    const bytes = new Uint8Array(binary.length);
                    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
                    return bytes.buffer;
                }}

                function bufferToB64url(buffer) {{
                    const bytes = new Uint8Array(buffer);
                    let binary = '';
                    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
                    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                }}

                if (options.challenge) {{
                    options.challenge = b64urlToBuffer(options.challenge);
                }}
                if (options.allowCredentials) {{
                    options.allowCredentials = options.allowCredentials.map(cred => ({{
                        ...cred,
                        id: b64urlToBuffer(cred.id)
                    }}));
                }}

                const credential = await navigator.credentials.get({{ publicKey: options }});

                const result = {{
                    id: credential.id,
                    rawId: bufferToB64url(credential.rawId),
                    type: credential.type,
                    response: {{
                        authenticatorData: bufferToB64url(credential.response.authenticatorData),
                        clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
                        signature: bufferToB64url(credential.response.signature),
                        userHandle: credential.response.userHandle
                            ? bufferToB64url(credential.response.userHandle)
                            : null
                    }}
                }};

                window.__auth_passkey_result = JSON.stringify(result);
                window.__auth_passkey_error = null;
            }} catch (e) {{
                window.__auth_passkey_result = null;
                window.__auth_passkey_error = e.name === 'NotAllowedError'
                    ? 'Authentication was cancelled or timed out.'
                    : ('Passkey error: ' + e.message);
            }}
        }})();
        "#
    );

    let _ = js_sys::eval(&js_code);
    poll_passkey_result("__auth_passkey_result", "__auth_passkey_error").await
}

/// Call `navigator.credentials.create()` with the given creation options JSON.
/// Returns the credential data as a JSON `Value`, or an error string.
///
/// Includes a guard: if `navigator.credentials` is unavailable (non-secure context),
/// returns an error immediately instead of crashing.
pub async fn browser_create_passkey(
    creation_options_json: &str,
) -> Result<serde_json::Value, String> {
    let js_code = format!(
        r#"
        (async function() {{
            try {{
                if (!navigator.credentials || !navigator.credentials.create) {{
                    window.__auth_passkey_reg_result = null;
                    window.__auth_passkey_reg_error = 'Passkeys are not supported in this browser or context.';
                    return;
                }}
                const raw = {creation_options_json};
                const options = raw.publicKey || raw;

                function b64urlToBuffer(b64url) {{
                    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
                    const pad = b64.length % 4;
                    const padded = pad ? b64 + '='.repeat(4 - pad) : b64;
                    const binary = atob(padded);
                    const bytes = new Uint8Array(binary.length);
                    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
                    return bytes.buffer;
                }}

                function bufferToB64url(buffer) {{
                    const bytes = new Uint8Array(buffer);
                    let binary = '';
                    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
                    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                }}

                if (options.challenge) {{
                    options.challenge = b64urlToBuffer(options.challenge);
                }}
                if (options.user && options.user.id) {{
                    if (typeof options.user.id === 'string') {{
                        options.user.id = b64urlToBuffer(options.user.id);
                    }}
                }}
                if (options.excludeCredentials) {{
                    options.excludeCredentials = options.excludeCredentials.map(cred => ({{
                        ...cred,
                        id: b64urlToBuffer(cred.id)
                    }}));
                }}

                const credential = await navigator.credentials.create({{ publicKey: options }});

                const result = {{
                    id: credential.id,
                    rawId: bufferToB64url(credential.rawId),
                    type: credential.type,
                    response: {{
                        attestationObject: bufferToB64url(credential.response.attestationObject),
                        clientDataJSON: bufferToB64url(credential.response.clientDataJSON)
                    }}
                }};

                window.__auth_passkey_reg_result = JSON.stringify(result);
                window.__auth_passkey_reg_error = null;
            }} catch (e) {{
                window.__auth_passkey_reg_result = null;
                window.__auth_passkey_reg_error = e.name === 'NotAllowedError'
                    ? 'Passkey creation was cancelled or timed out.'
                    : ('Passkey creation error: ' + e.message);
            }}
        }})().catch(function(e) {{
            window.__auth_passkey_reg_result = null;
            window.__auth_passkey_reg_error = 'Passkey creation error: ' + e.message;
        }});
        "#
    );

    if let Err(e) = js_sys::eval(&js_code) {
        let msg = e
            .as_string()
            .unwrap_or_else(|| format!("JS eval error: {:?}", e));
        return Err(format!("Passkey setup failed: {}", msg));
    }

    poll_passkey_result("__auth_passkey_reg_result", "__auth_passkey_reg_error").await
}

/// Check if `navigator.credentials` is available in the current browser context.
pub fn is_webauthn_available() -> bool {
    js_sys::eval("!!(navigator.credentials && navigator.credentials.create)")
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Poll window globals for a WebAuthn result. Timeout after 120 seconds.
async fn poll_passkey_result(
    result_key: &str,
    error_key: &str,
) -> Result<serde_json::Value, String> {
    let read_result = format!("window.{result_key}");
    let read_error = format!("window.{error_key}");
    let cleanup = format!("window.{result_key} = undefined; window.{error_key} = undefined;");

    for _ in 0..600 {
        gloo_timers::future::TimeoutFuture::new(200).await;

        let result = js_sys::eval(&read_result).ok().and_then(|v| v.as_string());
        let error = js_sys::eval(&read_error).ok().and_then(|v| v.as_string());

        if let Some(err) = error {
            let _ = js_sys::eval(&cleanup);
            return Err(err);
        }

        if let Some(result_json) = result {
            let _ = js_sys::eval(&cleanup);
            return serde_json::from_str(&result_json)
                .map_err(|_| "Failed to parse passkey response".to_string());
        }
    }

    let _ = js_sys::eval(&cleanup);
    Err("Passkey operation timed out".to_string())
}
