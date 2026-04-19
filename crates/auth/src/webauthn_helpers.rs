//! Shared WebAuthn browser helpers (WASM only).
//!
//! Provides async functions that invoke `navigator.credentials.create()` / `.get()`
//! via JS promises awaited through `wasm_bindgen_futures::JsFuture`.

use wasm_bindgen_futures::JsFuture;

/// Call `navigator.credentials.get()` with the given request options JSON.
/// Returns the assertion data as a JSON `Value`, or an error string.
///
/// Includes a guard: if `navigator.credentials` is unavailable (non-secure context),
/// returns an error immediately instead of crashing.
pub async fn browser_get_passkey(request_options_json: &str) -> Result<serde_json::Value, String> {
    let js_code = format!(
        r#"
        new Promise(function(resolve, reject) {{
            var timeout = setTimeout(function() {{
                reject(new Error('Passkey operation timed out'));
            }}, 120000);

            (async function() {{
                try {{
                    if (!navigator.credentials || !navigator.credentials.get) {{
                        throw new Error('Passkeys are not supported in this browser or context.');
                    }}
                    const raw = {request_options_json};
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

                    clearTimeout(timeout);
                    resolve(JSON.stringify({{
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
                    }}));
                }} catch (e) {{
                    clearTimeout(timeout);
                    reject(e);
                }}
            }})();
        }})
        "#
    );

    let promise = js_sys::eval(&js_code).map_err(|e| format!("JS eval error: {:?}", e))?;
    let promise = js_sys::Promise::from(promise);

    match JsFuture::from(promise).await {
        Ok(val) => {
            let json_str = val.as_string().ok_or("Passkey result was not a string")?;
            serde_json::from_str(&json_str)
                .map_err(|_| "Failed to parse passkey response".to_string())
        }
        Err(e) => {
            let msg = js_sys::Error::from(e)
                .message()
                .as_string()
                .unwrap_or_else(|| "Unknown passkey error".to_string());
            if msg.contains("NotAllowedError") {
                Err("Authentication was cancelled or timed out.".to_string())
            } else {
                Err(format!("Passkey error: {}", msg))
            }
        }
    }
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
        new Promise(function(resolve, reject) {{
            var timeout = setTimeout(function() {{
                reject(new Error('Passkey operation timed out'));
            }}, 120000);

            (async function() {{
                try {{
                    if (!navigator.credentials || !navigator.credentials.create) {{
                        throw new Error('Passkeys are not supported in this browser or context.');
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

                    clearTimeout(timeout);
                    resolve(JSON.stringify({{
                        id: credential.id,
                        rawId: bufferToB64url(credential.rawId),
                        type: credential.type,
                        response: {{
                            attestationObject: bufferToB64url(credential.response.attestationObject),
                            clientDataJSON: bufferToB64url(credential.response.clientDataJSON)
                        }}
                    }}));
                }} catch (e) {{
                    clearTimeout(timeout);
                    reject(e);
                }}
            }})();
        }})
        "#
    );

    let promise = js_sys::eval(&js_code).map_err(|e| format!("Passkey setup failed: {:?}", e))?;
    let promise = js_sys::Promise::from(promise);

    match JsFuture::from(promise).await {
        Ok(val) => {
            let json_str = val.as_string().ok_or("Passkey result was not a string")?;
            serde_json::from_str(&json_str)
                .map_err(|_| "Failed to parse passkey response".to_string())
        }
        Err(e) => {
            let msg = js_sys::Error::from(e)
                .message()
                .as_string()
                .unwrap_or_else(|| "Unknown passkey error".to_string());
            if msg.contains("NotAllowedError") {
                Err("Passkey creation was cancelled or timed out.".to_string())
            } else {
                Err(format!("Passkey creation error: {}", msg))
            }
        }
    }
}

/// Check if `navigator.credentials` is available in the current browser context.
pub fn is_webauthn_available() -> bool {
    js_sys::eval("!!(navigator.credentials && navigator.credentials.create)")
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}
