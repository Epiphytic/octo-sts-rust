//! GitHub App authentication
//!
//! Generates App JWTs and requests installation tokens.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use worker::{Fetch, Headers, Method, Request, RequestInit};

use crate::config::Config;
use crate::error::{ApiError, Result};

const GITHUB_API_BASE: &str = "https://api.github.com";

/// GitHub App JWT claims
#[derive(Serialize)]
struct AppJwtClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

/// Installation token response from GitHub
#[derive(Deserialize)]
struct InstallationTokenResponse {
    token: String,
    expires_at: String,
}

/// Create a GitHub installation token with scoped permissions
pub async fn create_installation_token(
    installation_id: u64,
    scope: &str,
    permissions: &HashMap<String, String>,
    config: &Config,
) -> Result<(String, String)> {
    // Generate App JWT for authentication
    let app_jwt = generate_app_jwt(config)?;

    // Extract repo name from scope (owner/repo -> repo)
    let repo = scope
        .split('/')
        .nth(1)
        .ok_or_else(|| ApiError::invalid_request("invalid scope format"))?;

    // Build request body
    let body = serde_json::json!({
        "repositories": [repo],
        "permissions": permissions
    });

    // Make request to GitHub
    let url = format!(
        "{}/app/installations/{}/access_tokens",
        GITHUB_API_BASE, installation_id
    );

    let mut headers = Headers::new();
    headers
        .set("Authorization", &format!("Bearer {}", app_jwt))
        .map_err(|_| ApiError::internal("failed to set headers"))?;
    headers
        .set("Accept", "application/vnd.github+json")
        .map_err(|_| ApiError::internal("failed to set headers"))?;
    headers
        .set("User-Agent", "octo-sts-rust")
        .map_err(|_| ApiError::internal("failed to set headers"))?;
    headers
        .set("X-GitHub-Api-Version", "2022-11-28")
        .map_err(|_| ApiError::internal("failed to set headers"))?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(body.to_string().into()));

    let request =
        Request::new_with_init(&url, &init).map_err(|_| ApiError::internal("failed to create request"))?;

    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to call GitHub API: {}", e)))?;

    if response.status_code() != 201 {
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown error".to_string());
        return Err(ApiError::upstream_error(format!(
            "GitHub API error ({}): {}",
            response.status_code(),
            error_body
        )));
    }

    let token_response: InstallationTokenResponse = response
        .json()
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to parse response: {}", e)))?;

    Ok((token_response.token, token_response.expires_at))
}

/// Generate a GitHub App JWT for API authentication
fn generate_app_jwt(config: &Config) -> Result<String> {
    // Get current time with clock skew buffer
    let now = chrono_lite_now();
    let iat = now - 60; // 60 second buffer for clock skew
    let exp = now + 600; // 10 minute expiry (GitHub maximum)

    let claims = AppJwtClaims {
        iat,
        exp,
        iss: config.github_app_id.clone(),
    };

    // Create JWT header and payload
    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT"
    });

    let header_b64 = base64_url_encode(&serde_json::to_vec(&header).map_err(|e| {
        ApiError::internal(format!("failed to serialize header: {}", e))
    })?);

    let payload_b64 = base64_url_encode(&serde_json::to_vec(&claims).map_err(|e| {
        ApiError::internal(format!("failed to serialize claims: {}", e))
    })?);

    let message = format!("{}.{}", header_b64, payload_b64);

    // Sign with RSA-SHA256
    // Note: In a real implementation, this would use Web Crypto API
    // For now, we'll use the jsonwebtoken crate if it supports WASM,
    // or implement signing manually
    let signature = sign_rs256(&message, &config.github_app_private_key)?;

    Ok(format!("{}.{}", message, signature))
}

/// Sign a message with RS256 using the private key
fn sign_rs256(message: &str, private_key_pem: &str) -> Result<String> {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    // Parse the PEM key
    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| ApiError::internal(format!("invalid private key: {}", e)))?;

    // We already have header and payload, but jsonwebtoken wants to create them
    // So we'll use it directly instead of our manual approach
    // This is a workaround - ideally we'd sign just the message

    // Actually, let's just return an error for now and mark this as TODO
    // The proper implementation requires either:
    // 1. Using Web Crypto API directly (complex in Rust/WASM)
    // 2. Using a WASM-compatible RSA crate
    // 3. Using jsonwebtoken's full encode function

    Err(ApiError::internal(
        "RS256 signing not yet implemented - requires Web Crypto API integration",
    ))
}

/// Base64 URL encode without padding
fn base64_url_encode(data: &[u8]) -> String {
    BASE64
        .encode(data)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

/// Get current Unix timestamp (seconds)
///
/// In WASM, we use js_sys::Date
fn chrono_lite_now() -> i64 {
    // js_sys::Date::now() returns milliseconds
    (js_sys::Date::now() / 1000.0) as i64
}

/// Get installation ID for an owner
pub async fn get_installation_id(owner: &str, config: &Config) -> Result<u64> {
    let app_jwt = generate_app_jwt(config)?;

    let url = format!("{}/orgs/{}/installation", GITHUB_API_BASE, owner);

    let mut headers = Headers::new();
    headers
        .set("Authorization", &format!("Bearer {}", app_jwt))
        .map_err(|_| ApiError::internal("failed to set headers"))?;
    headers
        .set("Accept", "application/vnd.github+json")
        .map_err(|_| ApiError::internal("failed to set headers"))?;
    headers
        .set("User-Agent", "octo-sts-rust")
        .map_err(|_| ApiError::internal("failed to set headers"))?;

    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);

    let request =
        Request::new_with_init(&url, &init).map_err(|_| ApiError::internal("failed to create request"))?;

    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to call GitHub API: {}", e)))?;

    // Try org endpoint first, fall back to user endpoint
    if response.status_code() == 404 {
        let url = format!("{}/users/{}/installation", GITHUB_API_BASE, owner);
        let mut headers = Headers::new();
        headers
            .set("Authorization", &format!("Bearer {}", app_jwt))
            .map_err(|_| ApiError::internal("failed to set headers"))?;
        headers
            .set("Accept", "application/vnd.github+json")
            .map_err(|_| ApiError::internal("failed to set headers"))?;
        headers
            .set("User-Agent", "octo-sts-rust")
            .map_err(|_| ApiError::internal("failed to set headers"))?;

        let mut init = RequestInit::new();
        init.with_method(Method::Get).with_headers(headers);

        let request = Request::new_with_init(&url, &init)
            .map_err(|_| ApiError::internal("failed to create request"))?;

        response = Fetch::Request(request)
            .send()
            .await
            .map_err(|e| ApiError::upstream_error(format!("failed to call GitHub API: {}", e)))?;
    }

    if response.status_code() == 404 {
        return Err(ApiError::installation_not_found(format!(
            "GitHub App not installed for '{}'",
            owner
        )));
    }

    if response.status_code() != 200 {
        return Err(ApiError::upstream_error(format!(
            "GitHub API error: {}",
            response.status_code()
        )));
    }

    #[derive(Deserialize)]
    struct InstallationResponse {
        id: u64,
    }

    let installation: InstallationResponse = response
        .json()
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to parse response: {}", e)))?;

    Ok(installation.id)
}
