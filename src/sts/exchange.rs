//! Token exchange endpoint implementation
//!
//! Exchanges OIDC tokens for GitHub installation tokens.

use serde::Serialize;
use worker::{Env, Request, Url};

use crate::config::Config;
use crate::error::{ApiError, Result};
use crate::github;
use crate::kv;
use crate::oidc;
use crate::policy;

/// Token exchange response
#[derive(Serialize)]
pub struct ExchangeResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Handle token exchange request
pub async fn handle(req: Request, env: &Env) -> Result<ExchangeResponse> {
    let config = Config::from_env(env)?;

    // 1. Parse request parameters
    let params = parse_request(&req)?;

    // 2. Extract and validate OIDC token
    let bearer_token = extract_bearer_token(&req)?;
    let claims = oidc::validate_token(&bearer_token, env).await?;

    // 3. Load trust policy (with caching)
    let policy = policy::load(&params.scope, &params.identity, env).await?;

    // 4. Check token against policy
    policy::check_token(&claims, &policy, &config.domain)?;

    // 5. Get installation ID (with caching)
    let owner = params.scope.split('/').next().ok_or_else(|| {
        ApiError::invalid_request("scope must be in format owner/repo")
    })?;
    let installation_id = kv::get_or_fetch_installation(owner, env, &config).await?;

    // 6. Generate GitHub installation token
    let (token, expires_at) = github::auth::create_installation_token(
        installation_id,
        &params.scope,
        &policy.permissions,
        &config,
    )
    .await?;

    // Calculate expires_in from expires_at (GitHub returns ISO 8601 timestamp)
    let expires_in = calculate_expires_in(&expires_at).unwrap_or(3600);

    Ok(ExchangeResponse {
        access_token: token,
        token_type: "bearer".to_string(),
        expires_in,
    })
}

/// Request parameters
struct RequestParams {
    scope: String,
    identity: String,
}

/// Parse scope and identity from query parameters
fn parse_request(req: &Request) -> Result<RequestParams> {
    let url = req.url().map_err(|_| ApiError::invalid_request("invalid URL"))?;

    let scope = get_query_param(&url, "scope")?;
    let identity = get_query_param(&url, "identity")?;

    // Validate scope format (owner/repo)
    if !scope.contains('/') || scope.split('/').count() != 2 {
        return Err(ApiError::invalid_request(
            "scope must be in format owner/repo",
        ));
    }

    Ok(RequestParams { scope, identity })
}

/// Extract a required query parameter
fn get_query_param(url: &Url, name: &str) -> Result<String> {
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.to_string())
        .ok_or_else(|| ApiError::invalid_request(format!("missing required parameter: {}", name)))
}

/// Extract bearer token from Authorization header
fn extract_bearer_token(req: &Request) -> Result<String> {
    let header = req
        .headers()
        .get("Authorization")
        .map_err(|_| ApiError::invalid_request("failed to read headers"))?
        .ok_or_else(|| ApiError::invalid_request("missing Authorization header"))?;

    if !header.starts_with("Bearer ") {
        return Err(ApiError::invalid_request(
            "Authorization header must use Bearer scheme",
        ));
    }

    Ok(header[7..].to_string())
}

/// Calculate expires_in from ISO 8601 expires_at timestamp
fn calculate_expires_in(expires_at: &str) -> Option<u64> {
    // Get current time
    let now_ms = js_sys::Date::now();
    let now_secs = (now_ms / 1000.0) as i64;
    calculate_expires_in_from_now(expires_at, now_secs)
}

/// Calculate expires_in from ISO 8601 expires_at timestamp given a specific "now" time
/// This is testable without js_sys
fn calculate_expires_in_from_now(expires_at: &str, now_secs: i64) -> Option<u64> {
    // Parse ISO 8601 timestamp (e.g., "2024-02-03T12:00:00Z")
    // GitHub always returns UTC timestamps
    use chrono::{DateTime, Utc};

    let expires_dt: DateTime<Utc> = expires_at.parse().ok()?;
    let expires_secs = expires_dt.timestamp();

    // Calculate difference
    let diff = expires_secs - now_secs;

    // Only return positive values (token not expired)
    if diff > 0 {
        Some(diff as u64)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_expires_in_valid_timestamp() {
        // expires_at is 3600 seconds (1 hour) in the future
        let now = 1706900000i64; // Fixed timestamp
        let expires_at = "2024-02-02T19:53:20Z"; // exactly 3600 seconds after now

        let result = calculate_expires_in_from_now(expires_at, now);
        assert_eq!(result, Some(3600));
    }

    #[test]
    fn test_calculate_expires_in_expired_token() {
        // expires_at is in the past
        let now = 1706900000i64;
        let expires_at = "2024-02-02T17:53:20Z"; // 2 hours before now

        let result = calculate_expires_in_from_now(expires_at, now);
        assert_eq!(result, None);
    }

    #[test]
    fn test_calculate_expires_in_invalid_timestamp() {
        let now = 1706900000i64;
        let expires_at = "invalid-timestamp";

        let result = calculate_expires_in_from_now(expires_at, now);
        assert_eq!(result, None);
    }

    #[test]
    fn test_calculate_expires_in_with_milliseconds() {
        // GitHub sometimes returns timestamps with milliseconds
        let now = 1706900000i64;
        let expires_at = "2024-02-02T19:53:20.123Z";

        let result = calculate_expires_in_from_now(expires_at, now);
        assert_eq!(result, Some(3600));
    }

    #[test]
    fn test_calculate_expires_in_realistic_github_response() {
        // Test with a realistic GitHub response format
        let now = 1706900000i64; // 2024-02-02T18:53:20Z
        let expires_at = "2024-02-02T19:53:20Z"; // 1 hour later

        let result = calculate_expires_in_from_now(expires_at, now);
        assert_eq!(result, Some(3600));
    }
}
