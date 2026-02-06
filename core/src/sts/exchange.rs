//! Token exchange endpoint implementation
//!
//! Exchanges OIDC tokens for GitHub installation tokens.

use serde::Serialize;

use crate::config::{Config, INSTALL_CACHE_TTL_SECS};
use crate::error::{ApiError, Result};
use crate::github;
use crate::oidc;
use crate::platform::{cache_get, cache_put, Cache, Clock, Environment, HttpClient, JwtSigner};
use crate::policy;

/// Token exchange response
#[derive(Serialize)]
pub struct ExchangeResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Platform-neutral exchange request
pub struct ExchangeRequest {
    pub scope: String,
    pub identity: String,
    pub bearer_token: String,
}

/// Handle token exchange request
pub async fn handle(
    request: ExchangeRequest,
    cache: &dyn Cache,
    http: &dyn HttpClient,
    env: &dyn Environment,
    clock: &dyn Clock,
    signer: &dyn JwtSigner,
) -> Result<ExchangeResponse> {
    let config = Config::from_env(env)?;

    // 1. Validate OIDC token
    let claims = oidc::validate_token(&request.bearer_token, http, clock).await?;

    // 2. Load trust policy (with caching)
    let compiled_policy = policy::load(&request.scope, &request.identity, cache, http, signer).await?;

    // 3. Extract target repo from scope for repository validation
    let parts: Vec<&str> = request.scope.split('/').collect();
    if parts.len() != 2 {
        return Err(ApiError::invalid_request("scope must be in format owner/repo"));
    }
    let owner = parts[0];
    let target_repo = parts[1];

    // 4. Check token against policy (including repository restrictions)
    policy::check_token_with_repo(&claims, &compiled_policy, &config.domain, Some(target_repo))?;

    // 5. Get installation ID (with caching)
    let installation_id = get_or_fetch_installation(owner, cache, http, signer, clock).await?;

    // 6. Generate GitHub installation token
    let (token, expires_at) = github::auth::create_installation_token(
        installation_id,
        &request.scope,
        &compiled_policy.permissions,
        signer,
        http,
        clock,
    )
    .await?;

    // Calculate expires_in from expires_at
    let expires_in = calculate_expires_in(&expires_at, clock).unwrap_or(3600);

    Ok(ExchangeResponse {
        access_token: token,
        token_type: "bearer".to_string(),
        expires_in,
    })
}

/// Get installation ID from cache or fetch from GitHub
async fn get_or_fetch_installation(
    owner: &str,
    cache: &dyn Cache,
    http: &dyn HttpClient,
    signer: &dyn JwtSigner,
    clock: &dyn Clock,
) -> Result<u64> {
    let cache_key = format!("install:{}", owner);

    // Try cache first
    if let Ok(Some(id)) = cache_get::<u64>(cache, &cache_key).await {
        return Ok(id);
    }

    // Fetch from GitHub
    let installation_id = github::auth::get_installation_id(owner, signer, http, clock).await?;

    // Cache the result
    let _ = cache_put(cache, &cache_key, &installation_id, INSTALL_CACHE_TTL_SECS).await;

    Ok(installation_id)
}

/// Calculate expires_in from ISO 8601 expires_at timestamp
fn calculate_expires_in(expires_at: &str, clock: &dyn Clock) -> Option<u64> {
    let now_secs = clock.now_secs() as i64;
    calculate_expires_in_from_now(expires_at, now_secs)
}

/// Calculate expires_in from ISO 8601 expires_at timestamp given a specific "now" time
/// This is testable without platform dependencies
fn calculate_expires_in_from_now(expires_at: &str, now_secs: i64) -> Option<u64> {
    use chrono::{DateTime, Utc};

    let expires_dt: DateTime<Utc> = expires_at.parse().ok()?;
    let expires_secs = expires_dt.timestamp();

    let diff = expires_secs - now_secs;

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
        let now = 1706900000i64;
        let expires_at = "2024-02-02T19:53:20Z";

        let result = calculate_expires_in_from_now(expires_at, now);
        assert_eq!(result, Some(3600));
    }

    #[test]
    fn test_calculate_expires_in_expired_token() {
        let now = 1706900000i64;
        let expires_at = "2024-02-02T17:53:20Z";

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
        let now = 1706900000i64;
        let expires_at = "2024-02-02T19:53:20.123Z";

        let result = calculate_expires_in_from_now(expires_at, now);
        assert_eq!(result, Some(3600));
    }

    #[test]
    fn test_calculate_expires_in_realistic_github_response() {
        let now = 1706900000i64;
        let expires_at = "2024-02-02T19:53:20Z";

        let result = calculate_expires_in_from_now(expires_at, now);
        assert_eq!(result, Some(3600));
    }
}
