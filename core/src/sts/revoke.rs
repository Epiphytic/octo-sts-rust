//! Token revocation endpoint implementation
//!
//! Revokes GitHub installation tokens via the GitHub API.

use crate::error::{ApiError, Result};
use crate::platform::HttpClient;

const GITHUB_REVOKE_URL: &str = "https://api.github.com/installation/token";

/// Handle token revocation request
pub async fn handle(bearer_token: &str, http: &dyn HttpClient) -> Result<()> {
    revoke_token(bearer_token, http).await
}

/// Revoke a GitHub installation token
async fn revoke_token(token: &str, http: &dyn HttpClient) -> Result<()> {
    let auth_header = format!("Bearer {}", token);
    let headers = [
        ("Authorization", auth_header.as_str()),
        ("Accept", "application/vnd.github+json"),
        ("User-Agent", "octo-sts-rust"),
    ];

    let response = http
        .delete(GITHUB_REVOKE_URL, &headers)
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to call GitHub API: {}", e)))?;

    match response.status {
        204 => Ok(()),
        401 => Err(ApiError::invalid_token("token is invalid or already revoked")),
        status => Err(ApiError::upstream_error(format!(
            "unexpected status from GitHub: {}",
            status
        ))),
    }
}
