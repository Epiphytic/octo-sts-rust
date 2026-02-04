//! Token revocation endpoint implementation
//!
//! Revokes GitHub installation tokens via the GitHub API.

use worker::{Env, Fetch, Headers, Method, Request, RequestInit};

use crate::error::{ApiError, Result};

const GITHUB_REVOKE_URL: &str = "https://api.github.com/installation/token";

/// Handle token revocation request
pub async fn handle(req: Request, _env: &Env) -> Result<()> {
    // Extract the token to revoke from Authorization header
    let token = extract_bearer_token(&req)?;

    // Call GitHub API to revoke the token
    revoke_token(&token).await
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

/// Revoke a GitHub installation token
async fn revoke_token(token: &str) -> Result<()> {
    let headers = Headers::new();
    headers
        .set("Authorization", &format!("Bearer {}", token))
        .map_err(|_| ApiError::internal("failed to set headers"))?;
    headers
        .set("Accept", "application/vnd.github+json")
        .map_err(|_| ApiError::internal("failed to set headers"))?;
    headers
        .set("User-Agent", "octo-sts-rust")
        .map_err(|_| ApiError::internal("failed to set headers"))?;

    let mut init = RequestInit::new();
    init.with_method(Method::Delete).with_headers(headers);

    let request = Request::new_with_init(GITHUB_REVOKE_URL, &init)
        .map_err(|_| ApiError::internal("failed to create request"))?;

    let response = Fetch::Request(request)
        .send()
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to call GitHub API: {}", e)))?;

    match response.status_code() {
        204 => Ok(()),
        401 => Err(ApiError::invalid_token("token is invalid or already revoked")),
        status => Err(ApiError::upstream_error(format!(
            "unexpected status from GitHub: {}",
            status
        ))),
    }
}
