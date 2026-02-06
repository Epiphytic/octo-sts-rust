//! JWKS (JSON Web Key Set) handling
//!
//! Fetches and caches JWKS for OIDC token validation.

use surrealdb_jsonwebtoken::jwk::JwkSet;

use crate::error::{ApiError, Result};
use crate::platform::HttpClient;

/// Fetch JWKS from a URI
pub async fn fetch_jwks(jwks_uri: &str, http: &dyn HttpClient) -> Result<JwkSet> {
    let response = http
        .get(
            jwks_uri,
            &[
                ("Accept", "application/json"),
                ("User-Agent", "octo-sts-rust"),
            ],
        )
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to fetch JWKS: {}", e)))?;

    if response.status != 200 {
        return Err(ApiError::token_verification_failed(format!(
            "failed to fetch JWKS: HTTP {}",
            response.status
        )));
    }

    let jwks: JwkSet = response
        .json()
        .map_err(|e| ApiError::token_verification_failed(format!("invalid JWKS: {}", e)))?;

    Ok(jwks)
}
