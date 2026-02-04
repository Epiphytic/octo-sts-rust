//! JWKS (JSON Web Key Set) handling
//!
//! Fetches and caches JWKS for OIDC token validation.

use jsonwebtoken::jwk::JwkSet;
use serde::Deserialize;
use worker::{Fetch, Headers, Method, Request, RequestInit};

use crate::error::{ApiError, Result};

/// Fetch JWKS from a URI
pub async fn fetch_jwks(jwks_uri: &str) -> Result<JwkSet> {
    let mut headers = Headers::new();
    headers
        .set("Accept", "application/json")
        .map_err(|_| ApiError::internal("failed to set headers"))?;
    headers
        .set("User-Agent", "octo-sts-rust")
        .map_err(|_| ApiError::internal("failed to set headers"))?;

    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);

    let request = Request::new_with_init(jwks_uri, &init)
        .map_err(|_| ApiError::internal("failed to create request"))?;

    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to fetch JWKS: {}", e)))?;

    if response.status_code() != 200 {
        return Err(ApiError::token_verification_failed(format!(
            "failed to fetch JWKS: HTTP {}",
            response.status_code()
        )));
    }

    let jwks: JwkSet = response
        .json()
        .await
        .map_err(|e| ApiError::token_verification_failed(format!("invalid JWKS: {}", e)))?;

    Ok(jwks)
}
