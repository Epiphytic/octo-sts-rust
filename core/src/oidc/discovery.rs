//! OIDC Discovery document fetching
//!
//! Fetches and parses OpenID Connect discovery documents.

use serde::Deserialize;

use crate::error::{ApiError, Result};
use crate::platform::HttpClient;

/// OIDC Discovery document (partial)
#[derive(Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
}

/// Fetch OIDC discovery document for an issuer
pub async fn fetch_discovery(issuer: &str, http: &dyn HttpClient) -> Result<DiscoveryDocument> {
    validate_issuer_url(issuer)?;

    let discovery_url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));

    let response = http
        .get(
            &discovery_url,
            &[
                ("Accept", "application/json"),
                ("User-Agent", "octo-sts-rust"),
            ],
        )
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to fetch discovery document: {}", e)))?;

    if response.status != 200 {
        return Err(ApiError::token_verification_failed(format!(
            "failed to fetch discovery document: HTTP {}",
            response.status
        )));
    }

    let doc: DiscoveryDocument = response
        .json()
        .map_err(|e| ApiError::token_verification_failed(format!("invalid discovery document: {}", e)))?;

    // Verify issuer matches
    if doc.issuer != issuer && doc.issuer != issuer.trim_end_matches('/') {
        return Err(ApiError::token_verification_failed(format!(
            "issuer mismatch: expected '{}', got '{}'",
            issuer, doc.issuer
        )));
    }

    Ok(doc)
}

/// Validate issuer URL format per RFC 8414 and OpenID Connect Core 1.0
fn validate_issuer_url(issuer: &str) -> Result<()> {
    let url = url::Url::parse(issuer)
        .map_err(|_| ApiError::invalid_token("invalid issuer URL"))?;

    let is_localhost = matches!(url.host_str(), Some("localhost") | Some("127.0.0.1") | Some("::1"));
    if url.scheme() != "https" && !is_localhost {
        return Err(ApiError::invalid_token("issuer must use HTTPS"));
    }

    if url.query().is_some() {
        return Err(ApiError::invalid_token("issuer URL must not have query string"));
    }

    if url.fragment().is_some() {
        return Err(ApiError::invalid_token("issuer URL must not have fragment"));
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(ApiError::invalid_token("issuer URL must not have userinfo"));
    }

    if let Some(host) = url.host_str() {
        for c in host.chars() {
            if !c.is_ascii() {
                return Err(ApiError::invalid_token(
                    "issuer hostname contains non-ASCII characters",
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_issuer_url_valid() {
        assert!(validate_issuer_url("https://example.com").is_ok());
        assert!(validate_issuer_url("https://example.com/").is_ok());
        assert!(validate_issuer_url("https://example.com/path").is_ok());
        assert!(validate_issuer_url("http://localhost").is_ok());
        assert!(validate_issuer_url("http://127.0.0.1").is_ok());
    }

    #[test]
    fn test_validate_issuer_url_invalid() {
        assert!(validate_issuer_url("http://example.com").is_err());
        assert!(validate_issuer_url("https://example.com?foo=bar").is_err());
        assert!(validate_issuer_url("https://example.com#frag").is_err());
        assert!(validate_issuer_url("https://user:pass@example.com").is_err());
    }
}
