//! OIDC token validation
//!
//! Validates OIDC tokens by verifying signatures and checking claims.

use surrealdb_jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::discovery::fetch_discovery;
use super::jwks::fetch_jwks;
use crate::error::{ApiError, Result};
use crate::platform::{Clock, HttpClient};

/// OIDC token claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClaims {
    /// Issuer
    pub iss: String,

    /// Subject
    pub sub: String,

    /// Audience (can be string or array)
    #[serde(deserialize_with = "deserialize_audience")]
    pub aud: Vec<String>,

    /// Expiration time
    pub exp: u64,

    /// Issued at
    pub iat: u64,

    /// Not before (optional)
    #[serde(default)]
    pub nbf: Option<u64>,

    /// Additional claims
    #[serde(flatten)]
    pub custom_claims: HashMap<String, serde_json::Value>,
}

/// Deserialize audience as either string or array
fn deserialize_audience<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};

    struct AudienceVisitor;

    impl<'de> Visitor<'de> for AudienceVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("string or array of strings")
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Vec<String>, E>
        where
            E: de::Error,
        {
            Ok(vec![value.to_string()])
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Vec<String>, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = seq.next_element()? {
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_any(AudienceVisitor)
}

/// Validate an OIDC token and return its claims
pub async fn validate_token(token: &str, http: &dyn HttpClient, clock: &dyn Clock) -> Result<OidcClaims> {
    // Decode header to get key ID and algorithm
    let header = decode_header(token)
        .map_err(|e| ApiError::invalid_token(format!("invalid JWT header: {}", e)))?;

    // Extract issuer from token (decode without verification first)
    let claims_preview = extract_unverified_claims(token)?;

    // Validate issuer format
    validate_issuer(&claims_preview.iss)?;

    // Validate subject format
    validate_subject(&claims_preview.sub)?;

    // Validate audience format
    for aud in &claims_preview.aud {
        validate_audience(aud)?;
    }

    // Fetch discovery document
    let discovery = fetch_discovery(&claims_preview.iss, http).await?;

    // Fetch JWKS
    let jwks = fetch_jwks(&discovery.jwks_uri, http).await?;

    // Find the key
    let kid = header.kid.as_ref().ok_or_else(|| {
        ApiError::invalid_token("JWT missing 'kid' header")
    })?;

    let jwk = jwks
        .find(kid)
        .ok_or_else(|| ApiError::token_verification_failed(format!("key '{}' not found in JWKS", kid)))?;

    // Build decoding key
    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| ApiError::token_verification_failed(format!("invalid JWK: {}", e)))?;

    // Set up validation
    // Note: We disable automatic exp validation because the JWT library uses std::time
    // which is not available in WASM. We validate expiration manually below.
    let mut validation = Validation::new(header.alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.set_issuer(&[&claims_preview.iss]);

    // Decode and verify signature
    let token_data = decode::<OidcClaims>(token, &decoding_key, &validation)
        .map_err(|e| ApiError::token_verification_failed(format!("token verification failed: {}", e)))?;

    // Manually validate time-based claims using platform clock
    let now_secs = clock.now_secs() as u64;

    // Validate expiration (exp)
    if token_data.claims.exp <= now_secs {
        return Err(ApiError::invalid_token("token has expired"));
    }

    // Validate not-before (nbf) if present
    if let Some(nbf) = token_data.claims.nbf {
        if nbf > now_secs + 60 {
            return Err(ApiError::invalid_token("token is not yet valid (nbf claim)"));
        }
    }

    // Validate issued-at (iat) - sanity checks
    let iat = token_data.claims.iat;

    if iat > now_secs + 60 {
        return Err(ApiError::invalid_token("token issued in the future (iat claim)"));
    }

    let max_age_secs = 24 * 60 * 60;
    if iat + max_age_secs < now_secs {
        return Err(ApiError::invalid_token("token is too old (iat claim)"));
    }

    if iat >= token_data.claims.exp {
        return Err(ApiError::invalid_token("invalid token: iat >= exp"));
    }

    Ok(token_data.claims)
}

/// Extract claims without verifying signature (for getting issuer to fetch JWKS)
fn extract_unverified_claims(token: &str) -> Result<OidcClaims> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(ApiError::invalid_token("invalid JWT format"));
    }

    let payload = base64_url_decode(parts[1])?;
    let claims: OidcClaims = serde_json::from_slice(&payload)
        .map_err(|e| ApiError::invalid_token(format!("invalid JWT claims: {}", e)))?;

    Ok(claims)
}

/// Base64 URL decode
fn base64_url_decode(input: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| {
            use base64::engine::general_purpose::URL_SAFE;
            URL_SAFE.decode(input)
        })
        .map_err(|e| ApiError::invalid_token(format!("invalid base64: {}", e)))
}

/// Validate issuer format per OIDC spec
fn validate_issuer(issuer: &str) -> Result<()> {
    if issuer.is_empty() {
        return Err(ApiError::invalid_token("issuer cannot be empty"));
    }

    if issuer.len() > 255 {
        return Err(ApiError::invalid_token("issuer too long"));
    }

    for c in issuer.chars() {
        if c.is_control() {
            return Err(ApiError::invalid_token("issuer contains control characters"));
        }
    }

    Ok(())
}

/// Validate subject format per OIDC spec
fn validate_subject(subject: &str) -> Result<()> {
    if subject.is_empty() {
        return Err(ApiError::invalid_token("subject cannot be empty"));
    }

    if subject.len() > 255 {
        return Err(ApiError::invalid_token("subject too long"));
    }

    let dangerous_chars = ['<', '>', '"', '\'', '\\', '`', '|', '&'];
    for c in subject.chars() {
        if c.is_control() || c.is_whitespace() {
            return Err(ApiError::invalid_token("subject contains invalid characters"));
        }
        if dangerous_chars.contains(&c) {
            return Err(ApiError::invalid_token("subject contains dangerous characters"));
        }
    }

    Ok(())
}

/// Validate audience format per OIDC spec
fn validate_audience(audience: &str) -> Result<()> {
    if audience.is_empty() {
        return Err(ApiError::invalid_token("audience cannot be empty"));
    }

    if audience.len() > 255 {
        return Err(ApiError::invalid_token("audience too long"));
    }

    let dangerous_chars = ['"', '\'', '`', '|', '&', '[', ']'];
    for c in audience.chars() {
        if c.is_control() || c.is_whitespace() {
            return Err(ApiError::invalid_token("audience contains invalid characters"));
        }
        if dangerous_chars.contains(&c) {
            return Err(ApiError::invalid_token("audience contains dangerous characters"));
        }
    }

    Ok(())
}
