//! GitHub App authentication
//!
//! Generates App JWTs and requests installation tokens.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use worker::{Fetch, Headers, Method, Request, RequestInit};

use crate::config::Config;
use crate::error::{ApiError, Result};

const GITHUB_API_BASE: &str = "https://api.github.com";

/// GitHub App JWT claims
#[derive(Serialize, Deserialize)]
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

    let headers = Headers::new();
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
    // Use jsonwebtoken crate for proper RS256 signing
    generate_app_jwt_with_jsonwebtoken(config)
}

/// Generate a GitHub App JWT for API authentication using jsonwebtoken
fn generate_app_jwt_with_jsonwebtoken(config: &Config) -> Result<String> {
    generate_app_jwt_with_timestamp(config, chrono_lite_now())
}

/// Generate a GitHub App JWT with a specific timestamp (for testing)
fn generate_app_jwt_with_timestamp(config: &Config, now: i64) -> Result<String> {
    use surrealdb_jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    // Apply clock skew buffer
    let iat = now - 60; // 60 second buffer for clock skew
    let exp = now + 600; // 10 minute expiry (GitHub maximum)

    let claims = AppJwtClaims {
        iat,
        exp,
        iss: config.github_app_id.clone(),
    };

    // Parse the PEM key - handle both PKCS#1 and PKCS#8 formats
    let key = EncodingKey::from_rsa_pem(config.github_app_private_key.as_bytes())
        .map_err(|e| ApiError::internal(format!("invalid private key: {}", e)))?;

    let header = Header::new(Algorithm::RS256);

    encode(&header, &claims, &key)
        .map_err(|e| ApiError::internal(format!("failed to encode JWT: {}", e)))
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

    let headers = Headers::new();
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
        let headers = Headers::new();
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

#[cfg(test)]
mod tests {
    use super::*;

    // Test RSA private key for testing (DO NOT USE IN PRODUCTION)
    // Generated specifically for tests
    const TEST_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA6MrBHOiK5PRe62kAoMcZ5Gs2H2HndnzFnRlVYVfWAIByrS9Z
DugSGRFleHtoG7a2e4bM5wrmzR72ov/+VADXENi/uxYZML5TtYD0YLnDCHXoT3tO
fGfzUy/NoPfQjFnBhPl5HOzuI7wx6NY2/YiacGPxynk4GdW4oEgPs2YQO543NWsT
K655fy/hxrNSYFKDKWtJIxMKXa7q/LnuW+aMWqTdo7VlYPU1GkSg/Caknd7utguF
5mpWeVn8bCjpeKeNVE0/EF4Be31bPY04ziMgMUrkjk3P4K/S8+EIAkvFJZzg2pT3
iHL89o4GtY/AkyPylGmYhSg/k7L2jEDq3lyPWQIDAQABAoIBAQDUrwmoQ71CWRGv
uotcWQuK6XjVSzmRw4U4dsDO4tUeODyNhci0GcsPJBm07eq8Bz7JtOrX29nqZfOo
EIJodSwItD7XyuTQ59LK7TpYdN9/h1nr5BhdCQwCYJZaDo926zonJ1ZD2yPnejWP
KMes83VGYcmy1vUuhVjc93mAyirii3hzYDCSJWgOPV/U/LV7xu5VcAGkwVW+mT0n
3A72omyQsuxsMzkMqEI/xArpj0QKJzrppG8S0JPZsXWgD442uAWzGMK4GkOj1Ywi
OhTfTJtW9KtbjjGSBM37NumjYIo+NnI5vSL02CWdQkrkIWxN9KqSLjQqKfCFxs2f
PYu7cdpRAoGBAPkSFiKHhUnoueg03RzOYB+5N/L8g2xlon1p0Re9ca8axTaTrYzo
n8A7of4LPptjLYNoQ8l+q+CZjBpYeLztkAHbC6F/fiVVKI0JC8pZNGdJPhBFrj/Z
jkFV5132ypDlN9QXRVhdk7STf9c8Q+TA41dV3z/FoNZ4HJuIA4z08oe3AoGBAO9E
urJ7iP/BQtS9K8KS+J8jy7yJgCEJ/i7fidd6yvnu7phOrUSbSOQnAE9SjK/3wkb1
VNdyXabT3IZ9ODpVvcHpwoovho3qiZ3b0ntUJEHlOm4vCDR62awFw3bdrdm8ZgF1
LLasnKSPjiRdP2gT2f36qMLY8100uuwVjO4GtAFvAoGAHyYH5qGUJb4ZIdUaofOd
SdpcCONTfEbpn02QfKuQgBmU+FJXrfuZnuzWQXMejUhF9N0hPR2+WQRa5SCTWO1M
yS6fsb7EA982hwzOkKu/Rft+64ILXKjUhY88tB+dDanc5YVTgs2RH1Ai+MPsqbsF
s3JlzQ/mIWw8B6dm6kXn3tkCgYANDUu95r0/blRt9G/JqmjDjZlUjI+fvcLO3cTQ
K1OdNKpxRoFvJ6VfRL1gllk0VCiV5FYfdo6jRhVWhMgnbnvucwj4rsUBQtUE9nPR
5HIh4hZA4nHpIvZyytGxzz/ni75ov/KTeHEHDQms9CU8UTDoCN9h2aHU6MZ1kGti
pJz3IwKBgEbqya7GswZmYXsyXP1HZlMZk+emjUSjZukNTQkksut6fnEHt/6BIMpm
9Vhm11LAE5A4QXWspnFgVPnuM8HVwTzQsjgbrlNKXT7uPQD5qu3cvmeYC2XigamA
4c/Pq3QHp/ThHVl+L9nHzg0WmgdbtyGY3seCRQYAtSVcPeIRD0eW
-----END RSA PRIVATE KEY-----"#;

    // Fixed timestamp for deterministic tests
    const TEST_TIMESTAMP: i64 = 1706900000; // 2024-02-02T18:53:20Z

    fn make_test_config() -> Config {
        Config {
            domain: "test.example.com".to_string(),
            github_app_id: "12345".to_string(),
            github_app_private_key: TEST_PRIVATE_KEY.to_string(),
            github_webhook_secret: "test-secret".to_string(),
        }
    }

    #[test]
    fn test_generate_app_jwt_produces_valid_jwt() {
        let config = make_test_config();
        let jwt = generate_app_jwt_with_timestamp(&config, TEST_TIMESTAMP)
            .expect("JWT generation should succeed");

        // JWT should have 3 parts separated by dots
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");

        // Each part should be non-empty
        assert!(!parts[0].is_empty(), "Header should not be empty");
        assert!(!parts[1].is_empty(), "Payload should not be empty");
        assert!(!parts[2].is_empty(), "Signature should not be empty");
    }

    #[test]
    fn test_generate_app_jwt_has_correct_header() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let config = make_test_config();
        let jwt = generate_app_jwt_with_timestamp(&config, TEST_TIMESTAMP)
            .expect("JWT generation should succeed");

        let parts: Vec<&str> = jwt.split('.').collect();
        let header_json = URL_SAFE_NO_PAD.decode(parts[0]).expect("Header should be valid base64");
        let header: serde_json::Value =
            serde_json::from_slice(&header_json).expect("Header should be valid JSON");

        assert_eq!(header["alg"], "RS256", "Algorithm should be RS256");
        assert_eq!(header["typ"], "JWT", "Type should be JWT");
    }

    #[test]
    fn test_generate_app_jwt_has_correct_claims() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let config = make_test_config();
        let jwt = generate_app_jwt_with_timestamp(&config, TEST_TIMESTAMP)
            .expect("JWT generation should succeed");

        let parts: Vec<&str> = jwt.split('.').collect();
        let payload_json = URL_SAFE_NO_PAD.decode(parts[1]).expect("Payload should be valid base64");
        let claims: serde_json::Value =
            serde_json::from_slice(&payload_json).expect("Payload should be valid JSON");

        assert_eq!(claims["iss"], "12345", "Issuer should be app ID");

        // Check iat is TEST_TIMESTAMP - 60 (clock skew buffer)
        let iat = claims["iat"].as_i64().expect("iat should be a number");
        assert_eq!(iat, TEST_TIMESTAMP - 60, "iat should be timestamp minus 60");

        // Check exp is TEST_TIMESTAMP + 600 (10 minute expiry)
        let exp = claims["exp"].as_i64().expect("exp should be a number");
        assert_eq!(exp, TEST_TIMESTAMP + 600, "exp should be timestamp plus 600");

        // exp - iat should be 660 seconds
        assert_eq!(exp - iat, 660, "exp - iat should be 660 seconds");
    }

    #[test]
    fn test_generate_app_jwt_with_invalid_key_fails() {
        let config = Config {
            domain: "test.example.com".to_string(),
            github_app_id: "12345".to_string(),
            github_app_private_key: "invalid-key".to_string(),
            github_webhook_secret: "test-secret".to_string(),
        };

        let result = generate_app_jwt_with_timestamp(&config, TEST_TIMESTAMP);
        assert!(result.is_err(), "Should fail with invalid key");
    }

    #[test]
    fn test_generate_app_jwt_can_be_decoded() {
        use surrealdb_jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

        let config = make_test_config();
        let jwt = generate_app_jwt_with_timestamp(&config, TEST_TIMESTAMP)
            .expect("JWT generation should succeed");

        // For testing, we'll use insecure validation that skips signature verification
        // and expiry validation (since we use a fixed past timestamp)
        let mut validation = Validation::new(Algorithm::RS256);
        validation.insecure_disable_signature_validation();
        validation.validate_exp = false; // Disable exp validation since we use a past timestamp
        validation.set_required_spec_claims::<&str>(&[]);

        let key = DecodingKey::from_secret(&[]); // Dummy key since we're not verifying

        let decoded = decode::<AppJwtClaims>(&jwt, &key, &validation)
            .expect("JWT should be decodable");

        assert_eq!(decoded.claims.iss, "12345");
        assert_eq!(decoded.claims.iat, TEST_TIMESTAMP - 60);
        assert_eq!(decoded.claims.exp, TEST_TIMESTAMP + 600);
    }
}
