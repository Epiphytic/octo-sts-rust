//! GitHub App authentication
//!
//! Generates App JWTs and requests installation tokens.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{ApiError, Result};
use crate::platform::{Clock, HttpClient, JwtSigner};

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

/// JWT signer that uses a local PEM private key
pub struct PemJwtSigner {
    pub app_id: String,
    pub pem_key: String,
}

#[async_trait(?Send)]
impl JwtSigner for PemJwtSigner {
    async fn sign_app_jwt(&self, now_secs: i64) -> Result<String> {
        use surrealdb_jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        let iat = now_secs - 60;
        let exp = now_secs + 600;

        let claims = AppJwtClaims {
            iat,
            exp,
            iss: self.app_id.clone(),
        };

        let key = EncodingKey::from_rsa_pem(self.pem_key.as_bytes())
            .map_err(|e| ApiError::internal(format!("invalid private key: {}", e)))?;

        let header = Header::new(Algorithm::RS256);

        encode(&header, &claims, &key)
            .map_err(|e| ApiError::internal(format!("failed to encode JWT: {}", e)))
    }
}

/// Create a GitHub installation token with scoped permissions
///
/// If `repositories` is non-empty, the token is restricted to those repos.
/// If empty, the token has access to all repos the installation can access.
pub async fn create_installation_token(
    installation_id: u64,
    repositories: &[String],
    permissions: &HashMap<String, String>,
    signer: &dyn JwtSigner,
    http: &dyn HttpClient,
    clock: &dyn Clock,
) -> Result<(String, String)> {
    let app_jwt = signer.sign_app_jwt(clock.now_secs() as i64).await?;

    let body = if repositories.is_empty() {
        serde_json::json!({
            "permissions": permissions
        })
    } else {
        serde_json::json!({
            "repositories": repositories,
            "permissions": permissions
        })
    };

    let url = format!(
        "{}/app/installations/{}/access_tokens",
        GITHUB_API_BASE, installation_id
    );

    let auth_header = format!("Bearer {}", app_jwt);
    let headers = [
        ("Authorization", auth_header.as_str()),
        ("Accept", "application/vnd.github+json"),
        ("User-Agent", "octo-sts-rust"),
        ("X-GitHub-Api-Version", "2022-11-28"),
    ];

    let body_bytes = body.to_string().into_bytes();
    let response = http
        .post(&url, &headers, &body_bytes)
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to call GitHub API: {}", e)))?;

    if response.status != 201 {
        let error_body = response.text().unwrap_or_else(|_| "unknown error".to_string());
        return Err(ApiError::upstream_error(format!(
            "GitHub API error ({}): {}",
            response.status, error_body
        )));
    }

    let token_response: InstallationTokenResponse = response
        .json()
        .map_err(|e| ApiError::upstream_error(format!("failed to parse response: {}", e)))?;

    Ok((token_response.token, token_response.expires_at))
}

/// Get installation ID for an owner
pub async fn get_installation_id(
    owner: &str,
    signer: &dyn JwtSigner,
    http: &dyn HttpClient,
    clock: &dyn Clock,
) -> Result<u64> {
    let app_jwt = signer.sign_app_jwt(clock.now_secs() as i64).await?;

    let url = format!("{}/orgs/{}/installation", GITHUB_API_BASE, owner);
    let auth_header = format!("Bearer {}", app_jwt);
    let headers = [
        ("Authorization", auth_header.as_str()),
        ("Accept", "application/vnd.github+json"),
        ("User-Agent", "octo-sts-rust"),
    ];

    let mut response = http
        .get(&url, &headers)
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to call GitHub API: {}", e)))?;

    // Try org endpoint first, fall back to user endpoint
    if response.status == 404 {
        let url = format!("{}/users/{}/installation", GITHUB_API_BASE, owner);
        response = http
            .get(&url, &headers)
            .await
            .map_err(|e| ApiError::upstream_error(format!("failed to call GitHub API: {}", e)))?;
    }

    if response.status == 404 {
        return Err(ApiError::installation_not_found(format!(
            "GitHub App not installed for '{}'",
            owner
        )));
    }

    if response.status != 200 {
        return Err(ApiError::upstream_error(format!(
            "GitHub API error: {}",
            response.status
        )));
    }

    #[derive(Deserialize)]
    struct InstallationResponse {
        id: u64,
    }

    let installation: InstallationResponse = response
        .json()
        .map_err(|e| ApiError::upstream_error(format!("failed to parse response: {}", e)))?;

    Ok(installation.id)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    const TEST_TIMESTAMP: i64 = 1706900000;

    fn make_test_signer() -> PemJwtSigner {
        PemJwtSigner {
            app_id: "12345".to_string(),
            pem_key: TEST_PRIVATE_KEY.to_string(),
        }
    }

    #[tokio::test]
    async fn test_generate_app_jwt_produces_valid_jwt() {
        let signer = make_test_signer();
        let jwt = signer
            .sign_app_jwt(TEST_TIMESTAMP)
            .await
            .expect("JWT generation should succeed");

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");

        assert!(!parts[0].is_empty(), "Header should not be empty");
        assert!(!parts[1].is_empty(), "Payload should not be empty");
        assert!(!parts[2].is_empty(), "Signature should not be empty");
    }

    #[tokio::test]
    async fn test_generate_app_jwt_has_correct_header() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let signer = make_test_signer();
        let jwt = signer
            .sign_app_jwt(TEST_TIMESTAMP)
            .await
            .expect("JWT generation should succeed");

        let parts: Vec<&str> = jwt.split('.').collect();
        let header_json = URL_SAFE_NO_PAD.decode(parts[0]).expect("Header should be valid base64");
        let header: serde_json::Value =
            serde_json::from_slice(&header_json).expect("Header should be valid JSON");

        assert_eq!(header["alg"], "RS256", "Algorithm should be RS256");
        assert_eq!(header["typ"], "JWT", "Type should be JWT");
    }

    #[tokio::test]
    async fn test_generate_app_jwt_has_correct_claims() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let signer = make_test_signer();
        let jwt = signer
            .sign_app_jwt(TEST_TIMESTAMP)
            .await
            .expect("JWT generation should succeed");

        let parts: Vec<&str> = jwt.split('.').collect();
        let payload_json = URL_SAFE_NO_PAD.decode(parts[1]).expect("Payload should be valid base64");
        let claims: serde_json::Value =
            serde_json::from_slice(&payload_json).expect("Payload should be valid JSON");

        assert_eq!(claims["iss"], "12345", "Issuer should be app ID");

        let iat = claims["iat"].as_i64().expect("iat should be a number");
        assert_eq!(iat, TEST_TIMESTAMP - 60, "iat should be timestamp minus 60");

        let exp = claims["exp"].as_i64().expect("exp should be a number");
        assert_eq!(exp, TEST_TIMESTAMP + 600, "exp should be timestamp plus 600");

        assert_eq!(exp - iat, 660, "exp - iat should be 660 seconds");
    }

    #[tokio::test]
    async fn test_generate_app_jwt_with_invalid_key_fails() {
        let signer = PemJwtSigner {
            app_id: "12345".to_string(),
            pem_key: "invalid-key".to_string(),
        };

        let result = signer.sign_app_jwt(TEST_TIMESTAMP).await;
        assert!(result.is_err(), "Should fail with invalid key");
    }

    #[tokio::test]
    async fn test_generate_app_jwt_can_be_decoded() {
        use surrealdb_jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

        let signer = make_test_signer();
        let jwt = signer
            .sign_app_jwt(TEST_TIMESTAMP)
            .await
            .expect("JWT generation should succeed");

        let mut validation = Validation::new(Algorithm::RS256);
        validation.insecure_disable_signature_validation();
        validation.validate_exp = false;
        validation.set_required_spec_claims::<&str>(&[]);

        let key = DecodingKey::from_secret(&[]);

        let decoded = decode::<AppJwtClaims>(&jwt, &key, &validation)
            .expect("JWT should be decodable");

        assert_eq!(decoded.claims.iss, "12345");
        assert_eq!(decoded.claims.iat, TEST_TIMESTAMP - 60);
        assert_eq!(decoded.claims.exp, TEST_TIMESTAMP + 600);
    }

    /// Generate a fresh RSA key pair at runtime (never touches disk)
    fn generate_rsa_keypair() -> (String, String) {
        use rand::rngs::OsRng;
        use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
        use rsa::RsaPrivateKey;

        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("key generation failed");
        let private_pem = private_key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("private key PEM export failed")
            .to_string();
        let public_pem = private_key
            .to_public_key()
            .to_pkcs1_pem(LineEnding::LF)
            .expect("public key PEM export failed");
        (private_pem, public_pem)
    }

    #[tokio::test]
    async fn test_generated_key_signs_valid_jwt() {
        let (private_pem, _public_pem) = generate_rsa_keypair();

        let signer = PemJwtSigner {
            app_id: "99999".to_string(),
            pem_key: private_pem,
        };

        let jwt = signer
            .sign_app_jwt(TEST_TIMESTAMP)
            .await
            .expect("signing with generated key should succeed");

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");
    }

    #[tokio::test]
    async fn test_generated_key_jwt_verifies_with_public_key() {
        use surrealdb_jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

        let (private_pem, public_pem) = generate_rsa_keypair();

        let signer = PemJwtSigner {
            app_id: "42".to_string(),
            pem_key: private_pem,
        };

        let jwt = signer
            .sign_app_jwt(TEST_TIMESTAMP)
            .await
            .expect("signing should succeed");

        // Verify with the matching public key (full cryptographic verification)
        let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .expect("public key should be valid");

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.set_required_spec_claims::<&str>(&[]);

        let decoded = decode::<AppJwtClaims>(&jwt, &decoding_key, &validation)
            .expect("JWT signature should verify with matching public key");

        assert_eq!(decoded.claims.iss, "42");
        assert_eq!(decoded.claims.iat, TEST_TIMESTAMP - 60);
        assert_eq!(decoded.claims.exp, TEST_TIMESTAMP + 600);
    }

    #[tokio::test]
    async fn test_generated_key_jwt_fails_with_wrong_public_key() {
        use surrealdb_jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

        let (private_pem, _) = generate_rsa_keypair();
        let (_, wrong_public_pem) = generate_rsa_keypair();

        let signer = PemJwtSigner {
            app_id: "42".to_string(),
            pem_key: private_pem,
        };

        let jwt = signer
            .sign_app_jwt(TEST_TIMESTAMP)
            .await
            .expect("signing should succeed");

        // Verification with a different key pair should fail
        let wrong_key = DecodingKey::from_rsa_pem(wrong_public_pem.as_bytes())
            .expect("public key should be valid");

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.set_required_spec_claims::<&str>(&[]);

        let result = decode::<AppJwtClaims>(&jwt, &wrong_key, &validation);
        assert!(result.is_err(), "JWT should NOT verify with wrong public key");
    }
}
