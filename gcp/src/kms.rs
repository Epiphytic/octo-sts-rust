//! GCP KMS JWT signer
//!
//! Signs GitHub App JWTs using GCP Cloud KMS asymmetricSign API.
//! The private key never leaves KMS — only the SHA-256 digest is sent for signing.

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;

use octo_sts_core::error::{ApiError, Result};
use octo_sts_core::platform::JwtSigner;

/// JWT signer backed by GCP Cloud KMS
///
/// Constructs the JWT header and claims locally, then sends the SHA-256 digest
/// to KMS for signing. The private key never leaves the HSM.
pub struct KmsJwtSigner {
    pub app_id: String,
    pub kms_key_name: String,
    client: reqwest::Client,
    /// Cached GCP access token: (token, expiry_secs)
    cached_token: RefCell<Option<(String, u64)>>,
}

impl KmsJwtSigner {
    pub fn new(app_id: String, kms_key_name: String) -> Self {
        Self {
            app_id,
            kms_key_name,
            client: reqwest::Client::new(),
            cached_token: RefCell::new(None),
        }
    }

    /// Get a GCP access token from the metadata server, with caching (~55 min TTL)
    async fn get_access_token(&self) -> Result<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check cache
        if let Some((ref token, expiry)) = *self.cached_token.borrow() {
            if now < expiry {
                return Ok(token.clone());
            }
        }

        // Fetch from metadata server
        let response = self
            .client
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map_err(|e| ApiError::internal(format!("failed to fetch GCP access token: {}", e)))?;

        if !response.status().is_success() {
            return Err(ApiError::internal(format!(
                "GCP metadata server error: {}",
                response.status()
            )));
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: u64,
        }

        let token_resp: TokenResponse = response
            .json()
            .await
            .map_err(|e| ApiError::internal(format!("failed to parse GCP token response: {}", e)))?;

        // Cache with 5-minute safety margin
        let expiry = now + token_resp.expires_in.saturating_sub(300);
        *self.cached_token.borrow_mut() = Some((token_resp.access_token.clone(), expiry));

        Ok(token_resp.access_token)
    }
}

#[derive(Serialize)]
struct AppJwtClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

#[derive(Serialize)]
struct AsymmetricSignRequest {
    digest: DigestWrapper,
}

#[derive(Serialize)]
struct DigestWrapper {
    sha256: String,
}

#[derive(Deserialize)]
struct AsymmetricSignResponse {
    signature: String,
}

#[async_trait(?Send)]
impl JwtSigner for KmsJwtSigner {
    async fn sign_app_jwt(&self, now_secs: i64) -> Result<String> {
        let iat = now_secs - 60;
        let exp = now_secs + 600;

        // Build header
        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT"
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());

        // Build claims
        let claims = AppJwtClaims {
            iat,
            exp,
            iss: self.app_id.clone(),
        };
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims)
            .map_err(|e| ApiError::internal(format!("failed to serialize JWT claims: {}", e)))?
            .as_bytes());

        // Compute signing input and its SHA-256 digest
        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let digest = Sha256::digest(signing_input.as_bytes());
        let digest_b64 = BASE64_STANDARD.encode(digest);

        // Get GCP access token
        let access_token = self.get_access_token().await?;

        // Call KMS asymmetricSign
        let url = format!(
            "https://cloudkms.googleapis.com/v1/{}:asymmetricSign",
            self.kms_key_name
        );

        let request_body = AsymmetricSignRequest {
            digest: DigestWrapper {
                sha256: digest_b64,
            },
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| ApiError::internal(format!("KMS asymmetricSign request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ApiError::internal(format!(
                "KMS asymmetricSign error ({}): {}",
                status, body
            )));
        }

        let sign_response: AsymmetricSignResponse = response
            .json()
            .await
            .map_err(|e| ApiError::internal(format!("failed to parse KMS response: {}", e)))?;

        // KMS returns standard base64 signature — convert to URL-safe base64 without padding
        let sig_bytes = BASE64_STANDARD
            .decode(&sign_response.signature)
            .map_err(|e| ApiError::internal(format!("invalid KMS signature encoding: {}", e)))?;
        let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);

        Ok(format!("{}.{}", signing_input, sig_b64))
    }
}
