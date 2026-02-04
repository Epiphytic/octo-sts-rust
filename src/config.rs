//! Configuration and secrets management

use worker::Env;

use crate::error::{ApiError, Result};

/// Application configuration loaded from environment
pub struct Config {
    /// Domain for audience validation (e.g., "octo-sts.example.com")
    pub domain: String,
    /// GitHub App numeric ID
    pub github_app_id: String,
    /// GitHub App private key (PEM format)
    pub github_app_private_key: String,
    /// Webhook secret for signature verification
    pub github_webhook_secret: String,
}

impl Config {
    /// Load configuration from Worker environment
    pub fn from_env(env: &Env) -> Result<Self> {
        Ok(Self {
            domain: env
                .var("DOMAIN")
                .map_err(|_| ApiError::internal("DOMAIN not configured"))?
                .to_string(),
            github_app_id: env
                .secret("GITHUB_APP_ID")
                .map_err(|_| ApiError::internal("GITHUB_APP_ID secret not set"))?
                .to_string(),
            github_app_private_key: env
                .secret("GITHUB_APP_PRIVATE_KEY")
                .map_err(|_| ApiError::internal("GITHUB_APP_PRIVATE_KEY secret not set"))?
                .to_string(),
            github_webhook_secret: env
                .secret("GITHUB_WEBHOOK_SECRET")
                .map_err(|_| ApiError::internal("GITHUB_WEBHOOK_SECRET secret not set"))?
                .to_string(),
        })
    }
}

/// KV namespace binding name
pub const KV_BINDING: &str = "OCTO_STS_KV";

/// Cache TTL for installation IDs (1 hour)
pub const INSTALL_CACHE_TTL_SECS: u64 = 3600;

/// Cache TTL for trust policies (5 minutes)
pub const POLICY_CACHE_TTL_SECS: u64 = 300;
