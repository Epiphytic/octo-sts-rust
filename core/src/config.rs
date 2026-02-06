//! Configuration and secrets management

use crate::error::{ApiError, Result};
use crate::platform::Environment;

/// Application configuration loaded from environment
///
/// Auth-related fields (app ID, private key) are handled by `JwtSigner` implementations.
pub struct Config {
    /// Domain for audience validation (e.g., "octo-sts.example.com")
    pub domain: String,
    /// Webhook secret for signature verification
    pub github_webhook_secret: String,
}

impl Config {
    /// Load configuration from platform environment
    pub fn from_env(env: &dyn Environment) -> Result<Self> {
        Ok(Self {
            domain: env
                .get_var("DOMAIN")
                .map_err(|_| ApiError::internal("DOMAIN not configured"))?,
            github_webhook_secret: env
                .get_secret("GITHUB_WEBHOOK_SECRET")
                .map_err(|_| ApiError::internal("GITHUB_WEBHOOK_SECRET secret not set"))?,
        })
    }
}

/// Cache TTL for installation IDs (1 hour)
pub const INSTALL_CACHE_TTL_SECS: u64 = 3600;

/// Cache TTL for trust policies (5 minutes)
pub const POLICY_CACHE_TTL_SECS: u64 = 300;
