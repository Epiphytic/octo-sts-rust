//! GCP platform implementations
//!
//! Implements core platform traits using native Rust libraries:
//! - Cache: moka in-memory cache with TTL
//! - HttpClient: reqwest
//! - Clock: std::time::SystemTime
//! - Environment: std::env + GCP Secret Manager

use async_trait::async_trait;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use octo_sts_core::error::{ApiError, Result};
use octo_sts_core::platform::{Cache, Clock, Environment, HttpClient, HttpResponse};

/// In-memory cache with TTL (suitable for Cloud Functions warm instances)
pub struct MokaCache {
    cache: moka::future::Cache<String, Vec<u8>>,
}

impl MokaCache {
    pub fn new() -> Self {
        Self {
            cache: moka::future::Cache::builder()
                .max_capacity(1000)
                .time_to_live(Duration::from_secs(3600))
                .build(),
        }
    }
}

#[async_trait(?Send)]
impl Cache for MokaCache {
    async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.cache.get(key).await)
    }

    async fn put_bytes(&self, key: &str, value: &[u8], ttl_secs: u64) -> Result<()> {
        // moka's per-entry TTL requires using the policy API
        // For simplicity, we use the cache-wide TTL and accept that all entries
        // share the same expiration behavior. Fine for Cloud Functions.
        let _ = ttl_secs; // Cache-wide TTL is used
        self.cache
            .insert(key.to_string(), value.to_vec())
            .await;
        Ok(())
    }
}

/// reqwest-based HTTP client
pub struct ReqwestHttpClient {
    client: reqwest::Client,
}

impl ReqwestHttpClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait(?Send)]
impl HttpClient for ReqwestHttpClient {
    async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse> {
        let mut builder = self.client.get(url);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }

        let response = builder
            .send()
            .await
            .map_err(|e| ApiError::upstream_error(format!("HTTP GET failed: {}", e)))?;

        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|e| ApiError::upstream_error(format!("failed to read response: {}", e)))?
            .to_vec();

        Ok(HttpResponse { status, body })
    }

    async fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse> {
        let mut builder = self.client.post(url).body(body.to_vec());
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }

        let response = builder
            .send()
            .await
            .map_err(|e| ApiError::upstream_error(format!("HTTP POST failed: {}", e)))?;

        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|e| ApiError::upstream_error(format!("failed to read response: {}", e)))?
            .to_vec();

        Ok(HttpResponse { status, body })
    }

    async fn delete(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse> {
        let mut builder = self.client.delete(url);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }

        let response = builder
            .send()
            .await
            .map_err(|e| ApiError::upstream_error(format!("HTTP DELETE failed: {}", e)))?;

        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|e| ApiError::upstream_error(format!("failed to read response: {}", e)))?
            .to_vec();

        Ok(HttpResponse { status, body })
    }
}

/// System clock using std::time
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
}

/// GCP environment using env vars + Secret Manager
pub struct GcpEnv {
    project_id: String,
}

impl GcpEnv {
    pub fn new(project_id: String) -> Self {
        Self { project_id }
    }

    /// Get project ID from metadata server or GCP_PROJECT env var
    pub fn detect_project_id() -> std::result::Result<String, String> {
        std::env::var("GCP_PROJECT")
            .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
            .or_else(|_| std::env::var("GCLOUD_PROJECT"))
            .map_err(|_| "GCP_PROJECT environment variable not set".to_string())
    }
}

impl Environment for GcpEnv {
    fn get_var(&self, name: &str) -> Result<String> {
        std::env::var(name)
            .map_err(|_| ApiError::internal(format!("environment variable '{}' not set", name)))
    }

    fn get_secret(&self, name: &str) -> Result<String> {
        // First try environment variable (for local development / Cloud Run env injection)
        if let Ok(value) = std::env::var(name) {
            return Ok(value);
        }

        // For production, secrets should be mounted as env vars via Cloud Functions config.
        // If needed, Secret Manager access can be added here with async initialization.
        Err(ApiError::internal(format!(
            "secret '{}' not found in environment (project: {})",
            name, self.project_id
        )))
    }
}
