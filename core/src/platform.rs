//! Platform abstraction traits
//!
//! These traits define the boundary between platform-agnostic core logic and
//! platform-specific implementations (Cloudflare Workers, GCP Cloud Functions, etc.)

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{ApiError, Result};

/// Key-value cache with TTL support (uses raw bytes to be dyn-compatible)
#[async_trait(?Send)]
pub trait Cache {
    async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn put_bytes(&self, key: &str, value: &[u8], ttl_secs: u64) -> Result<()>;
}

/// HTTP client for outbound requests (GitHub API, OIDC discovery)
#[async_trait(?Send)]
pub trait HttpClient {
    async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse>;
    async fn post(&self, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<HttpResponse>;
    async fn delete(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse>;
}

/// HTTP response from an outbound request
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Parse body as UTF-8 string
    pub fn text(&self) -> std::result::Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.body.clone())
    }

    /// Parse body as JSON
    pub fn json<T: DeserializeOwned>(&self) -> std::result::Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

/// Clock for current time (enables testing with deterministic timestamps)
pub trait Clock {
    fn now_secs(&self) -> u64;
}

/// Environment/secrets access
pub trait Environment {
    fn get_var(&self, name: &str) -> Result<String>;
    fn get_secret(&self, name: &str) -> Result<String>;
}

/// Typed cache get: deserialize from bytes
pub async fn cache_get<T: DeserializeOwned>(cache: &dyn Cache, key: &str) -> Result<Option<T>> {
    match cache.get_bytes(key).await? {
        Some(bytes) => {
            let value: T = serde_json::from_slice(&bytes)
                .map_err(|e| ApiError::internal(format!("cache deserialization error: {}", e)))?;
            Ok(Some(value))
        }
        None => Ok(None),
    }
}

/// Typed cache put: serialize to bytes
pub async fn cache_put<T: Serialize>(
    cache: &dyn Cache,
    key: &str,
    value: &T,
    ttl_secs: u64,
) -> Result<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| ApiError::internal(format!("cache serialization error: {}", e)))?;
    cache.put_bytes(key, &bytes, ttl_secs).await
}
