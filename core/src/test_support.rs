//! Mock implementations of platform traits for testing

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::{ApiError, Result};
use crate::platform::{Cache, Clock, Environment, HttpClient, HttpResponse};

/// Mock cache backed by an in-memory HashMap
pub struct MockCache {
    store: Mutex<HashMap<String, Vec<u8>>>,
}

impl MockCache {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait(?Send)]
impl Cache for MockCache {
    async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let store = self.store.lock().unwrap();
        Ok(store.get(key).cloned())
    }

    async fn put_bytes(&self, key: &str, value: &[u8], _ttl_secs: u64) -> Result<()> {
        self.store.lock().unwrap().insert(key.to_string(), value.to_vec());
        Ok(())
    }
}

/// Mock HTTP client with pre-configured responses
pub struct MockHttp {
    responses: Vec<(String, HttpResponse)>,
}

impl MockHttp {
    pub fn new(responses: Vec<(String, HttpResponse)>) -> Self {
        Self { responses }
    }
}

#[async_trait(?Send)]
impl HttpClient for MockHttp {
    async fn get(&self, url: &str, _headers: &[(&str, &str)]) -> Result<HttpResponse> {
        for (pattern, response) in &self.responses {
            if url.contains(pattern) {
                return Ok(HttpResponse {
                    status: response.status,
                    body: response.body.clone(),
                });
            }
        }
        Err(ApiError::upstream_error(format!("no mock response for GET {}", url)))
    }

    async fn post(&self, url: &str, _headers: &[(&str, &str)], _body: &[u8]) -> Result<HttpResponse> {
        for (pattern, response) in &self.responses {
            if url.contains(pattern) {
                return Ok(HttpResponse {
                    status: response.status,
                    body: response.body.clone(),
                });
            }
        }
        Err(ApiError::upstream_error(format!("no mock response for POST {}", url)))
    }

    async fn delete(&self, url: &str, _headers: &[(&str, &str)]) -> Result<HttpResponse> {
        for (pattern, response) in &self.responses {
            if url.contains(pattern) {
                return Ok(HttpResponse {
                    status: response.status,
                    body: response.body.clone(),
                });
            }
        }
        Err(ApiError::upstream_error(format!("no mock response for DELETE {}", url)))
    }
}

/// Mock clock with a fixed timestamp
pub struct MockClock(pub u64);

impl Clock for MockClock {
    fn now_secs(&self) -> u64 {
        self.0
    }
}

/// Mock environment backed by an in-memory HashMap
pub struct MockEnv {
    vars: HashMap<String, String>,
    secrets: HashMap<String, String>,
}

impl MockEnv {
    pub fn new(vars: HashMap<String, String>, secrets: HashMap<String, String>) -> Self {
        Self { vars, secrets }
    }
}

impl Environment for MockEnv {
    fn get_var(&self, name: &str) -> Result<String> {
        self.vars
            .get(name)
            .cloned()
            .ok_or_else(|| ApiError::internal(format!("variable '{}' not found", name)))
    }

    fn get_secret(&self, name: &str) -> Result<String> {
        self.secrets
            .get(name)
            .cloned()
            .ok_or_else(|| ApiError::internal(format!("secret '{}' not found", name)))
    }
}
