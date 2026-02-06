//! Cloudflare Workers platform implementations
//!
//! Implements the core platform traits for Workers KV, Fetch API, js_sys clock, and Env.

use async_trait::async_trait;
use worker::{Env, Fetch, Headers, Method, RequestInit};

use octo_sts_core::error::{ApiError, Result};
use octo_sts_core::platform::{Cache, Clock, Environment, HttpClient, HttpResponse};

const KV_BINDING: &str = "OCTO_STS_KV";

/// Workers KV cache adapter
pub struct WorkersKvCache<'a> {
    env: &'a Env,
}

impl<'a> WorkersKvCache<'a> {
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }
}

#[async_trait(?Send)]
impl Cache for WorkersKvCache<'_> {
    async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let kv = self
            .env
            .kv(KV_BINDING)
            .map_err(|_| ApiError::internal(format!("KV binding '{}' not found", KV_BINDING)))?;

        match kv.get(key).bytes().await {
            Ok(bytes) => Ok(bytes),
            Err(e) => {
                worker::console_log!("KV get error for key '{}': {}", key, e);
                Ok(None)
            }
        }
    }

    async fn put_bytes(&self, key: &str, value: &[u8], ttl_secs: u64) -> Result<()> {
        let kv = self
            .env
            .kv(KV_BINDING)
            .map_err(|_| ApiError::internal(format!("KV binding '{}' not found", KV_BINDING)))?;

        kv.put_bytes(key, value)
            .map_err(|e| ApiError::internal(format!("failed to create KV put: {}", e)))?
            .expiration_ttl(ttl_secs)
            .execute()
            .await
            .map_err(|e| ApiError::internal(format!("failed to cache value: {}", e)))?;

        Ok(())
    }
}

/// Workers Fetch API HTTP client
pub struct WorkersFetchClient;

#[async_trait(?Send)]
impl HttpClient for WorkersFetchClient {
    async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse> {
        fetch_with_method(Method::Get, url, headers, None).await
    }

    async fn post(&self, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<HttpResponse> {
        fetch_with_method(Method::Post, url, headers, Some(body)).await
    }

    async fn delete(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse> {
        fetch_with_method(Method::Delete, url, headers, None).await
    }
}

async fn fetch_with_method(
    method: Method,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<HttpResponse> {
    let worker_headers = Headers::new();
    for (name, value) in headers {
        worker_headers
            .set(name, value)
            .map_err(|_| ApiError::internal(format!("failed to set header: {}", name)))?;
    }

    let mut init = RequestInit::new();
    init.with_method(method).with_headers(worker_headers);

    if let Some(body_bytes) = body {
        init.with_body(Some(worker::js_sys::Uint8Array::from(body_bytes).into()));
    }

    let request = worker::Request::new_with_init(url, &init)
        .map_err(|_| ApiError::internal(format!("failed to create request for {}", url)))?;

    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|e| ApiError::upstream_error(format!("fetch failed for {}: {}", url, e)))?;

    let status = response.status_code();
    let body = response
        .bytes()
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to read response body: {}", e)))?;

    Ok(HttpResponse { status, body })
}

/// js_sys clock using Date.now()
pub struct JsClock;

impl Clock for JsClock {
    fn now_secs(&self) -> u64 {
        (js_sys::Date::now() / 1000.0) as u64
    }
}

/// Workers Env adapter for Environment trait
pub struct WorkersEnv<'a> {
    env: &'a Env,
}

impl<'a> WorkersEnv<'a> {
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }
}

impl Environment for WorkersEnv<'_> {
    fn get_var(&self, name: &str) -> Result<String> {
        self.env
            .var(name)
            .map(|v| v.to_string())
            .map_err(|_| ApiError::internal(format!("variable '{}' not found", name)))
    }

    fn get_secret(&self, name: &str) -> Result<String> {
        self.env
            .secret(name)
            .map(|v| v.to_string())
            .map_err(|_| ApiError::internal(format!("secret '{}' not found", name)))
    }
}
