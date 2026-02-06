//! octo-sts-rust: GitHub Security Token Service - GCP Cloud Functions adapter
//!
//! Lightweight HTTP server using hyper, deployable as a GCP Cloud Function or Cloud Run service.
//! Uses single-threaded tokio runtime (compatible with core's !Send async traits).

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use std::sync::Arc;

use octo_sts_core::error::{ApiError, ErrorResponse};
use octo_sts_core::github::auth::PemJwtSigner;
use octo_sts_core::platform::JwtSigner;
use octo_sts_core::sts;

mod kms;
mod platform;

use kms::KmsJwtSigner;
use platform::{GcpEnv, MokaCache, ReqwestHttpClient, SystemClock};

/// Shared application state
struct AppState {
    cache: MokaCache,
    http: ReqwestHttpClient,
    clock: SystemClock,
    env: GcpEnv,
    signer: Box<dyn JwtSigner>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .expect("PORT must be a number");

    let project_id = GcpEnv::detect_project_id().unwrap_or_else(|_| "unknown".into());

    // Detect signer mode: KMS if KMS_KEY_NAME is set, else PEM
    let signer: Box<dyn JwtSigner> = if let Ok(kms_key_name) = std::env::var("KMS_KEY_NAME") {
        let app_id = std::env::var("GITHUB_APP_ID")
            .expect("GITHUB_APP_ID must be set when using KMS signing");
        eprintln!(
            "octo-sts-gcp: using KMS signer (key: {})",
            kms_key_name
        );
        Box::new(KmsJwtSigner::new(app_id, kms_key_name))
    } else {
        let app_id = std::env::var("GITHUB_APP_ID")
            .expect("GITHUB_APP_ID must be set");
        let pem_key = std::env::var("GITHUB_APP_PRIVATE_KEY")
            .expect("GITHUB_APP_PRIVATE_KEY must be set when not using KMS");
        eprintln!("octo-sts-gcp: using PEM signer");
        Box::new(PemJwtSigner {
            app_id,
            pem_key,
        })
    };

    let state = Arc::new(AppState {
        cache: MokaCache::new(),
        http: ReqwestHttpClient::new(),
        clock: SystemClock,
        env: GcpEnv::new(project_id),
        signer,
    });

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .expect("failed to bind");

    eprintln!("octo-sts-gcp listening on port {}", port);

    loop {
        let (stream, _) = listener.accept().await.expect("accept failed");
        let state = state.clone();

        // Each connection is handled sequentially (single-threaded runtime)
        let io = hyper_util::rt::TokioIo::new(stream);
        let service = service_fn(move |req| {
            let state = state.clone();
            async move { handle_request(req, &state).await }
        });

        if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
            eprintln!("connection error: {}", e);
        }
    }
}

type HyperResponse = Response<Full<Bytes>>;

async fn handle_request(
    req: Request<Incoming>,
    state: &AppState,
) -> Result<HyperResponse, std::convert::Infallible> {
    let result = route_request(req, state).await;
    Ok(result)
}

async fn route_request(req: Request<Incoming>, state: &AppState) -> HyperResponse {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    match (method, path.as_str()) {
        (Method::GET, "/") => handle_health(),
        (Method::POST, "/sts/exchange") => handle_exchange(req, state).await,
        (Method::POST, "/sts/exchange/pat") => handle_exchange_pat(req, state).await,
        (Method::POST, "/sts/revoke") => handle_revoke(req, state).await,
        (Method::POST, "/webhook") => handle_webhook(req, state).await,
        _ => json_response(StatusCode::NOT_FOUND, &serde_json::json!({"error": "not_found"})),
    }
}

fn handle_health() -> HyperResponse {
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "name": "octo-sts",
            "platform": "gcp",
            "documentation": "https://github.com/octo-sts/app"
        }),
    )
}

async fn handle_exchange(req: Request<Incoming>, state: &AppState) -> HyperResponse {
    let bearer_token = match extract_bearer_token(req.headers()) {
        Ok(t) => t,
        Err(e) => return error_response(&e),
    };

    let query = req.uri().query().unwrap_or("");
    let params = match parse_exchange_params(query) {
        Ok(p) => p,
        Err(e) => return error_response(&e),
    };

    let request = sts::exchange::ExchangeRequest {
        scope: params.0,
        identity: params.1,
        bearer_token,
    };

    match sts::exchange::handle(
        request,
        &state.cache,
        &state.http,
        &state.env,
        &state.clock,
        state.signer.as_ref(),
    )
    .await
    {
        Ok(response) => json_response(StatusCode::OK, &response),
        Err(e) => error_response(&e),
    }
}

async fn handle_exchange_pat(req: Request<Incoming>, state: &AppState) -> HyperResponse {
    let bearer_token = match extract_bearer_token(req.headers()) {
        Ok(t) => t,
        Err(e) => return error_response(&e),
    };

    let query = req.uri().query().unwrap_or("");
    let params = match parse_exchange_params(query) {
        Ok(p) => p,
        Err(e) => return error_response(&e),
    };

    let request = sts::exchange_pat::PatExchangeRequest {
        scope: params.0,
        identity: params.1,
        bearer_token,
    };

    match sts::exchange_pat::handle(
        request,
        &state.cache,
        &state.http,
        &state.clock,
        state.signer.as_ref(),
    )
    .await
    {
        Ok(response) => json_response(StatusCode::OK, &response),
        Err(e) => error_response(&e),
    }
}

async fn handle_revoke(req: Request<Incoming>, state: &AppState) -> HyperResponse {
    let bearer_token = match extract_bearer_token(req.headers()) {
        Ok(t) => t,
        Err(e) => return error_response(&e),
    };

    match sts::revoke::handle(&bearer_token, &state.http).await {
        Ok(()) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Full::new(Bytes::new()))
            .unwrap(),
        Err(e) => error_response(&e),
    }
}

async fn handle_webhook(req: Request<Incoming>, state: &AppState) -> HyperResponse {
    let signature = req
        .headers()
        .get("X-Hub-Signature-256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let event_type = req
        .headers()
        .get("X-GitHub-Event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let body = match req.collect().await {
        Ok(b) => String::from_utf8_lossy(&b.to_bytes()).to_string(),
        Err(_) => return error_response(&ApiError::invalid_request("failed to read body")),
    };

    match octo_sts_core::github::webhook::handle(
        &body,
        &signature,
        &event_type,
        &state.http,
        &state.env,
        state.signer.as_ref(),
    )
    .await
    {
        Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"ok": true})),
        Err(e) => error_response(&e),
    }
}

/// Parse scope and identity from query string
fn parse_exchange_params(query: &str) -> Result<(String, String), ApiError> {
    let url = url::Url::parse(&format!("http://localhost?{}", query))
        .map_err(|_| ApiError::invalid_request("invalid query string"))?;

    let scope = url
        .query_pairs()
        .find(|(k, _)| k == "scope")
        .map(|(_, v)| v.to_string())
        .ok_or_else(|| ApiError::invalid_request("missing required parameter: scope"))?;

    let identity = url
        .query_pairs()
        .find(|(k, _)| k == "identity")
        .map(|(_, v)| v.to_string())
        .ok_or_else(|| ApiError::invalid_request("missing required parameter: identity"))?;

    Ok((scope, identity))
}

fn extract_bearer_token(headers: &hyper::HeaderMap) -> Result<String, ApiError> {
    let header = headers
        .get("Authorization")
        .ok_or_else(|| ApiError::invalid_request("missing Authorization header"))?
        .to_str()
        .map_err(|_| ApiError::invalid_request("invalid Authorization header encoding"))?;

    if !header.starts_with("Bearer ") {
        return Err(ApiError::invalid_request(
            "Authorization header must use Bearer scheme",
        ));
    }

    Ok(header[7..].to_string())
}

fn error_response(err: &ApiError) -> HyperResponse {
    let status =
        StatusCode::from_u16(err.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = ErrorResponse::from(err);
    json_response(status, &body)
}

fn json_response<T: serde::Serialize>(status: StatusCode, body: &T) -> HyperResponse {
    let json = serde_json::to_vec(body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(json)))
        .unwrap()
}
