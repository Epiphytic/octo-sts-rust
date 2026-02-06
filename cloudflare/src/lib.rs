//! octo-sts-rust: GitHub Security Token Service - Cloudflare Workers adapter

use worker::*;

use octo_sts_core::error::{ApiError, ErrorResponse};
use octo_sts_core::sts;

mod platform;

use platform::{JsClock, WorkersEnv, WorkersFetchClient, WorkersKvCache};

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        .get("/", |_, _| handle_health())
        .post_async("/sts/exchange", handle_exchange)
        .post_async("/sts/exchange/pat", handle_exchange_pat)
        .post_async("/sts/revoke", handle_revoke)
        .post_async("/webhook", handle_webhook)
        .run(req, env)
        .await
}

fn handle_health() -> Result<Response> {
    Response::from_json(&serde_json::json!({
        "name": "octo-sts",
        "documentation": "https://github.com/octo-sts/app"
    }))
}

async fn handle_exchange(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = &ctx.env;
    let cache = WorkersKvCache::new(env);
    let http = WorkersFetchClient;
    let clock = JsClock;
    let wenv = WorkersEnv::new(env);

    let request = match parse_exchange_request(&req) {
        Ok(r) => r,
        Err(e) => return error_response(&e),
    };

    match sts::exchange::handle(request, &cache, &http, &wenv, &clock).await {
        Ok(response) => Response::from_json(&response),
        Err(e) => error_response(&e),
    }
}

async fn handle_exchange_pat(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = &ctx.env;
    let cache = WorkersKvCache::new(env);
    let http = WorkersFetchClient;
    let clock = JsClock;
    let wenv = WorkersEnv::new(env);

    let request = match parse_pat_exchange_request(&req) {
        Ok(r) => r,
        Err(e) => return error_response(&e),
    };

    match sts::exchange_pat::handle(request, &cache, &http, &wenv, &clock).await {
        Ok(response) => Response::from_json(&response),
        Err(e) => error_response(&e),
    }
}

async fn handle_revoke(req: Request, _ctx: RouteContext<()>) -> Result<Response> {
    let http = WorkersFetchClient;

    let bearer_token = match extract_bearer_token(&req) {
        Ok(t) => t,
        Err(e) => return error_response(&e),
    };

    match sts::revoke::handle(&bearer_token, &http).await {
        Ok(()) => Ok(Response::empty()?.with_status(204)),
        Err(e) => error_response(&e),
    }
}

async fn handle_webhook(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = &ctx.env;
    let http = WorkersFetchClient;
    let wenv = WorkersEnv::new(env);

    let body = req
        .text()
        .await
        .map_err(|_| worker::Error::RustError("failed to read body".into()))?;

    let signature = req
        .headers()
        .get("X-Hub-Signature-256")
        .map_err(|_| worker::Error::RustError("failed to read headers".into()))?
        .unwrap_or_default();

    let event_type = req
        .headers()
        .get("X-GitHub-Event")
        .map_err(|_| worker::Error::RustError("failed to read headers".into()))?
        .unwrap_or_default();

    match octo_sts_core::github::webhook::handle(&body, &signature, &event_type, &http, &wenv)
        .await
    {
        Ok(()) => Response::from_json(&serde_json::json!({"ok": true})),
        Err(e) => error_response(&e),
    }
}

/// Convert ApiError to worker::Response
fn error_response(err: &ApiError) -> Result<Response> {
    let status = err.status_code();
    let body = ErrorResponse::from(err);
    Response::from_json(&body).map(|r| r.with_status(status))
}

/// Parse exchange request from worker::Request
fn parse_exchange_request(req: &Request) -> std::result::Result<sts::exchange::ExchangeRequest, ApiError> {
    let url = req
        .url()
        .map_err(|_| ApiError::invalid_request("invalid URL"))?;
    let scope = get_query_param(&url, "scope")?;
    let identity = get_query_param(&url, "identity")?;
    let bearer_token = extract_bearer_token(req)?;

    Ok(sts::exchange::ExchangeRequest {
        scope,
        identity,
        bearer_token,
    })
}

/// Parse PAT exchange request from worker::Request
fn parse_pat_exchange_request(req: &Request) -> std::result::Result<sts::exchange_pat::PatExchangeRequest, ApiError> {
    let url = req
        .url()
        .map_err(|_| ApiError::invalid_request("invalid URL"))?;
    let scope = get_query_param(&url, "scope")?;
    let identity = get_query_param(&url, "identity")?;
    let bearer_token = extract_bearer_token(req)?;

    Ok(sts::exchange_pat::PatExchangeRequest {
        scope,
        identity,
        bearer_token,
    })
}

/// Extract bearer token from Authorization header
fn extract_bearer_token(req: &Request) -> std::result::Result<String, ApiError> {
    let header = req
        .headers()
        .get("Authorization")
        .map_err(|_| ApiError::invalid_request("failed to read headers"))?
        .ok_or_else(|| ApiError::invalid_request("missing Authorization header"))?;

    if !header.starts_with("Bearer ") {
        return Err(ApiError::invalid_request(
            "Authorization header must use Bearer scheme",
        ));
    }

    Ok(header[7..].to_string())
}

/// Extract a required query parameter
fn get_query_param(url: &Url, name: &str) -> std::result::Result<String, ApiError> {
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.to_string())
        .ok_or_else(|| ApiError::invalid_request(format!("missing required parameter: {}", name)))
}
