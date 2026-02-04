//! octo-sts-rust: GitHub Security Token Service for Cloudflare Workers
//!
//! Exchanges OIDC tokens for short-lived GitHub API tokens based on trust policies.

use worker::*;

mod config;
mod error;
mod github;
mod kv;
mod oidc;
mod policy;
mod sts;

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        .get("/", |_, _| handle_health())
        .post_async("/sts/exchange", handle_exchange)
        .post_async("/sts/revoke", handle_revoke)
        .post_async("/webhook", handle_webhook)
        .run(req, env)
        .await
}

/// Health check endpoint
fn handle_health() -> Result<Response> {
    Response::from_json(&serde_json::json!({
        "name": "octo-sts",
        "documentation": "https://github.com/octo-sts/app"
    }))
}

/// Token exchange endpoint
async fn handle_exchange(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    match sts::exchange::handle(req, &ctx.env).await {
        Ok(response) => Response::from_json(&response),
        Err(e) => e.into_response(),
    }
}

/// Token revocation endpoint
async fn handle_revoke(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    match sts::revoke::handle(req, &ctx.env).await {
        Ok(()) => Ok(Response::empty()?.with_status(204)),
        Err(e) => e.into_response(),
    }
}

/// GitHub webhook handler
async fn handle_webhook(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    match github::webhook::handle(req, &ctx.env).await {
        Ok(()) => Response::from_json(&serde_json::json!({"ok": true})),
        Err(e) => e.into_response(),
    }
}
