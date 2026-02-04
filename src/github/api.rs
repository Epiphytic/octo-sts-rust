//! GitHub API client
//!
//! Fetches content from GitHub repositories.

use worker::{Env, Fetch, Headers, Method, Request, RequestInit};

use crate::config::Config;
use crate::error::{ApiError, Result};

use super::auth;

const GITHUB_API_BASE: &str = "https://api.github.com";

/// Get file content from a GitHub repository
pub async fn get_file_content(
    owner: &str,
    repo: &str,
    path: &str,
    git_ref: Option<&str>,
    env: &Env,
) -> Result<String> {
    let config = Config::from_env(env)?;

    // Get installation token for this owner
    let installation_id = auth::get_installation_id(owner, &config).await?;
    let (token, _) = auth::create_installation_token(
        installation_id,
        &format!("{}/{}", owner, repo),
        &[("contents".to_string(), "read".to_string())]
            .into_iter()
            .collect(),
        &config,
    )
    .await?;

    // Build URL
    let mut url = format!(
        "{}/repos/{}/{}/contents/{}",
        GITHUB_API_BASE, owner, repo, path
    );
    if let Some(r) = git_ref {
        url = format!("{}?ref={}", url, r);
    }

    let headers = Headers::new();
    headers
        .set("Authorization", &format!("Bearer {}", token))
        .map_err(|_| ApiError::internal("failed to set headers"))?;
    headers
        .set("Accept", "application/vnd.github.raw+json")
        .map_err(|_| ApiError::internal("failed to set headers"))?;
    headers
        .set("User-Agent", "octo-sts-rust")
        .map_err(|_| ApiError::internal("failed to set headers"))?;
    headers
        .set("X-GitHub-Api-Version", "2022-11-28")
        .map_err(|_| ApiError::internal("failed to set headers"))?;

    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);

    let request =
        Request::new_with_init(&url, &init).map_err(|_| ApiError::internal("failed to create request"))?;

    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to call GitHub API: {}", e)))?;

    match response.status_code() {
        200 => response
            .text()
            .await
            .map_err(|e| ApiError::upstream_error(format!("failed to read response: {}", e))),
        404 => Err(ApiError::policy_not_found(format!(
            "file not found: {}/{}/{}",
            owner, repo, path
        ))),
        status => Err(ApiError::upstream_error(format!(
            "GitHub API error: {}",
            status
        ))),
    }
}

/// Create a check run for policy validation
pub async fn create_check_run(
    owner: &str,
    repo: &str,
    head_sha: &str,
    name: &str,
    conclusion: &str,
    title: &str,
    summary: &str,
    env: &Env,
) -> Result<()> {
    let config = Config::from_env(env)?;

    // Get installation token
    let installation_id = auth::get_installation_id(owner, &config).await?;
    let (token, _) = auth::create_installation_token(
        installation_id,
        &format!("{}/{}", owner, repo),
        &[("checks".to_string(), "write".to_string())]
            .into_iter()
            .collect(),
        &config,
    )
    .await?;

    let url = format!("{}/repos/{}/{}/check-runs", GITHUB_API_BASE, owner, repo);

    let body = serde_json::json!({
        "name": name,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": title,
            "summary": summary
        }
    });

    let headers = Headers::new();
    headers
        .set("Authorization", &format!("Bearer {}", token))
        .map_err(|_| ApiError::internal("failed to set headers"))?;
    headers
        .set("Accept", "application/vnd.github+json")
        .map_err(|_| ApiError::internal("failed to set headers"))?;
    headers
        .set("User-Agent", "octo-sts-rust")
        .map_err(|_| ApiError::internal("failed to set headers"))?;
    headers
        .set("X-GitHub-Api-Version", "2022-11-28")
        .map_err(|_| ApiError::internal("failed to set headers"))?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(body.to_string().into()));

    let request =
        Request::new_with_init(&url, &init).map_err(|_| ApiError::internal("failed to create request"))?;

    let response = Fetch::Request(request)
        .send()
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to call GitHub API: {}", e)))?;

    if response.status_code() != 201 {
        return Err(ApiError::upstream_error(format!(
            "failed to create check run: {}",
            response.status_code()
        )));
    }

    Ok(())
}
