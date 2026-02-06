//! GitHub API client
//!
//! Fetches content from GitHub repositories.

use crate::config::Config;
use crate::error::{ApiError, Result};
use crate::platform::{Environment, HttpClient};

use super::auth;

const GITHUB_API_BASE: &str = "https://api.github.com";

/// Get file content from a GitHub repository
pub async fn get_file_content(
    owner: &str,
    repo: &str,
    path: &str,
    git_ref: Option<&str>,
    http: &dyn HttpClient,
    env: &dyn Environment,
) -> Result<String> {
    let config = Config::from_env(env)?;

    // For get_file_content we need a clock - use a simple wall clock approach
    // The caller provides http and env; we create a temporary clock for JWT generation
    // Note: This function is called in contexts where we don't have a Clock reference.
    // We accept this coupling because the JWT expiry is 10 minutes, so minor clock
    // differences don't matter for fetching policy files.
    let installation_id = auth::get_installation_id(owner, &config, http, &WallClock).await?;
    let (token, _) = auth::create_installation_token(
        installation_id,
        &format!("{}/{}", owner, repo),
        &[("contents".to_string(), "read".to_string())]
            .into_iter()
            .collect(),
        &config,
        http,
        &WallClock,
    )
    .await?;

    let mut url = format!(
        "{}/repos/{}/{}/contents/{}",
        GITHUB_API_BASE, owner, repo, path
    );
    if let Some(r) = git_ref {
        url = format!("{}?ref={}", url, r);
    }

    let auth_header = format!("Bearer {}", token);
    let headers = [
        ("Authorization", auth_header.as_str()),
        ("Accept", "application/vnd.github.raw+json"),
        ("User-Agent", "octo-sts-rust"),
        ("X-GitHub-Api-Version", "2022-11-28"),
    ];

    let response = http
        .get(&url, &headers)
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to call GitHub API: {}", e)))?;

    match response.status {
        200 => response
            .text()
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
    http: &dyn HttpClient,
    env: &dyn Environment,
) -> Result<()> {
    let config = Config::from_env(env)?;

    let installation_id = auth::get_installation_id(owner, &config, http, &WallClock).await?;
    let (token, _) = auth::create_installation_token(
        installation_id,
        &format!("{}/{}", owner, repo),
        &[("checks".to_string(), "write".to_string())]
            .into_iter()
            .collect(),
        &config,
        http,
        &WallClock,
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

    let auth_header = format!("Bearer {}", token);
    let headers = [
        ("Authorization", auth_header.as_str()),
        ("Accept", "application/vnd.github+json"),
        ("User-Agent", "octo-sts-rust"),
        ("X-GitHub-Api-Version", "2022-11-28"),
    ];

    let body_bytes = body.to_string().into_bytes();
    let response = http
        .post(&url, &headers, &body_bytes)
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to call GitHub API: {}", e)))?;

    if response.status != 201 {
        return Err(ApiError::upstream_error(format!(
            "failed to create check run: {}",
            response.status
        )));
    }

    Ok(())
}

/// Wall clock implementation for internal use in api.rs
/// This is used when we need a clock for JWT generation but the caller
/// doesn't pass one (e.g., webhook handlers, policy loading).
struct WallClock;

impl crate::platform::Clock for WallClock {
    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}
