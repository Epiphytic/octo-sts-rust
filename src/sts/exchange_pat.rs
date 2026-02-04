//! PAT (Personal Access Token) exchange endpoint
//!
//! Exchanges GitHub PAT/OAuth tokens for scoped GitHub App installation tokens.
//! This allows developers to use their `gh auth token` to get short-lived,
//! scoped tokens for specific operations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, Url};

use crate::config::Config;
use crate::error::{ApiError, Result};
use crate::github::auth;
use crate::kv;

/// PAT exchange response
#[derive(Serialize)]
pub struct ExchangeResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// GitHub user info from /user endpoint
#[derive(Deserialize)]
struct GitHubUser {
    login: String,
    id: u64,
}

/// GitHub org info from /user/orgs endpoint
#[derive(Deserialize)]
struct GitHubOrg {
    login: String,
}

/// PAT trust policy
#[derive(Debug, Serialize, Deserialize)]
pub struct PatTrustPolicy {
    /// Required org membership (user must be a member of this org)
    pub required_org: String,

    /// Permissions to grant
    pub permissions: HashMap<String, String>,

    /// Repositories to grant access to (empty = all org repos)
    #[serde(default)]
    pub repositories: Vec<String>,
}

/// Handle PAT exchange request
pub async fn handle(req: Request, env: &Env) -> Result<ExchangeResponse> {
    let config = Config::from_env(env)?;

    // 1. Parse request parameters
    let params = parse_request(&req)?;

    // 2. Extract PAT from Authorization header
    let pat = extract_bearer_token(&req)?;

    // 3. Validate PAT and get user info
    let user = validate_pat_and_get_user(&pat).await?;

    // 4. Load PAT trust policy
    let policy = load_pat_policy(&params.scope, &params.identity, env).await?;

    // 5. Check org membership
    check_org_membership(&pat, &policy.required_org, &user.login).await?;

    // 6. Get installation ID for the org
    let owner = params.scope.split('/').next().ok_or_else(|| {
        ApiError::invalid_request("scope must be in format owner/repo or owner/.github")
    })?;
    let installation_id = kv::get_or_fetch_installation(owner, env, &config).await?;

    // 7. Generate GitHub installation token with policy permissions
    let (token, expires_at) = auth::create_installation_token(
        installation_id,
        &params.scope,
        &policy.permissions,
        &config,
    )
    .await?;

    // Calculate expires_in from expires_at
    let expires_in = calculate_expires_in(&expires_at).unwrap_or(3600);

    Ok(ExchangeResponse {
        access_token: token,
        token_type: "bearer".to_string(),
        expires_in,
    })
}

/// Request parameters
struct RequestParams {
    scope: String,
    identity: String,
}

/// Parse scope and identity from query parameters
fn parse_request(req: &Request) -> Result<RequestParams> {
    let url = req.url().map_err(|_| ApiError::invalid_request("invalid URL"))?;

    let scope = get_query_param(&url, "scope")?;
    let identity = get_query_param(&url, "identity")?;

    Ok(RequestParams { scope, identity })
}

/// Extract a required query parameter
fn get_query_param(url: &Url, name: &str) -> Result<String> {
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.to_string())
        .ok_or_else(|| ApiError::invalid_request(format!("missing required parameter: {}", name)))
}

/// Extract bearer token from Authorization header
fn extract_bearer_token(req: &Request) -> Result<String> {
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

/// Validate PAT by calling GitHub API and get user info
async fn validate_pat_and_get_user(pat: &str) -> Result<GitHubUser> {
    let headers = Headers::new();
    headers
        .set("Authorization", &format!("Bearer {}", pat))
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
    init.with_method(Method::Get).with_headers(headers);

    let request = Request::new_with_init("https://api.github.com/user", &init)
        .map_err(|_| ApiError::internal("failed to create request"))?;

    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to validate PAT: {}", e)))?;

    match response.status_code() {
        200 => {
            let user: GitHubUser = response
                .json()
                .await
                .map_err(|e| ApiError::upstream_error(format!("failed to parse user info: {}", e)))?;
            Ok(user)
        }
        401 => Err(ApiError::invalid_token("invalid or expired PAT")),
        403 => Err(ApiError::permission_denied("PAT lacks required scopes")),
        _ => Err(ApiError::upstream_error(format!(
            "GitHub API error: {}",
            response.status_code()
        ))),
    }
}

/// Check if user is a member of the required org
async fn check_org_membership(pat: &str, required_org: &str, username: &str) -> Result<()> {
    let headers = Headers::new();
    headers
        .set("Authorization", &format!("Bearer {}", pat))
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
    init.with_method(Method::Get).with_headers(headers);

    // Check membership via /user/orgs
    let request = Request::new_with_init("https://api.github.com/user/orgs?per_page=100", &init)
        .map_err(|_| ApiError::internal("failed to create request"))?;

    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to check org membership: {}", e)))?;

    if response.status_code() != 200 {
        return Err(ApiError::upstream_error(format!(
            "failed to fetch user orgs: {}",
            response.status_code()
        )));
    }

    let orgs: Vec<GitHubOrg> = response
        .json()
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to parse orgs: {}", e)))?;

    // Check if user is a member of the required org (case-insensitive)
    let is_member = orgs
        .iter()
        .any(|org| org.login.eq_ignore_ascii_case(required_org));

    if !is_member {
        return Err(ApiError::permission_denied(format!(
            "user '{}' is not a member of org '{}'",
            username, required_org
        )));
    }

    Ok(())
}

/// Load PAT trust policy from the org's .github repo
async fn load_pat_policy(scope: &str, identity: &str, env: &Env) -> Result<PatTrustPolicy> {
    let parts: Vec<&str> = scope.split('/').collect();
    if parts.len() != 2 {
        return Err(ApiError::invalid_request("scope must be in format owner/repo"));
    }
    let owner = parts[0];

    let cache_key = format!("pat-policy:{}:{}", scope, identity);

    // Try cache first
    if let Some(policy) = kv::get_cached_pat_policy(&cache_key, env).await? {
        return Ok(policy);
    }

    // Fetch from GitHub (from org's .github repo)
    let path = format!(".github/chainguard/{}.pat.yaml", identity);
    let yaml_content = crate::github::api::get_file_content(owner, ".github", &path, None, env).await?;

    let policy: PatTrustPolicy = serde_yaml::from_str(&yaml_content)
        .map_err(|e| ApiError::invalid_request(format!("invalid PAT policy YAML: {}", e)))?;

    // Cache the policy
    kv::cache_pat_policy(&cache_key, &policy, 300, env).await?;

    Ok(policy)
}

/// Calculate expires_in from ISO 8601 expires_at timestamp
fn calculate_expires_in(expires_at: &str) -> Option<u64> {
    let now_ms = js_sys::Date::now();
    let now_secs = (now_ms / 1000.0) as i64;

    use chrono::{DateTime, Utc};
    let expires_dt: DateTime<Utc> = expires_at.parse().ok()?;
    let expires_secs = expires_dt.timestamp();

    let diff = expires_secs - now_secs;
    if diff > 0 {
        Some(diff as u64)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pat_policy_deserialization() {
        let yaml = r#"
required_org: Epiphytic
permissions:
  contents: write
  pull_requests: write
repositories:
  - octo-sts-rust
  - gear
"#;
        let policy: PatTrustPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.required_org, "Epiphytic");
        assert_eq!(policy.permissions.get("contents"), Some(&"write".to_string()));
        assert_eq!(policy.repositories.len(), 2);
    }

    #[test]
    fn test_pat_policy_without_repositories() {
        let yaml = r#"
required_org: Epiphytic
permissions:
  contents: read
"#;
        let policy: PatTrustPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.required_org, "Epiphytic");
        assert!(policy.repositories.is_empty());
    }
}
