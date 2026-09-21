//! PAT (Personal Access Token) exchange endpoint
//!
//! Exchanges GitHub PAT/OAuth tokens for scoped GitHub App installation tokens.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::config::INSTALL_CACHE_TTL_SECS;
use crate::error::{ApiError, Result};
use crate::github::auth;
use crate::platform::{cache_get, cache_put, Cache, Clock, HttpClient, JwtSigner};

/// PAT exchange response
#[derive(Serialize)]
pub struct ExchangeResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Platform-neutral PAT exchange request
pub struct PatExchangeRequest {
    pub scope: String,
    pub identity: String,
    pub bearer_token: String,
}

/// GitHub user info from /user endpoint
#[derive(Deserialize)]
struct GitHubUser {
    login: String,
    #[allow(dead_code)]
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
    /// Required organization membership or authenticated user-account login
    pub required_org: String,

    /// Permissions to grant
    pub permissions: HashMap<String, String>,

    /// Repositories to grant access to (empty = all org repos)
    #[serde(default)]
    pub repositories: Vec<String>,
}

/// Handle PAT exchange request
pub async fn handle(
    request: PatExchangeRequest,
    cache: &dyn Cache,
    http: &dyn HttpClient,
    clock: &dyn Clock,
    signer: &dyn JwtSigner,
) -> Result<ExchangeResponse> {
    // 1. Validate PAT and get user info
    let user = validate_pat_and_get_user(&request.bearer_token, http).await?;

    // 2. Load PAT trust policy
    let policy = load_pat_policy(&request.scope, &request.identity, cache, http, signer, clock).await?;

    // 3. Check organization membership or authenticated account ownership
    check_org_membership(&request.bearer_token, &policy.required_org, &user.login, http).await?;

    // 4. Validate repository access
    let parts: Vec<&str> = request.scope.split('/').collect();
    if parts.len() != 2 {
        return Err(ApiError::invalid_request(
            "scope must be in format owner/repo or owner/.github",
        ));
    }
    let owner = parts[0];
    let requested_repo = parts[1];

    check_repository_access(&policy, requested_repo)?;

    // 5. Get installation ID for the org
    let installation_id = get_or_fetch_installation(owner, cache, http, signer, clock).await?;

    // 6. Generate GitHub installation token with policy permissions
    let token_repos = if policy.repositories.is_empty() {
        vec![requested_repo.to_string()]
    } else {
        policy.repositories.clone()
    };

    let (token, expires_at) = auth::create_installation_token(
        installation_id,
        &token_repos,
        &policy.permissions,
        signer,
        http,
        clock,
    )
    .await?;

    let expires_in = calculate_expires_in(&expires_at, clock).unwrap_or(3600);

    Ok(ExchangeResponse {
        access_token: token,
        token_type: "bearer".to_string(),
        expires_in,
    })
}

/// Get installation ID from cache or fetch from GitHub
async fn get_or_fetch_installation(
    owner: &str,
    cache: &dyn Cache,
    http: &dyn HttpClient,
    signer: &dyn JwtSigner,
    clock: &dyn Clock,
) -> Result<u64> {
    let cache_key = format!("install:{}", owner);

    if let Ok(Some(id)) = cache_get::<u64>(cache, &cache_key).await {
        return Ok(id);
    }

    let installation_id = auth::get_installation_id(owner, signer, http, clock).await?;

    let _ = cache_put(cache, &cache_key, &installation_id, INSTALL_CACHE_TTL_SECS).await;

    Ok(installation_id)
}

/// Validate PAT by calling GitHub API and get user info
async fn validate_pat_and_get_user(pat: &str, http: &dyn HttpClient) -> Result<GitHubUser> {
    let auth_header = format!("Bearer {}", pat);
    let headers = [
        ("Authorization", auth_header.as_str()),
        ("Accept", "application/vnd.github+json"),
        ("User-Agent", "octo-sts-rust"),
        ("X-GitHub-Api-Version", "2022-11-28"),
    ];

    let response = http
        .get("https://api.github.com/user", &headers)
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to validate PAT: {}", e)))?;

    match response.status {
        200 => {
            let user: GitHubUser = response
                .json()
                .map_err(|e| ApiError::upstream_error(format!("failed to parse user info: {}", e)))?;
            Ok(user)
        }
        401 => Err(ApiError::invalid_token("invalid or expired PAT")),
        403 => Err(ApiError::permission_denied("PAT lacks required scopes")),
        _ => Err(ApiError::upstream_error(format!(
            "GitHub API error: {}",
            response.status
        ))),
    }
}

/// Check if the requested repository is allowed by the policy
fn check_repository_access(policy: &PatTrustPolicy, requested_repo: &str) -> Result<()> {
    if policy.repositories.is_empty() {
        return Ok(());
    }

    let is_allowed = policy
        .repositories
        .iter()
        .any(|r| r.eq_ignore_ascii_case(requested_repo));

    if !is_allowed {
        return Err(ApiError::permission_denied(format!(
            "repository '{}' is not allowed by this policy",
            requested_repo
        )));
    }

    Ok(())
}

/// Check organization membership or ownership, using the login validated by /user
async fn check_org_membership(
    pat: &str,
    required_org: &str,
    username: &str,
    http: &dyn HttpClient,
) -> Result<()> {
    // Only the authenticated /user login may establish ownership. Do this before
    // /user/orgs: an owner PAT need not have organization-reading scopes.
    // Collaborator access does not establish ownership or org membership.
    if username.eq_ignore_ascii_case(required_org) {
        return Ok(());
    }

    let auth_header = format!("Bearer {}", pat);
    let headers = [
        ("Authorization", auth_header.as_str()),
        ("Accept", "application/vnd.github+json"),
        ("User-Agent", "octo-sts-rust"),
        ("X-GitHub-Api-Version", "2022-11-28"),
    ];

    let response = http
        .get("https://api.github.com/user/orgs?per_page=100", &headers)
        .await
        .map_err(|e| ApiError::upstream_error(format!("failed to check org membership: {}", e)))?;

    if response.status != 200 {
        return Err(ApiError::upstream_error(format!(
            "failed to fetch user orgs: {}",
            response.status
        )));
    }

    let orgs: Vec<GitHubOrg> = response
        .json()
        .map_err(|e| ApiError::upstream_error(format!("failed to parse orgs: {}", e)))?;

    let is_member = orgs
        .iter()
        .any(|org| org.login.eq_ignore_ascii_case(required_org));

    if !is_member {
        return Err(ApiError::permission_denied(format!(
            "user '{}' is neither the required account nor a member of org '{}'",
            username, required_org
        )));
    }

    Ok(())
}

/// Load PAT trust policy from the org's .github repo
async fn load_pat_policy(
    scope: &str,
    identity: &str,
    cache: &dyn Cache,
    http: &dyn HttpClient,
    signer: &dyn JwtSigner,
    clock: &dyn Clock,
) -> Result<PatTrustPolicy> {
    crate::policy::validate_identity(identity)?;

    let parts: Vec<&str> = scope.split('/').collect();
    if parts.len() != 2 {
        return Err(ApiError::invalid_request("scope must be in format owner/repo"));
    }
    let owner = parts[0];

    let cache_key = format!("pat-policy:{}:{}", scope, identity);

    // Try cache first
    if let Some(policy) = cache_get::<PatTrustPolicy>(cache, &cache_key).await? {
        return Ok(policy);
    }

    // Fetch from GitHub (from org's .github repo)
    let path = format!(".github/chainguard/{}.pat.yaml", identity);
    let yaml_content = crate::github::api::get_file_content(owner, ".github", &path, None, http, signer, clock).await?;

    let policy: PatTrustPolicy = serde_yaml::from_str(&yaml_content)
        .map_err(|e| ApiError::invalid_request(format!("invalid PAT policy YAML: {}", e)))?;

    // Cache the policy
    let _ = cache_put(cache, &cache_key, &policy, 300).await;

    Ok(policy)
}

/// Calculate expires_in from ISO 8601 expires_at timestamp
fn calculate_expires_in(expires_at: &str, clock: &dyn Clock) -> Option<u64> {
    let now_secs = clock.now_secs() as i64;

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
    use super::{check_org_membership, check_repository_access, PatTrustPolicy};
    use crate::error::ApiError;
    use crate::platform::HttpResponse;
    use crate::test_support::MockHttp;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_check_org_membership_org_member_ok() {
        let http = MockHttp::new(vec![(
            "/user/orgs".to_string(),
            HttpResponse {
                status: 200,
                body: br#"[{"login":"Epiphytic"}]"#.to_vec(),
            },
        )]);
        check_org_membership("pat", "ePiPhYtIc", "someuser", &http)
            .await
            .expect("org member must pass");
    }

    #[tokio::test]
    async fn test_check_org_membership_owner_federation_ok() {
        // No org endpoint is configured: ownership must not depend on that API.
        let http = MockHttp::new(vec![]);
        for required_org in ["liamhelmer", "LIAMHELMER", "LiamHelmer"] {
            check_org_membership("pat", required_org, "liamhelmer", &http)
                .await
                .expect("authenticated owner must pass without org-reading scopes");
        }
    }

    #[tokio::test]
    async fn test_check_org_membership_denies_non_member() {
        let http = MockHttp::new(vec![(
            "/user/orgs".to_string(),
            HttpResponse {
                status: 200,
                body: br#"[{"login":"some-other-org"}]"#.to_vec(),
            },
        )]);
        let result = check_org_membership("pat", "liamhelmer", "someone-else", &http).await;
        assert!(matches!(result, Err(ApiError::PermissionDenied { .. })));
    }

    #[tokio::test]
    async fn test_owner_federation_rejects_near_matches() {
        let http = MockHttp::new(vec![(
            "/user/orgs".to_string(),
            HttpResponse {
                status: 200,
                body: b"[]".to_vec(),
            },
        )]);
        for required_org in [
            "liamhelmer ",
            " liamhelmer",
            "liаmhelmer",
            "liamhelmer-extra",
            "",
        ] {
            let result = check_org_membership("pat", required_org, "liamhelmer", &http).await;
            assert!(
                matches!(result, Err(ApiError::PermissionDenied { .. })),
                "{required_org:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_non_owner_org_errors_fail_closed() {
        for (status, body) in [(403, "[]"), (500, "[]"), (200, "not json")] {
            let http = MockHttp::new(vec![(
                "/user/orgs".to_string(),
                HttpResponse {
                    status,
                    body: body.as_bytes().to_vec(),
                },
            )]);
            let result = check_org_membership("pat", "Epiphytic", "someone-else", &http).await;
            assert!(matches!(result, Err(ApiError::UpstreamError { .. })));
        }
        let result =
            check_org_membership("pat", "Epiphytic", "someone-else", &MockHttp::new(vec![])).await;
        assert!(matches!(result, Err(ApiError::UpstreamError { .. })));
    }

    #[tokio::test]
    async fn test_owner_exchange_still_validates_pat_and_repository() {
        use super::{handle, PatExchangeRequest};
        use crate::github::auth::PemJwtSigner;
        use crate::platform::cache_put;
        use crate::test_support::{MockCache, MockClock};

        let cache = MockCache::new();
        let policy = PatTrustPolicy {
            required_org: "liamhelmer".to_string(),
            permissions: HashMap::from([("contents".to_string(), "read".to_string())]),
            repositories: vec!["allowed".to_string()],
        };
        cache_put(&cache, "pat-policy:liamhelmer/denied:test", &policy, 300)
            .await
            .unwrap();
        // Signing must never be reached for any of these rejected requests.
        let signer = PemJwtSigner {
            app_id: "123".to_string(),
            pem_key: String::new(),
        };
        for (status, body, expected_status) in [
            (401, "{}", 400),
            (403, "{}", 403),
            (200, "{}", 502),
            (200, r#"{"login":"liamhelmer","id":123}"#, 403),
        ] {
            let http = MockHttp::new(vec![(
                "https://api.github.com/user".to_string(),
                HttpResponse {
                    status,
                    body: body.as_bytes().to_vec(),
                },
            )]);
            let result = handle(
                PatExchangeRequest {
                    scope: "liamhelmer/denied".to_string(),
                    identity: "test".to_string(),
                    bearer_token: "pat".to_string(),
                },
                &cache,
                &http,
                &MockClock(1706900000),
                &signer,
            )
            .await;
            let err = result
                .err()
                .expect("request must be rejected before token creation");
            assert_eq!(err.status_code(), expected_status);
            if status == 200 && body.contains("liamhelmer") {
                assert!(err
                    .to_string()
                    .contains("repository 'denied' is not allowed"));
            }
        }
    }

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
        assert_eq!(
            policy.permissions.get("contents"),
            Some(&"write".to_string())
        );
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

    #[test]
    fn test_check_repository_access_empty_list_allows_all() {
        let policy = PatTrustPolicy {
            required_org: "test".to_string(),
            permissions: HashMap::new(),
            repositories: vec![],
        };

        assert!(check_repository_access(&policy, "any-repo").is_ok());
        assert!(check_repository_access(&policy, ".github").is_ok());
    }

    #[test]
    fn test_check_repository_access_allowed() {
        let policy = PatTrustPolicy {
            required_org: "test".to_string(),
            permissions: HashMap::new(),
            repositories: vec!["repo-a".to_string(), "repo-b".to_string()],
        };

        assert!(check_repository_access(&policy, "repo-a").is_ok());
        assert!(check_repository_access(&policy, "repo-b").is_ok());
        assert!(check_repository_access(&policy, "REPO-A").is_ok());
    }

    #[test]
    fn test_check_repository_access_denied() {
        let policy = PatTrustPolicy {
            required_org: "test".to_string(),
            permissions: HashMap::new(),
            repositories: vec!["repo-a".to_string()],
        };

        let result = check_repository_access(&policy, "repo-c");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not allowed"));
    }
}
