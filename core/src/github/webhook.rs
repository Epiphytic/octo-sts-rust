//! GitHub webhook handling
//!
//! Verifies webhook signatures and processes events for trust policy validation.

use serde::Deserialize;

use crate::config::Config;
use crate::error::{ApiError, Result};
use crate::github::api;
use crate::platform::{Environment, HttpClient, JwtSigner};
use crate::policy;

const POLICY_PATH_PREFIX: &str = ".github/chainguard/";
const POLICY_PATH_SUFFIX: &str = ".sts.yaml";

/// Handle incoming webhook request (platform adapter provides parsed body and headers)
pub async fn handle(
    body: &str,
    signature: &str,
    event_type: &str,
    http: &dyn HttpClient,
    env: &dyn Environment,
    signer: &dyn JwtSigner,
) -> Result<()> {
    let config = Config::from_env(env)?;

    // Verify signature
    verify_signature(body, signature, &config.github_webhook_secret)?;

    // Process based on event type
    match event_type {
        "push" => handle_push_event(body, http, signer).await,
        "pull_request" => handle_pull_request_event(body).await,
        "check_suite" => handle_check_suite_event(body).await,
        _ => Ok(()),
    }
}

/// Verify webhook signature using HMAC-SHA256
pub fn verify_signature(body: &str, signature: &str, secret: &str) -> Result<()> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let expected_prefix = "sha256=";
    if !signature.starts_with(expected_prefix) {
        return Err(ApiError::invalid_request("invalid signature format"));
    }
    let signature_hex = &signature[expected_prefix.len()..];

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| ApiError::internal("failed to create HMAC"))?;
    mac.update(body.as_bytes());

    let expected = hex::decode(signature_hex)
        .map_err(|_| ApiError::invalid_request("invalid signature hex"))?;

    mac.verify_slice(&expected)
        .map_err(|_| ApiError::invalid_request("signature verification failed"))
}

#[derive(Deserialize)]
struct PushEvent {
    repository: Repository,
    commits: Vec<Commit>,
    after: String,
}

#[derive(Deserialize)]
struct PullRequestEvent {
    action: String,
    #[allow(dead_code)]
    pull_request: PullRequest,
    #[allow(dead_code)]
    repository: Repository,
}

#[derive(Deserialize)]
struct CheckSuiteEvent {
    action: String,
    #[allow(dead_code)]
    check_suite: CheckSuite,
    #[allow(dead_code)]
    repository: Repository,
}

#[derive(Deserialize)]
struct Repository {
    owner: RepositoryOwner,
    name: String,
}

#[derive(Deserialize)]
struct RepositoryOwner {
    login: String,
}

#[derive(Deserialize)]
struct Commit {
    #[allow(dead_code)]
    id: String,
    added: Vec<String>,
    modified: Vec<String>,
}

#[derive(Deserialize)]
struct PullRequest {
    head: PullRequestHead,
}

#[derive(Deserialize)]
struct PullRequestHead {
    #[allow(dead_code)]
    sha: String,
}

#[derive(Deserialize)]
struct CheckSuite {
    #[allow(dead_code)]
    head_sha: String,
}

async fn handle_push_event(body: &str, http: &dyn HttpClient, signer: &dyn JwtSigner) -> Result<()> {
    let event: PushEvent =
        serde_json::from_str(body).map_err(|e| ApiError::invalid_request(format!("invalid JSON: {}", e)))?;

    let owner = &event.repository.owner.login;
    let repo = &event.repository.name;
    let head_sha = &event.after;

    let policy_files: Vec<&str> = event
        .commits
        .iter()
        .flat_map(|c| c.added.iter().chain(c.modified.iter()))
        .filter(|f| is_policy_file(f))
        .map(|s| s.as_str())
        .collect();

    validate_policy_files(owner, repo, head_sha, &policy_files, http, signer).await
}

async fn handle_pull_request_event(body: &str) -> Result<()> {
    let event: PullRequestEvent =
        serde_json::from_str(body).map_err(|e| ApiError::invalid_request(format!("invalid JSON: {}", e)))?;

    if event.action != "opened" && event.action != "synchronize" && event.action != "reopened" {
        return Ok(());
    }

    // TODO: Fetch changed files from PR API
    Ok(())
}

async fn handle_check_suite_event(body: &str) -> Result<()> {
    let event: CheckSuiteEvent =
        serde_json::from_str(body).map_err(|e| ApiError::invalid_request(format!("invalid JSON: {}", e)))?;

    if event.action != "requested" && event.action != "rerequested" {
        return Ok(());
    }

    // TODO: Implement check suite handling
    Ok(())
}

fn is_policy_file(path: &str) -> bool {
    path.starts_with(POLICY_PATH_PREFIX) && path.ends_with(POLICY_PATH_SUFFIX)
}

async fn validate_policy_files(
    owner: &str,
    repo: &str,
    head_sha: &str,
    files: &[&str],
    http: &dyn HttpClient,
    signer: &dyn JwtSigner,
) -> Result<()> {
    for file in files {
        let result = validate_single_policy(owner, repo, file, head_sha, http, signer).await;

        let (conclusion, title, summary) = match result {
            Ok(()) => ("success", "Policy valid", format!("{} is valid", file)),
            Err(e) => (
                "failure",
                "Policy invalid",
                format!("{}: {}", file, e),
            ),
        };

        let check_name = format!("octo-sts: {}", file);
        api::create_check_run(owner, repo, head_sha, &check_name, conclusion, title, &summary, http, signer)
            .await?;
    }

    Ok(())
}

async fn validate_single_policy(
    owner: &str,
    repo: &str,
    path: &str,
    git_ref: &str,
    http: &dyn HttpClient,
    signer: &dyn JwtSigner,
) -> Result<()> {
    let content = api::get_file_content(owner, repo, path, Some(git_ref), http, signer).await?;

    let is_org_policy = repo == ".github";

    if is_org_policy {
        let p: policy::OrgTrustPolicy = serde_yaml::from_str(&content)
            .map_err(|e| ApiError::invalid_request(format!("invalid YAML: {}", e)))?;
        policy::compile_policy(policy::types::PolicyType::Org(p))?;
    } else {
        let p: policy::TrustPolicy = serde_yaml::from_str(&content)
            .map_err(|e| ApiError::invalid_request(format!("invalid YAML: {}", e)))?;
        policy::compile_policy(policy::types::PolicyType::Repo(p))?;
    }

    Ok(())
}
