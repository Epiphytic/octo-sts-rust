//! GitHub webhook handling
//!
//! Verifies webhook signatures and processes events for trust policy validation.

use serde::Deserialize;
use worker::{Env, Request};

use crate::config::Config;
use crate::error::{ApiError, Result};
use crate::github::api;
use crate::policy;

const POLICY_PATH_PREFIX: &str = ".github/chainguard/";
const POLICY_PATH_SUFFIX: &str = ".sts.yaml";

/// Handle incoming webhook request
pub async fn handle(mut req: Request, env: &Env) -> Result<()> {
    let config = Config::from_env(env)?;

    // Get raw body for signature verification
    let body = req
        .text()
        .await
        .map_err(|_| ApiError::invalid_request("failed to read request body"))?;

    // Verify signature
    let signature = req
        .headers()
        .get("X-Hub-Signature-256")
        .map_err(|_| ApiError::invalid_request("failed to read headers"))?
        .ok_or_else(|| ApiError::invalid_request("missing X-Hub-Signature-256 header"))?;

    verify_signature(&body, &signature, &config.github_webhook_secret)?;

    // Get event type
    let event_type = req
        .headers()
        .get("X-GitHub-Event")
        .map_err(|_| ApiError::invalid_request("failed to read headers"))?
        .ok_or_else(|| ApiError::invalid_request("missing X-GitHub-Event header"))?;

    // Process based on event type
    match event_type.as_str() {
        "push" => handle_push_event(&body, env).await,
        "pull_request" => handle_pull_request_event(&body, env).await,
        "check_suite" => handle_check_suite_event(&body, env).await,
        _ => Ok(()), // Ignore other events
    }
}

/// Verify webhook signature using HMAC-SHA256
fn verify_signature(body: &str, signature: &str, secret: &str) -> Result<()> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // Signature format: sha256=<hex>
    let expected_prefix = "sha256=";
    if !signature.starts_with(expected_prefix) {
        return Err(ApiError::invalid_request("invalid signature format"));
    }
    let signature_hex = &signature[expected_prefix.len()..];

    // Compute HMAC
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| ApiError::internal("failed to create HMAC"))?;
    mac.update(body.as_bytes());

    // Decode expected signature
    let expected = hex::decode(signature_hex)
        .map_err(|_| ApiError::invalid_request("invalid signature hex"))?;

    // Constant-time comparison
    mac.verify_slice(&expected)
        .map_err(|_| ApiError::invalid_request("signature verification failed"))
}

#[derive(Deserialize)]
struct PushEvent {
    repository: Repository,
    commits: Vec<Commit>,
    after: String, // HEAD commit SHA
}

#[derive(Deserialize)]
struct PullRequestEvent {
    action: String,
    pull_request: PullRequest,
    repository: Repository,
}

#[derive(Deserialize)]
struct CheckSuiteEvent {
    action: String,
    check_suite: CheckSuite,
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
    sha: String,
}

#[derive(Deserialize)]
struct CheckSuite {
    head_sha: String,
}

async fn handle_push_event(body: &str, env: &Env) -> Result<()> {
    let event: PushEvent =
        serde_json::from_str(body).map_err(|e| ApiError::invalid_request(format!("invalid JSON: {}", e)))?;

    let owner = &event.repository.owner.login;
    let repo = &event.repository.name;
    let head_sha = &event.after;

    // Find policy files that were added or modified
    let policy_files: Vec<&str> = event
        .commits
        .iter()
        .flat_map(|c| c.added.iter().chain(c.modified.iter()))
        .filter(|f| is_policy_file(f))
        .map(|s| s.as_str())
        .collect();

    validate_policy_files(owner, repo, head_sha, &policy_files, env).await
}

async fn handle_pull_request_event(body: &str, env: &Env) -> Result<()> {
    let event: PullRequestEvent =
        serde_json::from_str(body).map_err(|e| ApiError::invalid_request(format!("invalid JSON: {}", e)))?;

    // Only process opened and synchronize actions
    if event.action != "opened" && event.action != "synchronize" && event.action != "reopened" {
        return Ok(());
    }

    let owner = &event.repository.owner.login;
    let repo = &event.repository.name;
    let head_sha = &event.pull_request.head.sha;

    // For PRs, we'd need to fetch the list of changed files
    // For now, we'll validate all policy files at the head SHA
    // TODO: Fetch changed files from PR API

    Ok(())
}

async fn handle_check_suite_event(body: &str, env: &Env) -> Result<()> {
    let event: CheckSuiteEvent =
        serde_json::from_str(body).map_err(|e| ApiError::invalid_request(format!("invalid JSON: {}", e)))?;

    if event.action != "requested" && event.action != "rerequested" {
        return Ok(());
    }

    // Similar to PR - would need to determine which files to validate
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
    env: &Env,
) -> Result<()> {
    for file in files {
        let result = validate_single_policy(owner, repo, file, head_sha, env).await;

        let (conclusion, title, summary) = match result {
            Ok(()) => ("success", "Policy valid", format!("{} is valid", file)),
            Err(e) => (
                "failure",
                "Policy invalid",
                format!("{}: {}", file, e),
            ),
        };

        // Create check run with result
        let check_name = format!("octo-sts: {}", file);
        api::create_check_run(owner, repo, head_sha, &check_name, conclusion, title, &summary, env)
            .await?;
    }

    Ok(())
}

async fn validate_single_policy(
    owner: &str,
    repo: &str,
    path: &str,
    git_ref: &str,
    env: &Env,
) -> Result<()> {
    // Fetch the policy file
    let content = api::get_file_content(owner, repo, path, Some(git_ref), env).await?;

    // Determine if it's an org policy or repo policy
    let is_org_policy = repo == ".github";

    // Parse and compile to validate
    if is_org_policy {
        let policy: policy::OrgTrustPolicy = serde_yaml::from_str(&content)
            .map_err(|e| ApiError::invalid_request(format!("invalid YAML: {}", e)))?;
        policy::compile_policy(policy::types::PolicyType::Org(policy))?;
    } else {
        let policy: policy::TrustPolicy = serde_yaml::from_str(&content)
            .map_err(|e| ApiError::invalid_request(format!("invalid YAML: {}", e)))?;
        policy::compile_policy(policy::types::PolicyType::Repo(policy))?;
    }

    Ok(())
}
