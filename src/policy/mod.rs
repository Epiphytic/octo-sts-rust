//! Trust policy module
//!
//! Handles parsing, compilation, and matching of trust policies.

mod check;
mod compile;
pub mod types;

pub use check::check_token;
pub use compile::compile_policy;
pub use types::{CompiledPolicy, OrgTrustPolicy, TrustPolicy};

use worker::Env;

use crate::config::POLICY_CACHE_TTL_SECS;
use crate::error::{ApiError, Result};
use crate::github;
use crate::kv;

/// Load a trust policy for the given scope and identity
///
/// Checks KV cache first, then fetches from GitHub if not cached.
pub async fn load(scope: &str, identity: &str, env: &Env) -> Result<CompiledPolicy> {
    let parts: Vec<&str> = scope.split('/').collect();
    if parts.len() != 2 {
        return Err(ApiError::invalid_request("scope must be in format owner/repo"));
    }
    let owner = parts[0];
    let repo = parts[1];

    let cache_key = format!("policy:{}:{}", scope, identity);

    // Try cache first
    if let Some(policy) = kv::get_cached_policy(&cache_key, env).await? {
        return Ok(policy);
    }

    // Fetch from GitHub
    let path = format!(".github/chainguard/{}.sts.yaml", identity);
    let yaml_content = github::api::get_file_content(owner, repo, &path, None, env).await?;

    // Parse and compile
    let is_org_policy = repo == ".github";
    let compiled = if is_org_policy {
        let policy: OrgTrustPolicy = serde_yaml::from_str(&yaml_content)
            .map_err(|e| ApiError::invalid_request(format!("invalid policy YAML: {}", e)))?;
        compile_policy(types::PolicyType::Org(policy))?
    } else {
        let policy: TrustPolicy = serde_yaml::from_str(&yaml_content)
            .map_err(|e| ApiError::invalid_request(format!("invalid policy YAML: {}", e)))?;
        compile_policy(types::PolicyType::Repo(policy))?
    };

    // Cache the compiled policy
    kv::cache_policy(&cache_key, &compiled, POLICY_CACHE_TTL_SECS, env).await?;

    Ok(compiled)
}
