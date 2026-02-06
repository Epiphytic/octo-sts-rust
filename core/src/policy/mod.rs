//! Trust policy module
//!
//! Handles parsing, compilation, and matching of trust policies.

mod check;
mod compile;
pub mod types;

pub use check::{check_token, check_token_with_repo};
pub use compile::compile_policy;
pub use types::{CompiledPolicy, OrgTrustPolicy, TrustPolicy};

use crate::config::POLICY_CACHE_TTL_SECS;
use crate::error::{ApiError, Result};
use crate::github;
use crate::platform::{cache_get, cache_put, Cache, Environment, HttpClient};

/// Validate identity parameter to prevent path traversal attacks.
/// Identity must contain only alphanumeric characters, hyphens, and underscores.
pub fn validate_identity(identity: &str) -> Result<()> {
    if identity.is_empty() {
        return Err(ApiError::invalid_request("identity cannot be empty"));
    }

    if identity.len() > 64 {
        return Err(ApiError::invalid_request("identity too long (max 64 characters)"));
    }

    // Check for path traversal sequences
    if identity.contains("..") || identity.contains('/') || identity.contains('\\') {
        return Err(ApiError::invalid_request(
            "identity contains invalid characters (path traversal attempt)",
        ));
    }

    // Only allow alphanumeric, hyphens, and underscores
    for c in identity.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            return Err(ApiError::invalid_request(format!(
                "identity contains invalid character: '{}'",
                c
            )));
        }
    }

    Ok(())
}

/// Load a trust policy for the given scope and identity
///
/// Checks cache first, then fetches from GitHub if not cached.
pub async fn load(
    scope: &str,
    identity: &str,
    cache: &dyn Cache,
    http: &dyn HttpClient,
    env: &dyn Environment,
) -> Result<CompiledPolicy> {
    // Validate identity to prevent path traversal
    validate_identity(identity)?;

    let parts: Vec<&str> = scope.split('/').collect();
    if parts.len() != 2 {
        return Err(ApiError::invalid_request("scope must be in format owner/repo"));
    }
    let owner = parts[0];
    let repo = parts[1];

    let cache_key = format!("policy:{}:{}", scope, identity);

    // Try cache first
    if let Some(mut policy) = cache_get::<CompiledPolicy>(cache, &cache_key).await? {
        if let Err(_e) = policy.recompile_patterns() {
            // Cache entry had bad patterns, fall through to refetch
        } else {
            return Ok(policy);
        }
    }

    // Fetch from GitHub
    let path = format!(".github/chainguard/{}.sts.yaml", identity);
    let yaml_content = github::api::get_file_content(owner, repo, &path, None, http, env).await?;

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
    let _ = cache_put(cache, &cache_key, &compiled, POLICY_CACHE_TTL_SECS).await;

    Ok(compiled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_identity_valid() {
        assert!(validate_identity("my-policy").is_ok());
        assert!(validate_identity("my_policy").is_ok());
        assert!(validate_identity("MyPolicy123").is_ok());
        assert!(validate_identity("org-member").is_ok());
        assert!(validate_identity("test").is_ok());
    }

    #[test]
    fn test_validate_identity_empty() {
        let result = validate_identity("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_validate_identity_too_long() {
        let long_identity = "a".repeat(65);
        let result = validate_identity(&long_identity);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn test_validate_identity_path_traversal() {
        // Direct path traversal
        let result = validate_identity("../../../etc/passwd");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("path traversal"));

        // Hidden path traversal
        let result = validate_identity("policy..name");
        assert!(result.is_err());

        // Forward slash
        let result = validate_identity("path/to/file");
        assert!(result.is_err());

        // Backslash
        let result = validate_identity("path\\to\\file");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_identity_invalid_characters() {
        // Space
        let result = validate_identity("my policy");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid character"));

        // Special characters
        assert!(validate_identity("policy@name").is_err());
        assert!(validate_identity("policy.name").is_err());
        assert!(validate_identity("policy:name").is_err());
        assert!(validate_identity("policy;name").is_err());
    }
}
