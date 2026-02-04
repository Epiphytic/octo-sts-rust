//! Trust policy compilation
//!
//! Validates and compiles trust policies, including regex pattern compilation.

use regex::Regex;
use std::collections::HashMap;

use super::types::{CompiledPolicy, PolicyType, TrustPolicy};
use crate::error::{ApiError, Result};

/// Compile a trust policy into a validated, ready-to-match form
pub fn compile_policy(policy: PolicyType) -> Result<CompiledPolicy> {
    match policy {
        PolicyType::Repo(p) => compile_trust_policy(p, vec![]),
        PolicyType::Org(p) => compile_trust_policy(p.base, p.repositories),
    }
}

fn compile_trust_policy(policy: TrustPolicy, repositories: Vec<String>) -> Result<CompiledPolicy> {
    // Validate: exactly one of issuer or issuer_pattern
    validate_exactly_one(
        policy.issuer.as_ref(),
        policy.issuer_pattern.as_ref(),
        "issuer",
    )?;

    // Validate: exactly one of subject or subject_pattern
    validate_exactly_one(
        policy.subject.as_ref(),
        policy.subject_pattern.as_ref(),
        "subject",
    )?;

    // Validate: at most one of audience or audience_pattern (both optional)
    if policy.audience.is_some() && policy.audience_pattern.is_some() {
        return Err(ApiError::invalid_request(
            "only one of audience or audience_pattern can be set",
        ));
    }

    // Compile patterns with anchoring
    let issuer_regex = policy
        .issuer_pattern
        .as_ref()
        .map(|p| compile_anchored_pattern(p))
        .transpose()?;

    let subject_regex = policy
        .subject_pattern
        .as_ref()
        .map(|p| compile_anchored_pattern(p))
        .transpose()?;

    let audience_regex = policy
        .audience_pattern
        .as_ref()
        .map(|p| compile_anchored_pattern(p))
        .transpose()?;

    // Compile claim patterns
    let mut claim_regexes = HashMap::new();
    let mut claim_patterns = HashMap::new();
    for (key, pattern) in policy.claim_patterns {
        let anchored = anchor_pattern(&pattern);
        let regex = Regex::new(&anchored).map_err(|e| {
            ApiError::invalid_request(format!("invalid regex for claim '{}': {}", key, e))
        })?;
        claim_regexes.insert(key.clone(), regex);
        claim_patterns.insert(key, anchored);
    }

    Ok(CompiledPolicy {
        issuer: policy.issuer,
        issuer_regex,
        issuer_pattern: policy.issuer_pattern.map(|p| anchor_pattern(&p)),
        subject: policy.subject,
        subject_regex,
        subject_pattern: policy.subject_pattern.map(|p| anchor_pattern(&p)),
        audience: policy.audience,
        audience_regex,
        audience_pattern: policy.audience_pattern.map(|p| anchor_pattern(&p)),
        claim_regexes,
        claim_patterns,
        permissions: policy.permissions,
        repositories,
    })
}

/// Validate that exactly one of the two options is set
fn validate_exactly_one(
    exact: Option<&String>,
    pattern: Option<&String>,
    field: &str,
) -> Result<()> {
    match (exact, pattern) {
        (None, None) => Err(ApiError::invalid_request(format!(
            "one of {} or {}_pattern must be set",
            field, field
        ))),
        (Some(_), Some(_)) => Err(ApiError::invalid_request(format!(
            "only one of {} or {}_pattern can be set",
            field, field
        ))),
        _ => Ok(()),
    }
}

/// Compile a pattern with automatic anchoring
fn compile_anchored_pattern(pattern: &str) -> Result<Regex> {
    let anchored = anchor_pattern(pattern);
    Regex::new(&anchored)
        .map_err(|e| ApiError::invalid_request(format!("invalid regex pattern: {}", e)))
}

/// Add anchors to a pattern if not already present
fn anchor_pattern(pattern: &str) -> String {
    let mut result = pattern.to_string();
    if !result.starts_with('^') {
        result = format!("^{}", result);
    }
    if !result.ends_with('$') {
        result = format!("{}$", result);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anchor_pattern() {
        assert_eq!(anchor_pattern("foo"), "^foo$");
        assert_eq!(anchor_pattern("^foo"), "^foo$");
        assert_eq!(anchor_pattern("foo$"), "^foo$");
        assert_eq!(anchor_pattern("^foo$"), "^foo$");
    }
}
