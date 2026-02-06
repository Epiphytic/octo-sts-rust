//! Trust policy compilation
//!
//! Validates and compiles trust policies, including regex pattern compilation.

use regex::Regex;
use std::collections::HashMap;

use super::types::{CompiledPolicy, PolicyType, TrustPolicy};
use crate::error::{ApiError, Result};

/// Maximum allowed length for regex patterns (to prevent abuse)
const MAX_PATTERN_LENGTH: usize = 256;

/// Maximum number of custom claim patterns allowed
const MAX_CLAIM_PATTERNS: usize = 10;

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

    // Validate pattern lengths to prevent abuse
    if let Some(ref p) = policy.issuer_pattern {
        validate_pattern_length(p, "issuer_pattern")?;
    }
    if let Some(ref p) = policy.subject_pattern {
        validate_pattern_length(p, "subject_pattern")?;
    }
    if let Some(ref p) = policy.audience_pattern {
        validate_pattern_length(p, "audience_pattern")?;
    }

    // Validate number of claim patterns
    if policy.claim_patterns.len() > MAX_CLAIM_PATTERNS {
        return Err(ApiError::invalid_request(format!(
            "too many claim patterns (max {})",
            MAX_CLAIM_PATTERNS
        )));
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
        validate_pattern_length(&pattern, &format!("claim pattern '{}'", key))?;
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

/// Validate pattern length to prevent ReDoS and abuse
fn validate_pattern_length(pattern: &str, field: &str) -> Result<()> {
    if pattern.len() > MAX_PATTERN_LENGTH {
        return Err(ApiError::invalid_request(format!(
            "{} is too long (max {} characters)",
            field, MAX_PATTERN_LENGTH
        )));
    }
    Ok(())
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
    use crate::policy::types::OrgTrustPolicy;

    #[test]
    fn test_anchor_pattern() {
        assert_eq!(anchor_pattern("foo"), "^foo$");
        assert_eq!(anchor_pattern("^foo"), "^foo$");
        assert_eq!(anchor_pattern("foo$"), "^foo$");
        assert_eq!(anchor_pattern("^foo$"), "^foo$");
    }

    #[test]
    fn test_compile_policy_with_exact_issuer_and_subject() {
        let policy = TrustPolicy {
            issuer: Some("https://example.com".to_string()),
            issuer_pattern: None,
            subject: Some("test-subject".to_string()),
            subject_pattern: None,
            audience: Some("my-audience".to_string()),
            audience_pattern: None,
            claim_patterns: HashMap::new(),
            permissions: [("contents".to_string(), "read".to_string())]
                .into_iter()
                .collect(),
        };

        let compiled = compile_policy(PolicyType::Repo(policy)).expect("Should compile");

        assert_eq!(compiled.issuer, Some("https://example.com".to_string()));
        assert!(compiled.issuer_regex.is_none());
        assert_eq!(compiled.subject, Some("test-subject".to_string()));
        assert!(compiled.subject_regex.is_none());
        assert_eq!(compiled.audience, Some("my-audience".to_string()));
        assert!(compiled.audience_regex.is_none());
        assert_eq!(
            compiled.permissions.get("contents"),
            Some(&"read".to_string())
        );
    }

    #[test]
    fn test_compile_policy_with_patterns() {
        let policy = TrustPolicy {
            issuer: None,
            issuer_pattern: Some("https://.*\\.example\\.com".to_string()),
            subject: None,
            subject_pattern: Some("repo:myorg/.*".to_string()),
            audience: None,
            audience_pattern: Some("https://.*".to_string()),
            claim_patterns: [("job_workflow_ref".to_string(), "myorg/.*".to_string())]
                .into_iter()
                .collect(),
            permissions: HashMap::new(),
        };

        let compiled = compile_policy(PolicyType::Repo(policy)).expect("Should compile");

        assert!(compiled.issuer.is_none());
        assert!(compiled.issuer_regex.is_some());
        assert!(compiled.subject.is_none());
        assert!(compiled.subject_regex.is_some());
        assert!(compiled.audience.is_none());
        assert!(compiled.audience_regex.is_some());
        assert_eq!(compiled.claim_regexes.len(), 1);

        // Verify patterns are anchored
        let issuer_regex = compiled.issuer_regex.as_ref().unwrap();
        assert!(issuer_regex.is_match("https://sub.example.com"));
        assert!(!issuer_regex.is_match("https://sub.example.com/extra"));
    }

    #[test]
    fn test_compile_policy_fails_without_issuer() {
        let policy = TrustPolicy {
            issuer: None,
            issuer_pattern: None,
            subject: Some("test".to_string()),
            subject_pattern: None,
            audience: None,
            audience_pattern: None,
            claim_patterns: HashMap::new(),
            permissions: HashMap::new(),
        };

        let result = compile_policy(PolicyType::Repo(policy));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("issuer"));
    }

    #[test]
    fn test_compile_policy_fails_without_subject() {
        let policy = TrustPolicy {
            issuer: Some("https://example.com".to_string()),
            issuer_pattern: None,
            subject: None,
            subject_pattern: None,
            audience: None,
            audience_pattern: None,
            claim_patterns: HashMap::new(),
            permissions: HashMap::new(),
        };

        let result = compile_policy(PolicyType::Repo(policy));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("subject"));
    }

    #[test]
    fn test_compile_policy_fails_with_both_issuer_and_pattern() {
        let policy = TrustPolicy {
            issuer: Some("https://example.com".to_string()),
            issuer_pattern: Some(".*".to_string()),
            subject: Some("test".to_string()),
            subject_pattern: None,
            audience: None,
            audience_pattern: None,
            claim_patterns: HashMap::new(),
            permissions: HashMap::new(),
        };

        let result = compile_policy(PolicyType::Repo(policy));
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_policy_fails_with_both_audience_and_pattern() {
        let policy = TrustPolicy {
            issuer: Some("https://example.com".to_string()),
            issuer_pattern: None,
            subject: Some("test".to_string()),
            subject_pattern: None,
            audience: Some("aud".to_string()),
            audience_pattern: Some(".*".to_string()),
            claim_patterns: HashMap::new(),
            permissions: HashMap::new(),
        };

        let result = compile_policy(PolicyType::Repo(policy));
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_policy_fails_with_invalid_regex() {
        let policy = TrustPolicy {
            issuer: None,
            issuer_pattern: Some("[invalid".to_string()),
            subject: Some("test".to_string()),
            subject_pattern: None,
            audience: None,
            audience_pattern: None,
            claim_patterns: HashMap::new(),
            permissions: HashMap::new(),
        };

        let result = compile_policy(PolicyType::Repo(policy));
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_org_policy_with_repositories() {
        let org_policy = OrgTrustPolicy {
            base: TrustPolicy {
                issuer: Some("https://accounts.google.com".to_string()),
                issuer_pattern: None,
                subject: None,
                subject_pattern: Some("^\\d+$".to_string()),
                audience: None,
                audience_pattern: None,
                claim_patterns: HashMap::new(),
                permissions: [("contents".to_string(), "read".to_string())]
                    .into_iter()
                    .collect(),
            },
            repositories: vec!["repo-a".to_string(), "repo-b".to_string()],
        };

        let compiled = compile_policy(PolicyType::Org(org_policy)).expect("Should compile");

        assert_eq!(compiled.repositories.len(), 2);
        assert!(compiled.repositories.contains(&"repo-a".to_string()));
        assert!(compiled.repositories.contains(&"repo-b".to_string()));
    }

    #[test]
    fn test_compile_policy_with_claim_patterns() {
        let policy = TrustPolicy {
            issuer: Some("https://example.com".to_string()),
            issuer_pattern: None,
            subject: Some("test".to_string()),
            subject_pattern: None,
            audience: None,
            audience_pattern: None,
            claim_patterns: [
                ("job_workflow_ref".to_string(), "myorg/.*@main".to_string()),
                ("environment".to_string(), "production".to_string()),
            ]
            .into_iter()
            .collect(),
            permissions: HashMap::new(),
        };

        let compiled = compile_policy(PolicyType::Repo(policy)).expect("Should compile");

        assert_eq!(compiled.claim_regexes.len(), 2);

        let job_ref_regex = compiled.claim_regexes.get("job_workflow_ref").unwrap();
        assert!(job_ref_regex.is_match("myorg/workflows@main"));
        assert!(!job_ref_regex.is_match("myorg/workflows@develop"));

        let env_regex = compiled.claim_regexes.get("environment").unwrap();
        assert!(env_regex.is_match("production"));
        assert!(!env_regex.is_match("staging"));
    }

    #[test]
    fn test_compile_policy_audience_is_optional() {
        let policy = TrustPolicy {
            issuer: Some("https://example.com".to_string()),
            issuer_pattern: None,
            subject: Some("test".to_string()),
            subject_pattern: None,
            audience: None,
            audience_pattern: None,
            claim_patterns: HashMap::new(),
            permissions: HashMap::new(),
        };

        let compiled = compile_policy(PolicyType::Repo(policy)).expect("Should compile");
        assert!(compiled.audience.is_none());
        assert!(compiled.audience_regex.is_none());
    }

    #[test]
    fn test_compile_policy_rejects_overly_long_pattern() {
        let long_pattern = "a".repeat(300);
        let policy = TrustPolicy {
            issuer: None,
            issuer_pattern: Some(long_pattern),
            subject: Some("test".to_string()),
            subject_pattern: None,
            audience: None,
            audience_pattern: None,
            claim_patterns: HashMap::new(),
            permissions: HashMap::new(),
        };

        let result = compile_policy(PolicyType::Repo(policy));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn test_compile_policy_rejects_too_many_claim_patterns() {
        let mut claim_patterns = HashMap::new();
        for i in 0..15 {
            claim_patterns.insert(format!("claim_{}", i), "value".to_string());
        }

        let policy = TrustPolicy {
            issuer: Some("https://example.com".to_string()),
            issuer_pattern: None,
            subject: Some("test".to_string()),
            subject_pattern: None,
            audience: None,
            audience_pattern: None,
            claim_patterns,
            permissions: HashMap::new(),
        };

        let result = compile_policy(PolicyType::Repo(policy));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too many"));
    }

    #[test]
    fn test_validate_pattern_length() {
        assert!(validate_pattern_length("^test$", "test").is_ok());

        let long_pattern = "a".repeat(300);
        let result = validate_pattern_length(&long_pattern, "test");
        assert!(result.is_err());
    }
}
