//! Trust policy token checking
//!
//! Validates OIDC token claims against compiled trust policies.

use super::types::CompiledPolicy;
use crate::error::{ApiError, Result};
use crate::oidc::OidcClaims;

/// Check if OIDC token claims match the trust policy
pub fn check_token(claims: &OidcClaims, policy: &CompiledPolicy, domain: &str) -> Result<()> {
    // Check issuer
    check_issuer(claims, policy)?;

    // Check subject
    check_subject(claims, policy)?;

    // Check audience
    check_audience(claims, policy, domain)?;

    // Check custom claims
    check_custom_claims(claims, policy)?;

    Ok(())
}

fn check_issuer(claims: &OidcClaims, policy: &CompiledPolicy) -> Result<()> {
    if let Some(ref exact) = policy.issuer {
        if claims.iss != *exact {
            return Err(ApiError::permission_denied(format!(
                "issuer mismatch: expected '{}', got '{}'",
                exact, claims.iss
            )));
        }
    } else if let Some(ref regex) = policy.issuer_regex {
        if !regex.is_match(&claims.iss) {
            return Err(ApiError::permission_denied(format!(
                "issuer '{}' does not match pattern",
                claims.iss
            )));
        }
    }
    Ok(())
}

fn check_subject(claims: &OidcClaims, policy: &CompiledPolicy) -> Result<()> {
    if let Some(ref exact) = policy.subject {
        if claims.sub != *exact {
            return Err(ApiError::permission_denied(format!(
                "subject mismatch: expected '{}', got '{}'",
                exact, claims.sub
            )));
        }
    } else if let Some(ref regex) = policy.subject_regex {
        if !regex.is_match(&claims.sub) {
            return Err(ApiError::permission_denied(format!(
                "subject '{}' does not match pattern",
                claims.sub
            )));
        }
    }
    Ok(())
}

fn check_audience(claims: &OidcClaims, policy: &CompiledPolicy, domain: &str) -> Result<()> {
    // If no audience specified in policy, default to domain
    let expected_audience = policy
        .audience
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or(domain);

    // Check if any audience in the token matches
    let audiences = &claims.aud;

    if let Some(ref regex) = policy.audience_regex {
        // Pattern matching: any audience must match
        if !audiences.iter().any(|a| regex.is_match(a)) {
            return Err(ApiError::permission_denied("no audience matches pattern"));
        }
    } else {
        // Exact matching: any audience must match expected
        if !audiences.iter().any(|a| a == expected_audience) {
            return Err(ApiError::permission_denied(format!(
                "audience mismatch: expected '{}', got {:?}",
                expected_audience, audiences
            )));
        }
    }

    Ok(())
}

fn check_custom_claims(claims: &OidcClaims, policy: &CompiledPolicy) -> Result<()> {
    for (claim_name, regex) in &policy.claim_regexes {
        let claim_value = claims.custom_claims.get(claim_name).ok_or_else(|| {
            ApiError::permission_denied(format!("missing required claim: {}", claim_name))
        })?;

        // Convert booleans to strings
        let value_str = match claim_value {
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => claim_value.to_string(),
        };

        if !regex.is_match(&value_str) {
            return Err(ApiError::permission_denied(format!(
                "claim '{}' value '{}' does not match pattern",
                claim_name, value_str
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;
    use std::collections::HashMap;

    fn make_claims(iss: &str, sub: &str, aud: Vec<&str>) -> OidcClaims {
        OidcClaims {
            iss: iss.to_string(),
            sub: sub.to_string(),
            aud: aud.into_iter().map(String::from).collect(),
            exp: 0,
            iat: 0,
            custom_claims: HashMap::new(),
        }
    }

    fn make_claims_with_custom(
        iss: &str,
        sub: &str,
        aud: Vec<&str>,
        custom: HashMap<String, serde_json::Value>,
    ) -> OidcClaims {
        OidcClaims {
            iss: iss.to_string(),
            sub: sub.to_string(),
            aud: aud.into_iter().map(String::from).collect(),
            exp: 0,
            iat: 0,
            custom_claims: custom,
        }
    }

    fn make_policy() -> CompiledPolicy {
        CompiledPolicy {
            issuer: Some("https://example.com".to_string()),
            issuer_regex: None,
            issuer_pattern: None,
            subject: Some("test-subject".to_string()),
            subject_regex: None,
            subject_pattern: None,
            audience: None,
            audience_regex: None,
            audience_pattern: None,
            claim_regexes: HashMap::new(),
            claim_patterns: HashMap::new(),
            permissions: HashMap::new(),
            repositories: vec![],
        }
    }

    #[test]
    fn test_check_issuer_exact() {
        let claims = make_claims("https://example.com", "sub", vec!["aud"]);
        let mut policy = make_policy();

        assert!(check_issuer(&claims, &policy).is_ok());

        policy.issuer = Some("https://other.com".to_string());
        assert!(check_issuer(&claims, &policy).is_err());
    }

    #[test]
    fn test_check_issuer_pattern() {
        let claims = make_claims("https://sub.example.com", "sub", vec!["aud"]);
        let mut policy = make_policy();
        policy.issuer = None;
        policy.issuer_regex = Some(Regex::new("^https://.*\\.example\\.com$").unwrap());

        assert!(check_issuer(&claims, &policy).is_ok());

        // Non-matching issuer
        let claims_bad = make_claims("https://other.com", "sub", vec!["aud"]);
        assert!(check_issuer(&claims_bad, &policy).is_err());
    }

    #[test]
    fn test_check_subject_exact() {
        let claims = make_claims("https://example.com", "test-subject", vec!["aud"]);
        let policy = make_policy();

        assert!(check_subject(&claims, &policy).is_ok());

        let claims_bad = make_claims("https://example.com", "wrong-subject", vec!["aud"]);
        assert!(check_subject(&claims_bad, &policy).is_err());
    }

    #[test]
    fn test_check_subject_pattern() {
        let claims = make_claims(
            "https://example.com",
            "repo:myorg/myrepo:ref:refs/heads/main",
            vec!["aud"],
        );
        let mut policy = make_policy();
        policy.subject = None;
        policy.subject_regex = Some(Regex::new("^repo:myorg/myrepo:.*$").unwrap());

        assert!(check_subject(&claims, &policy).is_ok());

        // Non-matching subject
        let claims_bad = make_claims(
            "https://example.com",
            "repo:other/repo:ref:main",
            vec!["aud"],
        );
        assert!(check_subject(&claims_bad, &policy).is_err());
    }

    #[test]
    fn test_check_audience_exact() {
        let claims = make_claims("https://example.com", "sub", vec!["my-audience"]);
        let mut policy = make_policy();
        policy.audience = Some("my-audience".to_string());

        assert!(check_audience(&claims, &policy, "default.com").is_ok());

        // Wrong audience
        let claims_bad = make_claims("https://example.com", "sub", vec!["wrong-audience"]);
        assert!(check_audience(&claims_bad, &policy, "default.com").is_err());
    }

    #[test]
    fn test_check_audience_defaults_to_domain() {
        let claims = make_claims("https://example.com", "sub", vec!["my-domain.com"]);
        let policy = make_policy(); // No audience set

        assert!(check_audience(&claims, &policy, "my-domain.com").is_ok());

        // Wrong audience when expecting domain
        let claims_bad = make_claims("https://example.com", "sub", vec!["wrong-domain.com"]);
        assert!(check_audience(&claims_bad, &policy, "my-domain.com").is_err());
    }

    #[test]
    fn test_check_audience_pattern() {
        let claims = make_claims(
            "https://example.com",
            "sub",
            vec!["https://my-app.example.com"],
        );
        let mut policy = make_policy();
        policy.audience_regex = Some(Regex::new("^https://.*\\.example\\.com$").unwrap());

        assert!(check_audience(&claims, &policy, "default.com").is_ok());

        // Non-matching audience pattern
        let claims_bad = make_claims(
            "https://example.com",
            "sub",
            vec!["https://my-app.other.com"],
        );
        assert!(check_audience(&claims_bad, &policy, "default.com").is_err());
    }

    #[test]
    fn test_check_audience_multiple() {
        let claims = make_claims(
            "https://example.com",
            "sub",
            vec!["other-aud", "my-audience", "third"],
        );
        let mut policy = make_policy();
        policy.audience = Some("my-audience".to_string());

        // Should match because "my-audience" is in the list
        assert!(check_audience(&claims, &policy, "default.com").is_ok());
    }

    #[test]
    fn test_check_custom_claims_string() {
        let custom = [(
            "job_workflow_ref".to_string(),
            serde_json::json!("myorg/workflows/.github/workflows/deploy.yaml@main"),
        )]
        .into_iter()
        .collect();
        let claims = make_claims_with_custom("https://example.com", "sub", vec!["aud"], custom);

        let mut policy = make_policy();
        policy.claim_regexes.insert(
            "job_workflow_ref".to_string(),
            Regex::new("^myorg/workflows/.*@main$").unwrap(),
        );

        assert!(check_custom_claims(&claims, &policy).is_ok());
    }

    #[test]
    fn test_check_custom_claims_boolean() {
        let custom = [("is_verified".to_string(), serde_json::json!(true))]
            .into_iter()
            .collect();
        let claims = make_claims_with_custom("https://example.com", "sub", vec!["aud"], custom);

        let mut policy = make_policy();
        policy
            .claim_regexes
            .insert("is_verified".to_string(), Regex::new("^true$").unwrap());

        assert!(check_custom_claims(&claims, &policy).is_ok());

        // Test false
        let custom_false = [("is_verified".to_string(), serde_json::json!(false))]
            .into_iter()
            .collect();
        let claims_false =
            make_claims_with_custom("https://example.com", "sub", vec!["aud"], custom_false);
        assert!(check_custom_claims(&claims_false, &policy).is_err());
    }

    #[test]
    fn test_check_custom_claims_missing() {
        let claims = make_claims("https://example.com", "sub", vec!["aud"]);
        let mut policy = make_policy();
        policy
            .claim_regexes
            .insert("required_claim".to_string(), Regex::new("^.*$").unwrap());

        let result = check_custom_claims(&claims, &policy);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("missing required claim"));
    }

    #[test]
    fn test_check_custom_claims_mismatch() {
        let custom = [("environment".to_string(), serde_json::json!("staging"))]
            .into_iter()
            .collect();
        let claims = make_claims_with_custom("https://example.com", "sub", vec!["aud"], custom);

        let mut policy = make_policy();
        policy.claim_regexes.insert(
            "environment".to_string(),
            Regex::new("^production$").unwrap(),
        );

        let result = check_custom_claims(&claims, &policy);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("does not match pattern"));
    }

    #[test]
    fn test_check_token_full_match() {
        let claims = make_claims("https://example.com", "test-subject", vec!["my-domain.com"]);
        let policy = make_policy();

        assert!(check_token(&claims, &policy, "my-domain.com").is_ok());
    }

    #[test]
    fn test_check_token_fails_on_issuer() {
        let claims = make_claims("https://wrong.com", "test-subject", vec!["my-domain.com"]);
        let policy = make_policy();

        let result = check_token(&claims, &policy, "my-domain.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("issuer"));
    }

    #[test]
    fn test_check_token_fails_on_subject() {
        let claims = make_claims(
            "https://example.com",
            "wrong-subject",
            vec!["my-domain.com"],
        );
        let policy = make_policy();

        let result = check_token(&claims, &policy, "my-domain.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("subject"));
    }

    #[test]
    fn test_check_token_fails_on_audience() {
        let claims = make_claims(
            "https://example.com",
            "test-subject",
            vec!["wrong-domain.com"],
        );
        let policy = make_policy();

        let result = check_token(&claims, &policy, "my-domain.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("audience"));
    }
}
