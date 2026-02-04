//! Trust policy token checking
//!
//! Validates OIDC token claims against compiled trust policies.

use std::collections::HashMap;

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

    #[test]
    fn test_check_issuer_exact() {
        let claims = make_claims("https://example.com", "sub", vec!["aud"]);
        let mut policy = CompiledPolicy {
            issuer: Some("https://example.com".to_string()),
            issuer_regex: None,
            issuer_pattern: None,
            subject: Some("sub".to_string()),
            subject_regex: None,
            subject_pattern: None,
            audience: None,
            audience_regex: None,
            audience_pattern: None,
            claim_regexes: HashMap::new(),
            claim_patterns: HashMap::new(),
            permissions: HashMap::new(),
            repositories: vec![],
        };

        assert!(check_issuer(&claims, &policy).is_ok());

        policy.issuer = Some("https://other.com".to_string());
        assert!(check_issuer(&claims, &policy).is_err());
    }
}
