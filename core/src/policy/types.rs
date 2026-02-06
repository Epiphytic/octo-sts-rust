//! Trust policy type definitions

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Repository-level trust policy (raw YAML structure)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrustPolicy {
    /// Exact issuer match
    #[serde(default)]
    pub issuer: Option<String>,

    /// Issuer regex pattern
    #[serde(default)]
    pub issuer_pattern: Option<String>,

    /// Exact subject match
    #[serde(default)]
    pub subject: Option<String>,

    /// Subject regex pattern
    #[serde(default)]
    pub subject_pattern: Option<String>,

    /// Exact audience match
    #[serde(default)]
    pub audience: Option<String>,

    /// Audience regex pattern
    #[serde(default)]
    pub audience_pattern: Option<String>,

    /// Custom claim patterns (key -> regex pattern)
    #[serde(default)]
    pub claim_patterns: HashMap<String, String>,

    /// GitHub permissions to grant
    #[serde(default)]
    pub permissions: HashMap<String, String>,
}

/// Organization-level trust policy (extends TrustPolicy with repo scoping)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OrgTrustPolicy {
    /// Base trust policy fields
    #[serde(flatten)]
    pub base: TrustPolicy,

    /// Optional list of repositories this policy applies to
    #[serde(default)]
    pub repositories: Vec<String>,
}

/// Policy type enum for parsing
pub enum PolicyType {
    Repo(TrustPolicy),
    Org(OrgTrustPolicy),
}

/// Compiled trust policy ready for matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPolicy {
    /// Exact issuer (if specified)
    pub issuer: Option<String>,

    /// Compiled issuer pattern (serialized as string)
    #[serde(skip)]
    pub issuer_regex: Option<Regex>,
    #[serde(default)]
    pub issuer_pattern: Option<String>,

    /// Exact subject (if specified)
    pub subject: Option<String>,

    /// Compiled subject pattern
    #[serde(skip)]
    pub subject_regex: Option<Regex>,
    #[serde(default)]
    pub subject_pattern: Option<String>,

    /// Exact audience (if specified)
    pub audience: Option<String>,

    /// Compiled audience pattern
    #[serde(skip)]
    pub audience_regex: Option<Regex>,
    #[serde(default)]
    pub audience_pattern: Option<String>,

    /// Compiled custom claim patterns
    #[serde(skip)]
    pub claim_regexes: HashMap<String, Regex>,
    #[serde(default)]
    pub claim_patterns: HashMap<String, String>,

    /// GitHub permissions to grant
    pub permissions: HashMap<String, String>,

    /// Repository restrictions (org policies only)
    #[serde(default)]
    pub repositories: Vec<String>,
}

impl CompiledPolicy {
    /// Recompile regex patterns from stored strings
    ///
    /// Called after deserializing from cache since Regex doesn't serialize
    pub fn recompile_patterns(&mut self) -> Result<(), regex::Error> {
        if let Some(ref pattern) = self.issuer_pattern {
            self.issuer_regex = Some(Regex::new(pattern)?);
        }
        if let Some(ref pattern) = self.subject_pattern {
            self.subject_regex = Some(Regex::new(pattern)?);
        }
        if let Some(ref pattern) = self.audience_pattern {
            self.audience_regex = Some(Regex::new(pattern)?);
        }
        for (key, pattern) in &self.claim_patterns {
            self.claim_regexes.insert(key.clone(), Regex::new(pattern)?);
        }
        Ok(())
    }
}
