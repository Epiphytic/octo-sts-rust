//! octo-sts-core: Platform-agnostic core logic for the GitHub Security Token Service
//!
//! This crate contains all business logic for OIDC token exchange, trust policy
//! matching, and GitHub API interactions. It depends only on abstract platform
//! traits (Cache, HttpClient, Clock, Environment) and never imports
//! platform-specific code.

pub mod config;
pub mod error;
pub mod github;
pub mod oidc;
pub mod platform;
pub mod policy;
pub mod sts;

#[cfg(test)]
pub mod test_support;
