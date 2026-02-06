//! OIDC (OpenID Connect) module
//!
//! Handles OIDC token validation including discovery, JWKS fetching, and claim verification.

mod discovery;
mod jwks;
mod validate;

pub use validate::{validate_token, OidcClaims};
