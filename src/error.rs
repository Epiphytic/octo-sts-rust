//! Error types and HTTP response mapping

use serde::Serialize;
use thiserror::Error;
use worker::Response;

/// Result type alias for API operations
pub type Result<T> = std::result::Result<T, ApiError>;

/// API error with HTTP status code mapping
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("invalid request: {message}")]
    InvalidRequest { message: String },

    #[error("invalid token: {message}")]
    InvalidToken { message: String },

    #[error("token verification failed: {message}")]
    TokenVerificationFailed { message: String },

    #[error("permission denied: {message}")]
    PermissionDenied { message: String },

    #[error("policy not found: {message}")]
    PolicyNotFound { message: String },

    #[error("installation not found: {message}")]
    InstallationNotFound { message: String },

    #[error("internal error: {message}")]
    Internal { message: String },

    #[error("upstream error: {message}")]
    UpstreamError { message: String },

    #[error("upstream timeout")]
    UpstreamTimeout,
}

impl ApiError {
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::InvalidRequest {
            message: message.into(),
        }
    }

    pub fn invalid_token(message: impl Into<String>) -> Self {
        Self::InvalidToken {
            message: message.into(),
        }
    }

    pub fn token_verification_failed(message: impl Into<String>) -> Self {
        Self::TokenVerificationFailed {
            message: message.into(),
        }
    }

    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::PermissionDenied {
            message: message.into(),
        }
    }

    pub fn policy_not_found(message: impl Into<String>) -> Self {
        Self::PolicyNotFound {
            message: message.into(),
        }
    }

    pub fn installation_not_found(message: impl Into<String>) -> Self {
        Self::InstallationNotFound {
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    pub fn upstream_error(message: impl Into<String>) -> Self {
        Self::UpstreamError {
            message: message.into(),
        }
    }

    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            Self::InvalidRequest { .. } => 400,
            Self::InvalidToken { .. } => 400,
            Self::TokenVerificationFailed { .. } => 401,
            Self::PermissionDenied { .. } => 403,
            Self::PolicyNotFound { .. } => 404,
            Self::InstallationNotFound { .. } => 404,
            Self::Internal { .. } => 500,
            Self::UpstreamError { .. } => 502,
            Self::UpstreamTimeout => 504,
        }
    }

    /// Get the error key for this error
    pub fn error_key(&self) -> &'static str {
        match self {
            Self::InvalidRequest { .. } => "invalid_request",
            Self::InvalidToken { .. } => "invalid_token",
            Self::TokenVerificationFailed { .. } => "token_verification_failed",
            Self::PermissionDenied { .. } => "permission_denied",
            Self::PolicyNotFound { .. } => "policy_not_found",
            Self::InstallationNotFound { .. } => "installation_not_found",
            Self::Internal { .. } => "internal_error",
            Self::UpstreamError { .. } => "upstream_error",
            Self::UpstreamTimeout => "upstream_timeout",
        }
    }

    /// Convert to HTTP response
    pub fn into_response(self) -> worker::Result<Response> {
        let status = self.status_code();
        let body = ErrorResponse {
            error: self.error_key().to_string(),
            message: self.to_string(),
        };

        Response::from_json(&body).map(|r| r.with_status(status))
    }
}

/// Error response body
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
}
