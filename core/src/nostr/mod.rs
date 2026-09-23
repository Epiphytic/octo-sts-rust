//! Strict NIP-98 authentication and explicit GitHub authorization.
mod assertion;
mod policy;
pub mod replay;
pub use assertion::{verify, Assertion, ExchangeRequest, MAX_AUTH, MAX_BODY, PATH};
pub use policy::Policy;

use crate::error::{ApiError, Result};
use crate::github::{api, auth};
use crate::platform::{Clock, HttpClient, JwtSigner};
use crate::sts::exchange_pat::ExchangeResponse;
use replay::ReplayStore;

/// Validate configuration before exposing the route. The audience is never inferred
/// from untrusted proxy headers. Operators must isolate independent replay stores.
pub fn validate_audience(audience: &str) -> Result<url::Url> {
    let url = url::Url::parse(audience).map_err(|_| ApiError::ServiceUnavailable)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.path() != PATH
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.as_str() != audience
    {
        return Err(ApiError::ServiceUnavailable);
    }
    Ok(url)
}

/// Authenticate first, authorize a fresh policy, atomically burn the nonce, then
/// mint exactly one repository's token. Upstream failures never relax scope.
pub async fn exchange(
    assertion: Assertion,
    store: &dyn ReplayStore,
    http: &dyn HttpClient,
    signer: &dyn JwtSigner,
    clock: &dyn Clock,
) -> Result<ExchangeResponse> {
    let (owner, repo) = assertion
        .request
        .scope
        .split_once('/')
        .ok_or_else(|| ApiError::invalid_request("invalid scope"))?;
    let path = format!(
        ".github/chainguard/{}.nostr.yaml",
        assertion.request.identity
    );
    let yaml = api::get_file_content(owner, ".github", &path, None, http, signer, clock)
        .await
        .map_err(|_| ApiError::permission_denied("Nostr policy unavailable"))?;
    let policy = Policy::parse(&yaml)?;
    policy.authorize(&assertion.public_key, repo)?;
    let installation = auth::get_installation_id(owner, signer, http, clock).await?;
    assertion.check_time(clock.now_secs())?;
    store.consume(&assertion.replay_claim()).await?;
    assertion.check_time(clock.now_secs())?;
    let (access_token, expiry) = auth::create_installation_token(
        installation,
        &[repo.to_owned()],
        &policy.permissions,
        signer,
        http,
        clock,
    )
    .await
    .map_err(|_| ApiError::upstream_error("GitHub token issuance failed"))?;
    let expires = chrono::DateTime::parse_from_rfc3339(&expiry)
        .map_err(|_| ApiError::upstream_error("invalid GitHub expiry"))?
        .timestamp();
    let expires_in = u64::try_from(expires)
        .unwrap_or(0)
        .saturating_sub(clock.now_secs());
    if expires_in == 0 {
        return Err(ApiError::upstream_error("expired GitHub token"));
    }
    Ok(ExchangeResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in,
    })
}

#[cfg(test)]
mod tests;
