//! State transition shared by atomic platform adapters. Never use Cache here.
use crate::error::{ApiError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub principal: String,
    pub key: String,
    pub expires_at: u64,
}

#[async_trait::async_trait(?Send)]
pub trait ReplayStore {
    /// Atomically consume and enforce a per-principal issuance limit. Fail closed
    /// on timeouts, contention exhaustion, or uncertain writes.
    async fn consume(&self, claim: &Claim) -> Result<()>;
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct ReplayState {
    nonces: BTreeMap<String, u64>,
    minute: u64,
    count: u32,
}

impl ReplayState {
    pub fn expires_at(&self) -> Result<String> {
        let expiry = self
            .nonces
            .values()
            .copied()
            .max()
            .ok_or(ApiError::ServiceUnavailable)?;
        let seconds = i64::try_from(expiry).map_err(|_| ApiError::ServiceUnavailable)?;
        Ok(chrono::DateTime::from_timestamp(seconds, 0)
            .ok_or(ApiError::ServiceUnavailable)?
            .to_rfc3339())
    }

    pub fn prune(&mut self, now: u64) {
        self.nonces.retain(|_, expiry| *expiry > now);
    }

    /// Call inside the database transaction; persist only a successful transition.
    pub fn consume(&mut self, claim: &Claim, now: u64, limit: u32) -> Result<()> {
        if !super::assertion::is_hex(&claim.key, 32)
            || !super::assertion::is_hex(&claim.principal, 32)
            || claim.expires_at <= now
            || claim.expires_at > now.saturating_add(185)
            || limit == 0
            || limit > 100
        {
            return Err(ApiError::ServiceUnavailable);
        }
        self.nonces.retain(|_, expiry| *expiry > now);
        if self.nonces.contains_key(&claim.key) {
            return Err(ApiError::token_verification_failed(
                "replayed Nostr assertion",
            ));
        }
        if self.minute != now / 60 {
            self.minute = now / 60;
            self.count = 0;
        }
        if self.count >= limit {
            return Err(ApiError::RateLimited);
        }
        self.count += 1;
        self.nonces.insert(claim.key.clone(), claim.expires_at);
        Ok(())
    }
}
