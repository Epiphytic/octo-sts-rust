//! KV cache operations
//!
//! Type-safe caching with TTL for installation IDs and trust policies.

use serde::{Deserialize, Serialize};
use worker::kv::KvStore;
use worker::Env;

use crate::config::{Config, INSTALL_CACHE_TTL_SECS, KV_BINDING};
use crate::error::{ApiError, Result};
use crate::github::auth;
use crate::policy::CompiledPolicy;

/// Cached installation ID
#[derive(Serialize, Deserialize)]
struct CachedInstallation {
    id: u64,
    cached_at: u64,
}

/// Get KV store binding
fn get_kv(env: &Env) -> Result<KvStore> {
    env.kv(KV_BINDING)
        .map_err(|_| ApiError::internal(format!("KV binding '{}' not found", KV_BINDING)))
}

/// Get installation ID from cache or fetch from GitHub
pub async fn get_or_fetch_installation(owner: &str, env: &Env, config: &Config) -> Result<u64> {
    let kv = get_kv(env)?;
    let cache_key = format!("install:{}", owner);

    // Try cache first
    if let Ok(Some(cached)) = kv.get(&cache_key).json::<CachedInstallation>().await {
        return Ok(cached.id);
    }

    // Fetch from GitHub
    let installation_id = auth::get_installation_id(owner, config).await?;

    // Cache the result
    let cached = CachedInstallation {
        id: installation_id,
        cached_at: current_timestamp(),
    };

    let _ = kv
        .put(&cache_key, serde_json::to_string(&cached).unwrap_or_default())
        .map(|b| b.expiration_ttl(INSTALL_CACHE_TTL_SECS))
        .map(|b| b.execute());

    Ok(installation_id)
}

/// Get cached trust policy
pub async fn get_cached_policy(cache_key: &str, env: &Env) -> Result<Option<CompiledPolicy>> {
    let kv = get_kv(env)?;

    match kv.get(cache_key).json::<CompiledPolicy>().await {
        Ok(Some(mut policy)) => {
            // Recompile regex patterns (they don't serialize)
            if let Err(e) = policy.recompile_patterns() {
                // Log error but return None to force refetch
                worker::console_log!("Failed to recompile cached policy patterns: {}", e);
                return Ok(None);
            }
            Ok(Some(policy))
        }
        Ok(None) => Ok(None),
        Err(e) => {
            // Log error but return None to force refetch
            worker::console_log!("Failed to read cached policy: {}", e);
            Ok(None)
        }
    }
}

/// Cache a compiled trust policy
pub async fn cache_policy(cache_key: &str, policy: &CompiledPolicy, ttl_secs: u64, env: &Env) -> Result<()> {
    let kv = get_kv(env)?;

    let value = serde_json::to_string(policy)
        .map_err(|e| ApiError::internal(format!("failed to serialize policy: {}", e)))?;

    kv.put(cache_key, value)
        .map_err(|e| ApiError::internal(format!("failed to create KV put: {}", e)))?
        .expiration_ttl(ttl_secs)
        .execute()
        .await
        .map_err(|e| ApiError::internal(format!("failed to cache policy: {}", e)))?;

    Ok(())
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}
